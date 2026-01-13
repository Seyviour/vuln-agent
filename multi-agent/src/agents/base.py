"""
Refactored base agent class with improved tool execution.

This module provides:
- BaseAgent abstract class with common functionality
- Better tool execution with error handling
- Prompt management utilities
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
import json
import logging

import httpx
from openai import AsyncOpenAI

from ..utils.types import AgentOutput, ToolResult, ToolCallRecord
from ..utils.exceptions import (
    AgentError,
    AgentExecutionError,
    AgentOutputParsingError,
    ToolNotFoundError,
    ToolNotAllowedError,
    ToolExecutionError,
)
from ..utils.constants import (
    MAX_TOOL_ITERATIONS_PER_AGENT,
)


logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Base class for all agents.
    
    Provides:
    - LLM client management
    - Tool execution with access control
    - Structured output handling
    - Logging and debugging utilities
    """
    
    # Subclasses should set these
    name: str = "BaseAgent"
    description: str = "Base agent class"
    
    def __init__(
        self,
        llm_config: "LLMConfig",
        tool_registry: Optional["ToolRegistry"] = None,
        allowed_tools: Optional[List[str]] = None
    ):
        """
        Initialize agent.
        
        Args:
            llm_config: LLM configuration
            tool_registry: Registry of available tools
            allowed_tools: List of tool names this agent can use
        """
        self.llm_config = llm_config
        self.tool_registry = tool_registry
        self.allowed_tools = allowed_tools or []
        self._model = None
        self._last_token_usage: Dict[str, int] = {}
        self._last_llm_calls: int = 0
        self._session_id: Optional[str] = None
        self._session_db_path: Optional[str] = None
        self._current_system_prompt: Optional[str] = None

    def set_session(self, session_id: Optional[str], db_path: Optional[str]) -> None:
        """Configure persistent session memory for this agent."""
        self._session_id = session_id
        self._session_db_path = db_path
    
    def _get_model(self):
        """Lazy-load the Agents SDK model with the configured provider."""
        if self._model is None:
            from agents import OpenAIProvider
            openai_client = AsyncOpenAI(
                api_key=self.llm_config.api_key,
                http_client=httpx.AsyncClient(),
            )
            provider = OpenAIProvider(
                openai_client=openai_client,
                use_responses=True,
            )
            self._model = provider.get_model(self.llm_config.model)
        return self._model
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent."""
        pass
    
    @abstractmethod
    def run(self, context: Dict[str, Any]) -> AgentOutput:
        """Run the agent with the given context."""
        pass
    
    def _build_agent_tools(
        self,
        tool_calls_log: List[ToolCallRecord],
    ) -> List[Any]:
        """Build Agents SDK tools from the registry."""
        if not self.tool_registry or not self.allowed_tools:
            return []

        from agents.tool import FunctionTool

        tools: List[Any] = []
        schemas = self.tool_registry.get_schemas(self.allowed_tools)
        for schema in schemas:
            tool_name = schema.get("name")
            if not tool_name:
                continue
            description = schema.get("description", "")
            params_schema = schema.get("parameters", {"type": "object", "properties": {}})

            async def _invoke(tool_ctx, args_json: str, *, _tool_name=tool_name) -> str:
                try:
                    arguments = json.loads(args_json) if args_json else {}
                except json.JSONDecodeError:
                    arguments = {}
                    logger.warning(f"Failed to parse tool arguments: {args_json}")

                result = self._execute_tool(_tool_name, arguments)
                tool_calls_log.append({
                    "tool": _tool_name,
                    "arguments": arguments,
                    "result": {
                        "success": result.success,
                        "output": result.output,
                        "error": result.error,
                        "metadata": result.metadata,
                    },
                    "success": result.success,
                    "system_prompt": self._current_system_prompt,
                })
                return result.output if result.success else f"Error: {result.error}"

            tools.append(
                FunctionTool(
                    name=tool_name,
                    description=description,
                    params_json_schema=params_schema,
                    on_invoke_tool=_invoke,
                    strict_json_schema=True,
                )
            )

        return tools

    def _execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> ToolResult:
        """
        Execute a tool by name with given arguments.
        
        Args:
            tool_name: Name of the tool to execute
            arguments: Arguments for the tool
        
        Returns:
            ToolResult from execution
        
        Raises:
            ToolNotFoundError: If tool doesn't exist
            ToolNotAllowedError: If tool isn't allowed for this agent
        """
        if self.tool_registry is None:
            return ToolResult(
                success=False,
                output="",
                error="No tool registry available"
            )
        
        if tool_name not in self.allowed_tools:
            logger.warning(f"{self.name} tried to use disallowed tool: {tool_name}")
            return ToolResult(
                success=False,
                output="",
                error=f"Tool '{tool_name}' is not allowed for {self.name}. "
                      f"Allowed tools: {self.allowed_tools}"
            )
        
        tool = self.tool_registry.get_tool(tool_name)
        if tool is None:
            return ToolResult(
                success=False,
                output="",
                error=f"Tool '{tool_name}' not found in registry"
            )
        
        logger.info(f"{self.name} executing tool: {tool_name}")
        logger.info(f"Tool arguments:\n{json.dumps(arguments, indent=2)}")
        
        try:
            result = tool.execute(**arguments)
            logger.info(f"Tool {tool_name}: {'✓' if result.success else '✗'}")
            if result.error:
                logger.info(f"Tool {tool_name} error: {result.error}")
            return result
        except Exception as e:
            logger.exception(f"Tool {tool_name} execution failed: {e}")
            return ToolResult(
                success=False,
                output="",
                error=f"Tool execution error: {str(e)}"
            )
    
    def _run_with_tools(
        self,
        user_prompt: str,
        max_iterations: int = MAX_TOOL_ITERATIONS_PER_AGENT
    ) -> Tuple[str, List[ToolCallRecord], Dict[str, int]]:
        """
        Run the agent with tool calling support.

        Uses the OpenAI Agents SDK to run the tool loop and capture tool calls.

        Args:
            user_prompt: The user prompt/input for this agent run
            max_iterations: Maximum tool calling iterations

        Returns:
            Tuple of (final_response_content, list_of_tool_calls, token_usage)
        """
        tool_calls_log: List[ToolCallRecord] = []

        # Log the full prompt for comprehensive logging
        logger.info(f"{self.name} - LLM call prompt ({len(user_prompt)} chars):\n{user_prompt}")

        # Get system prompt and store it for logging
        system_prompt = self.get_system_prompt()
        self._current_system_prompt = system_prompt

        tools = self._build_agent_tools(tool_calls_log)

        from agents import Agent, ModelSettings, Runner

        agent = Agent(
            name=self.name,
            instructions=system_prompt,
            model=self._get_model(),
            model_settings=ModelSettings(
                temperature=self.llm_config.temperature,
                max_tokens=self.llm_config.max_tokens,
            ),
            tools=tools,
        )

        effective_max_turns = max_iterations if max_iterations != -1 else 1_000_000
        remaining_interactions = None
        if self.tool_registry and isinstance(getattr(self.tool_registry, "state", None), dict):
            remaining_interactions = self.tool_registry.state.get("remaining_interactions")
            if isinstance(remaining_interactions, int):
                if remaining_interactions == 0:
                    logger.warning(f"{self.name} aborted: interaction budget exhausted")
                    return "", tool_calls_log, {
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "total_tokens": 0,
                    }
                if remaining_interactions > 0:
                    effective_max_turns = min(effective_max_turns, remaining_interactions)
        logger.debug(f"{self.name} starting agent run (max_turns={effective_max_turns})")
        logger.debug(f"{self.name} - System prompt ({len(system_prompt)} chars):\n{system_prompt}")

        session = None
        run_config = None
        if self._session_id and self._session_db_path:
            from agents.memory import SQLiteSession
            from agents.run import RunConfig

            def _session_input_callback(history, new_input):
                # If this is the first message in session, prepend system prompt as metadata
                if not history:
                    # Add a developer message with system prompt for session persistence
                    system_message = {
                        "role": "developer",
                        "content": f"[SYSTEM_PROMPT]\n{system_prompt}"
                    }
                    return [system_message] + new_input
                return history + new_input

            session = SQLiteSession(self._session_id, self._session_db_path)
            run_config = RunConfig(session_input_callback=_session_input_callback)

        result = Runner.run_sync(
            agent,
            user_prompt,
            max_turns=effective_max_turns,
            run_config=run_config,
            session=session,
        )

        if session is not None and hasattr(session, "close"):
            session.close()

        content = result.final_output
        if content is None:
            content_str = ""
        elif isinstance(content, str):
            content_str = content
        else:
            content_str = json.dumps(content, indent=2, default=str)

        token_usage = self._extract_token_usage(result)
        llm_calls = self._extract_llm_calls(result)
        self._last_token_usage = token_usage
        self._last_llm_calls = llm_calls
        if isinstance(remaining_interactions, int) and self.tool_registry and isinstance(getattr(self.tool_registry, "state", None), dict):
            if remaining_interactions >= 0:
                self.tool_registry.state["remaining_interactions"] = max(0, remaining_interactions - llm_calls)

        logger.info(f"{self.name} - LLM response ({len(content_str)} chars):\n{content_str}")

        return content_str, tool_calls_log, token_usage
    
    def _parse_json_from_response(
        self,
        response: str,
        required_keys: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Parse JSON from an LLM response.
        
        Handles:
        - JSON in code blocks
        - Raw JSON objects
        - Partial JSON recovery
        
        Args:
            response: LLM response text
            required_keys: Keys that must be present in the result
        
        Returns:
            Parsed dictionary
        """
        import re
        
        # Try JSON code block first
        json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
        if json_match:
            try:
                result = json.loads(json_match.group(1))
                if self._validate_parsed_json(result, required_keys):
                    return result
            except json.JSONDecodeError:
                pass
        
        # Try raw JSON object
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                result = json.loads(json_match.group(0))
                if self._validate_parsed_json(result, required_keys):
                    return result
            except json.JSONDecodeError:
                pass
        
        # Return raw response wrapped in dict
        return {
            "raw_response": response,
            "parse_error": "Could not extract structured JSON"
        }
    
    def _validate_parsed_json(
        self,
        data: Dict[str, Any],
        required_keys: Optional[List[str]]
    ) -> bool:
        """Validate that parsed JSON has required keys."""
        if not required_keys:
            return True
        return all(key in data for key in required_keys)
    
    def _create_success_output(
        self,
        content: Dict[str, Any],
        raw_response: str,
        tool_calls: List[ToolCallRecord],
        token_usage: Optional[Dict[str, int]] = None
    ) -> AgentOutput:
        """Create a successful AgentOutput."""
        return AgentOutput(
            agent_name=self.name,
            success=True,
            content=content,
            raw_response=raw_response,
            tool_calls=tool_calls,
            token_usage=token_usage or {},
            tool_calls_count=len(tool_calls),
            llm_calls=self._last_llm_calls
        )
    
    def _create_error_output(
        self,
        error: str,
        content: Optional[Dict[str, Any]] = None,
        token_usage: Optional[Dict[str, int]] = None
    ) -> AgentOutput:
        """Create an error AgentOutput."""
        return AgentOutput(
            agent_name=self.name,
            success=False,
            content=content or {},
            error=error,
            token_usage=token_usage or {},
            tool_calls_count=0,
            llm_calls=self._last_llm_calls
        )

    def _extract_token_usage(self, result: Any) -> Dict[str, int]:
        """Extract token usage from an Agents SDK run result."""
        usage = None
        for attr in ("usage", "token_usage"):
            if hasattr(result, attr):
                usage = getattr(result, attr)
                if usage:
                    break

        if usage is None and hasattr(result, "raw_responses"):
            raw_responses = getattr(result, "raw_responses") or []
            if raw_responses:
                last = raw_responses[-1]
                usage = getattr(last, "usage", None) if hasattr(last, "usage") else None
                if usage is None and isinstance(last, dict):
                    usage = last.get("usage")

        def _get_int(obj: Any, *names: str) -> Optional[int]:
            for name in names:
                if obj is None:
                    return None
                if isinstance(obj, dict) and name in obj:
                    value = obj.get(name)
                else:
                    value = getattr(obj, name, None)
                if isinstance(value, int):
                    return value
            return None

        prompt_tokens = _get_int(usage, "prompt_tokens", "input_tokens") or 0
        completion_tokens = _get_int(usage, "completion_tokens", "output_tokens") or 0
        total_tokens = _get_int(usage, "total_tokens")
        if total_tokens is None:
            total_tokens = prompt_tokens + completion_tokens

        return {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        }

    def _extract_llm_calls(self, result: Any) -> int:
        """Extract LLM call count from an Agents SDK run result."""
        context_wrapper = getattr(result, "context_wrapper", None)
        usage = getattr(context_wrapper, "usage", None) if context_wrapper else None
        requests = getattr(usage, "requests", None) if usage else None
        if isinstance(requests, int) and requests > 0:
            return requests
        raw_responses = getattr(result, "raw_responses", None)
        if isinstance(raw_responses, list) and raw_responses:
            return len(raw_responses)
        responses = getattr(result, "responses", None)
        if isinstance(responses, list) and responses:
            return len(responses)
        return 1
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(tools={self.allowed_tools})"
