"""
AskAgent tool implementation.

Allows the Coordinator to invoke specialist agents directly.
"""

from typing import Any, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import os

from .base import BaseTool, ToolResult
from ..config import LLMConfig
from ..utils.constants import DEFAULT_ARTIFACTS_DIR


logger = logging.getLogger(__name__)

# Thread pool for running nested agents (avoids asyncio event loop conflicts)
_agent_executor = ThreadPoolExecutor(max_workers=4)


class AskAgentTool(BaseTool):
    """
    Invoke another agent and return its response.

    This enables direct dialog between agents through a tool call.
    Uses a thread pool to avoid asyncio event loop conflicts when
    nesting agent calls.
    """

    name = "AskAgent"
    description = (
        "Invoke another agent to get analysis or feedback. "
        "Use this to consult ContextKnowledgeAgent, PatchAgent, or VerificationAgent."
    )

    def __init__(self, tool_registry: "ToolRegistry", llm_config: Optional[LLMConfig]):
        self.tool_registry = tool_registry
        self.llm_config = llm_config

    def set_llm_config(self, llm_config: Optional[LLMConfig]) -> None:
        self.llm_config = llm_config

    def execute(
        self,
        agent_name: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        context_keys: Optional[list[str]] = None,
        allow_tools: bool = True,
        use_session: bool = True,
    ) -> ToolResult:
        if not self.llm_config:
            return ToolResult(
                success=False,
                output="",
                error="LLM config is not set for AskAgent tool."
            )

        agent_cls = self._resolve_agent_class(agent_name)
        if agent_cls is None:
            return ToolResult(
                success=False,
                output="",
                error=f"Unknown agent '{agent_name}'. Allowed: {self._allowed_agent_names()}",
            )

        # Run the nested agent in a separate thread to avoid event loop conflicts
        future = _agent_executor.submit(
            self._run_agent_in_thread,
            agent_cls,
            agent_name,
            message,
            context,
            context_keys,
            allow_tools,
            use_session,
        )

        try:
            return future.result(timeout=300)  # 5 minute timeout
        except Exception as e:
            logger.exception(f"AskAgent failed to run {agent_name}: {e}")
            return ToolResult(
                success=False,
                output="",
                error=f"Failed to run {agent_name}: {str(e)}"
            )

    def _run_agent_in_thread(
        self,
        agent_cls,
        agent_name: str,
        message: str,
        context: Optional[Dict[str, Any]],
        context_keys: Optional[list[str]],
        allow_tools: bool,
        use_session: bool,
    ) -> ToolResult:
        """Run the agent in a separate thread with its own event loop."""
        try:
            registry = self.tool_registry if allow_tools else None
            agent = agent_cls(self.llm_config, tool_registry=registry)

            merged_context = self._merge_context(agent_name, context, context_keys)
            user_prompt = self._build_user_prompt(message, merged_context)

            if use_session:
                sample_id = merged_context.get("sample_id") or "unknown"
                session_id = f"{sample_id}:{agent.name}"
                artifacts_dir = os.getenv("ARTIFACTS_DIR", DEFAULT_ARTIFACTS_DIR)
                db_path = os.path.join(artifacts_dir, "agent_sessions.sqlite")
                os.makedirs(artifacts_dir, exist_ok=True)
                agent.set_session(session_id, db_path)

            response, tool_calls, token_usage = agent._run_with_tools(user_prompt, max_iterations=-1)

            metadata = {
                "agent_name": agent.name,
                "tool_calls": tool_calls,
                "token_usage": token_usage,
            }
            return ToolResult(success=True, output=response, metadata=metadata)
        except Exception as e:
            logger.exception(f"Agent {agent_name} execution failed in thread: {e}")
            return ToolResult(
                success=False,
                output="",
                error=f"Agent execution error: {str(e)}"
            )

    def get_schema(self) -> Dict[str, Any]:
        # Note: OpenAI function calling requires simple schemas.
        # Optional parameters with defaults are handled in execute().
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_name": {
                        "type": "string",
                        "description": "Agent to invoke.",
                        "enum": self._allowed_agent_names(),
                    },
                    "message": {
                        "type": "string",
                        "description": "Question or instruction for the target agent.",
                    },
                },
                "required": ["agent_name", "message"],
            },
        }

    def _resolve_agent_class(self, agent_name: str):
        from ..agents.context_knowledge import ContextKnowledgeAgent
        from ..agents.patch import PatchAgent
        from ..agents.verification import VerificationAgent

        mapping = {
            "ContextKnowledgeAgent": ContextKnowledgeAgent,
            "PatchAgent": PatchAgent,
            "VerificationAgent": VerificationAgent,
            "context_knowledge": ContextKnowledgeAgent,
            "patch": PatchAgent,
            "verification": VerificationAgent,
        }
        return mapping.get(agent_name)

    def _allowed_agent_names(self) -> list[str]:
        # Only specialist agents that can be consulted by the Coordinator
        return [
            "ContextKnowledgeAgent",
            "PatchAgent",
            "VerificationAgent",
            "context_knowledge",
            "patch",
            "verification",
        ]

    def _merge_context(
        self,
        agent_name: str,
        context: Optional[Dict[str, Any]],
        context_keys: Optional[list[str]],
    ) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}
        if self.tool_registry is not None:
            state = getattr(self.tool_registry, "state", None)
            sample = getattr(self.tool_registry, "sample", None)
            if isinstance(state, dict):
                keys = context_keys or self._default_context_keys(agent_name)
                for key in keys:
                    if key in state:
                        merged[key] = state[key]
            elif isinstance(sample, dict):
                keys = context_keys or self._default_context_keys(agent_name)
                for key in keys:
                    if key in sample:
                        merged[key] = sample[key]
        if context:
            merged.update(context)
        return merged

    def _build_user_prompt(self, message: str, context: Dict[str, Any]) -> str:
        context_json = json.dumps(context, indent=2, default=str)
        return (
            "## Message\n"
            f"{message}\n\n"
            "## Context\n"
            f"```json\n{context_json}\n```"
        )

    def _default_context_keys(self, agent_name: str) -> list[str]:
        base_keys = [
            "sample_id",
            "file_path",
            "vulnerable_code",
            "problem_statement",
            "programming_language",
            "cve_id",
            "cwe_id",
            "vulnerability_locations",
            "test_paths",
            "poc_test",
        ]
        name = agent_name.lower()
        if "context" in name:
            return base_keys + [
                "repo_url",
                "work_dir",
                "cwe_info",
                "patch_description",
            ]
        if "patch" in name:
            return base_keys + [
                "decision_record",
                "last_patch_success",
                "patch_result",
            ]
        if "verification" in name:
            return base_keys + [
                "patch_result",
                "edited_files",
                "verification_result",
            ]
        return base_keys
