"""
Tool registry for managing available tools.

Provides a central registry for tool registration, lookup, and schema generation.
"""

from typing import Any, Dict, List, Optional
import logging

from .base import BaseTool, ToolResult
from .docker import DockerExecutor
from .read_file import ReadFileTool
from .find_class import FindClassTool
from .edit_code import EditCodeTool
from .run_test import RunTestTool
from .symbol_verify import SymbolVerifyTool
from .ask_agent import AskAgentTool
from ..utils.constants import DEFAULT_FUZZY_THRESHOLD
from ..config import LLMConfig


logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    Registry of available tools.
    
    Manages tool registration, lookup, and provides schemas for LLM function calling.
    
    Attributes:
        docker: Docker executor for container operations
        sample: Sample information for context-aware tool configuration
    """
    
    def __init__(
        self,
        docker_executor: Optional[DockerExecutor] = None,
        sample: Optional[Dict[str, Any]] = None,
        llm_config: Optional[LLMConfig] = None,
        auto_register: bool = True
    ):
        """
        Initialize tool registry.
        
        Args:
            docker_executor: Docker executor for container operations
            sample: Sample dictionary for context (language, CVE, etc.)
            auto_register: Whether to automatically register default tools
        """
        self.docker = docker_executor
        self.sample = sample or {}
        self.llm_config = llm_config
        self.state: Optional[Dict[str, Any]] = None
        self._tools: Dict[str, BaseTool] = {}
        
        if auto_register:
            self._register_default_tools()
    
    def _register_default_tools(self) -> None:
        """Register the default set of tools."""
        language = self.sample.get("programming_language", "python")
        cve_id = self.sample.get("cve_id")
        
        # Register all tools
        self.register(ReadFileTool(self.docker))
        self.register(FindClassTool(self.docker))
        self.register(EditCodeTool(
            docker_executor=self.docker,
            language=language,
            fuzzy_threshold=DEFAULT_FUZZY_THRESHOLD,
            validate_syntax=True,
            auto_rollback=True
        ))
        self.register(RunTestTool(
            docker_executor=self.docker,
            cve_id=cve_id,
        ))
        self.register(SymbolVerifyTool(self.docker))
        self.register(AskAgentTool(self, self.llm_config))
        
        logger.debug(f"Registered {len(self._tools)} default tools")

    def set_state(self, state: Optional[Dict[str, Any]]) -> None:
        """Set the current workflow state for tools that need shared context."""
        self.state = state

    def set_llm_config(self, llm_config: Optional[LLMConfig]) -> None:
        """Set the LLM config for tools that run agents."""
        self.llm_config = llm_config
        tool = self._tools.get("AskAgent")
        if tool is not None and hasattr(tool, "set_llm_config"):
            tool.set_llm_config(llm_config)
    
    def register(self, tool: BaseTool) -> None:
        """
        Register a tool in the registry.
        
        Args:
            tool: Tool instance to register
        """
        self._tools[tool.name] = tool
        logger.debug(f"Registered tool: {tool.name}")
    
    def unregister(self, name: str) -> Optional[BaseTool]:
        """
        Unregister a tool from the registry.
        
        Args:
            name: Name of the tool to unregister
        
        Returns:
            The unregistered tool, or None if not found
        """
        return self._tools.pop(name, None)
    
    def get_tool(self, name: str) -> Optional[BaseTool]:
        """
        Get a tool by name.
        
        Args:
            name: Name of the tool
        
        Returns:
            Tool instance or None if not found
        """
        return self._tools.get(name)
    
    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools
    
    def get_all_tools(self) -> Dict[str, BaseTool]:
        """Get all registered tools."""
        return self._tools.copy()
    
    def get_tool_names(self) -> List[str]:
        """Get names of all registered tools."""
        return list(self._tools.keys())
    
    def get_schemas(
        self,
        tool_names: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get JSON schemas for specified tools (or all if none specified).
        
        Args:
            tool_names: List of tool names, or None for all tools
        
        Returns:
            List of OpenAI-compatible function schemas
        """
        if tool_names is None:
            tool_names = list(self._tools.keys())
        
        return [
            self._tools[name].get_schema()
            for name in tool_names
            if name in self._tools
        ]
    
    def execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> ToolResult:
        """
        Execute a tool by name with given arguments.
        
        Args:
            tool_name: Name of the tool to execute
            arguments: Arguments to pass to the tool
        
        Returns:
            ToolResult from the execution
        """
        tool = self.get_tool(tool_name)
        
        if tool is None:
            return ToolResult(
                success=False,
                output="",
                error=f"Tool '{tool_name}' not found. Available: {self.get_tool_names()}"
            )
        
        try:
            return tool.execute(**arguments)
        except Exception as e:
            logger.exception(f"Tool execution failed: {tool_name}")
            return ToolResult(
                success=False,
                output="",
                error=f"Tool execution error: {str(e)}"
            )
    
    def __len__(self) -> int:
        """Return number of registered tools."""
        return len(self._tools)
    
    def __contains__(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools
    
    def __repr__(self) -> str:
        return f"ToolRegistry(tools={list(self._tools.keys())})"
