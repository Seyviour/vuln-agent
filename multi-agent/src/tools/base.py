"""
Base classes for tool implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..utils.types import ToolResult


@dataclass
class ToolResult:
    """
    Result from a tool execution.
    
    Attributes:
        success: Whether the tool executed successfully
        output: The output from the tool (may be truncated for LLM context)
        error: Error message if execution failed
        metadata: Additional metadata about the execution
    """
    success: bool
    output: str
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __repr__(self) -> str:
        status = "✓" if self.success else "✗"
        return f"ToolResult({status}, output={len(self.output)} chars)"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "metadata": self.metadata,
        }


class BaseTool(ABC):
    """
    Abstract base class for all tools.
    
    Tools are the interface between agents and the external world (file system,
    containers, tests, etc.). Each tool:
    - Has a name and description for LLM function calling
    - Provides a JSON schema for parameters
    - Executes actions and returns structured results
    """
    
    name: str
    description: str
    
    @abstractmethod
    def execute(self, **kwargs: Any) -> ToolResult:
        """
        Execute the tool with given arguments.
        
        Args:
            **kwargs: Tool-specific arguments
        
        Returns:
            ToolResult with execution outcome
        """
        pass
    
    @abstractmethod
    def get_schema(self) -> Dict[str, Any]:
        """
        Get the JSON schema for LLM function calling.
        
        Returns:
            OpenAI-compatible function schema
        """
        pass
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name})"
