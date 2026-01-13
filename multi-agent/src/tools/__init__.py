"""
Tools module for the multi-agent vulnerability patching system.

This module provides:
- Base tool abstractions
- Tool implementations (ReadFile, FindClass, EditCode, RunTest)
- Tool registry for management
- Docker executor for container operations
"""

from .base import BaseTool, ToolResult
from .registry import ToolRegistry
from .docker import DockerExecutor
from .read_file import ReadFileTool
from .find_class import FindClassTool
from .edit_code import EditCodeTool
from .run_test import RunTestTool
from .matching import find_best_match, normalize_whitespace
from .diffing import create_unified_diff
from .validators import validate_syntax, validate_python_syntax
from .symbol_verify import SymbolVerifyTool
from .ask_agent import AskAgentTool

__all__ = [
    # Base classes
    "BaseTool",
    "ToolResult",
    # Registry
    "ToolRegistry",
    # Docker
    "DockerExecutor",
    # Tools
    "ReadFileTool",
    "FindClassTool",
    "EditCodeTool",
    "RunTestTool",
    "SymbolVerifyTool",
    "AskAgentTool",
    # Utilities
    "find_best_match",
    "normalize_whitespace",
    "create_unified_diff",
    "validate_syntax",
    "validate_python_syntax",
]
