"""
FindClass tool implementation.

Finds class/function definitions and usages in the repository.
"""

from typing import Any, Dict, List, Optional
import logging

from .base import BaseTool, ToolResult
from .docker import DockerExecutor
from ..utils.constants import DEFAULT_FILE_PATTERNS


logger = logging.getLogger(__name__)


class FindClassTool(BaseTool):
    """
    Find class/function definitions and usages.
    
    Uses grep-based search for:
    - Class definitions
    - Function definitions
    - Variable assignments
    - Symbol usages throughout the codebase
    """
    
    name = "FindClass"
    description = "Find definitions and usages of a class, function, or symbol in the repository."
    
    def __init__(self, docker_executor: Optional[DockerExecutor]):
        """
        Initialize FindClass tool.
        
        Args:
            docker_executor: Docker executor for container operations
        """
        self.docker = docker_executor
    
    def execute(
        self,
        symbol_name: str,
        search_type: str = "all",
        file_pattern: str = "*.py",
        max_results: int = 50
    ) -> ToolResult:
        """
        Find symbol definitions and/or usages.
        
        Args:
            symbol_name: Name of the class, function, or symbol to find
            search_type: Type of search - "definition", "usage", or "all"
            file_pattern: File pattern to search (default: *.py)
            max_results: Maximum number of results per category
        
        Returns:
            ToolResult with search results
        """
        if self.docker is None:
            return ToolResult(
                success=False,
                output="",
                error="No Docker executor available. Cannot search files."
            )
        
        try:
            results: List[str] = []
            total_matches = 0
            
            if search_type in ("definition", "all"):
                definition_results = self._find_definitions(
                    symbol_name, file_pattern, max_results
                )
                if definition_results:
                    results.append(definition_results)
                    total_matches += definition_results.count('\n')
            
            if search_type in ("usage", "all"):
                usage_results = self._find_usages(
                    symbol_name, file_pattern, max_results
                )
                if usage_results:
                    results.append(usage_results)
                    total_matches += usage_results.count('\n')
            
            if not results:
                return ToolResult(
                    success=True,
                    output=f"No matches found for '{symbol_name}'",
                    metadata={
                        "symbol_name": symbol_name,
                        "matches": 0,
                        "search_type": search_type
                    }
                )
            
            return ToolResult(
                success=True,
                output='\n\n'.join(results),
                metadata={
                    "symbol_name": symbol_name,
                    "search_type": search_type,
                    "file_pattern": file_pattern,
                    "approximate_matches": total_matches
                }
            )
            
        except Exception as e:
            logger.exception(f"FindClass failed: {e}")
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def _find_definitions(
        self,
        symbol_name: str,
        file_pattern: str,
        max_results: int
    ) -> str:
        """Find symbol definitions (class, def, assignment)."""
        patterns = [
            f"class {symbol_name}",
            f"def {symbol_name}",
            f"^{symbol_name} =",
            f"async def {symbol_name}",  # Also match async functions
        ]
        
        results = []
        for pattern in patterns:
            cmd = (
                f"grep -rn '{pattern}' --include='{file_pattern}' . "
                f"2>/dev/null | head -{max_results} || true"
            )
            exit_code, output = self.docker.exec_command(cmd)
            if output.strip():
                results.append(f"# Definitions matching '{pattern}':\n{output.strip()}")
        
        return '\n\n'.join(results) if results else ""
    
    def _find_usages(
        self,
        symbol_name: str,
        file_pattern: str,
        max_results: int
    ) -> str:
        """Find symbol usages throughout the codebase."""
        cmd = (
            f"grep -rn '{symbol_name}' --include='{file_pattern}' . "
            f"2>/dev/null | head -{max_results} || true"
        )
        exit_code, output = self.docker.exec_command(cmd)
        
        if output.strip():
            return f"# Usages of '{symbol_name}':\n{output.strip()}"
        return ""
    
    def get_schema(self) -> Dict[str, Any]:
        """Get JSON schema for LLM function calling."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "Name of the class, function, or symbol to find"
                    },
                    "search_type": {
                        "type": "string",
                        "enum": ["definition", "usage", "all"],
                        "description": "Type of search: find definitions, usages, or both"
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "File pattern to search (default: *.py)"
                    }
                },
                "required": ["symbol_name"]
            }
        }
