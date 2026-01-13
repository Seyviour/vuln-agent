"""
ReadFile tool implementation.

Reads file contents from the repository/container.
"""

from typing import Any, Dict, Optional
import logging

from .base import BaseTool, ToolResult
from .docker import DockerExecutor
from ..utils.security import build_safe_cat_command, sanitize_path, escape_shell_arg


logger = logging.getLogger(__name__)


class ReadFileTool(BaseTool):
    """
    Read file contents from the repository.
    
    Features:
    - Line range filtering
    - Automatic line numbering for context
    - Metadata about file structure
    """
    
    name = "ReadFile"
    description = "Read the contents of a file from the repository. Can read specific line ranges."
    
    def __init__(self, docker_executor: Optional[DockerExecutor]):
        """
        Initialize ReadFile tool.
        
        Args:
            docker_executor: Docker executor for container operations
        """
        self.docker = docker_executor
    
    def execute(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        include_line_numbers: bool = True
    ) -> ToolResult:
        """
        Read file contents, optionally within a line range.
        
        Args:
            file_path: Path to the file to read (relative to repo root)
            start_line: Starting line number (1-indexed, optional)
            end_line: Ending line number (inclusive, optional)
            include_line_numbers: Whether to prefix lines with numbers
        
        Returns:
            ToolResult with file contents or error
        """
        if self.docker is None:
            return ToolResult(
                success=False,
                output="",
                error="No Docker executor available. Cannot read files."
            )
        
        try:
            # Sanitize and validate the file path
            sanitize_path(file_path, allow_absolute=True)

            # Build safe command with proper escaping
            safe_path = escape_shell_arg(file_path)

            if start_line is not None and end_line is not None:
                cmd = f"sed -n '{start_line},{end_line}p' {safe_path}"
            elif start_line is not None:
                cmd = f"sed -n '{start_line},$p' {safe_path}"
            else:
                cmd = build_safe_cat_command(file_path)

            exit_code, output = self.docker.exec_command(cmd)
            
            if exit_code != 0:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Failed to read file '{file_path}': {output}"
                )
            
            # Add line numbers to output if requested
            if include_line_numbers:
                lines = output.split('\n')
                start = start_line or 1
                numbered_lines = [
                    f"{start + i:4d} | {line}" 
                    for i, line in enumerate(lines)
                ]
                formatted_output = '\n'.join(numbered_lines)
            else:
                formatted_output = output
                lines = output.split('\n')
            
            return ToolResult(
                success=True,
                output=formatted_output,
                metadata={
                    "file_path": file_path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "total_lines": len(lines),
                    "raw_content": output,  # Unformatted for programmatic use
                }
            )
            
        except Exception as e:
            logger.exception(f"ReadFile failed: {e}")
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def get_schema(self) -> Dict[str, Any]:
        """Get JSON schema for LLM function calling."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to read (relative to repo root)"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Starting line number (1-indexed, optional)"
                    },
                    "end_line": {
                        "type": "integer", 
                        "description": "Ending line number (inclusive, optional)"
                    }
                },
                "required": ["file_path"]
            }
        }
