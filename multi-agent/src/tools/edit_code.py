"""
EditCode tool implementation.

Applies code edits with fuzzy matching, syntax validation, and rollback.
"""

from typing import Any, Dict, Optional
import logging

from .base import BaseTool, ToolResult
from .docker import DockerExecutor
from .matching import (
    find_best_match,
    find_closest_match,
    count_occurrences,
)
from .diffing import create_unified_diff
from .validators import validate_syntax
from ..utils.constants import (
    DEFAULT_FUZZY_THRESHOLD,
    CODE_PREVIEW_LENGTH,
)
from ..utils.security import build_safe_cat_command, sanitize_path


logger = logging.getLogger(__name__)


class EditCodeTool(BaseTool):
    """
    Apply code edits to files with fuzzy matching and validation.
    
    Features:
    - Fuzzy matching: Handles minor whitespace/indentation differences
    - Syntax validation: Validates code after edit (Python/JS)
    - Auto-rollback: Reverts changes if syntax validation fails
    - Detailed error messages: Shows closest match for debugging
    """
    
    name = "EditCode"
    description = (
        "Edit code in a file by replacing a specific code block with new code. "
        "Supports fuzzy matching for whitespace differences and validates syntax after edit."
    )
    
    def __init__(
        self,
        docker_executor: Optional[DockerExecutor],
        language: str = "python",
        fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD,
        validate_syntax: bool = True,
        auto_rollback: bool = True
    ):
        """
        Initialize EditCode tool.
        
        Args:
            docker_executor: Docker executor for container operations
            language: Programming language for syntax validation
            fuzzy_threshold: Minimum similarity for fuzzy matching (0.0 to 1.0)
            validate_syntax: Whether to validate syntax after edit
            auto_rollback: Whether to rollback on syntax errors
        """
        self.docker = docker_executor
        self.language = language
        self.fuzzy_threshold = fuzzy_threshold
        self.validate_syntax_enabled = validate_syntax
        self.auto_rollback = auto_rollback
        self._backup_content: Optional[str] = None
        self._backup_path: Optional[str] = None
    
    def execute(
        self,
        file_path: str,
        old_code: str,
        new_code: str,
        fuzzy_match: bool = True,
        skip_validation: bool = False
    ) -> ToolResult:
        """
        Replace old_code with new_code in the specified file.
        
        Args:
            file_path: Path to the file to edit
            old_code: The code block to replace (supports fuzzy matching)
            new_code: The replacement code
            fuzzy_match: Whether to use fuzzy matching (default: True)
            skip_validation: Whether to skip syntax validation (default: False)
        
        Returns:
            ToolResult with success status, diff output, and metadata
        """
        if self.docker is None:
            return ToolResult(
                success=False,
                output="",
                error="No Docker executor available. Cannot edit files."
            )
        
        try:
            # Sanitize and validate the file path
            sanitize_path(file_path, allow_absolute=True)

            # Read the current file content using safe command
            safe_command = build_safe_cat_command(file_path)
            exit_code, file_content = self.docker.exec_command(safe_command)
            
            if exit_code != 0:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Cannot read file: {file_path}. Error: {file_content}"
                )
            
            # Save backup for potential rollback
            self._backup_content = file_content
            self._backup_path = file_path
            
            # Find the code block to replace
            matched_text = None
            match_type = "none"
            similarity = 0.0
            
            # Try exact match first
            if old_code in file_content:
                matched_text = old_code
                match_type = "exact"
                similarity = 1.0
                occurrences = count_occurrences(old_code, file_content)
                
                if occurrences > 1:
                    return ToolResult(
                        success=False,
                        output="",
                        error=(
                            f"Found {occurrences} exact occurrences of the code block. "
                            f"Please provide more context to uniquely identify the location."
                        )
                    )
            elif fuzzy_match:
                # Try fuzzy matching
                match = find_best_match(old_code, file_content, self.fuzzy_threshold)
                
                if match:
                    _, _, similarity, matched_text = match
                    match_type = "fuzzy"
                    logger.info(
                        f"Fuzzy match found with {similarity:.1%} similarity. "
                        f"Using matched text instead of provided old_code."
                    )
                else:
                    return self._create_no_match_error(old_code, file_content, file_path)
            else:
                return self._create_no_match_error(old_code, file_content, file_path)
            
            # Apply the replacement
            new_content = file_content.replace(matched_text, new_code, 1)
            
            # Validate syntax before writing
            if self.validate_syntax_enabled and not skip_validation:
                is_valid, syntax_error = validate_syntax(new_content, self.language)
                
                if not is_valid:
                    return ToolResult(
                        success=False,
                        output="",
                        error=(
                            f"Syntax validation failed after applying edit: {syntax_error}\n\n"
                            f"The edit would result in invalid {self.language} code. "
                            f"Please review your new_code for syntax errors."
                        ),
                        metadata={
                            "validation_error": syntax_error,
                            "file_path": file_path,
                            "match_type": match_type
                        }
                    )
            
            # Write the new content
            logger.info(
                f"EditCodeTool: Writing {len(new_content)} chars to {file_path} "
                f"(match_type={match_type})"
            )
            
            exit_code, write_output = self.docker.write_file(file_path, new_content)
            
            if exit_code != 0:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Failed to write file: {write_output}"
                )
            
            # Verify the write was successful
            verify_code, verify_content = self.docker.exec_command(f"cat '{file_path}'")
            if verify_code != 0 or new_code not in verify_content:
                if self.auto_rollback:
                    self._rollback()
                return ToolResult(
                    success=False,
                    output="",
                    error="Write verification failed - the edit may not have been applied correctly."
                )

            # Generate diff
            diff = create_unified_diff(matched_text, new_code, file_path)
            
            # Clear backup on success
            self._backup_content = None
            self._backup_path = None
            
            success_msg = f"Successfully edited {file_path}"
            if match_type == "fuzzy":
                success_msg += f" (fuzzy match, {similarity:.1%} similarity)"

            return ToolResult(
                success=True,
                output=success_msg,
                metadata={
                    "file_path": file_path,
                    "match_type": match_type,
                    "similarity": similarity,
                    "old_code_length": len(matched_text),
                    "new_code_length": len(new_code),
                    "diff": diff,
                    "full_file_content": verify_content,
                }
            )
            
        except Exception as e:
            if self.auto_rollback:
                self._rollback()
            logger.exception(f"EditCodeTool failed: {e}")
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def _rollback(self) -> bool:
        """Rollback to the backup content if available."""
        if self._backup_content is None or self._backup_path is None:
            return False
        
        try:
            logger.warning(f"Rolling back changes to {self._backup_path}")
            exit_code, _ = self.docker.write_file(self._backup_path, self._backup_content)
            self._backup_content = None
            self._backup_path = None
            return exit_code == 0
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
    
    def _create_no_match_error(
        self,
        old_code: str,
        file_content: str,
        file_path: str
    ) -> ToolResult:
        """Create a helpful error message when no match is found."""
        error_msg = f"Could not find the specified code block in {file_path}."
        
        # Try to find closest match for helpful feedback
        closest = find_closest_match(old_code, file_content)
        
        if closest:
            similarity, closest_text = closest
            old_preview = (
                old_code[:CODE_PREVIEW_LENGTH] + "..."
                if len(old_code) > CODE_PREVIEW_LENGTH
                else old_code
            )
            closest_preview = (
                closest_text[:CODE_PREVIEW_LENGTH] + "..."
                if len(closest_text) > CODE_PREVIEW_LENGTH
                else closest_text
            )
            
            error_msg += (
                f"\n\nClosest match ({similarity:.1%} similar):\n"
                f"```\n{closest_preview}\n```\n\n"
                f"Your provided old_code:\n"
                f"```\n{old_preview}\n```\n\n"
                f"Hint: Check for whitespace/indentation differences, "
                f"or try reading the file first."
            )
        else:
            error_msg += (
                "\n\nNo similar code found. The code may have been modified or removed. "
                "Try using ReadFile to get the current file contents."
            )
        
        return ToolResult(
            success=False,
            output="",
            error=error_msg,
            metadata={"file_path": file_path, "match_attempted": True}
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
                        "description": "Path to the file to edit"
                    },
                    "old_code": {
                        "type": "string",
                        "description": (
                            "The code block to replace. Supports fuzzy matching for minor "
                            "whitespace differences. Include enough context to uniquely identify the location."
                        )
                    },
                    "new_code": {
                        "type": "string",
                        "description": "The new code to insert in place of old_code"
                    },
                    "fuzzy_match": {
                        "type": "boolean",
                        "description": (
                            "Whether to use fuzzy matching for whitespace differences. "
                            "Default: true. Set to false for exact matching only."
                        )
                    },
                    "skip_validation": {
                        "type": "boolean",
                        "description": (
                            "Whether to skip syntax validation after edit. "
                            "Default: false. Only set to true for non-code files."
                        )
                    }
                },
                "required": ["file_path", "old_code", "new_code"]
            }
        }
