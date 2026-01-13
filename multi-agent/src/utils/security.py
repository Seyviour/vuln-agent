"""
Security utilities for safe command execution and path handling.

Provides functions to prevent command injection and path traversal attacks.
"""

import shlex
import os
from pathlib import Path
from typing import Optional


class SecurityError(Exception):
    """Base exception for security violations."""
    pass


class PathTraversalError(SecurityError):
    """Raised when path traversal is detected."""
    pass


class InvalidPathError(SecurityError):
    """Raised when path is invalid or unsafe."""
    pass


def sanitize_path(
    path: str,
    allow_absolute: bool = False,
    base_dir: Optional[str] = None
) -> str:
    """
    Sanitize a file path to prevent directory traversal attacks.

    Args:
        path: The path to sanitize
        allow_absolute: Whether to allow absolute paths
        base_dir: If provided, ensure path is within this directory

    Returns:
        Sanitized path string

    Raises:
        PathTraversalError: If path contains directory traversal
        InvalidPathError: If path is invalid

    Examples:
        >>> sanitize_path("test.py")
        'test.py'
        >>> sanitize_path("../etc/passwd")
        PathTraversalError: Path contains directory traversal
        >>> sanitize_path("/etc/passwd", allow_absolute=False)
        InvalidPathError: Absolute paths not allowed
    """
    if not path:
        raise InvalidPathError("Path cannot be empty")

    # Check for directory traversal
    if ".." in path:
        raise PathTraversalError(
            f"Path contains directory traversal: {path}"
        )

    # Check for absolute paths (unless allowed)
    if path.startswith("/") and not allow_absolute:
        # Special case: allow /workspace for Docker
        if not path.startswith("/workspace"):
            raise InvalidPathError(
                f"Absolute paths not allowed: {path}"
            )

    # If base_dir provided, ensure path is within it
    if base_dir:
        try:
            # Resolve to absolute paths
            abs_path = Path(os.path.join(base_dir, path)).resolve()
            abs_base = Path(base_dir).resolve()

            # Check if path is within base_dir
            if not str(abs_path).startswith(str(abs_base)):
                raise PathTraversalError(
                    f"Path {path} is outside base directory {base_dir}"
                )
        except (ValueError, OSError) as e:
            raise InvalidPathError(f"Invalid path: {e}")

    return path


def escape_shell_arg(arg: str) -> str:
    """
    Safely escape a shell argument using shlex.quote.

    This prevents command injection by properly quoting arguments
    for shell execution.

    Args:
        arg: The argument to escape

    Returns:
        Safely escaped argument

    Examples:
        >>> escape_shell_arg("test.py")
        "'test.py'"
        >>> escape_shell_arg("test; rm -rf /")
        "'test; rm -rf /'"
    """
    return shlex.quote(arg)


def build_safe_cat_command(file_path: str) -> str:
    """
    Build a safe 'cat' command for reading files.

    Args:
        file_path: Path to the file to read

    Returns:
        Safe shell command string

    Raises:
        PathTraversalError: If path contains directory traversal
    """
    # Sanitize path (allow absolute for /workspace)
    safe_path = sanitize_path(file_path, allow_absolute=True)

    # Escape for shell
    escaped = escape_shell_arg(safe_path)

    return f"cat {escaped}"


def build_safe_write_command(file_path: str) -> str:
    """
    Build a safe command for writing to files.

    Note: Content should be provided via stdin, not as a command argument.

    Args:
        file_path: Path to the file to write

    Returns:
        Safe shell command string (use with stdin)

    Raises:
        PathTraversalError: If path contains directory traversal
    """
    # Sanitize path
    safe_path = sanitize_path(file_path, allow_absolute=True)

    # Escape for shell
    escaped = escape_shell_arg(safe_path)

    return f"tee {escaped}"


def validate_file_path(
    file_path: str,
    allowed_extensions: Optional[list[str]] = None
) -> bool:
    """
    Validate a file path for safety.

    Args:
        file_path: Path to validate
        allowed_extensions: Optional list of allowed file extensions

    Returns:
        True if path is valid

    Raises:
        InvalidPathError: If path is invalid or unsafe
    """
    # Basic sanitization
    sanitize_path(file_path, allow_absolute=True)

    # Check extension if restrictions provided
    if allowed_extensions:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in allowed_extensions:
            raise InvalidPathError(
                f"File extension {ext} not in allowed list: {allowed_extensions}"
            )

    return True


# Precompiled list of dangerous characters/patterns
DANGEROUS_PATTERNS = [
    ";",      # Command separator
    "&",      # Background execution
    "|",      # Pipe
    "$(",     # Command substitution
    "`",      # Command substitution (backtick)
    "\n",     # Newline injection
    "\r",     # Carriage return
    "&&",     # Conditional execution
    "||",     # Conditional execution
]


def contains_dangerous_patterns(text: str) -> bool:
    """
    Check if text contains potentially dangerous shell patterns.

    This is a defense-in-depth check. Proper escaping should be
    used regardless.

    Args:
        text: Text to check

    Returns:
        True if dangerous patterns found
    """
    return any(pattern in text for pattern in DANGEROUS_PATTERNS)
