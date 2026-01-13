"""
Diff utilities for unified diff generation.
"""

import difflib


def create_unified_diff(old_code: str, new_code: str, filename: str = "file") -> str:
    """
    Create a unified diff between old and new code.

    Args:
        old_code: Original code
        new_code: Modified code
        filename: Filename for diff headers

    Returns:
        Unified diff string
    """
    old_lines = old_code.splitlines(keepends=True)
    new_lines = new_code.splitlines(keepends=True)

    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm=""
    )

    return "".join(diff)
