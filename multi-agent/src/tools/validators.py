"""
Syntax validators for code validation.

Provides validation for:
- Python syntax (using ast module)
"""

import ast
from typing import Tuple, Optional, Callable, Dict


def validate_python_syntax(code: str) -> Tuple[bool, Optional[str]]:
    """
    Validate Python code syntax using the ast module.
    
    Args:
        code: Python code to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        ast.parse(code)
        return (True, None)
    except SyntaxError as e:
        return (False, f"Syntax error at line {e.lineno}: {e.msg}")
    except Exception as e:
        return (False, f"Parse error: {str(e)}")


# Registry of validators by language
VALIDATORS: Dict[str, Callable[[str], Tuple[bool, Optional[str]]]] = {
    "python": validate_python_syntax,
    "py": validate_python_syntax,
}


def validate_syntax(code: str, language: str) -> Tuple[bool, Optional[str]]:
    """
    Validate code syntax for the given language.
    
    Args:
        code: Code to validate
        language: Programming language (case-insensitive)
    
    Returns:
        Tuple of (is_valid, error_message)
        Returns (True, None) for unknown languages
    """
    language_lower = language.lower() if language else "python"
    
    validator = VALIDATORS.get(language_lower)
    if validator:
        return validator(code)
    
    # For unknown languages, assume valid (can't validate)
    return (True, None)


def get_supported_languages() -> list[str]:
    """Get list of languages with syntax validation support."""
    return ["python"]
