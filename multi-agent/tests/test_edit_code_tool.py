"""Tests for the enhanced EditCodeTool with fuzzy matching and validation."""

import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.tools import (
    normalize_whitespace,
    find_best_match,
    validate_python_syntax,
    validate_syntax,
    create_unified_diff,
)


class TestNormalizeWhitespace:
    """Test whitespace normalization."""
    
    def test_strips_trailing_whitespace(self):
        code = "def foo():   \n    pass  \n"
        expected = "def foo():\n    pass\n"
        assert normalize_whitespace(code) == expected
    
    def test_normalizes_line_endings(self):
        code = "line1\r\nline2\rline3\n"
        result = normalize_whitespace(code)
        assert '\r' not in result
        assert result.count('\n') == 3
    
    def test_preserves_leading_indentation(self):
        code = "    indented\n        more_indented"
        result = normalize_whitespace(code)
        assert result.startswith("    indented")
        assert "        more_indented" in result


class TestFindBestMatch:
    """Test fuzzy matching functionality."""
    
    def test_exact_match(self):
        haystack = "def foo():\n    return 42\n\ndef bar():\n    pass"
        needle = "def foo():\n    return 42"
        
        result = find_best_match(needle, haystack)
        
        assert result is not None
        start, end, similarity, matched = result
        assert similarity == 1.0
        assert "def foo()" in matched
    
    def test_fuzzy_match_trailing_whitespace(self):
        haystack = "def foo():   \n    return 42  \n"
        needle = "def foo():\n    return 42\n"
        
        result = find_best_match(needle, haystack)
        
        assert result is not None
        _, _, similarity, _ = result
        assert similarity >= 0.85
    
    def test_no_match_below_threshold(self):
        haystack = "completely different code"
        needle = "def foo():\n    return 42"
        
        result = find_best_match(needle, haystack, threshold=0.85)
        
        assert result is None
    
    def test_finds_closest_match(self):
        haystack = """
def helper():
    pass

def target_function():
    vulnerable_call(user_input)
    return result

def other():
    pass
"""
        needle = "def target_function():\n    vulnerable_call(user_input)\n    return result"
        
        result = find_best_match(needle, haystack)
        
        assert result is not None
        _, _, similarity, matched = result
        assert similarity >= 0.85
        assert "target_function" in matched


class TestSyntaxValidation:
    """Test syntax validation functions."""
    
    def test_valid_python(self):
        code = """
def hello():
    print("Hello, World!")
    return True
"""
        is_valid, error = validate_python_syntax(code)
        assert is_valid is True
        assert error is None
    
    def test_invalid_python_missing_colon(self):
        code = "def hello()\n    pass"
        is_valid, error = validate_python_syntax(code)
        assert is_valid is False
        assert "Syntax error" in error
    
    def test_invalid_python_unbalanced_parens(self):
        code = "print(hello("
        is_valid, error = validate_python_syntax(code)
        assert is_valid is False
    
    def test_validate_syntax_python(self):
        is_valid, _ = validate_syntax("def foo(): pass", "python")
        assert is_valid is True
    
    def test_validate_syntax_unknown_language(self):
        # Unknown languages should return valid (we can't check them)
        is_valid, _ = validate_syntax("anything goes", "rust")
        assert is_valid is True


class TestCreateUnifiedDiff:
    """Test unified diff generation."""
    
    def test_generates_diff(self):
        old = "def foo():\n    return 1"
        new = "def foo():\n    return 2"
        
        diff = create_unified_diff(old, new, "test.py")
        
        assert "--- a/test.py" in diff
        assert "+++ b/test.py" in diff
        assert "-    return 1" in diff
        assert "+    return 2" in diff
    
    def test_empty_diff_for_identical_code(self):
        code = "def foo(): pass"
        diff = create_unified_diff(code, code, "test.py")
        
        # For identical files, unified_diff returns minimal output
        assert "-" not in diff or "---" in diff


class TestIntegration:
    """Integration tests for the full edit workflow."""
    
    def test_fuzzy_match_then_validate(self):
        """Test the complete flow: fuzzy match -> validate -> generate diff."""
        original_file = """
def process_input(user_data):
    # Vulnerable: no validation
    eval(user_data)
    return True
"""
        
        # Agent might provide slightly different whitespace
        old_code_from_agent = "def process_input(user_data):\n    # Vulnerable: no validation\n    eval(user_data)\n    return True"
        
        new_code = """def process_input(user_data):
    # Fixed: validate input
    import ast
    ast.literal_eval(user_data)
    return True"""
        
        # Step 1: Find match
        match = find_best_match(old_code_from_agent, original_file)
        assert match is not None
        _, _, similarity, matched_text = match
        assert similarity >= 0.85
        
        # Step 2: Apply replacement
        patched_file = original_file.replace(matched_text, new_code, 1)
        
        # Step 3: Validate syntax
        is_valid, error = validate_python_syntax(patched_file)
        assert is_valid is True, f"Syntax error: {error}"
        
        # Step 4: Generate diff
        diff = create_unified_diff(matched_text, new_code, "vulnerable.py")
        assert "ast.literal_eval" in diff


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
