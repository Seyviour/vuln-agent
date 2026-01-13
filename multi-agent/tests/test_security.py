"""
Security tests for path traversal and command injection prevention.

These tests verify that security utilities properly prevent common attacks.
"""

import pytest
from src.utils.security import (
    sanitize_path,
    escape_shell_arg,
    build_safe_cat_command,
    PathTraversalError,
    InvalidPathError,
    contains_dangerous_patterns,
)


class TestPathSanitization:
    """Test path sanitization functions."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_safe_relative_path(self):
        """Test that safe relative paths are accepted."""
        result = sanitize_path("test.py")
        assert result == "test.py"

        result = sanitize_path("src/utils/helpers.py")
        assert result == "src/utils/helpers.py"

    @pytest.mark.security
    @pytest.mark.unit
    def test_directory_traversal_rejected(self):
        """Test that directory traversal attempts are rejected."""
        with pytest.raises(PathTraversalError):
            sanitize_path("../etc/passwd")

        with pytest.raises(PathTraversalError):
            sanitize_path("../../etc/shadow")

        with pytest.raises(PathTraversalError):
            sanitize_path("safe/../../etc/passwd")

    @pytest.mark.security
    @pytest.mark.unit
    def test_absolute_paths_controlled(self):
        """Test that absolute paths are controlled by allow_absolute flag."""
        # Reject by default (except /workspace)
        with pytest.raises(InvalidPathError):
            sanitize_path("/etc/passwd", allow_absolute=False)

        # Allow when flag is set
        result = sanitize_path("/etc/passwd", allow_absolute=True)
        assert result == "/etc/passwd"

        # Always allow /workspace
        result = sanitize_path("/workspace/test.py", allow_absolute=False)
        assert result == "/workspace/test.py"

    @pytest.mark.security
    @pytest.mark.unit
    def test_empty_path_rejected(self):
        """Test that empty paths are rejected."""
        with pytest.raises(InvalidPathError):
            sanitize_path("")


class TestShellEscaping:
    """Test shell argument escaping."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_simple_path_escaped(self):
        """Test that simple paths are properly escaped."""
        result = escape_shell_arg("test.py")
        assert result == "'test.py'"

    @pytest.mark.security
    @pytest.mark.unit
    def test_injection_prevented(self):
        """Test that command injection is prevented."""
        # Attempt to inject commands
        malicious = "test.py; rm -rf /"
        result = escape_shell_arg(malicious)

        # Should be quoted to prevent execution
        assert "'" in result
        # Original semicolon should be preserved but quoted
        assert ";" in result

    @pytest.mark.security
    @pytest.mark.unit
    def test_special_characters_handled(self):
        """Test that special characters are properly handled."""
        result = escape_shell_arg("file with spaces.txt")
        assert result == "'file with spaces.txt'"

        result = escape_shell_arg("file$var.txt")
        assert result == "'file$var.txt'"


class TestSafeCommands:
    """Test safe command builders."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_build_safe_cat_command(self):
        """Test building safe cat commands."""
        cmd = build_safe_cat_command("test.py")
        assert "cat" in cmd
        assert "test.py" in cmd
        assert "'" in cmd  # Should be quoted

    @pytest.mark.security
    @pytest.mark.unit
    def test_cat_command_prevents_injection(self):
        """Test that cat command prevents injection."""
        # Should raise exception for directory traversal
        with pytest.raises(PathTraversalError):
            build_safe_cat_command("../etc/passwd")

    @pytest.mark.security
    @pytest.mark.unit
    def test_workspace_paths_allowed(self):
        """Test that /workspace paths work correctly."""
        cmd = build_safe_cat_command("/workspace/repo/test.py")
        assert "cat" in cmd
        assert "/workspace/repo/test.py" in cmd


class TestDangerousPatterns:
    """Test dangerous pattern detection."""

    @pytest.mark.security
    @pytest.mark.unit
    def test_detects_command_separators(self):
        """Test that command separators are detected."""
        assert contains_dangerous_patterns("test; rm -rf /")
        assert contains_dangerous_patterns("test && malicious")
        assert contains_dangerous_patterns("test || fallback")

    @pytest.mark.security
    @pytest.mark.unit
    def test_detects_command_substitution(self):
        """Test that command substitution is detected."""
        assert contains_dangerous_patterns("$(whoami)")
        assert contains_dangerous_patterns("`whoami`")

    @pytest.mark.security
    @pytest.mark.unit
    def test_detects_pipes(self):
        """Test that pipes are detected."""
        assert contains_dangerous_patterns("cat file | bash")

    @pytest.mark.security
    @pytest.mark.unit
    def test_safe_content_passes(self):
        """Test that safe content doesn't trigger detection."""
        assert not contains_dangerous_patterns("test.py")
        assert not contains_dangerous_patterns("def function():")
        assert not contains_dangerous_patterns("path/to/file.txt")


class TestIntegration:
    """Integration tests combining multiple security features."""

    @pytest.mark.security
    @pytest.mark.integration
    def test_end_to_end_safe_file_read(self, mock_docker):
        """Test end-to-end safe file reading."""
        from src.tools.read_file import ReadFileTool

        tool = ReadFileTool(mock_docker)

        # Safe read should work
        mock_docker.exec_command.return_value = (0, "file contents")
        result = tool.execute(file_path="test.py")
        assert result.success

        # Unsafe read should fail
        result = tool.execute(file_path="../etc/passwd")
        assert not result.success
        assert "traversal" in result.error.lower()

    @pytest.mark.security
    @pytest.mark.integration
    def test_end_to_end_safe_file_edit(self, mock_docker):
        """Test end-to-end safe file editing."""
        from src.tools.edit_code import EditCodeTool

        tool = EditCodeTool(mock_docker, language="python")

        # Mock file reading
        mock_docker.exec_command.return_value = (0, "old code")

        # Safe edit should work (though it may fail for other reasons)
        result = tool.execute(
            file_path="test.py",
            old_code="old code",
            new_code="new code"
        )
        # May succeed or fail, but shouldn't raise security exception

        # Unsafe edit should fail
        result = tool.execute(
            file_path="../etc/passwd",
            old_code="old",
            new_code="new"
        )
        assert not result.success


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
