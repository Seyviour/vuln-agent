"""
Pytest configuration and shared fixtures.

This module provides reusable test fixtures for the multi-agent system tests.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any

# Import project modules
import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from src.config import LLMConfig, OrchestratorConfig
from src.tools import ToolRegistry, DockerExecutor
from src.utils.types import AgentOutput, ToolResult


# =============================================================================
# Configuration Fixtures
# =============================================================================

@pytest.fixture
def llm_config():
    """Test LLM configuration."""
    return LLMConfig(
        model="gpt-4o-mini",
        temperature=0.0,
        max_tokens=4096,
        api_key="test-api-key-12345"
    )


@pytest.fixture
def orchestrator_config():
    """Test orchestrator configuration."""
    return OrchestratorConfig(
        max_rounds=3,
        max_total_interactions=-1,
        timeout_seconds=300,
        verbose=False,
        log_level="WARNING"
    )


# =============================================================================
# Mock Docker Fixtures
# =============================================================================

@pytest.fixture
def mock_docker():
    """Mock Docker executor."""
    docker = Mock(spec=DockerExecutor)

    # Default successful responses
    docker.exec_command.return_value = (0, "success")
    docker.verify_container.return_value = True
    docker.write_file.return_value = (0, "File written")

    # Make container_id accessible
    docker.container_id = "test-container"
    docker.work_dir = "/workspace"

    return docker


@pytest.fixture
def mock_docker_with_files(mock_docker):
    """Mock Docker executor with file reading capabilities."""

    file_contents = {
        "test.py": "def vulnerable():\n    return request.args.get('data')\n",
        "app/views.py": "from flask import request\n\ndef index():\n    data = request.args.get('input')\n    return data\n",
        "utils/helpers.py": "def helper():\n    pass\n"
    }

    def mock_exec_command(cmd: str, **kwargs):
        """Mock exec_command that returns file contents."""
        # Extract file path from cat command
        if "cat" in cmd:
            for path, content in file_contents.items():
                if path in cmd:
                    return (0, content)
            return (1, f"File not found: {cmd}")

        return (0, "success")

    mock_docker.exec_command.side_effect = mock_exec_command
    mock_docker.file_contents = file_contents  # For test access

    return mock_docker


# =============================================================================
# Tool Fixtures
# =============================================================================

@pytest.fixture
def mock_tool_registry(mock_docker):
    """Mock tool registry with all tools registered."""
    registry = ToolRegistry(
        docker_executor=mock_docker,
        sample={"programming_language": "python", "cve_id": "CVE-2021-1234"},
        auto_register=True
    )
    return registry


@pytest.fixture
def mock_tool_result_success():
    """Factory for successful tool results."""
    def _make_result(output="success", **metadata):
        return ToolResult(
            success=True,
            output=output,
            error=None,
            metadata=metadata
        )
    return _make_result


@pytest.fixture
def mock_tool_result_failure():
    """Factory for failed tool results."""
    def _make_result(error="Tool execution failed", **metadata):
        return ToolResult(
            success=False,
            output="",
            error=error,
            metadata=metadata
        )
    return _make_result


# =============================================================================
# Sample Data Fixtures
# =============================================================================

@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability data."""
    return {
        "sample_id": "CVE-2021-1234",
        "cve_id": "CVE-2021-1234",
        "cwe_id": "CWE-79",
        "file_path": "app/views.py",
        "vulnerable_code": "def index():\n    data = request.args.get('input')\n    return data",
        "programming_language": "Python",
        "line_hint": 2,
        "problem_statement": "XSS vulnerability in input handling",
        "vulnerability_locations": [
            {"file": "app/views.py", "line": 2, "function": "index"}
        ],
        "cwe_info": {
            "id": "CWE-79",
            "name": "Cross-site Scripting (XSS)",
            "description": "Improper neutralization of input"
        }
    }


@pytest.fixture
def sample_constraint_sheet():
    """Sample constraint sheet from context agent."""
    return {
        "api_contracts": [
            {
                "function": "index",
                "signature": "index() -> str",
                "returns": "HTML string"
            }
        ],
        "data_flow": {
            "sources": ["request.args.get"],
            "sinks": ["return"]
        },
        "conventions": {
            "naming": "snake_case",
            "imports": "grouped at top"
        },
        "security_requirements": [
            "All user input must be sanitized",
            "HTML must be escaped"
        ]
    }


@pytest.fixture
def sample_knowledge_packet():
    """Sample knowledge packet from context agent."""
    return {
        "cwe_info": {
            "id": "CWE-79",
            "name": "XSS",
            "description": "Cross-site scripting vulnerability"
        },
        "fix_strategies": [
            {
                "name": "HTML Escaping",
                "description": "Escape HTML special characters",
                "example": "from markupsafe import escape\nreturn escape(data)"
            }
        ],
        "recommended_approach": "Use framework's built-in escaping (e.g., markupsafe.escape)"
    }


@pytest.fixture
def sample_decision_record():
    """Sample decision record from planner."""
    return {
        "strategies": [
            {
                "rank": 1,
                "name": "Add HTML escaping",
                "description": "Use markupsafe.escape to sanitize user input",
                "changes": [
                    {
                        "file": "app/views.py",
                        "location": "index function",
                        "change_type": "modify",
                        "description": "Add escape() call"
                    }
                ],
                "trade_offs": {
                    "pros": ["Simple", "Secure", "Maintained by framework"],
                    "cons": ["Requires import"],
                    "risk_level": "low"
                }
            }
        ],
        "decision": {
            "chosen_strategy": 1,
            "rationale": "Best practice for Flask applications",
            "expected_effect": "Prevent XSS attacks"
        },
        "next_action": {
            "action_type": "edit",
            "target_file": "app/views.py",
            "target_location": "index function",
            "guidance": "Import escape and wrap user input",
            "security_requirements": ["HTML must be escaped"],
            "must_preserve": ["Return type", "Function signature"]
        }
    }


# =============================================================================
# Agent Output Fixtures
# =============================================================================

@pytest.fixture
def mock_agent_output_success():
    """Factory for successful agent outputs."""
    def _make_output(content: Dict[str, Any], **kwargs):
        return AgentOutput(
            agent_name=kwargs.get("agent_name", "TestAgent"),
            success=True,
            content=content,
            raw_response=str(content),
            tool_calls=kwargs.get("tool_calls", []),
            token_usage=kwargs.get("token_usage", {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }),
            tool_calls_count=kwargs.get("tool_calls_count", 0)
        )
    return _make_output


@pytest.fixture
def mock_agent_output_failure():
    """Factory for failed agent outputs."""
    def _make_output(error: str, **kwargs):
        return AgentOutput(
            agent_name=kwargs.get("agent_name", "TestAgent"),
            success=False,
            content={},
            error=error,
            token_usage={},
            tool_calls_count=0
        )
    return _make_output


# =============================================================================
# State Fixtures
# =============================================================================

@pytest.fixture
def initial_agent_state(sample_vulnerability):
    """Initial workflow state."""
    from src.utils.state import create_initial_state

    return create_initial_state(
        sample=sample_vulnerability,
        max_rounds=3,
        max_total_interactions=-1,
        ablation_mode="full"
    )


# =============================================================================
# Mock LLM Fixtures
# =============================================================================

@pytest.fixture
def mock_llm_response():
    """Factory for mock LLM responses."""
    def _make_response(content: str, **kwargs):
        response = Mock()
        response.choices = [Mock()]
        response.choices[0].message = Mock()
        response.choices[0].message.content = content
        response.usage = Mock()
        response.usage.prompt_tokens = kwargs.get("prompt_tokens", 100)
        response.usage.completion_tokens = kwargs.get("completion_tokens", 50)
        response.usage.total_tokens = kwargs.get("total_tokens", 150)
        return response
    return _make_response


@pytest.fixture
def patch_llm_call():
    """Patch LLM API calls to avoid real requests."""
    with patch("src.agents.base.BaseAgent._run_with_tools") as mock:
        mock.return_value = (
            '{"result": "mocked"}',
            [],
            {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        )
        yield mock


# =============================================================================
# Utility Fixtures
# =============================================================================

@pytest.fixture
def temp_workspace(tmp_path):
    """Temporary workspace directory for tests."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace


@pytest.fixture
def sample_python_file(temp_workspace):
    """Create a sample Python file for testing."""
    file_path = temp_workspace / "test.py"
    content = '''def vulnerable_function():
    """A vulnerable function."""
    user_input = request.args.get('data')
    return user_input
'''
    file_path.write_text(content)
    return file_path


# =============================================================================
# Markers
# =============================================================================

def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests for individual components")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow-running tests")
    config.addinivalue_line("markers", "docker: Tests requiring Docker")
    config.addinivalue_line("markers", "llm: Tests calling LLM APIs")
    config.addinivalue_line("markers", "security: Security-related tests")
