"""
Custom exceptions for the multi-agent vulnerability patching system.

This module defines exceptions that are actually used in the codebase.
Cleaned up to remove unused exception definitions.
"""

from typing import Any, Dict, Optional


class VulnAgentError(Exception):
    """Base exception for all multi-agent system errors."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.cause = cause

    def __str__(self) -> str:
        msg = self.message
        if self.details:
            msg += f" | Details: {self.details}"
        if self.cause:
            msg += f" | Caused by: {self.cause}"
        return msg


# =============================================================================
# Configuration Errors
# =============================================================================

class ConfigurationError(VulnAgentError):
    """Error in configuration or environment setup."""
    pass


class MissingAPIKeyError(ConfigurationError):
    """API key is missing or invalid."""

    def __init__(self, key_name: str = "OPENAI_API_KEY"):
        super().__init__(
            f"Missing required API key: {key_name}. "
            f"Please set the {key_name} environment variable."
        )
        self.key_name = key_name


class InvalidConfigurationError(ConfigurationError):
    """Configuration value is invalid."""

    def __init__(self, field: str, value: Any, reason: str):
        super().__init__(
            f"Invalid configuration for '{field}': {value}. {reason}"
        )
        self.field = field
        self.value = value
        self.reason = reason


# =============================================================================
# Agent Errors
# =============================================================================

class AgentError(VulnAgentError):
    """Base exception for agent-related errors."""

    def __init__(
        self,
        agent_name: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message, details, cause)
        self.agent_name = agent_name


class AgentExecutionError(AgentError):
    """Agent failed during execution."""
    pass


class AgentOutputParsingError(AgentError):
    """Failed to parse agent output."""

    def __init__(self, agent_name: str, raw_output: str, reason: str):
        super().__init__(
            agent_name,
            f"Failed to parse output from '{agent_name}': {reason}",
            details={"raw_output_preview": raw_output[:500]}
        )
        self.raw_output = raw_output


# =============================================================================
# Tool Errors
# =============================================================================

class ToolNotFoundError(VulnAgentError):
    """Requested tool does not exist."""

    def __init__(self, tool_name: str, available_tools: list[str]):
        super().__init__(
            f"Tool '{tool_name}' not found. Available: {available_tools}"
        )
        self.tool_name = tool_name
        self.available_tools = available_tools


class ToolNotAllowedError(VulnAgentError):
    """Tool is not allowed for the current agent."""

    def __init__(self, tool_name: str, agent_name: str, allowed_tools: list[str]):
        super().__init__(
            f"Tool '{tool_name}' is not allowed for agent '{agent_name}'. "
            f"Allowed tools: {allowed_tools}"
        )
        self.tool_name = tool_name
        self.agent_name = agent_name
        self.allowed_tools = allowed_tools


class ToolExecutionError(VulnAgentError):
    """Tool execution failed."""

    def __init__(
        self,
        tool_name: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message, details, cause)
        self.tool_name = tool_name


# =============================================================================
# Docker Errors
# =============================================================================

class DockerError(VulnAgentError):
    """Base exception for Docker-related errors."""
    pass


class DockerNotAvailableError(DockerError):
    """Docker daemon is not available."""

    def __init__(self):
        super().__init__(
            "Docker is not available. Please ensure Docker daemon is running."
        )


class ContainerNotFoundError(DockerError):
    """Docker container does not exist."""

    def __init__(self, container_id: str):
        super().__init__(f"Container not found: {container_id}")
        self.container_id = container_id


class ContainerExecutionError(DockerError):
    """Command execution in container failed."""

    def __init__(
        self,
        container_id: str,
        command: str,
        exit_code: int,
        output: str
    ):
        super().__init__(
            f"Command failed in container {container_id} with exit code {exit_code}",
            details={"command": command, "output_preview": output[:500]}
        )
        self.container_id = container_id
        self.command = command
        self.exit_code = exit_code
        self.output = output


# =============================================================================
# Workflow Errors
# =============================================================================

class WorkflowError(VulnAgentError):
    """Base exception for workflow orchestration errors."""
    pass


# =============================================================================
# LLM Errors
# =============================================================================

class LLMError(VulnAgentError):
    """Base exception for LLM-related errors."""
    pass


# =============================================================================
# Patch Errors
# =============================================================================

class PatchError(VulnAgentError):
    """Base exception for patch-related errors."""
    pass
