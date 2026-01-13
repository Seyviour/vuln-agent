"""
Configuration for the multi-agent vulnerability patching system.

This module provides:
- Dataclass-based configuration with validation
- Environment variable loading
- Configuration merging and overrides
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import os
import logging

from .utils.constants import (
    DEFAULT_LLM_MODEL,
    DEFAULT_TEMPERATURE,
    DEFAULT_MAX_TOKENS,
    DEFAULT_MAX_ROUNDS,
    DEFAULT_MAX_INTERACTIONS,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_ARTIFACTS_DIR,
    DEFAULT_TOOL_LIMITS,
    DEFAULT_DOCKER_TIMEOUT,
    ENV_OPENAI_API_KEY,
    ENV_LLM_MODEL,
    ENV_LLM_TEMPERATURE,
    ENV_MAX_ROUNDS,
    ENV_MAX_INTERACTIONS,
)
from .utils.types import AblationMode, LineHintPrecision
from .utils.exceptions import InvalidConfigurationError, MissingAPIKeyError


logger = logging.getLogger(__name__)


def _validate_positive(value: int, field_name: str) -> int:
    """Validate that a value is positive."""
    if value <= 0:
        raise InvalidConfigurationError(field_name, value, "Must be positive")
    return value


def _validate_positive_or_infinite(value: int, field_name: str) -> int:
    """Validate that a value is positive, or -1 for infinite."""
    if value == -1:
        return value
    return _validate_positive(value, field_name)


def _validate_range(value: float, min_val: float, max_val: float, field_name: str) -> float:
    """Validate that a value is within a range."""
    if not min_val <= value <= max_val:
        raise InvalidConfigurationError(
            field_name, value, f"Must be between {min_val} and {max_val}"
        )
    return value


@dataclass
class LLMConfig:
    """
    LLM configuration with validation.
    
    Attributes:
        model: The LLM model identifier (e.g., 'gpt-4.1', 'claude-3-opus')
        temperature: Sampling temperature (0.0 = deterministic)
        max_tokens: Maximum tokens for responses
        api_key: API key for the LLM provider
    """
    model: str = DEFAULT_LLM_MODEL
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS
    api_key: Optional[str] = field(
        default=None,
        repr=False  # Don't include in repr for security
    )
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        # Load API key from environment if not provided
        if self.api_key is None:
            self.api_key = os.getenv(ENV_OPENAI_API_KEY)
        
        # Validate temperature
        self.temperature = _validate_range(
            self.temperature, 0.0, 2.0, "temperature"
        )
        
        # Validate max_tokens
        self.max_tokens = _validate_positive(self.max_tokens, "max_tokens")
    
    def validate_api_key(self) -> None:
        """
        Validate that API key is present.
        
        Raises:
            MissingAPIKeyError: If API key is not configured
        """
        if not self.api_key:
            raise MissingAPIKeyError(ENV_OPENAI_API_KEY)
    
    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Create configuration from environment variables."""
        return cls(
            model=os.getenv(ENV_LLM_MODEL, DEFAULT_LLM_MODEL),
            temperature=float(os.getenv(ENV_LLM_TEMPERATURE, str(DEFAULT_TEMPERATURE))),
            api_key=os.getenv(ENV_OPENAI_API_KEY),
        )


@dataclass
class ToolConfig:
    """
    Tool permissions and limits.
    
    Controls which tools are enabled and their per-round usage limits.
    """
    read_file_enabled: bool = True
    find_class_enabled: bool = True
    edit_code_enabled: bool = True
    run_test_enabled: bool = True
    
    # Limits per tool per round
    max_read_file_calls: int = DEFAULT_TOOL_LIMITS["max_read_file_calls"]
    max_find_class_calls: int = DEFAULT_TOOL_LIMITS["max_find_class_calls"]
    max_edit_code_calls: int = DEFAULT_TOOL_LIMITS["max_edit_code_calls"]
    max_run_test_calls: int = DEFAULT_TOOL_LIMITS["max_run_test_calls"]
    
    def __post_init__(self):
        """Validate limits."""
        for attr in ["max_read_file_calls", "max_find_class_calls", 
                     "max_edit_code_calls", "max_run_test_calls"]:
            value = getattr(self, attr)
            if value < 0:
                raise InvalidConfigurationError(attr, value, "Cannot be negative")
    
    def get_enabled_tools(self) -> list[str]:
        """Get list of enabled tool names."""
        tools = []
        if self.read_file_enabled:
            tools.append("ReadFile")
        if self.find_class_enabled:
            tools.append("FindClass")
        if self.edit_code_enabled:
            tools.append("EditCode")
        if self.run_test_enabled:
            tools.append("RunTest")
        return tools


@dataclass
class OrchestratorConfig:
    """
    Orchestrator configuration.
    
    Controls the repair loop behavior and resource limits.
    """
    max_rounds: int = DEFAULT_MAX_ROUNDS
    max_total_interactions: int = DEFAULT_MAX_INTERACTIONS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    
    # State management
    persist_artifacts: bool = True
    artifacts_dir: str = DEFAULT_ARTIFACTS_DIR
    
    # Logging
    verbose: bool = True
    log_level: str = "INFO"
    
    def __post_init__(self):
        """Validate configuration."""
        self.max_rounds = _validate_positive_or_infinite(self.max_rounds, "max_rounds")
        self.max_total_interactions = _validate_positive_or_infinite(
            self.max_total_interactions, "max_total_interactions"
        )
        if self.timeout_seconds < 0:
            raise InvalidConfigurationError(
                "timeout_seconds", self.timeout_seconds, "Cannot be negative"
            )
        
        # Validate log level
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_levels:
            raise InvalidConfigurationError(
                "log_level", self.log_level, f"Must be one of {valid_levels}"
            )


@dataclass
class DockerConfig:
    """Docker-related configuration."""
    timeout: int = DEFAULT_DOCKER_TIMEOUT
    work_dir: str = "/workspace"
    cleanup_on_exit: bool = True
    
    def __post_init__(self):
        """Validate configuration."""
        if self.timeout < 0:
            raise InvalidConfigurationError(
                "timeout", self.timeout, "Cannot be negative"
            )


@dataclass
class ExperimentConfig:
    """
    Full experiment configuration.
    
    Combines all sub-configurations for a complete experiment setup.
    """
    # Core settings
    llm: LLMConfig = field(default_factory=LLMConfig)
    tools: ToolConfig = field(default_factory=ToolConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    docker: DockerConfig = field(default_factory=DockerConfig)
    
    # Ablation settings
    ablation_mode: AblationMode = AblationMode.FULL
    line_hint_precision: LineHintPrecision = LineHintPrecision.PRECISE
    
    # Dataset settings
    language_filter: str = "Python"
    dataset_path: str = "../PatchEval/patcheval/datasets/input.json"
    
    def __post_init__(self):
        """Convert string ablation mode to enum if needed."""
        if isinstance(self.ablation_mode, str):
            self.ablation_mode = AblationMode(self.ablation_mode)
        if isinstance(self.line_hint_precision, str):
            self.line_hint_precision = LineHintPrecision(self.line_hint_precision)
    
    @classmethod
    def from_env(cls) -> "ExperimentConfig":
        """Create configuration from environment variables."""
        return cls(
            llm=LLMConfig.from_env(),
            orchestrator=OrchestratorConfig(
                max_rounds=int(os.getenv(ENV_MAX_ROUNDS, str(DEFAULT_MAX_ROUNDS))),
                max_total_interactions=int(
                    os.getenv(ENV_MAX_INTERACTIONS, str(DEFAULT_MAX_INTERACTIONS))
                ),
            ),
        )
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "ExperimentConfig":
        """Create configuration from a dictionary."""
        llm_dict = config_dict.get("llm", {})
        tools_dict = config_dict.get("tools", {})
        orch_dict = config_dict.get("orchestrator", {})
        docker_dict = config_dict.get("docker", {})
        
        return cls(
            llm=LLMConfig(**llm_dict) if llm_dict else LLMConfig(),
            tools=ToolConfig(**tools_dict) if tools_dict else ToolConfig(),
            orchestrator=OrchestratorConfig(**orch_dict) if orch_dict else OrchestratorConfig(),
            docker=DockerConfig(**docker_dict) if docker_dict else DockerConfig(),
            ablation_mode=AblationMode(config_dict.get("ablation_mode", "full")),
            line_hint_precision=LineHintPrecision(
                config_dict.get("line_hint_precision", "precise")
            ),
            language_filter=config_dict.get("language_filter", "Python"),
            dataset_path=config_dict.get("dataset_path", cls.dataset_path),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "llm": {
                "model": self.llm.model,
                "temperature": self.llm.temperature,
                "max_tokens": self.llm.max_tokens,
            },
            "tools": {
                "read_file_enabled": self.tools.read_file_enabled,
                "find_class_enabled": self.tools.find_class_enabled,
                "edit_code_enabled": self.tools.edit_code_enabled,
                "run_test_enabled": self.tools.run_test_enabled,
            },
            "orchestrator": {
                "max_rounds": self.orchestrator.max_rounds,
                "max_total_interactions": self.orchestrator.max_total_interactions,
                "timeout_seconds": self.orchestrator.timeout_seconds,
            },
            "docker": {
                "timeout": self.docker.timeout,
                "work_dir": self.docker.work_dir,
            },
            "ablation_mode": self.ablation_mode.value,
            "line_hint_precision": self.line_hint_precision.value,
            "language_filter": self.language_filter,
            "dataset_path": self.dataset_path,
        }
    
    def validate(self) -> None:
        """
        Validate the complete configuration.
        
        Raises:
            ConfigurationError: If any configuration is invalid
        """
        self.llm.validate_api_key()
        # Additional cross-config validation could go here


# =============================================================================
# Backward Compatibility Exports
# =============================================================================

# Re-export from types for backward compatibility
__all__ = [
    "LLMConfig",
    "ToolConfig", 
    "OrchestratorConfig",
    "DockerConfig",
    "ExperimentConfig",
    "AblationMode",
    "LineHintPrecision",
]
