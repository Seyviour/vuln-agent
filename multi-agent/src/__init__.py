"""Multi-Agent Vulnerability Patching System.

This package implements a multi-agent system for automatically patching
security vulnerabilities using a Coordinator-based architecture.

Architecture:
- CoordinatorAgent: Strategist and orchestrator that leads the team
- ContextKnowledgeAgent: Repo analysis + CWE/CVE knowledge
- PatchAgent: Applies code patches
- VerificationAgent: Validates via testing
"""

# Exceptions
from .utils.exceptions import (
    VulnAgentError,
    ConfigurationError,
    ToolExecutionError,
    DockerError,
    LLMError,
    WorkflowError,
    PatchError,
)

# Types
from .utils.types import (
    AgentRole,
    RunStatus,
    AblationMode,
    LineHintPrecision,
)

# Constants
from .utils.constants import (
    LLMConstants,
    WorkflowConstants,
    DockerConstants,
    ToolConstants,
)

# Configuration
from .config import (
    LLMConfig,
    OrchestratorConfig,
    ExperimentConfig,
)

# Data loading
from .utils.data_loader import PatchEvalDataset, Sample, load_dataset

# Orchestration (Coordinator-based)
from .orchestrator import (
    PatchingOrchestrator,
    RunResult,
    RoundResultData,
    run_sample,
)
# Backward compat alias
Orchestrator = PatchingOrchestrator

# Tools
from .tools import ToolRegistry, DockerExecutor

# Agents
from .agents import CoordinatorAgent

# State utilities (still useful for compatibility)
from .utils.state import AgentState, create_initial_state

__all__ = [
    # Exceptions
    'VulnAgentError',
    'ConfigurationError',
    'ToolExecutionError',
    'DockerError',
    'LLMError',
    'WorkflowError',
    'PatchError',
    # Types
    'AgentRole',
    'RunStatus',
    'AblationMode',
    'LineHintPrecision',
    # Constants
    'LLMConstants',
    'WorkflowConstants',
    'DockerConstants',
    'ToolConstants',
    # Config
    'LLMConfig',
    'OrchestratorConfig',
    'ExperimentConfig',
    # Data
    'PatchEvalDataset',
    'Sample',
    'load_dataset',
    # Orchestrator
    'PatchingOrchestrator',
    'Orchestrator',
    'RunResult',
    'RoundResultData',
    'run_sample',
    # Tools
    'ToolRegistry',
    'DockerExecutor',
    # Agents
    'CoordinatorAgent',
    # State
    'AgentState',
    'create_initial_state',
]

__version__ = '3.0.0'
