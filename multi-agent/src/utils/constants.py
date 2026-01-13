"""
Constants for the multi-agent vulnerability patching system.

This module centralizes all magic numbers, default values, and 
configuration constants used throughout the codebase.
"""

from typing import Dict, List, Set
import os


# =============================================================================
# Constants Classes (for typed access)
# =============================================================================

class LLMConstants:
    """LLM-related constants."""
    DEFAULT_MODEL = "gpt-4.1"
    DEFAULT_TEMPERATURE = 0.0
    DEFAULT_MAX_TOKENS = 4096


class WorkflowConstants:
    """Workflow/orchestrator constants."""
    DEFAULT_MAX_ROUNDS = 1
    DEFAULT_MAX_INTERACTIONS = 100
    DEFAULT_TIMEOUT_SECONDS = 600


class DockerConstants:
    """Docker-related constants."""
    DEFAULT_TIMEOUT = 300
    DEFAULT_SCRIPT_TIMEOUT = 120
    DEFAULT_WORK_DIR = "/workspace"
    REGISTRY = "ghcr.io/anonymous2578-data"


class ToolConstants:
    """Tool-related constants."""
    DEFAULT_FUZZY_THRESHOLD = 0.85
    MINIMUM_FUZZY_THRESHOLD = 0.5
    CODE_PREVIEW_LENGTH = 300


# =============================================================================
# LLM Configuration Defaults (legacy module-level constants)
# =============================================================================

DEFAULT_LLM_MODEL = "gpt-4.1"
DEFAULT_TEMPERATURE = 0.0
DEFAULT_MAX_TOKENS = 4096

# Model-specific context limits (approximate)
MODEL_CONTEXT_LIMITS: Dict[str, int] = {
    "gpt-4o": 128000,
    "gpt-4o-mini": 128000,
    "gpt-4-turbo": 128000,
    "gpt-4": 8192,
    "gpt-3.5-turbo": 16385,
    "claude-3-opus": 200000,
    "claude-3-sonnet": 200000,
    "claude-3-haiku": 200000,
}


# =============================================================================
# Orchestrator Defaults
# =============================================================================

DEFAULT_MAX_ROUNDS = 3
DEFAULT_MAX_INTERACTIONS = 100
DEFAULT_TIMEOUT_SECONDS = 600  # 10 minutes per sample

# Repair loop limits
MAX_TOOL_ITERATIONS_PER_AGENT = -1


# =============================================================================
# Tool Limits
# =============================================================================

DEFAULT_TOOL_LIMITS = {
    "max_read_file_calls": 100,
    "max_find_class_calls": 100,
    "max_edit_code_calls": 100,
    "max_run_test_calls": 100,
}

# Fuzzy matching threshold for code matching
DEFAULT_FUZZY_THRESHOLD = 0.85
MINIMUM_FUZZY_THRESHOLD = 0.5  # Below this, no match is reported

# Code preview lengths for error messages
CODE_PREVIEW_LENGTH = 300
ERROR_OUTPUT_PREVIEW_LENGTH = 500
LLM_OUTPUT_TRUNCATION_LENGTH = 1000


# =============================================================================
# Docker Configuration
# =============================================================================

DEFAULT_DOCKER_TIMEOUT = 300  # 5 minutes
DEFAULT_SCRIPT_TIMEOUT = 120  # 2 minutes per script


# =============================================================================
# File System
# =============================================================================

DEFAULT_ARTIFACTS_DIR = os.getenv("ARTIFACTS_DIR", "./artifacts")

# Supported file extensions by language
LANGUAGE_EXTENSIONS: Dict[str, List[str]] = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".mjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "c": [".c", ".h"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".hh"],
    "go": [".go"],
    "ruby": [".rb"],
    "php": [".php"],
    "rust": [".rs"],
}

# Default file pattern for grep searches
DEFAULT_FILE_PATTERNS: Dict[str, str] = {
    "python": "*.py",
    "javascript": "*.js",
    "typescript": "*.ts",
    "java": "*.java",
    "c": "*.c",
    "cpp": "*.cpp",
    "go": "*.go",
}


# =============================================================================
# Agent Configuration
# =============================================================================

# Agent names (used for logging and identification)
AGENT_NAMES = {
    "context_knowledge": "ContextKnowledgeAgent",
    "planner": "PlannerAgent",
    "patch": "PatchAgent",
    "verification": "VerificationAgent",
}

# Agent tool access
AGENT_TOOL_ACCESS: Dict[str, List[str]] = {
    "ContextKnowledgeAgent": ["ReadFile", "FindClass"],
    "PlannerAgent": ["ReadFile"],
    "PatchAgent": ["EditCode", "ReadFile"],
    "VerificationAgent": ["RunTest"],
}


# =============================================================================
# CWE Categories
# =============================================================================

# CWE categories for knowledge guidance
CWE_CATEGORIES: Dict[str, str] = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-200": "Information Disclosure",
    "CWE-287": "Improper Authentication",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-400": "Resource Exhaustion",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "Open Redirect",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}

# CWEs that commonly require specific fix patterns
CWE_FIX_FUNCTIONS: Dict[str, List[str]] = {
    "CWE-22": ["os.path.normpath", "os.path.realpath", "os.path.abspath"],
    "CWE-78": ["subprocess.run", "shlex.quote", "shlex.split"],
    "CWE-79": ["html.escape", "markupsafe.escape", "bleach.clean"],
    "CWE-89": ["parameterized queries", "cursor.execute with params"],
    "CWE-94": ["ast.parse", "ast.literal_eval"],
    "CWE-200": ["logging module", "generic error responses"],
    "CWE-287": ["hmac.compare_digest", "bcrypt", "hashlib with salt"],
    "CWE-352": ["csrf_token", "validate_csrf"],
    "CWE-400": ["content-length checks", "timeouts", "resource limits"],
    "CWE-502": ["json.loads", "yaml.safe_load"],
    "CWE-601": ["urlparse", "url_for", "relative URL validation"],
    "CWE-918": ["allowlist validation", "urlparse checks"],
}


# Failure markers for extracting error details
FAILURE_MARKERS: Set[str] = {
    "error",
    "fail",
    "failed",
    "exception",
    "traceback",
    "assert",
    "assertion",
    "timeout",
}


# =============================================================================
# Environment Variables
# =============================================================================

ENV_OPENAI_API_KEY = "OPENAI_API_KEY"
ENV_LLM_MODEL = "LLM_MODEL"
ENV_LLM_TEMPERATURE = "LLM_TEMPERATURE"
ENV_MAX_ROUNDS = "MAX_ROUNDS"
ENV_MAX_INTERACTIONS = "MAX_INTERACTIONS"
ENV_DEBUG = "VULN_AGENT_DEBUG"
