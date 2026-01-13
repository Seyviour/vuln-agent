"""
Type definitions and data structures for the multi-agent system.

This module provides essential types that are actually used in the codebase.
Cleaned up to remove unused type definitions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, TypedDict


# =============================================================================
# Enums
# =============================================================================

class AgentRole(Enum):
    """Agent role identifiers."""
    REPO_CONTEXT = "repo_context"
    KNOWLEDGE = "knowledge"
    PLANNER = "planner"
    PATCH = "patch"
    VERIFICATION = "verification"


class RunStatus(Enum):
    """Status of a patching run."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAIL_NO_FIX = "fail_no_fix"
    FAIL_REGRESSION = "fail_regression"
    FAIL_MAX_ROUNDS = "fail_max_rounds"
    FAIL_MAX_INTERACTIONS = "fail_max_interactions"
    FAIL_ERROR = "fail_error"
    FAIL_PATCH = "fail_patch"
    FAIL_TEST = "fail_test"


class AblationMode(Enum):
    """Ablation study modes for component analysis."""
    FULL = "full"                    # All agents enabled
    WITHOUT_KNOWLEDGE = "without_knowledge"  # No Knowledge Agent
    SINGLE_TURN = "single_turn"      # No feedback loop
    WITHOUT_CONTEXT = "without_context"  # No Repo Context Agent


class LineHintPrecision(Enum):
    """Line hint precision levels within the provided function."""
    WITHOUT_LINE = "without_line"  # Only function, no line hints
    PRECISE = "precise"            # Exact line numbers
    APPROXIMATE = "approximate"    # ±5 lines
    IMPRECISE = "imprecise"        # Only start/end of function


# =============================================================================
# TypedDicts for Structured Data (Used Types Only)
# =============================================================================

class ConstraintSheet(TypedDict, total=False):
    """Complete constraint sheet from ContextKnowledgeAgent."""
    function_semantics: Optional[Dict[str, Any]]
    api_contract: Optional[Dict[str, Any]]
    security_analysis: Optional[Dict[str, Any]]
    repo_conventions: Optional[Dict[str, Any]]
    patch_constraints: Optional[Dict[str, Any]]
    raw_analysis: Optional[str]
    parse_error: Optional[str]


class KnowledgePacket(TypedDict, total=False):
    """Knowledge packet from ContextKnowledgeAgent (legacy, being phased out)."""
    cwe_id: str
    cwe_name: str
    vulnerability_pattern: str
    fix_strategies: List[Dict[str, Any]]
    predated_examples: List[Dict[str, Any]]
    recommended_approach: str


class PatchStrategy(TypedDict, total=False):
    """A patch strategy from PlannerAgent."""
    rank: int
    name: str
    description: str
    changes: List[Dict[str, Any]]
    trade_offs: Optional[Dict[str, Any]]


class NextAction(TypedDict, total=False):
    """Next action instruction from PlannerAgent."""
    action_type: str  # "edit", "add", "delete"
    target_file: str
    target_location: str
    instruction: str
    old_code_hint: str
    new_code_template: str


class FeedbackResponse(TypedDict, total=False):
    """Feedback response in decision record."""
    addressed_issues: List[str]
    remaining_concerns: List[str]


class DecisionRecord(TypedDict, total=False):
    """Complete decision record from PlannerAgent."""
    strategies: List[PatchStrategy]
    decision: Optional[Dict[str, Any]]
    next_action: NextAction
    feedback_response: FeedbackResponse


class PatchChange(TypedDict, total=False):
    """A single patch change applied."""
    file: str
    description: str
    old_code_summary: str
    new_code_summary: str
    success: bool
    diff: str
    full_file_content: Optional[str]


class PatchResult(TypedDict, total=False):
    """Result from PatchAgent."""
    patch_applied: bool
    changes: List[PatchChange]
    mitigation_mapping: Dict[str, str]
    diff: str
    tool_calls_summary: List[Dict[str, Any]]


class VerificationResult(TypedDict, total=False):
    """Result from VerificationAgent."""
    poc_result: Optional[Dict[str, Any]]
    regression_result: Optional[Dict[str, Any]]
    overall_verdict: str
    feedback_for_planner: Optional[Dict[str, Any]]
    error: Optional[str]


class RoundResult(TypedDict, total=False):
    """Result of a single patching round."""
    round_number: int
    decision_record: DecisionRecord
    patch_result: PatchResult
    verification_result: VerificationResult
    status: str
    duration_seconds: float


# =============================================================================
# Tool-Related Types
# =============================================================================

class ToolCallRecord(TypedDict, total=False):
    """Record of a tool call."""
    tool: str
    arguments: Dict[str, Any]
    result: Dict[str, Any]
    success: bool
    system_prompt: Optional[str]  # Added for logging


# =============================================================================
# Result Dataclasses
# =============================================================================

@dataclass
class ToolResult:
    """Result from a tool execution."""
    success: bool
    output: str
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        status = "✓" if self.success else "✗"
        return f"ToolResult({status}, output={len(self.output)} chars)"


@dataclass
class AgentOutput:
    """Structured output from an agent."""
    agent_name: str
    success: bool
    content: Dict[str, Any]
    raw_response: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    token_usage: Dict[str, int] = field(default_factory=dict)
    tool_calls_count: int = 0
    llm_calls: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "success": self.success,
            "content": self.content,
            "tool_calls": self.tool_calls,
            "token_usage": self.token_usage,
            "tool_calls_count": self.tool_calls_count,
            "llm_calls": self.llm_calls,
            "error": self.error
        }
