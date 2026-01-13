"""
Refactored state management for the multi-agent vulnerability patching system.

This module provides:
- LangGraph-compatible state definitions
- State creation and conversion utilities
- Proper typing with TypedDicts
"""

from typing import Annotated, Any, Dict, List, Optional, TypedDict
import operator
import time

from .types import (
    RunStatus,
    ConstraintSheet,
    KnowledgePacket,
    DecisionRecord,
    PatchResult,
    VerificationResult,
    RoundResult,
)


class AgentState(TypedDict, total=False):
    """
    Shared state for the LangGraph workflow.
    
    This state is passed between all nodes in the graph and accumulates
    information as the workflow progresses.
    
    Using TypedDict with total=False for LangGraph compatibility - all fields
    are optional so nodes can return partial updates.
    """
    
    # --- Input Data (set at start) ---
    sample_id: str
    cve_id: str
    cwe_id: str
    file_path: str
    vulnerable_code: str
    programming_language: str
    line_hint: Optional[int]
    repo_url: Optional[str]
    docker_image: Optional[str]
    test_paths: List[str]
    poc_test: Optional[str]
    work_dir: Optional[str]
    problem_statement: str
    vulnerability_locations: List[Dict[str, Any]]
    cwe_info: Dict[str, Any]
    patch_description: str
    
    # --- Configuration ---
    max_rounds: int
    max_total_interactions: int
    ablation_mode: str
    
    # --- Phase 1: Context Gathering ---
    constraint_sheet: ConstraintSheet
    knowledge_packet: KnowledgePacket
    context_insights: Dict[str, Any]
    
    # --- Phase 2: Repair Loop State ---
    current_round: int
    decision_record: DecisionRecord
    patch_result: PatchResult
    verification_result: VerificationResult
    prev_feedback: Optional[Dict[str, Any]]
    last_patch_success: bool  # Track if last patch was applied successfully
    tests_passed: bool  # Track if tests passed
    poc_tests_passed: bool  # Track if POC tests passed
    regression_tests_passed: bool  # Track if regression/unit tests passed
    edited_files: List[str]  # Track files modified during patching
    
    # --- Accumulated Results ---
    rounds: Annotated[List[RoundResult], operator.add]
    messages: List[Dict[str, Any]]
    
    # --- Final Status ---
    status: str
    final_patch: Optional[Dict[str, Any]]
    error: Optional[str]
    
    # --- Statistics ---
    llm_calls: int
    tool_calls: int
    start_time: float
    total_duration_seconds: float
    completed_rounds: int
    current_tool_calls: List[Dict[str, Any]]
    agent_stats: Dict[str, Dict[str, int]]
    max_interactions_exceeded: bool


def create_initial_state(
    sample: Dict[str, Any],
    max_rounds: int = 1,
    max_total_interactions: int = -1,
    ablation_mode: str = "full"
) -> Dict[str, Any]:
    """
    Create the initial state from a sample dictionary.
    
    Args:
        sample: Sample from PatchEval dataset
        max_rounds: Maximum repair rounds
        ablation_mode: Ablation study mode (full, without_knowledge, etc.)
    
    Returns:
        Initialized state dictionary
    """
    return {
        # Input data
        "sample_id": sample.get("sample_id", "unknown"),
        "cve_id": sample.get("cve_id", ""),
        "cwe_id": sample.get("cwe_id", ""),
        "file_path": sample.get("file_path", ""),
        "vulnerable_code": sample.get("vulnerable_code", ""),
        "programming_language": sample.get("programming_language", "Python"),
        "line_hint": sample.get("line_hint"),
        "repo_url": sample.get("repo_url"),
        "docker_image": sample.get("docker_image"),
        "test_paths": sample.get("test_paths", []),
        "poc_test": sample.get("poc_test"),
        "work_dir": sample.get("work_dir"),
        "problem_statement": sample.get("problem_statement", ""),
        "vulnerability_locations": sample.get("vulnerability_locations", []),
        "cwe_info": sample.get("cwe_info", {}),
        "patch_description": sample.get("patch_description", ""),
        
        # Configuration
        "max_rounds": max_rounds,
        "max_total_interactions": max_total_interactions,
        "ablation_mode": ablation_mode,
        
        # Initialize empty state
        "constraint_sheet": {},
        "knowledge_packet": {},
        "context_insights": {},
        "current_round": 0,
        "decision_record": {},
        "patch_result": {},
        "verification_result": {},
        "prev_feedback": None,
        "rounds": [],
        "status": RunStatus.PENDING.value,
        "final_patch": None,
        "error": None,
        "edited_files": [],  # Track files modified during patching
        "last_patch_success": False,  # Track if last patch was applied successfully
        "tests_passed": False,  # Track if tests passed
        
        # Statistics
        "llm_calls": 0,
        "tool_calls": 0,
        "start_time": time.time(),
        "total_duration_seconds": 0.0,
        "current_tool_calls": [],
        "messages": [],
        "agent_stats": {},
        "max_interactions_exceeded": False,
    }


def state_to_run_result(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert final AgentState to a RunResult-like dictionary.
    
    This provides backward compatibility with the old orchestrator output format.
    
    Args:
        state: Final workflow state
    
    Returns:
        Dictionary compatible with RunResult expectations
    """
    # Calculate total duration
    start_time = state.get("start_time", 0)
    total_duration = time.time() - start_time if start_time else 0
    
    return {
        "sample_id": state.get("sample_id", "unknown"),
        "status": state.get("status", "unknown"),
        "rounds": state.get("rounds", []),
        "constraint_sheet": state.get("constraint_sheet", {}),
        "knowledge_packet": state.get("knowledge_packet", {}),
        "final_patch": state.get("final_patch"),
        "total_duration_seconds": state.get("total_duration_seconds", total_duration),
        "total_llm_calls": state.get("llm_calls", 0),
        "total_tool_calls": state.get("tool_calls", 0),
        "agent_stats": state.get("agent_stats", {}),
        "total_tokens": sum(
            agent.get("total_tokens", 0) for agent in state.get("agent_stats", {}).values()
        ),
        "error": state.get("error"),
    }


