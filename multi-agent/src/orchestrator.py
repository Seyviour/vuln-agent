"""
Orchestrator for the multi-agent vulnerability patching system.

This module uses the Coordinator Agent pattern for natural agent collaboration
instead of a rigid state machine workflow.
"""

from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional
import logging
import time
import sqlite3
import os

from .utils.types import RunStatus
from .config import LLMConfig, OrchestratorConfig, ExperimentConfig
from .tools import ToolRegistry, DockerExecutor
from .agents.coordinator import CoordinatorAgent


logger = logging.getLogger(__name__)


def _clear_agent_sessions(sample_id: str, artifacts_dir: str) -> None:
    """Remove persisted agent sessions/messages for this sample."""
    if not sample_id:
        return
    db_path = os.path.join(artifacts_dir, "agent_sessions.sqlite")
    if not os.path.exists(db_path):
        return
    session_prefix = f"{sample_id}:"
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM agent_messages WHERE session_id LIKE ?",
                (session_prefix + "%",),
            )
            cur.execute(
                "DELETE FROM agent_sessions WHERE session_id LIKE ?",
                (session_prefix + "%",),
            )
            conn.commit()
    except Exception as exc:
        logger.warning("Failed to clear agent sessions for %s: %s", sample_id, exc)


def _merge_token_usage(target: Dict[str, int], source: Dict[str, int]) -> Dict[str, int]:
    """Merge token usage counters into target."""
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        if key in source:
            target[key] = target.get(key, 0) + (source.get(key) or 0)
    return target


def _merge_agent_stats(
    target: Dict[str, Dict[str, int]],
    incoming: Dict[str, Dict[str, int]]
) -> Dict[str, Dict[str, int]]:
    """Merge agent token stats by summing counters."""
    for agent_name, tokens in incoming.items():
        if agent_name not in target:
            target[agent_name] = dict(tokens)
        else:
            _merge_token_usage(target[agent_name], tokens)
    return target


def _collect_tool_stats(
    tool_calls: Optional[List[Dict[str, Any]]]
) -> tuple[int, int, Dict[str, Dict[str, int]]]:
    """
    Collect tool and LLM call stats from tool call records.

    Returns (total_tool_calls, total_llm_calls, agent_stats).
    """
    total_tool_calls = 0
    total_llm_calls = 0
    agent_stats: Dict[str, Dict[str, int]] = {}

    for call in tool_calls or []:
        total_tool_calls += 1
        result = call.get("result", {}) if isinstance(call, dict) else {}
        metadata = result.get("metadata", {}) if isinstance(result, dict) else {}
        if isinstance(metadata, dict):
            agent_name = metadata.get("agent_name")
            token_usage = metadata.get("token_usage", {})
            if agent_name and isinstance(token_usage, dict):
                total_llm_calls += 1
                _merge_agent_stats(agent_stats, {agent_name: token_usage})

            nested_tool_calls = metadata.get("tool_calls")
            if isinstance(nested_tool_calls, list) and nested_tool_calls:
                nested_tool_count, nested_llm_count, nested_agent_stats = _collect_tool_stats(
                    nested_tool_calls
                )
                total_tool_calls += nested_tool_count
                total_llm_calls += nested_llm_count
                _merge_agent_stats(agent_stats, nested_agent_stats)

    return total_tool_calls, total_llm_calls, agent_stats


def _extract_json_payload(text: str) -> Optional[Dict[str, Any]]:
    """Extract a JSON object from a text response."""
    if not text:
        return None

    fence_match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
    if fence_match:
        try:
            payload = json.loads(fence_match.group(1))
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass

    obj_match = re.search(r"{[\s\S]*}", text)
    if obj_match:
        try:
            payload = json.loads(obj_match.group(0))
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass

    return None


def _extract_rounds_from_tool_calls(
    tool_calls: Optional[List[Dict[str, Any]]]
) -> List["RoundResultData"]:
    """Treat each VerificationAgent call as a completed round."""
    rounds: List[RoundResultData] = []
    round_number = 0

    for call in tool_calls or []:
        if not isinstance(call, dict):
            continue
        if call.get("tool") != "AskAgent":
            continue

        args = call.get("arguments", {}) or {}
        agent_name = (args.get("agent_name") or "").lower()
        if "verification" not in agent_name:
            continue

        round_number += 1
        result = call.get("result", {}) or {}
        raw_output = result.get("output", "") or ""
        verification_result = _extract_json_payload(raw_output)
        if verification_result is None:
            verification_result = {"raw_output": raw_output}

        status = verification_result.get("overall_verdict", "unknown")

        rounds.append(RoundResultData(
            round_number=round_number,
            decision_record={},
            patch_result={},
            verification_result=verification_result,
            status=status,
            duration_seconds=0.0,
        ))

    return rounds


@dataclass
class RoundResultData:
    """Result of a single patching round."""
    round_number: int
    decision_record: Dict[str, Any]
    patch_result: Dict[str, Any]
    verification_result: Dict[str, Any]
    status: str
    duration_seconds: float


@dataclass
class RunResult:
    """Complete result of a vulnerability patching run."""
    sample_id: str
    status: RunStatus
    rounds: List[RoundResultData] = field(default_factory=list)
    constraint_sheet: Dict[str, Any] = field(default_factory=dict)
    knowledge_packet: Dict[str, Any] = field(default_factory=dict)
    final_patch: Optional[Dict[str, Any]] = None
    total_duration_seconds: float = 0.0
    total_llm_calls: int = 0
    total_tool_calls: int = 0
    agent_stats: Dict[str, Dict[str, int]] = field(default_factory=dict)
    total_tokens: int = 0
    poc_tests_passed: bool = False
    regression_tests_passed: bool = False
    error: Optional[str] = None
    raw_output: Optional[Dict[str, Any]] = None

    @classmethod
    def from_coordinator_output(cls, sample_id: str, output: "AgentOutput", duration: float) -> "RunResult":
        """Create RunResult from CoordinatorAgent output."""
        content = output.content or {}

        # Determine status
        if output.success:
            status = RunStatus.SUCCESS
        elif output.error:
            status = RunStatus.FAIL_ERROR
        else:
            status = RunStatus.FAIL_NO_FIX

        token_usage = output.token_usage or {}
        tool_calls = output.tool_calls or []
        tool_count, nested_llm_calls, nested_agent_stats = _collect_tool_stats(tool_calls)
        rounds = _extract_rounds_from_tool_calls(tool_calls)
        agent_stats: Dict[str, Dict[str, int]] = {"CoordinatorAgent": token_usage}
        _merge_agent_stats(agent_stats, nested_agent_stats)
        total_tokens = sum(stats.get("total_tokens", 0) for stats in agent_stats.values())

        return cls(
            sample_id=sample_id,
            status=status,
            rounds=rounds,
            total_duration_seconds=duration,
            total_llm_calls=1 + nested_llm_calls,
            total_tool_calls=tool_count,
            agent_stats=agent_stats,
            total_tokens=total_tokens,
            poc_tests_passed=output.success,
            regression_tests_passed=output.success,
            error=output.error,
            raw_output=content,
        )

    def is_success(self) -> bool:
        """Check if the run was successful."""
        return self.status == RunStatus.SUCCESS

    def get_summary(self) -> str:
        """Get a human-readable summary."""
        return (
            f"Sample: {self.sample_id} | "
            f"Status: {self.status.value} | "
            f"Rounds: {len(self.rounds)} | "
            f"Duration: {self.total_duration_seconds:.1f}s"
        )


class PatchingOrchestrator:
    """
    Orchestrator for the multi-agent vulnerability patching system.

    Uses the CoordinatorAgent pattern for natural agent collaboration.
    The Coordinator acts as both strategist and orchestrator, delegating
    to specialist agents (Context, Patch, Verification) as needed.
    """

    def __init__(
        self,
        llm_config: LLMConfig,
        orch_config: Optional[OrchestratorConfig] = None,
        exp_config: Optional[ExperimentConfig] = None
    ):
        """
        Initialize orchestrator.

        Args:
            llm_config: LLM configuration (model, temperature, etc.)
            orch_config: Orchestrator settings (max rounds, timeouts)
            exp_config: Experiment settings (ablation mode, etc.)
        """
        self.llm_config = llm_config
        self.orch_config = orch_config or OrchestratorConfig()
        self.exp_config = exp_config or ExperimentConfig()

        # Statistics from last run
        self.last_run_llm_calls = 0
        self.last_run_tool_calls = 0

    def run(
        self,
        sample: Dict[str, Any],
        container_name: Optional[str] = None
    ) -> RunResult:
        """
        Run the complete patching workflow for a sample.

        Args:
            sample: Sample dictionary with vulnerability details
            container_name: Optional Docker container name

        Returns:
            RunResult with complete execution details
        """
        sample_id = sample.get("sample_id", sample.get("cve_id", "unknown"))
        logger.info(f"Starting patching run for {sample_id}")
        start_time = time.time()

        coordinator: Optional[CoordinatorAgent] = None
        try:
            # Create Docker executor if container provided
            docker_executor = None
            if container_name:
                work_dir = sample.get("work_dir")
                if not work_dir:
                    repo_url = sample.get("repo_url") or sample.get("repo", "")
                    if repo_url:
                        repo_name = repo_url.rstrip("/").split("/")[-1]
                        if repo_name.endswith(".git"):
                            repo_name = repo_name[:-4]
                        work_dir = f"/workspace/{repo_name}"
                    else:
                        work_dir = "/workspace"
                docker_executor = DockerExecutor(container_name, work_dir)
                logger.info(f"Using container: {container_name}, work_dir: {work_dir}")

            _clear_agent_sessions(sample_id, self.orch_config.artifacts_dir)

            # Create tool registry
            tool_registry = ToolRegistry(
                docker_executor=docker_executor,
                sample=sample,
                llm_config=self.llm_config,
                auto_register=True,
            )
            state = dict(sample)
            state["max_total_interactions"] = self.orch_config.max_total_interactions
            state["remaining_interactions"] = self.orch_config.max_total_interactions
            tool_registry.set_state(state)

            # Unlimited turns; overall budget enforced via remaining_interactions
            max_iterations = -1

            # Create and run the coordinator
            coordinator = CoordinatorAgent(
                llm_config=self.llm_config,
                tool_registry=tool_registry,
                max_iterations=max_iterations,
            )

            # Build context from sample
            context = {
                "sample_id": sample_id,
                "cve_id": sample.get("cve_id", ""),
                "cwe_id": sample.get("cwe_id", ""),
                "file_path": sample.get("file_path", ""),
                "vulnerable_code": sample.get("vulnerable_code", ""),
                "problem_statement": sample.get("problem_statement", ""),
                "programming_language": sample.get("programming_language", "Python"),
            }

            # Run the coordinator
            output = coordinator.run(context)

            # Calculate duration
            duration = time.time() - start_time

            # Create result
            result = RunResult.from_coordinator_output(sample_id, output, duration)

            # Update statistics
            self.last_run_llm_calls = result.total_llm_calls
            self.last_run_tool_calls = result.total_tool_calls

            logger.info(f"Completed: {result.get_summary()}")
            return result

        except Exception as e:
            logger.exception(f"Patching run failed: {e}")
            duration = time.time() - start_time
            agent_stats = {}
            if coordinator is not None:
                token_usage = getattr(coordinator, "_last_token_usage", {}) or {}
                agent_stats = {"CoordinatorAgent": token_usage}
            return RunResult(
                sample_id=sample_id,
                status=RunStatus.FAIL_ERROR,
                error=str(e),
                total_duration_seconds=duration,
                agent_stats=agent_stats,
                total_tokens=sum(stats.get("total_tokens", 0) for stats in agent_stats.values()),
            )


def run_sample(
    sample: Dict[str, Any],
    llm_config: LLMConfig,
    orchestrator_config: Optional[OrchestratorConfig] = None,
    experiment_config: Optional[ExperimentConfig] = None,
    container_name: Optional[str] = None
) -> RunResult:
    """
    Convenience function to run patching on a sample.

    Args:
        sample: Sample dictionary from PatchEval
        llm_config: LLM configuration
        orchestrator_config: Optional orchestrator settings
        experiment_config: Optional experiment settings
        container_name: Optional Docker container name

    Returns:
        RunResult with execution details
    """
    orchestrator = PatchingOrchestrator(
        llm_config=llm_config,
        orch_config=orchestrator_config,
        exp_config=experiment_config
    )
    return orchestrator.run(sample, container_name)


# Backward compatibility alias
Orchestrator = PatchingOrchestrator

__all__ = [
    "PatchingOrchestrator",
    "Orchestrator",
    "RunResult",
    "RoundResultData",
    "run_sample",
    "RunStatus",
]
