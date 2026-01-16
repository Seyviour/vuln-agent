#!/usr/bin/env python3
"""
Run the single-agent system inside PatchEval Docker containers.

This is the single-agent counterpart to multi-agent/scripts/run_patcheval_docker_eval.py.
It starts PatchEval containers per CVE and executes the single-agent orchestrator inside.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import subprocess

from dotenv import load_dotenv


REPO_ROOT = Path(__file__).resolve().parents[2]
SINGLE_AGENT_SRC = Path(__file__).resolve().parents[1] / "src"
MULTI_AGENT_ROOT = REPO_ROOT / "multi-agent"
PATCHEVAL_ROOT = REPO_ROOT / "PatchEval"
PATCHEVAL_EVAL = PATCHEVAL_ROOT / "patcheval" / "evaluation"
PATCHEVAL_DATASET = PATCHEVAL_ROOT / "patcheval" / "datasets" / "input.json"

sys.path.insert(0, str(SINGLE_AGENT_SRC))
sys.path.insert(0, str(MULTI_AGENT_ROOT))
sys.path.insert(0, str(PATCHEVAL_EVAL))

load_dotenv(REPO_ROOT / ".env")
load_dotenv(MULTI_AGENT_ROOT / ".env")

from src.config import LLMConfig, OrchestratorConfig  # noqa: E402
from src.utils import constants as ma_constants  # noqa: E402
from src.utils.data_loader import load_dataset  # noqa: E402
from orchestrator import run_sample  # noqa: E402
from run_evaluation import DockerManager  # noqa: E402


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run single-agent PatchEval evaluation in Docker containers"
    )
    parser.add_argument(
        "--dataset",
        "-d",
        default=str(PATCHEVAL_DATASET),
        help="Path to PatchEval dataset JSON",
    )
    parser.add_argument(
        "--sample", "-s", help="Specific CVE ID to run (e.g., CVE-2021-3281)"
    )
    parser.add_argument(
        "--samples",
        nargs="+",
        help="Specific sample IDs to run",
    )
    parser.add_argument(
        "--all", "-a", action="store_true", help="Run all samples in the dataset"
    )
    parser.add_argument(
        "--max-items",
        "-n",
        type=int,
        help="Maximum number of samples to process",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="evaluation_output/single_agent",
        help="Output directory for results",
    )
    parser.add_argument(
        "--model",
        default="gpt-4.1-2025-04-14",
        help="LLM model to use (default: gpt-4.1-2025-04-14)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Sampling temperature (default: 0.0)",
    )
    parser.add_argument(
        "--api-key",
        help="OpenAI API key (default: from OPENAI_API_KEY env var)",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=5,
        help="Maximum repair rounds (deprecated; overall interaction budget controls runs)",
    )
    parser.add_argument(
        "--max-total-interactions",
        type=int,
        default=-1,
        help="Max tool calls across all rounds (default: -1 for unlimited)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        help="Max parallel workers (default: 1 for sequential)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )
    parser.add_argument(
        "--language",
        default="Python",
        help="Filter samples by programming language (default: Python)",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        default=True,
        help="Skip samples that already have an output folder in the results directory",
    )
    parser.add_argument(
        "--skip-patcheval-eval",
        action="store_true",
        default=True,
        help="Skip PatchEval evaluation; only generate patches",
    )
    parser.add_argument(
        "--run-patcheval-eval",
        action="store_true",
        default=False,
        help="Run PatchEval evaluation on generated patches for compatibility outputs",
    )
    return parser.parse_args()


def save_result(
    result: Any,
    output_dir: Path,
    patch: Optional[str] = None,
) -> None:
    sample_dir = output_dir / result.sample_id.replace("-", "_")
    sample_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "sample_id": result.sample_id,
        "status": result.status.value,
        "poc_tests_passed": result.poc_tests_passed,
        "regression_tests_passed": result.regression_tests_passed,
        "total_duration_seconds": result.total_duration_seconds,
        "total_llm_calls": result.total_llm_calls,
        "total_tool_calls": result.total_tool_calls,
        "total_tokens": result.total_tokens,
        "agent_stats": result.agent_stats,
        "rounds": len(result.rounds),
        "error": result.error,
    }

    with open(sample_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    if patch:
        patch_file = sample_dir / "generated_patch.patch"
        with open(patch_file, "w") as f:
            f.write(patch)

    logger.info("Saved results to %s", sample_dir)


def _extract_fix_patch_from_container(container_name: str) -> Optional[str]:
    """Read /workspace/fix.patch from the container if present."""
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "bash", "-c", "cat /workspace/fix.patch"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.info(
                "Extracted patch via /workspace/fix.patch (%s bytes)",
                len(result.stdout),
            )
            return result.stdout
    except Exception as exc:
        logger.debug("Failed to read /workspace/fix.patch: %s", exc)
    return None


def _extract_git_diff_from_container(
    container_name: str,
    work_dir: str,
) -> Optional[str]:
    """Fallback: extract git diff from the container."""
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "bash", "-c", f"cd {work_dir} && git diff"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout + "\n"

        result = subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "bash",
                "-c",
                f"cd {work_dir} && git add -A && git diff --cached",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout + "\n"

        return None
    except Exception as exc:
        logger.debug("Git diff extraction failed: %s", exc)
        return None


def run_single_agent_in_container(
    sample_dict: Dict[str, Any],
    llm_config: LLMConfig,
    orch_config: OrchestratorConfig,
    output_dir: Path,
) -> tuple[Optional[Any], Optional[str]]:
    cve = sample_dict.get("cve_id") or sample_dict.get("sample_id")
    if not cve:
        logger.error("Sample missing cve_id/sample_id")
        return None, None

    docker_manager = DockerManager(logger, cve)
    container_name = f"single_agent_{cve.lower()}_{secrets.token_hex(4)}"

    if docker_manager.is_container_exist(container_name):
        docker_manager.rm_container(container_name)

    started = docker_manager.start_container(cve, container_name, llm_patch=None)
    if not started:
        logger.error("Failed to start container for %s", cve)
        return None, None

    cve_log_handler = None
    attached_loggers: list[logging.Logger] = []
    logs_dir = output_dir / cve.replace("-", "_") / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    try:
        cve_log_file = logs_dir / "agent_execution.log"
        cve_log_handler = logging.FileHandler(cve_log_file)
        cve_log_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        cve_log_handler.setLevel(logger.level)
        for logger_name in ("", "src", "single_agents", "orchestrator"):
            target_logger = logging.getLogger(logger_name)
            target_logger.addHandler(cve_log_handler)
            attached_loggers.append(target_logger)
        for noisy_logger in ("httpcore", "httpx", "openai"):
            logging.getLogger(noisy_logger).setLevel(logging.WARNING)

        result = run_sample(
            sample=sample_dict,
            llm_config=llm_config,
            orchestrator_config=orch_config,
            container_name=container_name,
        )
        work_dir = sample_dict.get("work_dir")
        if not work_dir:
            repo_url = sample_dict.get("repo_url") or sample_dict.get("repo", "")
            if repo_url:
                repo_name = repo_url.rstrip("/").split("/")[-1]
                if repo_name.endswith(".git"):
                    repo_name = repo_name[:-4]
                work_dir = f"/workspace/{repo_name}"
            else:
                work_dir = "/workspace"
        patch = _extract_fix_patch_from_container(container_name)
        if not patch:
            patch = _extract_git_diff_from_container(container_name, work_dir)
        return result, patch
    finally:
        if cve_log_handler:
            for target_logger in attached_loggers:
                target_logger.removeHandler(cve_log_handler)
            cve_log_handler.close()
        docker_manager.rm_container(container_name)


def main() -> None:
    args = parse_args()
    if args.sample and args.samples:
        logger.error("Cannot specify both --sample and --samples")
        raise SystemExit(1)

    log_level = getattr(logging, args.log_level.upper())
    logging.getLogger().setLevel(log_level)
    logger.setLevel(log_level)

    if args.max_workers and args.max_workers > 1:
        logger.warning("max-workers > 1 is not supported; running sequentially")

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        logger.error("OpenAI API key not provided. Set OPENAI_API_KEY or use --api-key")
        raise SystemExit(1)

    dataset = load_dataset(args.dataset)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = output_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    os.environ["ARTIFACTS_DIR"] = str(artifacts_dir)
    ma_constants.DEFAULT_ARTIFACTS_DIR = str(artifacts_dir)

    llm_config = LLMConfig(
        model=args.model,
        temperature=args.temperature,
        api_key=api_key,
    )
    orch_config = OrchestratorConfig(
        max_rounds=args.max_rounds,
        max_total_interactions=args.max_total_interactions,
        artifacts_dir=str(artifacts_dir),
    )

    if args.language:
        samples = dataset.filter_by_language(args.language)
    else:
        samples = dataset.samples

    available_samples = [s for s in samples if s.docker_image]
    if not available_samples:
        logger.error("No samples with available Docker images found")
        raise SystemExit(1)
    samples = available_samples

    if args.sample or args.samples:
        sample_ids = args.samples or [args.sample]
        samples = [s for s in samples if s.cve_id in sample_ids]
        if not samples:
            logger.error("Requested samples not found in dataset")
            raise SystemExit(1)
    elif not args.all:
        logger.error("Specify --sample/--samples or --all")
        raise SystemExit(1)

    if args.skip_existing:
        filtered_samples = []
        skipped = 0
        for sample in samples:
            sample_dir = output_dir / sample.cve_id.replace("-", "_")
            if sample_dir.exists():
                skipped += 1
                continue
            filtered_samples.append(sample)
        if skipped:
            logger.info("Skipped %s samples with existing results", skipped)
        samples = filtered_samples

    samples = sorted(samples, key=lambda s: s.cve_id, reverse=True)

    if args.max_items and len(samples) > args.max_items:
        samples = samples[:args.max_items]
        logger.info("Limited to %s samples", len(samples))

    processed_samples = []
    if args.sample and not args.samples:
        sample = samples[0]
        result, patch = run_single_agent_in_container(
            sample.to_dict(), llm_config, orch_config, output_dir
        )
        if result is None:
            raise SystemExit(1)
        save_result(result, output_dir, patch=patch)
        processed_samples.append(sample)
    elif args.all or args.samples or args.max_items:
        for sample in samples:
            try:
                result, patch = run_single_agent_in_container(
                    sample.to_dict(), llm_config, orch_config, output_dir
                )
                if result is not None:
                    save_result(result, output_dir, patch=patch)
                    processed_samples.append(sample)
            except Exception as exc:
                logger.exception("Error processing %s: %s", sample.sample_id, exc)
    else:
        logger.error("Specify --sample/--samples or --all")
        raise SystemExit(1)

    # Export patches in PatchEval JSONL/JSON format
    patches = []
    for sample in processed_samples:
        sample_dir = output_dir / sample.cve_id.replace("-", "_")
        patch_path = sample_dir / "generated_patch.patch"
        if patch_path.exists():
            patch_text = patch_path.read_text()
            if patch_text.strip():
                patches.append({
                    "cve": sample.cve_id,
                    "fix_patch": patch_text,
                })

    patches_json_path = output_dir / "patches.json"
    with open(patches_json_path, "w") as f:
        json.dump(patches, f, indent=2)

    patches_jsonl_path = output_dir / "patches.jsonl"
    with open(patches_jsonl_path, "w") as f:
        for entry in patches:
            f.write(json.dumps(entry) + "\n")

    # Run PatchEval evaluation using generated patches
    patcheval_eval_out = output_dir / "patcheval_eval"
    if not args.skip_patcheval_eval and patches_json_path.exists():
        logger.info("Running PatchEval evaluation with %s", patches_json_path)
        try:
            patcheval_output_name = "patcheval_eval"
            subprocess.run(
                [
                    sys.executable,
                    "run_evaluation.py",
                    "--output",
                    patcheval_output_name,
                    "--patch_file",
                    str(patches_json_path.resolve()),
                ],
                check=True,
                cwd=str(PATCHEVAL_EVAL),
            )

            patcheval_source = PATCHEVAL_EVAL / "evaluation_output" / patcheval_output_name
            if patcheval_source.exists():
                if patcheval_eval_out.exists():
                    shutil.rmtree(patcheval_eval_out)
                shutil.copytree(patcheval_source, patcheval_eval_out)
        except subprocess.CalledProcessError as exc:
            logger.error("PatchEval evaluation failed: %s", exc)
    return

if __name__ == "__main__":
    main()
