#!/usr/bin/env python3
"""
Docker-based patch generation script for PatchEval datasets.

This script:
1. Filters to samples with Docker images configured in the dataset
2. Runs the multi-agent system to generate patches within Docker containers
3. Emits PatchEval-compatible patch files
4. Delegates evaluation to PatchEval's run_evaluation.py for reporting
"""

import argparse
from dataclasses import asdict
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import MemoryHandler
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import tqdm

# Load .env file if present
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

# Add parent directory to path for multi-agent imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Add PatchEval to path for evaluation
PATCHEVAL_PATH = Path(__file__).parent.parent.parent / "PatchEval"
sys.path.insert(0, str(PATCHEVAL_PATH / "patcheval" / "evaluation"))

from src.config import (
    LLMConfig,
    OrchestratorConfig,
    ExperimentConfig,
)
from src.utils import constants as ma_constants
from src.utils.types import AblationMode
from src.utils.data_loader import load_dataset
from src.orchestrator import run_sample

# Import PatchEval's evaluation components
from run_evaluation import DockerManager


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def normalize_cve_id(cve_id: str) -> str:
    """Normalize CVE ID format for Docker image lookup."""
    return cve_id.lower()


class MultiAgentEvaluator:
    """
    Evaluator that runs multi-agent patch generation inside PatchEval containers.
    """
    
    def __init__(
        self,
        llm_config: LLMConfig,
        orch_config: OrchestratorConfig,
        exp_config: ExperimentConfig,
        output_dir: Path,
        log_manager: Any = None,
        cve: str = "",
        task_logger: Any = None,
    ):
        self.llm_config = llm_config
        self.orch_config = orch_config
        self.exp_config = exp_config
        self.output_dir = output_dir
        self.cve = cve
        
        if log_manager is not None:
            log_manager.bind_current_task(cve)
            self.logger = log_manager.get_current_logger()
        else:
            self.logger = task_logger or logger
        
        # Use PatchEval's DockerManager (required)
        self.docker_manager: DockerManager = DockerManager(self.logger, self.cve)
    
    def run_multi_agent_in_container(
        self,
        cve: str,
        sample_dict: Dict,
        container_name: str,
    ) -> Tuple[Optional[str], Dict]:
        """
        Run multi-agent system inside an existing container.
        
        Returns:
            Tuple of (patch_string, multi_agent_result_dict)
        """
        self.logger.info(f"Running multi-agent for {cve} in container {container_name}")
        
        try:
            # Run multi-agent system with the container
            result = run_sample(
                sample=sample_dict,
                llm_config=self.llm_config,
                orchestrator_config=self.orch_config,
                experiment_config=self.exp_config,
                container_name=container_name
            )
            
            # Extract patch via git diff from container
            work_dir = sample_dict.get('work_dir')
            if not work_dir:
                repo_url = sample_dict.get('repo_url') or sample_dict.get('repo', '')
                if repo_url:
                    repo_name = repo_url.rstrip('/').split('/')[-1]
                    work_dir = f"/workspace/{repo_name}"
                else:
                    work_dir = "/workspace"
            
            patch = self._extract_fix_patch_from_container(container_name)
            if not patch:
                patch = self._extract_git_diff_from_container(
                    container_name,
                    work_dir
                )
            if patch:
                self.logger.info(f"Extracted patch via git diff ({len(patch)} bytes)")

            # Extract full file content from EditCode tool calls for inspection
            edited_files = self._extract_edited_files_from_result(result)
            
            result_dict = {
                "status": result.status.value,
                "rounds": len(result.rounds),
                "rounds_detail": [asdict(r) for r in result.rounds],
                "duration": result.total_duration_seconds,
                "total_llm_calls": result.total_llm_calls,
                "total_tool_calls": result.total_tool_calls,
                "total_tokens": result.total_tokens,
                "agent_stats": result.agent_stats,
                "patch_generated": patch is not None and len(patch.strip()) > 0,
                "poc_tests_passed": result.poc_tests_passed,
                "regression_tests_passed": result.regression_tests_passed,
                "edited_files": edited_files,  # Include edited file contents
            }

            return patch, result_dict
            
        except Exception as e:
            self.logger.exception(f"Multi-agent failed: {e}")
            return None, {"status": "error", "error": str(e)}
    
    def _extract_edited_files_from_result(self, result) -> Dict[str, str]:
        """
        Extract full file contents from EditCode tool calls in the result.
        
        Returns:
            Dict mapping file paths to their full content after editing
        """
        edited_files = {}
        
        try:
            self.logger.debug(f"Extracting edited files from {len(result.rounds)} rounds")
            for round_result in result.rounds:
                patch_result = round_result.patch_result
                if not patch_result:
                    self.logger.debug(f"Round {round_result.round_number}: no patch_result")
                    continue
                
                self.logger.debug(f"Round {round_result.round_number} patch_result keys: {patch_result.keys() if isinstance(patch_result, dict) else 'not a dict'}")
                
                # Look for tool_calls_summary or changes with full_file_content
                changes = patch_result.get('changes', [])
                self.logger.debug(f"Found {len(changes)} changes")
                for change in changes:
                    self.logger.debug(f"Change keys: {change.keys()}, success={change.get('success')}")
                    if change.get('success') and 'full_file_content' in change:
                        file_path = change.get('file', 'unknown')
                        edited_files[file_path] = change['full_file_content']
                        self.logger.info(f"Extracted edited file: {file_path}")
                
                # Also check tool_calls_summary for metadata
                tool_calls = patch_result.get('tool_calls_summary', [])
                self.logger.debug(f"Found {len(tool_calls)} tool_calls in summary")
                for tc in tool_calls:
                    if tc.get('tool') == 'EditCode' and tc.get('success'):
                        # The full content might be in the result metadata
                        metadata = tc.get('result', {}).get('metadata', {})
                        self.logger.debug(f"EditCode metadata keys: {metadata.keys() if isinstance(metadata, dict) else 'not a dict'}")
                        if 'full_file_content' in metadata:
                            file_path = metadata.get('file_path', 'unknown')
                            edited_files[file_path] = metadata['full_file_content']
                            self.logger.info(f"Extracted edited file from tool_calls: {file_path}")
        except Exception as e:
            self.logger.debug(f"Could not extract edited files: {e}")
        
        self.logger.debug(f"Total edited files extracted: {len(edited_files)}")
        return edited_files

    def _extract_fix_patch_from_container(self, container_name: str) -> Optional[str]:
        """Read /workspace/fix.patch from the container if present."""
        try:
            result = subprocess.run(
                ["docker", "exec", container_name, "bash", "-c", "cat /workspace/fix.patch"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                self.logger.info(
                    "Extracted patch via /workspace/fix.patch (%s bytes)",
                    len(result.stdout),
                )
                return result.stdout
        except Exception as e:
            self.logger.debug(f"Failed to read /workspace/fix.patch: {e}")
        return None
    
    def _extract_git_diff_from_container(
        self,
        container_name: str,
        work_dir: str,
    ) -> Optional[str]:
        """
        Extract git diff from container as fallback patch extraction.
        
        Similar to how ClaudeCode extracts patches.
        """
        try:
            # First try: git diff (unstaged changes)
            result = subprocess.run(
                ["docker", "exec", container_name, "bash", "-c",
                 f"cd {work_dir} && git diff"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout + "\n"
            
            # Second try: git diff --cached (staged changes)
            result = subprocess.run(
                ["docker", "exec", container_name, "bash", "-c",
                 f"cd {work_dir} && git add -A && git diff --cached"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout + "\n"
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Git diff extraction failed: {e}")
            return None
    
    def run_patch_generation(
        self,
        cve: str,
        sample_dict: Dict,
        language: str,
        test_name: str = "multi_agent",
    ) -> Dict:
        """
        Run multi-agent generation inside a PatchEval container.
        
        Returns:
            Dict with patch and multi-agent metadata
        """
        container_name = f"{test_name}_{cve.lower()}_tmp_{secrets.token_hex(4)}"
        
        # Cleanup any existing container
        if self.docker_manager.is_container_exist(container_name):
            self.docker_manager.rm_container(container_name)
            self.logger.debug(f"Removed existing container {container_name}")
        
        result = {
            "cve": cve,
            "language": language,
            "multi_agent_result": None,
            "patch": None,
        }
        
        # Step 1: Start container for multi-agent (no patch mounted)
        started = self.docker_manager.start_container(cve, container_name, llm_patch=None)
        if not started:
            result["error"] = "Failed to start container for multi-agent"
            self.logger.error(result["error"])
            return result
        
        try:
            # Step 2: Run multi-agent to generate patch
            patch, multi_agent_result = self.run_multi_agent_in_container(
                cve=cve,
                sample_dict=sample_dict,
                container_name=container_name,
            )

            diff_result = None
            try:
                work_dir = sample_dict.get('work_dir')
                if not work_dir:
                    repo_url = sample_dict.get('repo_url') or sample_dict.get('repo', '')
                    if repo_url:
                        repo_name = repo_url.rstrip('/').split('/')[-1]
                        work_dir = f"/workspace/{repo_name}"
                    else:
                        work_dir = "/workspace"
                diff_result = subprocess.run(
                    ["docker", "exec", container_name, "bash", "-c", f"cd {work_dir} && git diff"],
                    capture_output=True, text=True, timeout=30
                )
            except Exception as e:
                self.logger.debug(f"Failed to run git diff for final patch: {e}")
            
            patch = diff_result.stdout + "\n" if diff_result and diff_result.returncode == 0 and diff_result.stdout.strip() else patch
            result["multi_agent_result"] = multi_agent_result
            result["patch"] = patch
            
            # Step 3: Read the edited file directly from container (fallback)
            # This ensures we always have the full file for inspection
            edited_files = multi_agent_result.get('edited_files', {})
            if not edited_files and patch:
                # Try to read the file that was edited based on the sample
                file_path = sample_dict.get('file_path', '')
                if file_path:
                    work_dir = sample_dict.get('work_dir', '/workspace')
                    full_path = f"{work_dir}/{file_path}" if not file_path.startswith('/') else file_path
                    
                    try:
                        read_result = subprocess.run(
                            ["docker", "exec", container_name, "cat", full_path],
                            capture_output=True, text=True, timeout=30
                        )
                        if read_result.returncode == 0:
                            edited_files[file_path] = read_result.stdout
                            multi_agent_result['edited_files'] = edited_files
                            self.logger.info(f"Read edited file from container: {file_path}")
                    except Exception as e:
                        self.logger.debug(f"Failed to read edited file from container: {e}")
            
            if not patch:
                result["status"] = "no_patch_generated"
                self.logger.warning(f"No patch generated for {cve}")
                return result
            
        finally:
            # Always cleanup the multi-agent container
            pass
            self.docker_manager.rm_container(container_name)

        result["status"] = "patch_generated"
        return result
    
    def save_results(self, cve: str, result: Dict):
        """Save evaluation results to output directory."""
        sample_dir = self.output_dir / cve.replace('-', '_')
        sample_dir.mkdir(parents=True, exist_ok=True)
        
        # Create logs subdirectory
        logs_dir = sample_dir / 'logs'
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Save main result (without full file contents to keep it readable)
        result_for_json = result.copy()
        edited_files = result_for_json.pop('edited_files', {})
        multi_agent_result = result_for_json.get('multi_agent_result', {})
        if isinstance(multi_agent_result, dict):
            multi_agent_result.pop('edited_files', None)
        
        with open(sample_dir / 'evaluation_result.json', 'w') as f:
            json.dump(result_for_json, f, indent=2, default=str)

        # Save a summary.json aligned with single-agent reporting
        multi_agent_result = result.get("multi_agent_result", {})
        rounds_detail = []
        if isinstance(multi_agent_result, dict):
            rounds_detail = multi_agent_result.get("rounds_detail", []) or []
        summary = {
            "sample_id": result.get("cve", cve),
            "status": (multi_agent_result.get("status") if isinstance(multi_agent_result, dict) else None)
                     or result.get("status", "unknown"),
            "poc_tests_passed": bool(multi_agent_result.get("poc_tests_passed")) if isinstance(multi_agent_result, dict) else False,
            "regression_tests_passed": bool(multi_agent_result.get("regression_tests_passed")) if isinstance(multi_agent_result, dict) else False,
            "total_duration_seconds": (multi_agent_result.get("duration") if isinstance(multi_agent_result, dict) else None) or 0.0,
            "total_llm_calls": (multi_agent_result.get("total_llm_calls") if isinstance(multi_agent_result, dict) else None) or 0,
            "total_tool_calls": (multi_agent_result.get("total_tool_calls") if isinstance(multi_agent_result, dict) else None) or 0,
            "total_tokens": (multi_agent_result.get("total_tokens") if isinstance(multi_agent_result, dict) else None) or 0,
            "agent_stats": (multi_agent_result.get("agent_stats") if isinstance(multi_agent_result, dict) else None) or {},
            "rounds": (multi_agent_result.get("rounds") if isinstance(multi_agent_result, dict) else None) or len(rounds_detail),
            "error": (multi_agent_result.get("error") if isinstance(multi_agent_result, dict) else None) or result.get("error"),
        }

        with open(sample_dir / "summary.json", "w") as f:
            json.dump(summary, f, indent=2, default=str)
        
        # Save patch if generated
        if result.get("patch"):
            with open(sample_dir / 'generated_patch.patch', 'w') as f:
                f.write(result["patch"])
        
        # Save edited files to logs directory for inspection
        if edited_files:
            for file_path, content in edited_files.items():
                # Create a safe filename from the path
                safe_name = file_path.replace('/', '_').replace('\\', '_')
                if safe_name.startswith('_'):
                    safe_name = safe_name[1:]
                
                edited_file_path = logs_dir / f"edited_{safe_name}"
                with open(edited_file_path, 'w') as f:
                    f.write(content)
                
                self.logger.info(f"Saved edited file to {edited_file_path}")
        
def process_sample(
    sample,
    llm_config: LLMConfig,
    orch_config: OrchestratorConfig,
    exp_config: ExperimentConfig,
    output_dir: Path,
    log_level: int,
    main_logger: logging.Logger,
) -> Optional[Tuple]:
    """
    Process a single sample - thread-safe function for parallel execution.
    
    Mirrors PatchEval's process_patch function.
    """
    cve = sample.cve_id
    language = sample.programming_language
    
    # Create per-CVE log directory and file
    cve_dir = output_dir / cve.replace('-', '_')
    cve_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = cve_dir / 'logs'
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    # Create thread-local logger with file handler for this CVE
    task_logger_name = f"task-{cve}-{threading.get_ident()}"
    task_logger = logging.getLogger(task_logger_name)
    task_logger.setLevel(log_level)
    task_logger.propagate = False
    
    # Add file handler for per-CVE agent logs
    cve_log_file = logs_dir / 'agent_execution.log'
    cve_file_handler = logging.FileHandler(cve_log_file)
    cve_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    cve_file_handler.setLevel(log_level)
    cve_file_handler.addFilter(
        lambda record: record.name.startswith("src.agents")
        or record.name.startswith("src.tools")
        or record.name.startswith("task-")
    )
    task_logger.addHandler(cve_file_handler)

    # Silence noisy HTTP client debug logs in per-CVE logs.
    for noisy_logger in ("httpcore", "httpx", "openai"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)
    
    # Attach handler only once at the root to avoid duplicate propagation.
    root_logger = logging.getLogger("")
    root_logger.setLevel(log_level)
    root_logger.addHandler(cve_file_handler)
    
    # Buffer handler for thread-safe logging to main log
    buffer_handler = None
    if main_logger.handlers:
        main_file_handler = main_logger.handlers[0]
        buffer_handler = MemoryHandler(capacity=1024, target=main_file_handler)
        task_logger.addHandler(buffer_handler)
    
    try:
        evaluator = MultiAgentEvaluator(
            llm_config=llm_config,
            orch_config=orch_config,
            exp_config=exp_config,
            output_dir=output_dir,
            cve=cve,
            task_logger=task_logger,
        )
        
        result = evaluator.run_patch_generation(
            cve=cve,
            sample_dict=sample.to_dict(),
            language=language,
            test_name="multi_agent_eval",
        )
        
        evaluator.save_results(cve, result)
        patch = result.get("patch")
        patch_generated = bool(patch and patch.strip())
        return (cve, patch_generated, False)
        
    except Exception as e:
        task_logger.error(f"{cve} RUN ERROR: {e}")
        return (cve, False, True)
        
    finally:
        # Clean up handlers
        if buffer_handler is not None:
            buffer_handler.flush()
            buffer_handler.close()
            task_logger.removeHandler(buffer_handler)
        
        # Clean up CVE-specific file handler
        cve_file_handler.flush()
        cve_file_handler.close()
        task_logger.removeHandler(cve_file_handler)
        
        # Remove handler from root logger
        root_logger.removeHandler(cve_file_handler)


def main():
    parser = argparse.ArgumentParser(
        description='Run multi-agent patch generation with PatchEval Docker images'
    )
    
    parser.add_argument(
        '--dataset', '-d',
        default=str(PATCHEVAL_PATH / "patcheval/datasets/input.json"),
        help='Path to PatchEval dataset (JSON or JSONL format)'
    )
    parser.add_argument(
        '--output', '-o',
        default='evaluation_output/multi_agent',
        help='Output directory'
    )
    parser.add_argument(
        '--sample',
        help='Specific sample ID to run (e.g., CVE-2021-3281)'
    )
    parser.add_argument(
        '--samples', '-s',
        nargs='+',
        help='Specific sample IDs to run'
    )
    parser.add_argument(
        '--all', '-a',
        action='store_true',
        help='Run all samples in the dataset'
    )
    parser.add_argument(
        '--max-items', '-n',
        type=int,
        help='Maximum number of samples to process'
    )
    parser.add_argument(
        '--model',
        default='gpt-4.1-2025-04-14',
        help='LLM model'
    )
    parser.add_argument(
        '--temperature',
        type=float,
        default=0.0,
        help='Sampling temperature (default: 0.0)'
    )
    parser.add_argument(
        '--api-key',
        help='OpenAI API key (default: from OPENAI_API_KEY env var)'
    )
    parser.add_argument(
        '--max-rounds',
        type=int,
        default=3,
        help='Max repair rounds (deprecated; overall interaction budget controls runs)'
    )
    parser.add_argument(
        '--max-total-interactions',
        type=int,
        default=-1,
        help='Max tool calls across all rounds (default: -1 for unlimited)'
    )
    parser.add_argument(
        '--ablation',
        choices=['full', 'without_knowledge', 'single_turn', 'without_context'],
        default='full'
    )
    parser.add_argument(
        '--max-workers',
        type=int,
        default=1,
        help='Max parallel workers (default: 1 for sequential)'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='DEBUG',
        help='Logging level'
    )
    parser.add_argument(
        '--language',
        default='Python',
        help='Filter samples by programming language (default: Python)'
    )
    parser.add_argument(
        '--skip-patcheval-eval',
        action='store_true',
        default=True,
        help='Skip PatchEval evaluation; only generate patches'
    )
    parser.add_argument(
        '--run-patcheval-eval',
        action='store_true',
        default=False,
        help='Run PatchEval evaluation on generated patches for compatibility outputs'
    )
    parser.add_argument(
        '--skip-existing',
        action='store_true',
        default=True,
        help='Skip samples that already have an output folder in the results directory'
    )
    
    args = parser.parse_args()
    if args.sample and args.samples:
        parser.error("Cannot specify both --sample and --samples")
    if args.sample:
        args.samples = [args.sample]
    
    # Setup logging
    log_level = getattr(logging, args.log_level.upper())
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = output_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    os.environ["ARTIFACTS_DIR"] = str(artifacts_dir)
    ma_constants.DEFAULT_ARTIFACTS_DIR = str(artifacts_dir)
    
    # Create main logger with file handler (mirrors PatchEval)
    main_logger = logging.getLogger("multi_agent_eval")
    main_logger.setLevel(log_level)
    file_handler = logging.FileHandler(output_dir / 'run_evaluation.log')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    main_logger.addHandler(file_handler)
    
    main_logger.info(f"Starting evaluation with args: {args}")
    
    # Load dataset
    dataset = load_dataset(args.dataset)
    main_logger.info(f"Loaded {len(dataset)} samples")
    
    # Filter by programming language using dataloader
    if args.language:
        samples = dataset.filter_by_language(args.language)
        main_logger.info(f"Filtered to {len(samples)} samples for language: {args.language}")
    else:
        samples = dataset.samples
    
    # Filter to samples with Docker images configured by the dataloader
    available_samples = [sample for sample in samples if sample.docker_image]
    main_logger.info(f"Found {len(available_samples)} samples with Docker images configured")
    
    if not available_samples:
        main_logger.error("No samples with available Docker images found!")
        print("No samples with available Docker images found!")
        return

    # Filter by specific samples if requested
    if args.samples:
        available_samples = [s for s in available_samples if s.cve_id in args.samples]
        main_logger.info(f"Filtered to {len(available_samples)} requested samples")
    elif not args.all:
        main_logger.error("Specify --sample/--samples or --all")
        print("Specify --sample/--samples or --all")
        return

    if args.skip_existing:
        filtered_samples = []
        skipped = 0
        for sample in available_samples:
            sample_dir = output_dir / sample.cve_id.replace('-', '_')
            if sample_dir.exists():
                skipped += 1
                continue
            filtered_samples.append(sample)
        if skipped:
            main_logger.info(f"Skipped {skipped} samples with existing results")
        available_samples = filtered_samples

    # Sort for deterministic limiting
    available_samples = sorted(available_samples, key=lambda s: s.cve_id)

    # Limit if requested
    if args.max_items and len(available_samples) > args.max_items:
        available_samples = available_samples[:args.max_items]
        main_logger.info(f"Limited to {len(available_samples)} samples")
    
    # Setup configs
    llm_config = LLMConfig(
        model=args.model,
        temperature=args.temperature,
        api_key=args.api_key or os.environ.get("OPENAI_API_KEY", "")
    )
    
    orch_config = OrchestratorConfig(
        max_rounds=args.max_rounds,
        max_total_interactions=args.max_total_interactions,
        artifacts_dir=str(artifacts_dir),
    )
    
    ablation_map = {
        'full': AblationMode.FULL,
        'without_knowledge': AblationMode.WITHOUT_KNOWLEDGE,
        'single_turn': AblationMode.SINGLE_TURN,
        'without_context': AblationMode.WITHOUT_CONTEXT,
    }
    exp_config = ExperimentConfig(ablation_mode=ablation_map[args.ablation])
    
    # Run evaluation (mirrors PatchEval's multi-threaded execution)
    all_results = []
    
    if args.max_workers > 1:
        # Multi-threaded execution
        with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            future_to_sample = {
                executor.submit(
                    process_sample,
                    sample,
                    llm_config,
                    orch_config,
                    exp_config,
                    output_dir,
                    log_level,
                    main_logger,
                ): sample
                for sample in available_samples
            }
            
            for future in tqdm.tqdm(as_completed(future_to_sample), total=len(available_samples)):
                try:
                    result = future.result()
                    if result:
                        all_results.append(result)
                except Exception as e:
                    sample = future_to_sample[future]
                    main_logger.error(f"Task for CVE {sample.cve_id} failed unexpectedly: {e}")
    else:
        # Sequential execution
        for sample in tqdm.tqdm(available_samples):
            result = process_sample(
                sample,
                llm_config,
                orch_config,
                exp_config,
                output_dir,
                log_level,
                main_logger,
            )
            if result:
                all_results.append(result)
    
    total_samples = len(available_samples)
    total_generated = sum(1 for _, generated, is_error in all_results if generated)
    total_errors = sum(1 for _, _, is_error in all_results if is_error)
    main_logger.info(
        "Patch generation complete: %s/%s patches, %s errors",
        total_generated,
        total_samples,
        total_errors,
    )
    
    # Export patches in PatchEval JSONL/JSON format
    patches = []
    for sample in available_samples:
        sample_dir = output_dir / sample.cve_id.replace('-', '_')
        patch_path = sample_dir / 'generated_patch.patch'
        if patch_path.exists():
            patch_text = patch_path.read_text()
            if patch_text.strip():
                patches.append({
                    "cve": sample.cve_id,
                    "fix_patch": patch_text
                })
    
    patches_json_path = output_dir / 'patches.json'
    with open(patches_json_path, 'w') as f:
        json.dump(patches, f, indent=2)
    
    patches_jsonl_path = output_dir / 'patches.jsonl'
    with open(patches_jsonl_path, 'w') as f:
        for entry in patches:
            f.write(json.dumps(entry) + "\n")

    # Run PatchEval evaluation using generated patches
    patcheval_eval_out = output_dir / "patcheval_eval"
    if not args.skip_patcheval_eval and patches_json_path.exists():
        main_logger.info(f"Running PatchEval evaluation with {patches_json_path}")
        try:
            patcheval_eval_dir = PATCHEVAL_PATH / "patcheval" / "evaluation"
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
                cwd=str(patcheval_eval_dir),
            )

            patcheval_source = patcheval_eval_dir / "evaluation_output" / patcheval_output_name
            if patcheval_source.exists():
                if patcheval_eval_out.exists():
                    shutil.rmtree(patcheval_eval_out)
                shutil.copytree(patcheval_source, patcheval_eval_out)
        except subprocess.CalledProcessError as e:
            main_logger.error(f"PatchEval evaluation failed: {e}")

    main_logger.info(f"Results saved to: {output_dir}")


if __name__ == '__main__':
    main()
