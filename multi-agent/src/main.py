#!/usr/bin/env python3
"""
Main entry point for the multi-agent vulnerability patching system.

This is a shim that delegates to scripts/run_patcheval_docker_eval.py for actual execution.
The docker eval script provides the full functionality with proper container management.

Usage:
    # Run a single sample
    python -m src.main --dataset path/to/dataset.json --sample CVE-2021-1234

    # Run all samples
    python -m src.main --dataset path/to/dataset.json --all --output results/

    # With custom settings
    python -m src.main --dataset data.json -s CVE-2021-1234 --model gpt-4-turbo --max-rounds 5
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def create_argument_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser matching docker eval script interface."""
    parser = argparse.ArgumentParser(
        description="Multi-agent vulnerability patching system (shim to docker eval)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run on a single sample
  %(prog)s -d dataset.json -s CVE-2021-1234

  # Run on all samples with output
  %(prog)s -d dataset.json --all -o results/

  # Ablation study
  %(prog)s -d dataset.json -s CVE-2021-1234 --ablation without_knowledge

  # Use different model
  %(prog)s -d dataset.json -s CVE-2021-1234 --model gpt-4-turbo
        """
    )

    # Dataset options
    data_group = parser.add_argument_group("Data options")
    data_group.add_argument(
        "--dataset", "-d",
        required=True,
        help="Path to PatchEval dataset JSON file"
    )
    data_group.add_argument(
        "--sample", "-s",
        help="Specific sample ID to process (e.g., CVE-2021-1234)"
    )
    data_group.add_argument(
        "--all", "-a",
        action="store_true",
        help="Process all samples in dataset"
    )

    # Output options
    output_group = parser.add_argument_group("Output options")
    output_group.add_argument(
        "--output", "-o",
        default="results",
        help="Output directory for results (default: results/)"
    )
    output_group.add_argument(
        "--json-logs",
        action="store_true",
        help="Use JSON format for log output"
    )

    # LLM options
    llm_group = parser.add_argument_group("LLM options")
    llm_group.add_argument(
        "--model",
        default="gpt-4.1-2025-04-14",
        help="LLM model to use (default: gpt-4.1-2025-04-14)"
    )
    llm_group.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="LLM temperature (default: 0.0)"
    )
    llm_group.add_argument(
        "--api-key",
        help="OpenAI API key (default: from OPENAI_API_KEY env var)"
    )

    # Orchestrator options
    orch_group = parser.add_argument_group("Orchestrator options")
    orch_group.add_argument(
        "--max-rounds",
        type=int,
        default=3,
        help="Maximum repair rounds (default: 3)"
    )

    # Experiment options
    exp_group = parser.add_argument_group("Experiment options")
    exp_group.add_argument(
        "--ablation",
        choices=["full", "without_knowledge", "single_turn", "without_context"],
        default="full",
        help="Ablation mode (default: full)"
    )

    # Debug options
    debug_group = parser.add_argument_group("Debug options")
    debug_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (debug) logging"
    )
    debug_group.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel workers (default: 1)"
    )

    return parser


def build_docker_eval_command(args: argparse.Namespace) -> List[str]:
    """
    Build command to invoke docker eval script with equivalent arguments.

    Args:
        args: Parsed command line arguments

    Returns:
        Command list for subprocess
    """
    # Get path to docker eval script
    script_dir = Path(__file__).parent.parent
    docker_eval_script = script_dir / "scripts" / "run_patcheval_docker_eval.py"

    if not docker_eval_script.exists():
        raise FileNotFoundError(f"Docker eval script not found: {docker_eval_script}")

    # Build command
    cmd = [sys.executable, str(docker_eval_script)]

    # Required arguments
    cmd.extend(["--dataset", args.dataset])
    cmd.extend(["--output-dir", args.output])

    # Sample selection
    if args.sample:
        cmd.extend(["--cve", args.sample])
    elif args.all:
        # Docker eval script processes all by default if no --cve specified
        pass
    else:
        raise ValueError("Must specify either --sample or --all")

    # LLM options
    cmd.extend(["--model", args.model])
    cmd.extend(["--temperature", str(args.temperature)])

    # API key
    if args.api_key:
        # Pass via environment variable
        os.environ["OPENAI_API_KEY"] = args.api_key

    # Orchestrator options
    cmd.extend(["--max-rounds", str(args.max_rounds)])

    # Experiment options
    cmd.extend(["--ablation", args.ablation])

    # Debug options
    if args.verbose:
        cmd.append("--verbose")

    cmd.extend(["--workers", str(args.workers)])

    return cmd


def main(cli_args: Optional[List[str]] = None) -> int:
    """
    Main entry point (shim).

    Args:
        cli_args: Optional command line arguments (for testing)

    Returns:
        Exit code from docker eval script
    """
    parser = create_argument_parser()
    args = parser.parse_args(cli_args)

    # Validate mutually exclusive options
    if not args.sample and not args.all:
        parser.error("Must specify either --sample or --all")

    if args.sample and args.all:
        parser.error("Cannot specify both --sample and --all")

    try:
        # Build docker eval command
        cmd = build_docker_eval_command(args)

        # Print notice
        print("=" * 60)
        print("NOTE: Delegating to Docker evaluation script...")
        print(f"Command: {' '.join(cmd)}")
        print("=" * 60)
        print()

        # Execute docker eval script
        result = subprocess.run(cmd, check=False)
        return result.returncode

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
