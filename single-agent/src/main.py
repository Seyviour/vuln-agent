"""
Main entry point for single-agent vulnerability patching system.

This is the single-agent equivalent of multi-agent/src/main.py.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add multi-agent package root to path to reuse utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../multi-agent"))

from src.config import LLMConfig, OrchestratorConfig
from src.utils.data_loader import load_dataset
from orchestrator import SingleAgentOrchestrator, RunResult


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Single-agent vulnerability patching system"
    )

    # Basic options
    parser.add_argument(
        "--dataset", "-d",
        required=True,
        help="Path to PatchEval dataset JSON file"
    )
    parser.add_argument(
        "--sample", "-s",
        help="Specific CVE ID to process (e.g., CVE-2021-3281)"
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Process all samples in dataset"
    )
    parser.add_argument(
        "--output", "-o",
        default="results/",
        help="Output directory for results (default: results/)"
    )

    # LLM options
    parser.add_argument(
        "--model",
        default="gpt-4.1-2025-04-14",
        help="LLM model to use (default: gpt-4.1-2025-04-14)"
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Temperature for LLM responses (default: 0.0)"
    )
    parser.add_argument(
        "--api-key",
        help="OpenAI API key (default: from OPENAI_API_KEY env var)"
    )

    # Orchestrator options
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=3,
        help="Maximum repair iterations (default: 3)"
    )
    parser.add_argument(
        "--max-total-interactions",
        type=int,
        default=-1,
        help="Max tool calls across all rounds (default: -1 for unlimited)"
    )

    # Debug options
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--container",
        help="Docker container name (optional)"
    )

    return parser.parse_args()


def setup_logging(verbose: bool):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True
    )


def save_result(result: RunResult, output_dir: Path):
    """Save result to output directory."""
    sample_dir = output_dir / result.sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)

    # Save summary
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

    summary_file = sample_dir / "summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    logger.info(f"Saved results to {sample_dir}")


def run_single_sample(
    sample: dict,
    llm_config: LLMConfig,
    orch_config: OrchestratorConfig,
    output_dir: Path,
    container_name: str = None
) -> RunResult:
    """Run patching on a single sample."""
    sample_id = sample.get("sample_id", sample.get("cve_id", "unknown"))
    logger.info(f"Processing sample: {sample_id}")

    orchestrator = SingleAgentOrchestrator(
        llm_config=llm_config,
        orch_config=orch_config
    )

    result = orchestrator.run(sample, container_name=container_name)

    # Save result
    save_result(result, output_dir)

    logger.info(f"Result: {result.get_summary()}")
    return result


def main():
    """Main entry point."""
    load_dotenv()
    args = parse_args()
    setup_logging(args.verbose)

    # Setup API key
    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        logger.error("OpenAI API key not provided. Set OPENAI_API_KEY or use --api-key")
        sys.exit(1)

    # Load dataset
    logger.info(f"Loading dataset from {args.dataset}")
    dataset = load_dataset(args.dataset)
    logger.info(f"Loaded {len(dataset)} samples")

    # Create configurations
    llm_config = LLMConfig(
        model=args.model,
        temperature=args.temperature,
        api_key=api_key
    )

    orch_config = OrchestratorConfig(
        max_rounds=args.max_rounds,
        max_total_interactions=args.max_total_interactions
    )

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Process sample(s)
    if args.sample:
        # Single sample
        sample = dataset.get_by_id(args.sample)
        if not sample:
            logger.error(f"Sample {args.sample} not found in dataset")
            sys.exit(1)

        result = run_single_sample(
            sample.to_dict(),
            llm_config,
            orch_config,
            output_dir,
            args.container
        )

        if result.is_success():
            logger.info("SUCCESS!")
            sys.exit(0)
        else:
            logger.error(f"FAILED: {result.status.value}")
            sys.exit(1)

    elif args.all:
        # All samples
        results = []
        for sample in dataset:
            try:
                result = run_single_sample(
                    sample.to_dict(),
                    llm_config,
                    orch_config,
                    output_dir,
                    args.container
                )
                results.append(result)
            except Exception as e:
                logger.exception(f"Error processing {sample.sample_id}: {e}")

        # Save aggregate results
        aggregate = {
            "total_samples": len(results),
            "successful": sum(1 for r in results if r.is_success()),
            "failed": sum(1 for r in results if not r.is_success()),
            "results": [
                {
                    "sample_id": r.sample_id,
                    "status": r.status.value,
                    "duration": r.total_duration_seconds
                }
                for r in results
            ]
        }

        aggregate_file = output_dir / "aggregate_results.json"
        with open(aggregate_file, "w") as f:
            json.dump(aggregate, f, indent=2)

        logger.info(f"Processed {len(results)} samples")
        logger.info(f"Success: {aggregate['successful']}, Failed: {aggregate['failed']}")

    else:
        logger.error("Must specify --sample or --all")
        sys.exit(1)


if __name__ == "__main__":
    main()
