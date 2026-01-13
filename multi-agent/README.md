# Multi-Agent Vulnerability Patching System

An automated system for patching security vulnerabilities using coordinated AI agents. Built for the [PatchEval benchmark](https://github.com/patcheval/patcheval).

## Overview

This system uses multiple specialized AI agents working together to automatically fix security vulnerabilities in code:

- **CoordinatorAgent**: Orchestrates the patching workflow and makes strategic decisions
- **ContextKnowledgeAgent**: Analyzes the codebase to understand structure and constraints
- **PatchAgent**: Applies code modifications based on the coordinator's strategy
- **VerificationAgent**: Validates patches through automated testing

The agents collaborate through multiple rounds of patching and verification until the vulnerability is fixed or the maximum iteration limit is reached.

## Quick Start

### Installation

```bash
cd multi-agent
pip install -r requirements.txt

# Set your OpenAI API key
export OPENAI_API_KEY="your-api-key-here"
```

### Required PatchEval Fix

**IMPORTANT**: Before running experiments, you must apply a required fix to the PatchEval submodule:

```bash
cd ../PatchEval-patches
./apply-patcheval-fix.sh
```

This fixes a bug in PatchEval's Docker manager that causes premature deletion of temporary patch files.

**Required PatchEval Version**: Commit `0ec3f4b56c6d59f416d6c43e057da8d0930b7eaf`

See [../PatchEval-patches/README.md](../PatchEval-patches/README.md) for full details and troubleshooting.

### Running the Experiment

#### Single Sample

Run the system on a specific vulnerability:

```bash
python -m src.main \
    --dataset ../PatchEval/patcheval/datasets/patcheval_dataset.json \
    --sample CVE-2021-3281 \
    --output results/
```

#### Batch Evaluation

Run on all samples in the dataset:

```bash
python scripts/run_patcheval_docker_eval.py \
    --dataset ../PatchEval/patcheval/datasets/patcheval_dataset.json \
    --output-dir artifacts/results/ \
    --model gpt-4.1-2025-04-14 \
    --max-rounds 3
```

#### With Custom Settings

```bash
python -m src.main \
    --dataset path/to/dataset.json \
    --sample CVE-2021-3281 \
    --model gpt-4.1 \
    --max-rounds 5 \
    --temperature 0.0 \
    --verbose
```

## Configuration Options

### Basic Options

- `--dataset, -d`: Path to PatchEval dataset JSON file (required)
- `--sample, -s`: Specific CVE ID to process (e.g., CVE-2021-3281)
- `--all, -a`: Process all samples in dataset
- `--output, -o`: Output directory for results (default: `results/`)

### LLM Options

- `--model`: LLM model to use (default: `gpt-4.1-2025-04-14`)
- `--temperature`: Temperature for LLM responses (default: `0.0`)
- `--api-key`: OpenAI API key (default: from `OPENAI_API_KEY` env var)

### Orchestrator Options

- `--max-rounds`: Maximum repair iterations (default: `3`)
- `--max-total-interactions`: Max tool calls across all rounds (default: `-1` for unlimited)

### Experiment Options

- `--ablation`: Ablation study mode:
  - `full` - All agents enabled (default)
  - `without_knowledge` - Skip ContextKnowledgeAgent
  - `single_turn` - No feedback loop (1 round only)
  - `without_context` - Skip repository context gathering

### Debug Options

- `--verbose, -v`: Enable verbose logging
- `--workers`: Number of parallel workers for batch processing (default: `1`)

## Output Structure

Results are saved to the output directory with the following structure:

```
results/
├── CVE-2021-3281/
│   ├── summary.json              # Overall result summary
│   ├── artifacts/
│   │   ├── constraint_sheet.json # Repository analysis
│   │   ├── round_1.json          # First repair attempt
│   │   ├── round_2.json          # Second repair attempt (if needed)
│   │   └── final_patch.json      # Successful patch (if any)
│   └── logs/
│       └── execution.log         # Detailed execution logs
└── aggregate_results.json        # Summary across all samples
```

### Result Status Values

- `success` - Vulnerability successfully patched and all tests pass
- `fail_no_fix` - Patch applied but PoC tests still fail
- `fail_regression` - PoC passes but regression tests fail
- `fail_max_rounds` - Maximum repair iterations reached
- `fail_error` - System error occurred

## Programmatic Usage

```python
from src import Orchestrator, LLMConfig, OrchestratorConfig
from src.utils.data_loader import load_dataset

# Load dataset
dataset = load_dataset("path/to/patcheval_dataset.json")
sample = dataset.get_by_id("CVE-2021-3281")

# Configure system
llm_config = LLMConfig(
    model="gpt-4.1-2025-04-14",
    temperature=0.0
)
orch_config = OrchestratorConfig(
    max_rounds=3
)

# Run patching
orchestrator = Orchestrator(llm_config, orch_config)
result = orchestrator.run(sample.to_dict())

# Check results
print(f"Status: {result.status}")
print(f"Rounds: {len(result.rounds)}")
if result.final_patch:
    print(f"Patch: {result.final_patch['diff']}")
```

## Architecture

The system uses a **Coordinator-Specialist** pattern where a central CoordinatorAgent orchestrates specialist agents through an iterative repair loop:

```
CoordinatorAgent
      │
      ├─→ ContextKnowledgeAgent (analyze codebase)
      │
      └─→ Repair Loop (up to max_rounds):
            ├─→ Generate patch strategy
            ├─→ PatchAgent (apply changes)
            └─→ VerificationAgent (run tests)
                  ├─→ Success → Done
                  └─→ Failure → Feedback to next round
```

For detailed architecture documentation, see [src/agents/architecture.md](src/agents/architecture.md).

## Research Applications

### Experimental Variables

The system exposes several research knobs:

| Variable | Parameter | Options |
|----------|-----------|---------|
| Model | `--model` | `gpt-4.1`, `gpt-4.1-mini`, etc. |
| Max Rounds | `--max-rounds` | 1-10 |
| Temperature | `--temperature` | 0.0-2.0 |
| Ablation Mode | `--ablation` | `full`, `without_knowledge`, `single_turn`, `without_context` |

## Requirements

- Python 3.10+
- Docker (for test execution in isolated containers)
- OpenAI API key
- PatchEval dataset
- **PatchEval fix applied** (see Installation section above)

## Project Structure

```
multi-agent/
├── src/
│   ├── agents/          # Agent implementations
│   ├── tools/           # Tool implementations
│   ├── utils/           # Utilities (types, constants, etc.)
│   ├── config.py        # Configuration classes
│   ├── orchestrator.py  # Main orchestration logic
│   └── main.py          # CLI entry point
├── scripts/
│   └── run_patcheval_docker_eval.py  # Batch evaluation
├── tests/               # Unit tests
└── requirements.txt     # Python dependencies
```

## Troubleshooting

### Docker Issues

If you see "Docker daemon is not available":
```bash
# Check Docker is running
docker ps

# Restart Docker if needed
sudo systemctl restart docker  # Linux
# or restart Docker Desktop     # macOS/Windows
```

### API Rate Limits

If you hit OpenAI rate limits:
```bash
# Reduce parallel workers
python scripts/run_patcheval_docker_eval.py --workers 1 ...

# Or add delay between requests (modify script)
```

### Out of Memory

If you run out of memory:
```bash
# Reduce max_rounds to limit token usage
python -m src.main --max-rounds 1 ...

# Or process samples sequentially
python scripts/run_patcheval_docker_eval.py --workers 1 ...
```

## License

MIT