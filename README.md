# Vulnerability Patching Experiments

This repo runs PatchEval experiments with single-agent and multi-agent patching systems.

## Prerequisites

- Python 3.10+
- Docker running
- OpenAI API key
- PatchEval dataset

## Setup

```bash
export OPENAI_API_KEY="your-api-key-here"
```

Apply the required PatchEval fix:

```bash
cd PatchEval-patches
./apply-patcheval-fix.sh
```

Required PatchEval commit: `0ec3f4b56c6d59f416d6c43e057da8d0930b7eaf`.

## Run Single-Agent

Single CVE:

```bash
python single-agent/scripts/run_patcheval_docker_eval.py \
  --dataset PatchEval/patcheval/datasets/input.json \
  --sample CVE-2021-3281
```

Batch (first 30, alphabetically):

```bash
python single-agent/scripts/run_patcheval_docker_eval.py \
  --dataset PatchEval/patcheval/datasets/input.json \
  --all \
  --max-items 30
```

## Run Multi-Agent

Single CVE:

```bash
python multi-agent/scripts/run_patcheval_docker_eval.py \
  --dataset PatchEval/patcheval/datasets/input.json \
  --sample CVE-2021-3281
```

Batch (first 30, alphabetically):

```bash
python multi-agent/scripts/run_patcheval_docker_eval.py \
  --dataset PatchEval/patcheval/datasets/input.json \
  --all \
  --max-items 30
```

## Outputs

Default output locations:

- Multi-agent: `evaluation_output/multi_agent`
- Single-agent: `evaluation_output/single_agent`

Each CVE directory contains:

- `summary.json` (single-agent) or `evaluation_result.json` + `summary.json` (multi-agent)
- `generated_patch.patch`
- `logs/agent_execution.log`

Top-level files in each output directory:

- `patches.json`
- `patches.jsonl`

## Run PatchEval Evaluation (from JSONL)

PatchEval evaluation must be run from the PatchEval evaluation directory. The
`--output` value is a subpath under `evaluation_output/`.

Example (output at `result/patche_eval_output/single_agent` in this repo):

```bash
cd PatchEval/patcheval/evaluation
python run_evaluation.py \
  --patch_file ../../../evaluation_output/single_agent/patches.jsonl \
  --output ../../../../result/patche_eval_output/single_agent
```

## Notes

- Runs only include CVEs with PatchEval Docker images.
- Results are deterministic with `--temperature 0.0`.
