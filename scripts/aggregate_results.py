#!/usr/bin/env python3
"""
Aggregate single- and multi-agent evaluation results into a CSV.

Reads summary.json (preferred) or evaluation_result.json (fallback) from:
  evaluation_output/single_agent
  evaluation_output/multi_agent
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


DEFAULT_BASE_DIR = Path("evaluation_output")


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _extract_from_summary(agent_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "agent_type": agent_type,
        "cve": data.get("sample_id", ""),
        "status": data.get("status", ""),
        "poc_tests_passed": data.get("poc_tests_passed", False),
        "regression_tests_passed": data.get("regression_tests_passed", False),
        "total_duration_seconds": data.get("total_duration_seconds", 0.0),
        "total_llm_calls": data.get("total_llm_calls", 0),
        "total_tool_calls": data.get("total_tool_calls", 0),
        "total_tokens": data.get("total_tokens", 0),
    }


def _extract_from_evaluation(agent_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    result = data.get("multi_agent_result", {}) if agent_type == "multi" else {}
    return {
        "agent_type": agent_type,
        "cve": data.get("cve", ""),
        "status": result.get("status", data.get("status", "")),
        "poc_tests_passed": result.get("poc_tests_passed", False),
        "regression_tests_passed": result.get("regression_tests_passed", False),
        "total_duration_seconds": result.get("duration", 0.0),
        "total_llm_calls": result.get("total_llm_calls", 0),
        "total_tool_calls": result.get("total_tool_calls", 0),
        "total_tokens": result.get("total_tokens", 0),
    }


def _iter_results(agent_type: str, base_dir: Path) -> Iterable[Dict[str, Any]]:
    for cve_dir in sorted(base_dir.iterdir()):
        if not cve_dir.is_dir():
            continue
        summary_path = cve_dir / "summary.json"
        eval_path = cve_dir / "evaluation_result.json"
        data = None
        if summary_path.exists():
            data = _load_json(summary_path)
            if data:
                yield _extract_from_summary(agent_type, data)
                continue
        if eval_path.exists():
            data = _load_json(eval_path)
            if data:
                yield _extract_from_evaluation(agent_type, data)


def _write_csv(rows: List[Dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "agent_type",
        "cve",
        "status",
        "poc_tests_passed",
        "regression_tests_passed",
        "total_duration_seconds",
        "total_llm_calls",
        "total_tool_calls",
        "total_tokens",
    ]
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate evaluation results to CSV.")
    parser.add_argument(
        "--base-dir",
        default=str(DEFAULT_BASE_DIR),
        help="Base evaluation_output directory",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=str(DEFAULT_BASE_DIR / "results.csv"),
        help="Output CSV path",
    )
    args = parser.parse_args()

    base_dir = Path(args.base_dir)
    rows: List[Dict[str, Any]] = []
    rows.extend(_iter_results("single", base_dir / "single_agent"))
    rows.extend(_iter_results("multi", base_dir / "multi_agent"))

    _write_csv(rows, Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
