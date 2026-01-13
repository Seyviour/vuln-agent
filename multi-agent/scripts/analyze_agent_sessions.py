#!/usr/bin/env python3
"""
Analyze agent session history stored in agent_sessions.sqlite.

Outputs per-session and per-run summaries. A "run" is inferred from the
session_id prefix before the first ":" (typically the CVE/sample id).
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


DEFAULT_DB_PATH = Path("multi-agent/artifacts/agent_sessions.sqlite")


def _parse_session_id(session_id: str) -> Tuple[str, str]:
    if ":" in session_id:
        sample_id, agent_name = session_id.split(":", 1)
        return sample_id, agent_name
    return session_id, "unknown"


def _safe_json_loads(raw: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        return data
    return None


@dataclass
class SessionStats:
    session_id: str
    sample_id: str
    agent_name: str
    message_count: int = 0
    invalid_json_count: int = 0
    role_counts: Counter = None
    type_counts: Counter = None
    tool_counts: Counter = None
    first_message_at: Optional[str] = None
    last_message_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["role_counts"] = dict(self.role_counts)
        payload["type_counts"] = dict(self.type_counts)
        payload["tool_counts"] = dict(self.tool_counts)
        return payload


def _init_stats(session_id: str) -> SessionStats:
    sample_id, agent_name = _parse_session_id(session_id)
    return SessionStats(
        session_id=session_id,
        sample_id=sample_id,
        agent_name=agent_name,
        role_counts=Counter(),
        type_counts=Counter(),
        tool_counts=Counter(),
    )


def _update_stats(stats: SessionStats, created_at: str, message_data: str) -> None:
    stats.message_count += 1
    if stats.first_message_at is None:
        stats.first_message_at = created_at
    stats.last_message_at = created_at

    data = _safe_json_loads(message_data)
    if data is None:
        stats.invalid_json_count += 1
        return

    role = data.get("role")
    if isinstance(role, str):
        stats.role_counts[role] += 1

    item_type = data.get("type")
    if isinstance(item_type, str):
        stats.type_counts[item_type] += 1

    if item_type == "function_call":
        tool_name = data.get("name")
        if isinstance(tool_name, str):
            stats.tool_counts[tool_name] += 1


def _load_session_stats(conn: sqlite3.Connection) -> List[SessionStats]:
    cur = conn.cursor()
    cur.execute("SELECT session_id FROM agent_sessions")
    sessions = {row[0] for row in cur.fetchall()}
    stats_by_session: Dict[str, SessionStats] = {
        session_id: _init_stats(session_id) for session_id in sessions
    }

    cur.execute(
        "SELECT session_id, created_at, message_data "
        "FROM agent_messages ORDER BY created_at ASC"
    )
    for session_id, created_at, message_data in cur.fetchall():
        stats = stats_by_session.get(session_id)
        if stats is None:
            stats = _init_stats(session_id)
            stats_by_session[session_id] = stats
        _update_stats(stats, created_at, message_data)

    return list(stats_by_session.values())


def _aggregate_runs(stats_list: Iterable[SessionStats]) -> Dict[str, Dict[str, Any]]:
    runs: Dict[str, Dict[str, Any]] = {}
    for stats in stats_list:
        run = runs.setdefault(
            stats.sample_id,
            {
                "sample_id": stats.sample_id,
                "sessions": [],
                "agent_counts": Counter(),
                "role_counts": Counter(),
                "type_counts": Counter(),
                "tool_counts": Counter(),
                "message_count": 0,
            },
        )
        run["sessions"].append(stats.session_id)
        run["agent_counts"][stats.agent_name] += 1
        run["role_counts"].update(stats.role_counts)
        run["type_counts"].update(stats.type_counts)
        run["tool_counts"].update(stats.tool_counts)
        run["message_count"] += stats.message_count

    for run in runs.values():
        run["agent_counts"] = dict(run["agent_counts"])
        run["role_counts"] = dict(run["role_counts"])
        run["type_counts"] = dict(run["type_counts"])
        run["tool_counts"] = dict(run["tool_counts"])
    return runs


def _format_table(stats_list: List[SessionStats], runs: Dict[str, Dict[str, Any]]) -> str:
    lines: List[str] = []
    header = (
        "session_id\tmessages\ttool_calls\tfirst_message\tlast_message"
    )
    lines.append(header)
    for stats in sorted(stats_list, key=lambda s: (s.sample_id, s.agent_name)):
        tool_calls = sum(stats.tool_counts.values())
        lines.append(
            f"{stats.session_id}\t{stats.message_count}\t{tool_calls}\t"
            f"{stats.first_message_at or '-'}\t{stats.last_message_at or '-'}"
        )

    lines.append("")
    lines.append("runs")
    lines.append("sample_id\tsessions\tmessages\ttool_calls")
    for sample_id in sorted(runs.keys()):
        run = runs[sample_id]
        tool_calls = sum(run["tool_counts"].values())
        lines.append(
            f"{sample_id}\t{len(run['sessions'])}\t{run['message_count']}\t{tool_calls}"
        )

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze agent session history.")
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help="Path to agent_sessions.sqlite",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write output to a file instead of stdout.",
    )
    args = parser.parse_args()

    if not args.db.exists():
        raise SystemExit(f"Database not found: {args.db}")

    conn = sqlite3.connect(str(args.db))
    try:
        stats_list = _load_session_stats(conn)
    finally:
        conn.close()

    runs = _aggregate_runs(stats_list)

    if args.format == "json":
        output = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "sessions": [stats.to_dict() for stats in stats_list],
            "runs": runs,
        }
        rendered = json.dumps(output, indent=2, sort_keys=True)
    else:
        rendered = _format_table(stats_list, runs)

    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
