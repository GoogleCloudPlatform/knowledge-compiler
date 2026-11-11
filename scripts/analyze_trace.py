#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
analyze_trace.py - Trace Ingestion Helper for WikiSkill Evolution
Parses transcript.jsonl logs and error_traces.jsonl records to extract
tool errors, failed steps, and explicit user corrections.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_CORRECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bfailed\b", re.IGNORECASE),
    re.compile(r"\berror\b", re.IGNORECASE),
    re.compile(r"\bwrong\b", re.IGNORECASE),
    re.compile(r"\bdoesn['’]?t\s+work\b", re.IGNORECASE),
    re.compile(r"\bdidn['’]?t\s+work\b", re.IGNORECASE),
    re.compile(r"\bnot\s+working\b", re.IGNORECASE),
    re.compile(r"\bdon['’]?t\s+see\b", re.IGNORECASE),
    re.compile(r"\binstead\b", re.IGNORECASE),
    re.compile(r"\bincorrect\b", re.IGNORECASE),
    re.compile(r"\bstop\s+doing\b", re.IGNORECASE),
    re.compile(r"\bnever\s+(?:do|use|run|write)\b", re.IGNORECASE),
    re.compile(
        r"\bno,\s+(?:don['’]?t|do\s+not|use|try|stop|that['’]?s|that\s+is|it['’]?s|it\s+is)\b",
        re.IGNORECASE,
    ),
)


def _is_user_correction(text: str) -> bool:
    """Return True if text matches an explicit user-correction trigger."""
    return any(pat.search(text) for pat in _CORRECTION_PATTERNS)


def _resolve_default_error_log() -> Path | None:
    """Locate default error_traces.jsonl under XDG_STATE_HOME or plugin data dir."""
    candidates: list[Path] = []
    xdg_state = (os.environ.get("XDG_STATE_HOME") or "").strip()
    if xdg_state:
        candidates.append(
            Path(xdg_state).expanduser()
            / "knowledge-compiler"
            / "logs"
            / "error_traces.jsonl"
        )
    for env_key in ("PLUGIN_DATA", "ANTIGRAVITY_EXECUTABLE_DATA_DIR", "KC_DATA_DIR"):
        val = (os.environ.get(env_key) or "").strip()
        if val:
            candidates.append(
                Path(val).expanduser() / "logs" / "error_traces.jsonl"
            )
    candidates.append(
        Path("~/.local/share/knowledge-compiler").expanduser()
        / "logs"
        / "error_traces.jsonl"
    )
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _load_error_traces(err_path: Path) -> list[dict[str, Any]]:
    """Read structured records from an error_traces.jsonl file."""
    records: list[dict[str, Any]] = []
    with open(err_path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                records.append(
                    {
                        "line": line_num,
                        "timestamp": rec.get("timestamp", ""),
                        "harness": rec.get("harness", ""),
                        "tool_name": rec.get("tool_name", "unknown"),
                        "step_index": rec.get("step_index"),
                        "conversation_id": rec.get("conversation_id"),
                        "error": str(rec.get("error", ""))[:300],
                    }
                )
    return records


def analyze_transcript(
    transcript_path: str | Path | None = None,
    error_log_path: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    corrections: list[dict[str, Any]] = []
    tool_calls: list[str] = []
    step_count = 0
    resolved_transcript: str | None = None

    if transcript_path is not None:
        path = Path(transcript_path)
        if not path.exists():
            print(f"Error: Transcript not found at {transcript_path}", file=sys.stderr)
            sys.exit(1)
        resolved_transcript = str(path)

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue

                step_count += 1
                step_type = entry.get("type", "")
                status = entry.get("status", "")
                content = entry.get("content", "")
                raw_content = str(content)

                # Check for tool errors
                if (
                    status == "ERROR"
                    or "Encountered error in tool execution" in raw_content
                ):
                    errors.append(
                        {
                            "step_index": entry.get("step_index", line_num),
                            "created_at": entry.get("created_at", ""),
                            "summary": raw_content[:300],
                        }
                    )

                # Count user corrections ONLY from explicit human turns without <SYSTEM_MESSAGE>
                if step_type == "USER_INPUT":
                    source = entry.get("source")
                    if (
                        source in (None, "USER_EXPLICIT")
                        and "<SYSTEM_MESSAGE>" not in raw_content
                        and _is_user_correction(raw_content)
                    ):
                        corrections.append(
                            {
                                "step_index": entry.get("step_index", line_num),
                                "source": source or "USER_EXPLICIT",
                                "content": raw_content[:300],
                            }
                        )

                # Track tool usage
                for tc in entry.get("tool_calls") or []:
                    if isinstance(tc, dict):
                        tool_calls.append(
                            tc.get("toolAction", tc.get("toolSummary", "tool_call"))
                        )

    explicit_error_log = error_log_path is not None
    error_traces: list[dict[str, Any]] = []
    resolved_error_log: str | None = None

    if explicit_error_log:
        err_path = Path(error_log_path).expanduser()  # type: ignore[arg-type]
        if not err_path.exists():
            print(f"Error: Error log not found at {error_log_path}", file=sys.stderr)
            sys.exit(1)
        resolved_error_log = str(err_path)
        error_traces = _load_error_traces(err_path)
    else:
        default_err = _resolve_default_error_log()
        if default_err is not None:
            resolved_error_log = str(default_err)
            error_traces = _load_error_traces(default_err)

    transcript_error_count = len(errors)
    error_trace_count = len(error_traces)
    if explicit_error_log or transcript_path is None:
        total_tool_errors = transcript_error_count + error_trace_count
    else:
        total_tool_errors = transcript_error_count

    report: dict[str, Any] = {
        "transcript_file": resolved_transcript,
        "error_log_file": resolved_error_log,
        "total_steps": step_count,
        "tool_error_count": total_tool_errors,
        "transcript_error_count": transcript_error_count,
        "error_trace_count": error_trace_count,
        "user_correction_count": len(corrections),
        "errors": errors,
        "error_traces": error_traces,
        "corrections": corrections,
    }

    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Analyze transcript.jsonl and error_traces.jsonl logs for WikiSkill."
    )
    parser.add_argument(
        "transcript_path",
        nargs="?",
        default=None,
        help="Path to transcript.jsonl.",
    )
    parser.add_argument(
        "--transcript",
        "-t",
        dest="transcript_opt",
        default=None,
        help="Path to transcript.jsonl.",
    )
    parser.add_argument(
        "--error-log",
        "-e",
        dest="error_log",
        default=None,
        help="Path to error_traces.jsonl.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON.",
    )
    args = parser.parse_args(argv)

    transcript = args.transcript_opt or args.transcript_path
    if transcript is None and args.error_log is None:
        if _resolve_default_error_log() is None:
            parser.print_help(sys.stderr)
            sys.exit(1)

    report = analyze_transcript(
        transcript_path=transcript,
        error_log_path=args.error_log,
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
