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
Parses Antigravity transcript.jsonl logs to extract tool errors, failed steps, and user corrections.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def analyze_transcript(transcript_path: str) -> dict:
    path = Path(transcript_path)
    if not path.exists():
        print(f"Error: Transcript not found at {transcript_path}", file=sys.stderr)
        sys.exit(1)

    errors = []
    corrections = []
    tool_calls = []
    step_count = 0

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            step_count += 1
            step_type = entry.get("type", "")
            status = entry.get("status", "")
            content = entry.get("content", "")

            # Check for tool errors
            if status == "ERROR" or "Encountered error in tool execution" in str(
                content
            ):
                errors.append(
                    {
                        "step_index": entry.get("step_index", line_num),
                        "created_at": entry.get("created_at", ""),
                        "summary": str(content)[:300],
                    }
                )

            # Check for user corrections
            if step_type == "USER_INPUT":
                text = str(content).lower()
                triggers = [
                    "failed",
                    "error",
                    "wrong",
                    "doesn't work",
                    "don't see",
                    "instead",
                    "no ",
                ]
                if any(t in text for t in triggers):
                    corrections.append(
                        {
                            "step_index": entry.get("step_index", line_num),
                            "content": str(content)[:300],
                        }
                    )

            # Track tool usage
            for tc in entry.get("tool_calls", []):
                tool_calls.append(
                    tc.get("toolAction", tc.get("toolSummary", "tool_call"))
                )

    report = {
        "transcript_file": str(path),
        "total_steps": step_count,
        "tool_error_count": len(errors),
        "user_correction_count": len(corrections),
        "errors": errors,
        "corrections": corrections,
    }

    return report


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_trace.py <path_to_transcript.jsonl>")
        sys.exit(1)

    report = analyze_transcript(sys.argv[1])
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
