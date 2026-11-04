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
log_tool_failure.py - PostToolUse Hook for WikiSkill Autonomous Learning
Captures failed tool executions from stdin and appends structured error traces
for closed-loop analysis by /wikiskill. Safely avoids writing into shared cloud source mounts.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_HARNESS_1P_TAG = "antigravity"
_HARNESS_1P_ALT = "ANTIGRAVITY"
_SHARED_MOUNT_A = "/mnt/shared/cloud/"
_SHARED_MOUNT_B = "/Volumes/shared/cloud/"
_SENSITIVE_KEY_RE = re.compile(
    r"(token|password|secret|key|auth|cookie|credential|bearer)", re.IGNORECASE
)


def detect_harness(payload: dict | None = None) -> str:
    """Detect the active agent harness."""
    payload = payload or {}
    transcript_path = str(payload.get("transcriptPath", ""))
    if (
        f"/.gemini/{_HARNESS_1P_TAG}/" in transcript_path
        or "/.gemini/llmext_bridge/" in transcript_path
    ):
        return _HARNESS_1P_TAG
    if "/.gemini/antigravity/" in transcript_path:
        return "antigravity"

    for key in os.environ:
        upper = key.upper()
        if upper.startswith(_HARNESS_1P_TAG.upper()) or upper.startswith(_HARNESS_1P_ALT):
            return _HARNESS_1P_TAG
        if upper.startswith("ANTIGRAVITY"):
            return "antigravity"

    try:
        cwd_str = str(Path.cwd().resolve())
        if cwd_str.startswith((_SHARED_MOUNT_A, _SHARED_MOUNT_B)):
            return _HARNESS_1P_TAG
    except Exception:
        pass

    return "antigravity"


def get_plugin_data_dir() -> Path:
    """Return the per-user writable runtime data directory (outside immutable plugin source)."""
    for env_key in ("PLUGIN_DATA", "ANTIGRAVITY_EXECUTABLE_DATA_DIR", "KC_DATA_DIR"):
        val = (os.environ.get(env_key) or "").strip()
        if val:
            return Path(val).expanduser()
    return Path("~/.local/share/knowledge-compiler").expanduser()


def resolve_default_trace_file(cwd: Path | None = None) -> Path:
    """Resolve safe output path for error traces, avoiding shared source mount pollution."""
    try:
        active_cwd = (cwd or Path.cwd()).resolve()
        cwd_str = str(active_cwd)
    except Exception:
        active_cwd = Path.cwd()
        cwd_str = str(active_cwd)

    if cwd_str.startswith((_SHARED_MOUNT_A, _SHARED_MOUNT_B)):
        return get_plugin_data_dir() / "logs" / "error_traces.jsonl"

    if (active_cwd / ".agents").is_dir():
        return active_cwd / ".agents" / "error_traces.jsonl"

    return get_plugin_data_dir() / "logs" / "error_traces.jsonl"


def _redact_args(raw_args: object) -> object:
    """Redact credentials, tokens, and secrets from tool arguments before logging."""
    if isinstance(raw_args, dict):
        cleaned: dict[str, object] = {}
        for k, v in raw_args.items():
            if _SENSITIVE_KEY_RE.search(str(k)):
                cleaned[str(k)] = "[REDACTED]"
            else:
                cleaned[str(k)] = _redact_args(v)
        return cleaned
    if isinstance(raw_args, list):
        return [_redact_args(item) for item in raw_args]
    if isinstance(raw_args, str):
        return re.sub(
            r"(Bearer\s+|token=|TFE_TOKEN=|API_KEY=)[A-Za-z0-9._~+/-]+",
            r"\1[REDACTED]",
            raw_args,
            flags=re.IGNORECASE,
        )
    return raw_args


def process_hook(input_data: dict, output_file: Path) -> None:
    error = input_data.get("error")
    if not error:
        return

    output_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(output_file.parent, 0o700)
    except Exception:
        pass
    tool_name = input_data.get("toolName") or input_data.get("toolCall") or "unknown"
    trace_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "harness": detect_harness(input_data),
        "conversation_id": input_data.get("conversationId"),
        "tool_name": tool_name,
        "step_index": input_data.get("stepIdx"),
        "error": error,
        "args": _redact_args(input_data.get("args", {})),
    }

    with open(output_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(trace_record) + "\n")


def main() -> None:
    try:
        raw_input = sys.stdin.read().strip()
        if not raw_input:
            print("{}", end="")
            return
        payload = json.loads(raw_input)
    except Exception:
        print("{}", end="")
        return

    try:
        trace_file = resolve_default_trace_file()
        process_hook(payload, trace_file)
    except Exception:
        pass

    # PostToolUse contract expects an empty JSON object on stdout
    print("{}", end="")


if __name__ == "__main__":
    main()
