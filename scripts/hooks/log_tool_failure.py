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
    r"(token|password|passwd|secret|key|auth|cookie|credential|bearer)", re.IGNORECASE
)
MAX_TRACE_FILE_BYTES = 5 * 1024 * 1024
MAX_ERROR_CHARS = 2048
MAX_ARGS_CHARS = 4096
_MAX_SCAN_CHARS = 16384
_MAX_META_CHARS = 128

_SECRET_TEXT_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"AIza[0-9A-Za-z_-]{20,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"ya29\.[0-9A-Za-z._-]+"), "[REDACTED_OAUTH_TOKEN]"),
    (
        re.compile(r"(?:gh[pousr]_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,})"),
        "[REDACTED_GH_TOKEN]",
    ),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(
            r"(?<![A-Za-z0-9_.-])(Authorization[ \t]*:[ \t]*(?:Bearer|Basic|Token)[ \t]+|(?:Bearer|Basic)[ \t]+)[A-Za-z0-9._~+/=-]+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"""(['"])([^'"\r\n]{0,128}(?:token|password|passwd|secret|api_?key|access_key|auth|authorization|cookie|credential|private_key)[^'"\r\n]{0,64})\1[ \t]*:[ \t]*(['"])[^'"\r\n]*\3""",
            re.IGNORECASE,
        ),
        r"\1\2\1: \3[REDACTED]\3",
    ),
    (
        re.compile(
            r"""(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{0,128}(?:token|password|passwd|secret|api_?key|access_key|auth|authorization|cookie|credential|private_key)[A-Za-z0-9_.-]{0,64})([ \t]*(?:=>|=|:)[ \t]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[|>-]?(?:[ \t]*\r?\n[ \t]+[^\r\n]+){1,8}|[^\s"'&,;]+)""",
            re.IGNORECASE,
        ),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(
            r"""(?<![A-Za-z0-9_-])(--?(?:password|passwd|token|api[-_]?key|secret|access[-_]?token|client[-_]?secret))(=|[ \t]+)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+)""",
            re.IGNORECASE,
        ),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(
            r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+){1,8}(?![A-Za-z0-9-])"
        ),
        "[REDACTED_EMAIL]",
    ),
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
            cand = Path(val).expanduser()
            if cand.is_absolute():
                return cand
    return Path("~/.local/share/knowledge-compiler").expanduser()


def resolve_default_trace_file(cwd: Path | None = None) -> Path:
    """Resolve user-state output path for error traces (never inside CWD/repo)."""
    _ = cwd
    xdg_state = (os.environ.get("XDG_STATE_HOME") or "").strip()
    if xdg_state:
        cand = Path(xdg_state).expanduser()
        if cand.is_absolute():
            return cand / "knowledge-compiler" / "logs" / "error_traces.jsonl"
    return get_plugin_data_dir() / "logs" / "error_traces.jsonl"


def redact_secrets(text: str) -> str:
    """Redact credentials, tokens, private keys, and email addresses from text."""
    cleaned = text[:_MAX_SCAN_CHARS] if len(text) > _MAX_SCAN_CHARS else text
    for pattern, repl in _SECRET_TEXT_REPLACEMENTS:
        cleaned = pattern.sub(repl, cleaned)
    return cleaned


def _redact_args(raw_args: object) -> object:
    """Redact credentials, tokens, secrets, and emails from tool arguments before logging."""
    if isinstance(raw_args, dict):
        cleaned: dict[str, object] = {}
        for k, v in list(raw_args.items())[:256]:
            safe_key = _truncate_text(redact_secrets(str(k)), 256)
            if _SENSITIVE_KEY_RE.search(safe_key):
                cleaned[safe_key] = "[REDACTED]"
            else:
                cleaned[safe_key] = _redact_args(v)
        return cleaned
    if isinstance(raw_args, list):
        return [_redact_args(item) for item in raw_args[:256]]
    if isinstance(raw_args, str):
        return redact_secrets(raw_args)
    return raw_args


def _truncate_text(text: str, max_chars: int = MAX_ERROR_CHARS) -> str:
    if len(text) <= max_chars:
        return text
    suffix = "...[truncated]"
    if max_chars <= len(suffix):
        return text[:max_chars]
    return text[: max_chars - len(suffix)] + suffix


def _cap_args(args: object, max_chars: int = MAX_ARGS_CHARS) -> object:
    serialized = json.dumps(args, ensure_ascii=False)
    if len(serialized) <= max_chars:
        return args
    capped: dict[str, object] = {
        "_truncated": True,
        "_original_length": len(serialized),
        "preview": serialized[: max(0, max_chars - 128)],
    }
    while len(json.dumps(capped, ensure_ascii=False)) > max_chars and capped["preview"]:
        preview_str = str(capped["preview"])
        capped["preview"] = preview_str[: max(0, len(preview_str) - 64)]
    return capped


def _rotate_trace_if_needed(output_file: Path, max_bytes: int = MAX_TRACE_FILE_BYTES) -> None:
    try:
        if output_file.exists() and not output_file.is_symlink():
            if output_file.stat().st_size >= max_bytes:
                rotated = output_file.with_name(f"{output_file.name}.1")
                if rotated.is_symlink():
                    return
                os.replace(output_file, rotated)
    except OSError:
        pass


def _has_symlink_target_or_parent(output_file: Path) -> bool:
    """Return True if trace file or its log/app parent directories are symlinks."""
    for candidate in (output_file, output_file.parent, output_file.parent.parent):
        try:
            if candidate.is_symlink():
                return True
        except OSError:
            return True
    return False


def process_hook(input_data: dict, output_file: Path) -> None:
    raw_error = input_data.get("error")
    if not raw_error:
        return

    if _has_symlink_target_or_parent(output_file):
        return

    output_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(output_file.parent, 0o700)
    except OSError:
        pass

    if isinstance(raw_error, str):
        redacted_error = redact_secrets(raw_error)
    else:
        redacted_error = json.dumps(_redact_args(raw_error), ensure_ascii=False)
    capped_error = _truncate_text(redacted_error, MAX_ERROR_CHARS)

    redacted_args = _redact_args(input_data.get("args", {}))
    capped_args = _cap_args(redacted_args, MAX_ARGS_CHARS)

    raw_tool_name = input_data.get("toolName") or input_data.get("toolCall") or "unknown"
    tool_name = _truncate_text(redact_secrets(str(raw_tool_name)), _MAX_META_CHARS)
    raw_conv_id = input_data.get("conversationId")
    conv_id = (
        _truncate_text(redact_secrets(str(raw_conv_id)), _MAX_META_CHARS)
        if raw_conv_id is not None
        else None
    )
    raw_step_idx = input_data.get("stepIdx")
    step_index = (
        raw_step_idx
        if isinstance(raw_step_idx, int)
        else (
            _truncate_text(redact_secrets(str(raw_step_idx)), 64)
            if raw_step_idx is not None
            else None
        )
    )
    trace_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "harness": detect_harness(input_data),
        "conversation_id": conv_id,
        "tool_name": tool_name,
        "step_index": step_index,
        "error": capped_error,
        "args": capped_args,
    }
    payload_bytes = (json.dumps(trace_record, ensure_ascii=False) + "\n").encode("utf-8")

    _rotate_trace_if_needed(output_file)
    fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        try:
            os.chmod(output_file, 0o600)
        except OSError:
            pass
        view = memoryview(payload_bytes)
        written = 0
        while written < len(payload_bytes):
            n = os.write(fd, view[written:])
            if n <= 0:
                break
            written += n
    finally:
        os.close(fd)


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
