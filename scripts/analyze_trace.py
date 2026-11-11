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
analyze_trace.py - Trace Ingestion & Proposal Helper for WikiSkill Evolution
Parses transcript.jsonl logs and error_traces.jsonl records to extract
tool errors, failed steps, explicit user corrections, and optional diff-only proposals.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any

try:
    from hooks.log_tool_failure import redact_secrets as _hook_redact_secrets  # type: ignore[import-not-found]
except ImportError:
    try:
        from scripts.hooks.log_tool_failure import redact_secrets as _hook_redact_secrets  # type: ignore[no-redef]
    except ImportError:
        _hook_redact_secrets = None  # type: ignore[assignment]

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

_FALLBACK_SECRET_RES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bya29\.[0-9A-Za-z._-]+\b"), "[REDACTED_OAUTH_TOKEN]"),
    (re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]+\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b"),
        "[REDACTED_JWT]",
    ),
    (re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9._+/=-]{8,}"), r"\1 [REDACTED_TOKEN]"),
    (re.compile(r"(?i)\b(Basic)\s+[A-Za-z0-9+/=]{8,}"), r"\1 [REDACTED_TOKEN]"),
    (
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|CREDENTIAL)[A-Z0-9_]*)\s*=\s*(['\"]?)[^\s'\";]+(\2)"
        ),
        r"\1=\2[REDACTED]\3",
    ),
    (
        re.compile(
            r"(?i)\b((?:token|secret|password|passwd|api[_-]?key|access[_-]?key|credential)\s*[:=]\s*)(['\"]?)[^\s'\";,]+(\2)"
        ),
        r"\1\2[REDACTED]\3",
    ),
)

_PROTECTED_FILENAMES = frozenset({"skill.md", "agents.md", "gemini.md", "claude.md"})


def _redact_proposal_text(text: str) -> str:
    """Redact credentials, tokens, and secrets before writing trace proposals."""
    redacted = str(text)
    if _hook_redact_secrets is not None:
        try:
            redacted = _hook_redact_secrets(redacted)
        except Exception:
            pass
    for pat, repl in _FALLBACK_SECRET_RES:
        redacted = pat.sub(repl, redacted)
    return redacted


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


def _resolve_proposal_dir(proposal_dir: str | Path | None = None) -> Path:
    """Resolve and validate a safe out-of-vault proposal output directory (0700)."""
    if proposal_dir is not None:
        raw_target = Path(proposal_dir).expanduser()
    else:
        xdg_state = (os.environ.get("XDG_STATE_HOME") or "").strip()
        plugin_data = (
            os.environ.get("PLUGIN_DATA")
            or os.environ.get("ANTIGRAVITY_EXECUTABLE_DATA_DIR")
            or os.environ.get("KC_DATA_DIR")
            or ""
        ).strip()
        if xdg_state:
            raw_target = Path(xdg_state).expanduser() / "knowledge-compiler" / "proposals"
        elif plugin_data:
            raw_target = Path(plugin_data).expanduser() / "proposals"
        else:
            raw_target = (
                Path("~/.local/share/knowledge-compiler").expanduser() / "proposals"
            )

    if raw_target.name.lower() in _PROTECTED_FILENAMES:
        raise ValueError(
            f"Refusing protected instruction path for proposal output: {raw_target}"
        )
    if raw_target.is_symlink():
        raise ValueError(f"Refusing symlinked proposal directory: {raw_target}")

    for part in raw_target.parts:
        if part.lower() == "wiki":
            raise ValueError(
                f"Refusing proposal directory inside wiki subtree: {raw_target}"
            )

    abs_target = Path(os.path.abspath(str(raw_target)))
    resolved_target = abs_target.resolve()

    # Check symlinks along existing ancestors
    cur = abs_target
    while cur != cur.parent:
        if cur.is_symlink():
            raise ValueError(f"Refusing symlinked ancestor in proposal path: {cur}")
        if (cur / "wiki").is_dir() and (cur / "index.md").is_file():
            raise ValueError(
                f"Refusing proposal directory inside vault root '{cur}': {raw_target}"
            )
        cur = cur.parent

    for env_v in ("OBSIDIAN_VAULT_PATH", "KC_VAULT_PATH"):
        v_raw = (os.environ.get(env_v) or "").strip()
        if v_raw:
            v_resolved = Path(v_raw).expanduser().resolve()
            if resolved_target == v_resolved or v_resolved in resolved_target.parents:
                raise ValueError(
                    f"Refusing proposal directory inside ${env_v} ('{v_resolved}'): {raw_target}"
                )

    abs_target.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(abs_target, 0o700)
    return abs_target


def _atomic_write_private_file(target: Path, content: str) -> None:
    """Atomically write a 0600 file rejecting symlinks."""
    if target.is_symlink() or target.parent.is_symlink():
        raise ValueError(f"Refusing symlink proposal target: {target}")
    tmp_path = target.parent / f".{target.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.chmod(tmp_path, 0o600)
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, target)
        os.chmod(target, 0o600)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _normalize_signature(text: str) -> str:
    """Collapse paths, numbers, and whitespace to group recurring error/correction themes."""
    clean = _redact_proposal_text(text).strip()
    clean = re.sub(r"\b\d+\b", "<N>", clean)
    clean = re.sub(r"([\"'`])[^\"'`]{1,120}\1", "<ARG>", clean)
    clean = re.sub(r"\s+", " ", clean).strip().lower()
    return clean[:120]


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40] or "guardrail"


def _build_candidate_proposals(
    errors: list[dict[str, Any]],
    error_traces: list[dict[str, Any]],
    corrections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Cluster tool failures and explicit user corrections into diff-only proposals."""
    err_clusters: dict[str, dict[str, Any]] = {}
    for err in error_traces:
        tool = str(err.get("tool_name") or "tool").strip() or "tool"
        raw_msg = _redact_proposal_text(str(err.get("error") or ""))
        sig = f"{tool.lower()}::{_normalize_signature(raw_msg)}"
        bucket = err_clusters.setdefault(
            sig,
            {"tool": tool, "samples": [], "count": 0},
        )
        bucket["count"] += 1
        if len(bucket["samples"]) < 5:
            bucket["samples"].append(f"[{tool}] {raw_msg[:200]}")

    for err in errors:
        raw_msg = _redact_proposal_text(str(err.get("summary") or ""))
        sig = f"transcript::{_normalize_signature(raw_msg)}"
        bucket = err_clusters.setdefault(
            sig,
            {"tool": "transcript", "samples": [], "count": 0},
        )
        bucket["count"] += 1
        if len(bucket["samples"]) < 5:
            bucket["samples"].append(raw_msg[:200])

    corr_clusters: dict[str, list[str]] = defaultdict(list)
    for corr in corrections:
        raw_c = _redact_proposal_text(str(corr.get("content") or ""))
        sig = _normalize_signature(raw_c)
        if len(corr_clusters[sig]) < 5:
            corr_clusters[sig].append(raw_c[:200])

    proposals: list[dict[str, Any]] = []
    idx = 1

    sorted_err_buckets = sorted(
        err_clusters.items(),
        key=lambda kv: (-kv[1]["count"], kv[0]),
    )
    for _sig, bucket in sorted_err_buckets[:10]:
        tool_lbl = bucket["tool"]
        sample_line = bucket["samples"][0] if bucket["samples"] else tool_lbl
        guardrail = (
            f"Before calling `{tool_lbl}`, validate inputs and pre-check error conditions "
            f"(observed trigger: {sample_line[:140]})."
        )
        diff_preview = (
            "--- baseline/SKILL.md\n"
            "+++ candidate/SKILL.md\n"
            "@@ -0,0 +1,2 @@\n"
            f"+### Guardrail: `{tool_lbl}`\n"
            f"+- {guardrail}\n"
        )
        proposals.append(
            {
                "proposal_id": f"prop-{idx:03d}-{_slugify(tool_lbl)}",
                "category": "tool-error-guardrail",
                "trigger_count": bucket["count"],
                "evidence": bucket["samples"],
                "proposed_guardrail": guardrail,
                "diff_preview": diff_preview,
            }
        )
        idx += 1

    sorted_corr_buckets = sorted(
        corr_clusters.items(),
        key=lambda kv: (-len(kv[1]), kv[0]),
    )
    for sig, samples in sorted_corr_buckets[:10]:
        sample_line = samples[0] if samples else sig
        guardrail = (
            f"Enforce user-specified workflow constraint derived from explicit feedback: "
            f"{sample_line[:160]}"
        )
        diff_preview = (
            "--- baseline/SKILL.md\n"
            "+++ candidate/SKILL.md\n"
            "@@ -0,0 +1,2 @@\n"
            "+### Guardrail: User Correction\n"
            f"+- {guardrail}\n"
        )
        proposals.append(
            {
                "proposal_id": f"prop-{idx:03d}-user-correction",
                "category": "user-correction-directive",
                "trigger_count": len(samples),
                "evidence": samples,
                "proposed_guardrail": guardrail,
                "diff_preview": diff_preview,
            }
        )
        idx += 1

    return proposals


def _format_proposals_markdown(proposals: list[dict[str, Any]]) -> str:
    """Format candidate proposals as a human-reviewable diff-only Markdown report."""
    lines = [
        "# WikiSkill Diff-Only Evolution Proposals",
        "",
        "Review and evaluate with `vault-wikiskill-eval` before editing any `SKILL.md` manually.",
        "",
    ]
    if not proposals:
        lines.append("_No recurring tool errors or explicit user corrections detected._")
        return "\n".join(lines) + "\n"

    for prop in proposals:
        lines.extend(
            [
                f"## {prop['proposal_id']} (`{prop['category']}`, count={prop['trigger_count']})",
                f"- **Proposed Guardrail**: {prop['proposed_guardrail']}",
                "- **Evidence**:",
            ]
        )
        for ev in prop["evidence"]:
            lines.append(f"  - `{ev}`")
        lines.extend(
            [
                "",
                "```diff",
                prop["diff_preview"].rstrip(),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


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
                        "error": _redact_proposal_text(str(rec.get("error", ""))[:300]),
                    }
                )
    return records


def analyze_transcript(
    transcript_path: str | Path | None = None,
    error_log_path: str | Path | None = None,
    *,
    propose: bool = False,
    proposal_dir: str | Path | None = None,
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
                            "summary": _redact_proposal_text(raw_content[:300]),
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
                                "content": _redact_proposal_text(raw_content[:300]),
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

    if propose:
        out_dir = _resolve_proposal_dir(proposal_dir)
        proposals = _build_candidate_proposals(errors, error_traces, corrections)
        json_file = out_dir / "latest_proposals.json"
        md_file = out_dir / "latest_proposals.md"
        payload = {
            "transcript_file": resolved_transcript,
            "error_log_file": resolved_error_log,
            "proposals": proposals,
        }
        _atomic_write_private_file(json_file, json.dumps(payload, indent=2) + "\n")
        _atomic_write_private_file(md_file, _format_proposals_markdown(proposals))
        report["proposals"] = proposals
        report["proposal_file"] = str(json_file)
        report["proposal_markdown_file"] = str(md_file)

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
        "--propose",
        action="store_true",
        help="Cluster redacted failures into diff-only candidate proposals in an out-of-vault directory.",
    )
    parser.add_argument(
        "--proposal-dir",
        default=None,
        help="Override out-of-vault directory for diff-only proposals (mode 0700).",
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

    try:
        report = analyze_transcript(
            transcript_path=transcript,
            error_log_path=args.error_log,
            propose=args.propose,
            proposal_dir=args.proposal_dir,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
