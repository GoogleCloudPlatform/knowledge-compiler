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
OKF v0.3 Knowledge Compiler Vault Linter & Conformance Auditor (with v0.2 compatibility).
Validates OKF v0.3 bundle conformance (root `.`, compiled concepts in `wiki/`),
relative Markdown link and `[[wikilink]]` integrity, table formatting invariants,
orphan notes, ranked `wanted_pages`, trust-tier breakdown (`verified[].at >= generated.at`),
freshness (`stale_after`), `superseded_by` lifecycle edges, `x-kc-*` epistemic
extension keys, and Workspace Profile root files.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import sys
import tempfile
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import okf  # noqa: E402

SUPPORTED_OKF_VERSION = okf.SUPPORTED_OKF_VERSION
UPSTREAM_OKF_REPO_URL = "https://github.com/open-knowledge-format/open-knowledge-format"
UPSTREAM_OKF_SPEC_RAW_URL = (
    "https://raw.githubusercontent.com/open-knowledge-format/open-knowledge-format/main/SPEC.md"
)
UPSTREAM_OKF_COMMITS_API_URL = (
    "https://api.github.com/repos/open-knowledge-format/open-knowledge-format/commits/main"
)

IGNORED_DIR_NAMES = frozenset(
    {".obsidian", ".git", "__pycache__", ".venv", ".agents", ".gemini"}
)
RESERVED_BUNDLE_FILENAMES = frozenset({"index.md", "log.md"})
_PROTECTED_LINT_FIX_FILENAMES = frozenset(
    {
        "gemini.md",
        "agents.md",
        "claude.md",
        "skill.md",
        "hooks.json",
        "plugin.json",
        "log.md",
        "purpose.md",
    }
)
_PROTECTED_LINT_FIX_DIRS = frozenset(
    {"skills", "rules", ".agents", ".gemini", "raw", "archive"}
)
_PORTABLE_LINK_PROTECTED_FILENAMES = frozenset(
    {
        "gemini.md",
        "agents.md",
        "claude.md",
        "skill.md",
        "hooks.json",
        "plugin.json",
        "log.md",
    }
)
EPISTEMIC_EDGE_CANONICAL_TYPES = (
    "corroborates",
    "complements",
    "extends",
    "contradicts",
    "supersedes",
)
EPISTEMIC_EDGE_X_PREFIX = "x-kc-"
EPISTEMIC_EDGE_X_KEYS = tuple(
    f"{EPISTEMIC_EDGE_X_PREFIX}{k}" for k in EPISTEMIC_EDGE_CANONICAL_TYPES
)
EPISTEMIC_EDGE_KEYS = EPISTEMIC_EDGE_X_KEYS + EPISTEMIC_EDGE_CANONICAL_TYPES


def _epistemic_edge_type_for_key(key: str) -> str | None:
    """Map an `x-kc-<rel>` or legacy `<rel>` frontmatter key to canonical uppercase edge type."""
    low = str(key).strip().lower()
    if low.startswith(EPISTEMIC_EDGE_X_PREFIX):
        low = low[len(EPISTEMIC_EDGE_X_PREFIX) :]
    if low in EPISTEMIC_EDGE_CANONICAL_TYPES:
        return low.upper()
    return None


_HEADING_RE = re.compile(r"^[ \t]{0,3}#{1,6}(?:[ \t]|$)")
_BQ_PREFIX_RE = re.compile(r"^((?:[ \t]*>[ \t]?)*)([\s\S]*)$")
_LIST_MARKER_RE = re.compile(r"^([ \t]*(?:[-*+]|\d+[.)])[ \t]+(?:\[[ xX]\][ \t]+)?)")
_OPEN_FENCE_LINE_RE = re.compile(r"^([ \t]*)(`{3,}|~{3,})([^\r\n]*)$")
_WIKILINK_RE = re.compile(r"\[\[([^\]\n]+)\]\]")
_PORTABLE_WIKILINK_RE = re.compile(r"(?<!!)\[\[([^\]\n]+)\]\]")
_MD_LINK_RE = re.compile(
    r"(?<!!)\[[^\]\n]+\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)"
)
_TABLE_ESCAPED_PIPE_RE = re.compile(r"\[\[([^\]\n]+?\\\|[^\]\n]+)\]\]")
_FOOTNOTE_DEF_RE = re.compile(r"(?m)^[ \t]*\[\^([^\]\s]+)\]:")
_FOOTNOTE_REF_RE = re.compile(r"\[\^([^\]\s]+)\](?!:)")
_LOG_H2_RE = re.compile(r"^[ \t]{0,3}##[ \t]+(.*)$")
_LOG_DATE_HEADING_RE = re.compile(
    r"^(?:\[(\d{4}-\d{2}-\d{2})\]|(\d{4}-\d{2}-\d{2}))(?=$|[ \t|—\-:])"
)


def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """Convert a version string like '0.2' or '0.3.1' into an integer tuple for comparison."""
    parts = re.findall(r"\d+", version_str or "")
    return tuple(int(p) for p in parts) if parts else (0,)


def check_upstream_okf_version(timeout: float = 5.0) -> dict[str, Any]:
    """Check upstream open-knowledge-format/open-knowledge-format SPEC.md version."""
    result: dict[str, Any] = {
        "supported_version": SUPPORTED_OKF_VERSION,
        "upstream_version": None,
        "status": "unknown",
        "is_up_to_date": True,
        "newer_version_available": False,
        "repo_url": UPSTREAM_OKF_REPO_URL,
        "spec_url": f"{UPSTREAM_OKF_REPO_URL}/blob/main/SPEC.md",
        "latest_commit_sha": None,
        "latest_commit_date": None,
        "latest_commit_message": None,
        "error": None,
    }

    headers = {
        "User-Agent": "knowledge-compiler-okf-checker/1.3.0",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        req = urllib.request.Request(UPSTREAM_OKF_SPEC_RAW_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            spec_text = resp.read().decode("utf-8", errors="replace")

        header_chunk = "\n".join(spec_text.splitlines()[:40])
        m = re.search(
            r"(?:\*\*Version\s+([0-9]+(?:\.[0-9]+)+)[^*\r\n]*\*\*|Version[:\s]+([0-9]+(?:\.[0-9]+)+))",
            header_chunk,
            re.IGNORECASE,
        )
        if m:
            upstream_ver = (m.group(1) or m.group(2)).strip()
            result["upstream_version"] = upstream_ver
            sup_tuple = _parse_version_tuple(SUPPORTED_OKF_VERSION)
            up_tuple = _parse_version_tuple(upstream_ver)
            if up_tuple > sup_tuple:
                result["is_up_to_date"] = False
                result["newer_version_available"] = True
                result["status"] = "update_available"
            elif up_tuple == sup_tuple:
                result["is_up_to_date"] = True
                result["newer_version_available"] = False
                result["status"] = "up_to_date"
            else:
                result["status"] = "ahead_of_upstream"
        else:
            result["status"] = "version_parse_failed"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result["status"] = "offline"
        result["error"] = str(exc)
        return result

    try:
        commit_req = urllib.request.Request(UPSTREAM_OKF_COMMITS_API_URL, headers=headers)
        with urllib.request.urlopen(commit_req, timeout=timeout) as resp:
            commit_data = json.loads(resp.read().decode("utf-8", errors="replace"))
            sha = str(commit_data.get("sha", ""))
            result["latest_commit_sha"] = sha[:7] if sha else None
            commit_info = commit_data.get("commit", {}) or {}
            author_info = commit_info.get("author", {}) or {}
            result["latest_commit_date"] = author_info.get("date")
            msg = str(commit_info.get("message", "")).splitlines()
            result["latest_commit_message"] = msg[0].strip() if msg else None
    except Exception:
        pass

    return result


def find_vault_root(start_path: Path) -> Path:
    """Locate vault root by finding GEMINI.md or wiki/ folder."""
    curr = start_path.resolve()
    while curr != curr.parent:
        if (curr / "GEMINI.md").exists() or (curr / "wiki").exists():
            return curr
        curr = curr.parent
    env_vault = os.environ.get("OBSIDIAN_VAULT_PATH")
    if env_vault:
        ep = Path(env_vault).expanduser().resolve()
        if (ep / "wiki").exists() and start_path.resolve() == Path.cwd().resolve():
            return ep
    default_vault = (Path.home() / "ObsidianVault").resolve()
    if (default_vault / "wiki").exists() and start_path.resolve() == Path.cwd().resolve():
        return default_vault
    return start_path.resolve()


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse YAML frontmatter using OKF v0.2 parser (PyYAML + pure-stdlib fallback)."""
    try:
        parsed = okf.parse_frontmatter(text, strict=False)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return {}


def _is_protected_from_migrate_sources(rel_path: str) -> bool:
    """Return True if `rel_path` is an instruction, config, or non-bundle file that even `--migrate-sources` must never mutate."""
    rel_norm = rel_path.replace("\\", "/").strip("/")
    parts = [p.lower() for p in Path(rel_norm).parts]
    if not parts:
        return True
    if parts[-1] in _PROTECTED_LINT_FIX_FILENAMES:
        return True
    if any(p in _PROTECTED_LINT_FIX_DIRS or p.startswith(".") for p in parts[:-1]):
        return True
    if rel_norm.lower() == "wiki/skill-impact.md":
        return True
    return False


def _is_protected_from_lint_fix(rel_path: str) -> bool:
    """Return True if `rel_path` is an instruction, config, or historical provenance file that `--fix` body repair must never mutate."""
    if _is_protected_from_migrate_sources(rel_path):
        return True
    rel_norm = rel_path.replace("\\", "/").strip("/")
    parts = [p.lower() for p in Path(rel_norm).parts]
    if len(parts) >= 2 and parts[0] == "wiki" and parts[1] == "sources":
        return True
    return False


def _read_text_preserve_eol(path: Path) -> tuple[str, bool]:
    """Read `path` preserving CRLF/LF line endings, returning `(text, is_valid_utf8)`."""
    raw_bytes = path.read_bytes()
    try:
        return raw_bytes.decode("utf-8"), True
    except UnicodeDecodeError:
        return raw_bytes.decode("utf-8", errors="ignore"), False


def _atomic_write_text(target_path: Path, content: str) -> None:
    """Atomically write `content` to `target_path` via a sibling `.tmp` + `os.replace`."""
    orig_mode: int | None = None
    try:
        if target_path.exists():
            orig_mode = stat.S_IMODE(target_path.stat().st_mode)
    except OSError:
        orig_mode = None

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target_path.name}.",
        suffix=".tmp",
        dir=str(target_path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if orig_mode is not None:
            os.chmod(tmp_path, orig_mode)
        os.replace(tmp_path, target_path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


_PUA_CANDIDATE_BASES: tuple[int, ...] = (
    0xE000,
    0xE200,
    0xE400,
    0xF0000,
    *range(0xE600, 0xF800, 0x40),
    *range(0xF2000, 0xFE000, 0x40),
    0x10F000,
)


def _find_pua_sentinel_base(text: str) -> tuple[str, str, int, bool]:
    """Pick an unused Private Use Area alphabet and report whether it is collision-free."""
    if text.isascii():
        return "\ue000", "\ue001", 0xE010, True
    used_ords = {ord(ch) for ch in text if 0xE000 <= ord(ch) <= 0x10FFFF}
    for base in _PUA_CANDIDATE_BASES:
        digit_base = base + 0x10
        slot = (base, base + 1, *range(digit_base, digit_base + 16))
        if used_ords.isdisjoint(slot):
            return chr(base), chr(base + 1), digit_base, True
    return "\U0010f000", "\U0010f001", 0x10F010, False


def _select_pua_sentinel_base(text: str) -> tuple[str, str, int]:
    """Pick an unused Private Use Area alphabet for masking protected spans."""
    open_ch, close_ch, digit_base, _clean = _find_pua_sentinel_base(text)
    return open_ch, close_ch, digit_base


def _mask_html_comments(text: str, encode_fn: Any) -> str:
    """Mask HTML comments (`<!-- ... -->`) in strictly linear O(N) time."""
    if "<!--" not in text:
        return text
    out: list[str] = []
    pos = 0
    n = len(text)
    while pos < n:
        start = text.find("<!--", pos)
        if start < 0:
            out.append(text[pos:])
            break
        end = text.find("-->", start + 4)
        if end < 0:
            out.append(text[pos:])
            break
        out.append(text[pos:start])
        out.append(encode_fn(text[start : end + 3]))
        pos = end + 3
    return "".join(out)


def _mask_inline_code_spans(text: str, encode_fn: Any) -> str:
    """Mask inline code spans (`...`, ``...``) in strictly linear O(N) time."""
    if "`" not in text:
        return text

    parts: list[str] = []
    for chunk_idx, chunk in enumerate(re.split(r"((?:\r?\n){2,})", text)):
        if chunk_idx % 2 == 1 or not chunk or "`" not in chunk:
            parts.append(chunk)
            continue

        runs: list[tuple[int, int, int]] = []
        by_len: dict[int, list[int]] = {}
        i = 0
        cn = len(chunk)
        while i < cn:
            pos = chunk.find("`", i)
            if pos < 0:
                break
            end = pos + 1
            while end < cn and chunk[end] == "`":
                end += 1
            rlen = end - pos
            run_idx = len(runs)
            runs.append((pos, end, rlen))
            by_len.setdefault(rlen, []).append(run_idx)
            i = end

        next_ptr: dict[int, int] = {rlen: 0 for rlen in by_len}
        out: list[str] = []
        cursor = 0
        r_idx = 0
        num_runs = len(runs)
        while r_idx < num_runs:
            r_start, _r_end, r_len = runs[r_idx]
            if r_start < cursor:
                r_idx += 1
                continue
            indices = by_len[r_len]
            ptr = next_ptr[r_len]
            while ptr < len(indices) and indices[ptr] <= r_idx:
                ptr += 1
            next_ptr[r_len] = ptr
            if ptr < len(indices):
                close_run_idx = indices[ptr]
                _close_start, close_end, _ = runs[close_run_idx]
                next_ptr[r_len] = ptr + 1
                out.append(chunk[cursor:r_start])
                out.append(encode_fn(chunk[r_start:close_end]))
                cursor = close_end
                r_idx = close_run_idx + 1
            else:
                r_idx += 1

        if cursor < cn:
            out.append(chunk[cursor:])
        parts.append("".join(out))

    return "".join(parts)


def _line_indent_width(line: str) -> int:
    width = 0
    for ch in line:
        if ch == " ":
            width += 1
        elif ch == "\t":
            width += 4 - (width % 4)
        else:
            break
    return width


def _mask_indented_code_blocks(
    text: str,
    encode_fn: Any,
    fence_placeholders: set[str],
) -> str:
    """Mask 4-space indented code blocks while preserving tight and loose list items."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    idx = 0
    can_start_indented = True
    list_code_threshold: int | None = None

    while idx < len(lines):
        line = lines[idx]
        stripped_no_nl = line.rstrip("\r\n")
        stripped = stripped_no_nl.strip()
        indent = _line_indent_width(stripped_no_nl)

        if not stripped:
            out.append(line)
            can_start_indented = True
            idx += 1
            continue

        list_match = _LIST_MARKER_RE.match(stripped_no_nl)
        if list_match and indent < (
            list_code_threshold if list_code_threshold is not None else 4
        ):
            list_code_threshold = len(list_match.group(0).expandtabs(4)) + 4
            can_start_indented = False
            out.append(line)
            idx += 1
            continue

        min_code_indent = list_code_threshold if list_code_threshold is not None else 4
        if can_start_indented and indent >= min_code_indent and not list_match:
            block_lines: list[str] = [line]
            idx += 1
            while idx < len(lines):
                nxt = lines[idx]
                nxt_no_nl = nxt.rstrip("\r\n")
                if not nxt_no_nl.strip():
                    block_lines.append(nxt)
                    idx += 1
                elif _line_indent_width(nxt_no_nl) >= min_code_indent:
                    block_lines.append(nxt)
                    idx += 1
                else:
                    break
            trailing_blanks: list[str] = []
            while block_lines and not block_lines[-1].rstrip("\r\n").strip():
                trailing_blanks.append(block_lines.pop())
            raw_block = "".join(block_lines)
            last_nl = (
                "\r\n"
                if raw_block.endswith("\r\n")
                else ("\n" if raw_block.endswith("\n") else "")
            )
            core_block = raw_block[: -len(last_nl)] if last_nl else raw_block
            out.append(encode_fn(core_block) + last_nl)
            for tb in reversed(trailing_blanks):
                out.append(tb)
            can_start_indented = True
            continue

        if indent == 0 and not list_match:
            list_code_threshold = None

        out.append(line)
        is_fence_or_heading = bool(
            _HEADING_RE.match(stripped_no_nl) or stripped in fence_placeholders
        )
        can_start_indented = is_fence_or_heading
        idx += 1

    return "".join(out)


def _mask_markdown_code(body: str) -> tuple[str, Any, bool]:
    """Mask HTML comments, fenced/indented code blocks, and inline code spans.

    Returns `(masked_text, restore_fn, has_unclosed_fence)`.
    """
    tokens: list[str] = []
    fence_placeholders: set[str] = set()
    open_ch, close_ch, digit_base = _select_pua_sentinel_base(body)

    def _encode(raw: str) -> str:
        idx = len(tokens)
        tokens.append(raw)
        encoded = "".join(chr(digit_base + int(ch, 16)) for ch in format(idx, "x"))
        return f"{open_ch}{encoded}{close_ch}"

    # Mask HTML comments first so stray fence markers inside <!-- --> never open blocks
    masked = _mask_html_comments(body, _encode)

    lines = masked.splitlines(keepends=True)
    out_lines: list[str] = []
    has_unclosed_fence = False
    i = 0
    while i < len(lines):
        line_no_nl = lines[i].rstrip("\r\n")
        m_bq = _BQ_PREFIX_RE.match(line_no_nl)
        bq_prefix = m_bq.group(1) if m_bq else ""
        bq_depth = bq_prefix.count(">")
        inner = m_bq.group(2) if m_bq else line_no_nl

        m_open = _OPEN_FENCE_LINE_RE.match(inner)
        if not m_open:
            m_list = _LIST_MARKER_RE.match(inner)
            if m_list:
                m_open = _OPEN_FENCE_LINE_RE.match(inner[len(m_list.group(0)) :])

        if m_open:
            fence_seq, info = m_open.group(2), m_open.group(3)
            fence_char = fence_seq[0]
            fence_len = len(fence_seq)
            if fence_char == "`" and "`" in info:
                out_lines.append(lines[i])
                i += 1
                continue

            close_re = re.compile(
                rf"^[ \t]*{re.escape(fence_char)}{{{fence_len},}}[ \t]*$"
            )
            closed_idx: int | None = None
            for j in range(i + 1, len(lines)):
                j_no_nl = lines[j].rstrip("\r\n")
                j_bq = _BQ_PREFIX_RE.match(j_no_nl)
                j_bq_depth = (j_bq.group(1) if j_bq else "").count(">")
                j_inner = j_bq.group(2) if j_bq else j_no_nl
                if j_bq_depth < bq_depth:
                    break
                if close_re.match(j_inner):
                    closed_idx = j
                    break

            if closed_idx is None:
                has_unclosed_fence = True
                raw_block = "".join(lines[i:])
                last_nl = (
                    "\r\n"
                    if raw_block.endswith("\r\n")
                    else ("\n" if raw_block.endswith("\n") else "")
                )
                core_block = raw_block[: -len(last_nl)] if last_nl else raw_block
                ph = _encode(core_block)
                fence_placeholders.add(ph)
                out_lines.append(ph + last_nl)
                break

            raw_block = "".join(lines[i : closed_idx + 1])
            last_nl = (
                "\r\n"
                if raw_block.endswith("\r\n")
                else ("\n" if raw_block.endswith("\n") else "")
            )
            core_block = raw_block[: -len(last_nl)] if last_nl else raw_block
            ph = _encode(core_block)
            fence_placeholders.add(ph)
            out_lines.append(ph + last_nl)
            i = closed_idx + 1
            continue

        out_lines.append(lines[i])
        i += 1

    masked = _mask_inline_code_spans("".join(out_lines), _encode)
    masked = _mask_indented_code_blocks(masked, _encode, fence_placeholders)

    def _restore(updated: str) -> str:
        if open_ch not in updated:
            return updated
        digit_lo = re.escape(chr(digit_base))
        digit_hi = re.escape(chr(digit_base + 15))
        ph_re = re.compile(
            rf"{re.escape(open_ch)}([{digit_lo}-{digit_hi}]+){re.escape(close_ch)}"
        )
        expanded_cache: dict[int, str] = {}

        def _expand(encoded_idx: str, max_idx: int) -> str:
            idx = 0
            for ch in encoded_idx:
                d = ord(ch) - digit_base
                if d < 0 or d > 15:
                    return f"{open_ch}{encoded_idx}{close_ch}"
                idx = (idx << 4) | d
            if idx >= max_idx:
                return f"{open_ch}{encoded_idx}{close_ch}"
            cached = expanded_cache.get(idx)
            if cached is not None:
                return cached
            raw = tokens[idx]
            if open_ch in raw and idx > 0:
                raw = ph_re.sub(lambda m: _expand(m.group(1), idx), raw)
            expanded_cache[idx] = raw
            return raw

        return ph_re.sub(lambda m: _expand(m.group(1), len(tokens)), updated)

    return masked, _restore, has_unclosed_fence


def _validate_log_headings(
    body: str, rel_path: str, *, check_date_order: bool = True
) -> list[dict[str, str]]:
    """Verify `log.md` level-2 headings match `## YYYY-MM-DD` (OKF v0.3) or legacy `## [YYYY-MM-DD]` and optionally are newest-first."""
    masked_body, _restore, _unclosed = _mask_markdown_code(body)
    issues: list[dict[str, str]] = []
    seen_dates: list[tuple[int, str]] = []
    for line_no, raw_line in enumerate(masked_body.splitlines(), start=1):
        m = _LOG_H2_RE.match(raw_line)
        if not m:
            continue
        heading_rest = m.group(1).strip()
        dm = _LOG_DATE_HEADING_RE.match(heading_rest)
        if not dm:
            issues.append(
                {
                    "file": rel_path,
                    "rule": "okf_log_date_heading",
                    "message": (
                        f"log.md line {line_no} heading '## {heading_rest}' must start with "
                        "'## YYYY-MM-DD' or legacy '## [YYYY-MM-DD]'"
                    ),
                }
            )
            continue
        date_str = dm.group(1) or dm.group(2)
        try:
            datetime.date.fromisoformat(date_str)
        except ValueError:
            issues.append(
                {
                    "file": rel_path,
                    "rule": "okf_log_date_heading",
                    "message": f"log.md line {line_no} has invalid calendar date '{date_str}'",
                }
            )
            continue
        seen_dates.append((line_no, date_str))
    if check_date_order:
        for (_, newer), (line_no, older) in zip(seen_dates, seen_dates[1:]):
            if older > newer:
                issues.append(
                    {
                        "file": rel_path,
                        "rule": "okf_log_date_order",
                        "message": (
                            f"log.md line {line_no} date '{older}' follows older date '{newer}'; "
                            "OKF v0.3 §9 puts newest date first"
                        ),
                    }
                )
    return issues


def _has_symlink_component(target: Path, stop_at: Path) -> bool:
    """Return True if `target` or any component below `stop_at` is a symlink."""
    if target.is_symlink():
        return True
    try:
        rel = target.relative_to(stop_at)
    except ValueError:
        return True
    curr = stop_at
    for part in rel.parts:
        curr = curr / part
        if curr.is_symlink():
            return True
    return False


def _sanitize_human_actor(raw_actor: str | None) -> tuple[str | None, str | None]:
    """Resolve and validate an OKF §7 `human:<id>` actor string."""
    if raw_actor is None:
        candidate = ""
        for env_key in ("USER", "LOGNAME", "USERNAME"):
            val = (os.environ.get(env_key) or "").strip()
            if val:
                candidate = val
                break
        if not candidate:
            try:
                candidate = getpass.getuser().strip()
            except Exception:
                candidate = ""
        candidate = candidate.split("@", 1)[0].strip()
        sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", candidate).strip(".-")
        return f"human:{sanitized or 'reviewer'}", None

    cleaned = raw_actor.strip().strip("\"'")
    if not cleaned:
        return None, "Actor identifier cannot be empty"
    if ":" in cleaned:
        prefix, rest = cleaned.split(":", 1)
        if prefix != "human":
            return None, f"--approve-human requires a 'human:<id>' actor, got {raw_actor!r}"
        actor_id = rest.strip()
    else:
        actor_id = cleaned

    if not actor_id or not re.fullmatch(r"[A-Za-z0-9._@+-]+", actor_id):
        return None, f"Invalid human actor identifier: {raw_actor!r}"
    return f"human:{actor_id}", None


def approve_human_note(
    vault_root: Path,
    note_path: Path | str,
    actor: str | None = None,
    at_iso: str | None = None,
) -> dict[str, Any]:
    """Stamp human verification (`verified: [{ by: human:<id>, at: ... }]`) onto a note inside `wiki/`."""
    raw_vault = Path(vault_root)
    if not raw_vault.exists() or not raw_vault.is_dir():
        return {"success": False, "error": f"Vault directory not found: {raw_vault}"}
    v_root = raw_vault.resolve()
    wiki_dir = v_root / "wiki"
    if wiki_dir.is_symlink() or not wiki_dir.is_dir():
        return {"success": False, "error": f"Vault wiki directory not found at {wiki_dir}"}
    wiki_root = wiki_dir.resolve()

    clean_actor, actor_err = _sanitize_human_actor(actor)
    if actor_err or not clean_actor:
        return {"success": False, "error": actor_err or "Invalid human actor"}

    raw_note = Path(note_path)
    if raw_note.is_absolute():
        if raw_note.is_symlink():
            return {"success": False, "error": f"Refusing symlink target: {raw_note}"}
        candidate = Path(os.path.normpath(str(raw_note)))
    else:
        cand_in_vault = Path(os.path.normpath(str(v_root / raw_note)))
        cand_in_cwd = Path(os.path.normpath(str(Path.cwd() / raw_note)))
        if (
            not cand_in_vault.exists()
            and not cand_in_vault.is_symlink()
            and (cand_in_cwd.exists() or cand_in_cwd.is_symlink())
        ):
            candidate = cand_in_cwd
        else:
            candidate = cand_in_vault

    # Enforce strict containment inside <vault_root>/wiki/ and zero symlinks
    if _has_symlink_component(candidate, v_root):
        return {
            "success": False,
            "error": f"Target must reside inside {wiki_root} without symlinks: {note_path}",
        }
    try:
        resolved = candidate.resolve()
        resolved.relative_to(wiki_root)
    except (OSError, ValueError):
        return {
            "success": False,
            "error": f"Target must resolve strictly inside wiki/: {note_path}",
        }
    if resolved == wiki_root:
        return {"success": False, "error": "Target must be a markdown note file inside wiki/"}

    rel_parts = resolved.relative_to(v_root).parts
    if any(part in IGNORED_DIR_NAMES for part in rel_parts):
        return {"success": False, "error": f"Target sits inside an ignored directory: {note_path}"}
    if resolved.suffix.lower() != ".md":
        return {"success": False, "error": f"Target must be a .md note inside wiki/: {note_path}"}
    if resolved.name.lower() in RESERVED_BUNDLE_FILENAMES:
        return {"success": False, "error": f"Reserved filename cannot be approved as a concept: {resolved.name}"}
    if not resolved.is_file():
        return {"success": False, "error": f"Target wiki note not found: {resolved}"}

    orig_text, valid_utf8 = _read_text_preserve_eol(resolved)
    if not valid_utf8:
        return {
            "success": False,
            "error": f"Target wiki note is not valid UTF-8: {resolved.name}",
        }
    try:
        updated_text = okf.stamp_human_verification(orig_text, clean_actor, at_iso=at_iso)
    except Exception as exc:
        return {"success": False, "error": f"Failed to stamp verification on {resolved.name}: {exc}"}

    rel_posix = resolved.relative_to(v_root).as_posix()
    if updated_text != orig_text:
        _atomic_write_text(resolved, updated_text)

    doc = okf.parse_okf_document(updated_text, strict=False)
    fm = doc.get("frontmatter") or {}
    return {
        "success": True,
        "vault_path": str(v_root),
        "file": rel_posix,
        "actor": clean_actor,
        "trust_tier": okf.derive_trust_tier(fm),
        "verified": okf.normalize_verified_list(fm.get("verified")),
    }


def _extract_epistemic_wikilinks(fm: dict[str, Any]) -> list[str]:
    """Extract targets from frontmatter `x-kc-*` / legacy epistemic keys and OKF v0.3 `superseded_by`."""
    targets: list[str] = []
    fm_lower = {str(k).lower(): v for k, v in fm.items()} if isinstance(fm, dict) else {}
    for ep_k in EPISTEMIC_EDGE_KEYS:
        val = fm_lower.get(ep_k)
        items = val if isinstance(val, list) else ([val] if isinstance(val, str) else [])
        for item in items:
            if not isinstance(item, str):
                continue
            raw_str = item.strip()
            if not raw_str:
                continue
            wl_matches = list(_WIKILINK_RE.finditer(raw_str))
            if wl_matches:
                for m in wl_matches:
                    raw_link = m.group(1).strip()
                    tgt = re.split(r"\\?\|", raw_link)[0].strip()
                    if tgt and not tgt.startswith("#"):
                        tgt = tgt.split("#", 1)[0].strip()
                        if tgt:
                            targets.append(tgt)
                continue
            md_matches = list(_MD_LINK_RE.finditer(raw_str))
            if md_matches:
                for m in md_matches:
                    href = m.group(1).strip()
                    if not href or href.startswith(("#", "//")) or _URI_SCHEME_RE.match(href):
                        continue
                    clean_href = (
                        urllib.parse.unquote(href.split("#", 1)[0].split("?", 1)[0])
                        .strip()
                        .lstrip("/")
                    )
                    if clean_href:
                        targets.append(clean_href)
                continue
            if not raw_str.startswith(("#", "//")) and not _URI_SCHEME_RE.match(raw_str):
                clean_item = (
                    urllib.parse.unquote(raw_str.split("#", 1)[0].split("?", 1)[0])
                    .strip()
                    .lstrip("/")
                )
                if clean_item:
                    targets.append(clean_item)
    sup_by = fm_lower.get("superseded_by")
    if isinstance(sup_by, str) and sup_by.strip():
        clean_sup = re.sub(r"^\[\[|\]\]$", "", sup_by.strip())
        clean_sup = re.split(r"\\?\|", clean_sup)[0].split("#", 1)[0].split("?", 1)[0].strip()
        if clean_sup and not _URI_SCHEME_RE.match(clean_sup) and not clean_sup.startswith("//"):
            clean_sup = urllib.parse.unquote(clean_sup).lstrip("/")
            if clean_sup:
                targets.append(clean_sup)
    return targets


def _resolve_target(
    target: str,
    name_to_rel: dict[str, str],
    graph: dict[str, dict[str, Any]],
) -> str | None:
    """Resolve a wikilink target string to a vault-relative file path if present."""
    target_clean = target.lower().removesuffix(".md")
    target_basename = target_clean.split("/")[-1]

    if target_clean in name_to_rel:
        return name_to_rel[target_clean]
    if target.lower() in name_to_rel:
        return name_to_rel[target.lower()]
    if target_basename in name_to_rel:
        return name_to_rel[target_basename]

    for candidate, c_data in graph.items():
        fm = c_data.get("frontmatter")
        if not isinstance(fm, dict):
            continue
        fm_title = str(fm.get("title", "")).strip().lower()
        if fm_title and fm_title in (target_clean, target_basename):
            return candidate
        aliases = fm.get("aliases")
        if isinstance(aliases, list):
            for alias in aliases:
                if str(alias).strip().lower() in (target_clean, target_basename):
                    return candidate
    return None


def _build_wanted_pages(broken_links: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Aggregate unresolved `[[Target]]` wikilinks ranked by inbound reference count."""
    grouped_sources: dict[str, set[str]] = {}
    spelling_counts: dict[str, Counter[str]] = {}

    for item in broken_links:
        raw_target = item["target"].strip()
        src = item["source"]
        key = raw_target.removesuffix(".md").lower()
        if not key:
            continue
        grouped_sources.setdefault(key, set()).add(src)
        spelling_counts.setdefault(key, Counter())[raw_target] += 1

    wanted: list[dict[str, Any]] = []
    for key, srcs in grouped_sources.items():
        counts = spelling_counts[key]
        canonical_target = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        sorted_srcs = sorted(srcs)
        wanted.append(
            {
                "target": canonical_target,
                "inbound_count": len(sorted_srcs),
                "sources": sorted_srcs,
            }
        )

    wanted.sort(key=lambda w: (-w["inbound_count"], w["target"].lower()))
    return wanted


_LINKABLE_WIKI_PREFIXES = ("wiki/entities/", "wiki/concepts/", "wiki/patterns/")
_MENTION_STOPWORDS = frozenset(
    {
        "overview",
        "notes",
        "summary",
        "index",
        "system",
        "guide",
        "pattern",
        "concept",
        "entity",
        "concepts",
        "patterns",
        "entities",
        "synthesis",
        "workflow",
        "readme",
        "default",
        "config",
        "model",
        "models",
        "template",
        "templates",
        "example",
        "examples",
    }
)
_MD_HEADING_12_RE = re.compile(r"^[ \t]{0,3}#{1,2}[ \t]+(.+)$", re.MULTILINE)
_INLINE_MD_LINK_MASK_RE = re.compile(r"!?\[[^\]\n]*\]\([^)\n]*\)")
_URL_MASK_RE = re.compile(r"https?://\S+")


def _extract_iso_date(val: Any) -> str | None:
    """Return a validated YYYY-MM-DD prefix from a date, datetime, or string."""
    if isinstance(val, datetime.datetime):
        return val.date().isoformat()
    if isinstance(val, datetime.date):
        return val.isoformat()
    if isinstance(val, str):
        cand = val.strip()[:10]
        if len(cand) == 10:
            try:
                return datetime.date.fromisoformat(cand).isoformat()
            except ValueError:
                return None
    return None


def _resolve_dep_path(
    raw_ref: str,
    src_rel: str,
    name_to_rel: dict[str, str],
    graph: dict[str, dict[str, Any]],
) -> str | None:
    """Resolve a wikilink, markdown path, or sources[].resource string to a vault-relative note."""
    text = (raw_ref or "").strip()
    if not text:
        return None
    if text.startswith("[[") and text.endswith("]]"):
        text = text[2:-2].strip()
    text = re.split(r"\\?\|", text)[0].strip()
    if "#" in text:
        text = text.split("#", 1)[0].strip()
    if "?" in text:
        text = text.split("?", 1)[0].strip()
    if not text or text.startswith(("http://", "https://", "mailto:")):
        return None

    candidates = [text]
    if not text.startswith("/"):
        joined = os.path.normpath(str(Path(src_rel).parent / text)).replace("\\", "/")
        if not joined.startswith(".."):
            candidates.append(joined)
    for cand in candidates:
        resolved = _resolve_target(cand.lstrip("/"), name_to_rel, graph)
        if resolved and resolved in graph and resolved.startswith("wiki/"):
            return resolved
    return None


def _detect_stale_syntheses(
    all_md_files: dict[str, dict[str, Any]],
    graph: dict[str, dict[str, Any]],
    name_to_rel: dict[str, str],
) -> list[dict[str, Any]]:
    """Detect wiki/synthesis/*.md notes whose resolved wiki/ dependencies were updated later."""
    stale_syntheses: list[dict[str, Any]] = []
    for rel_path in sorted(all_md_files):
        if (
            not rel_path.startswith("wiki/synthesis/")
            or not rel_path.endswith(".md")
            or Path(rel_path).name.lower() in RESERVED_BUNDLE_FILENAMES
        ):
            continue
        data = graph.get(rel_path) or {}
        fm = data.get("frontmatter")
        if not isinstance(fm, dict) or not data.get("has_fm"):
            continue

        synth_date: str | None = None
        gen = fm.get("generated")
        if isinstance(gen, dict):
            synth_date = _extract_iso_date(gen.get("at"))
        if not synth_date:
            synth_date = _extract_iso_date(fm.get("updated"))
        if not synth_date:
            synth_date = _extract_iso_date(fm.get("created"))
        if not synth_date:
            continue

        raw_refs: list[str] = list(data.get("outbound") or ()) + list(data.get("outbound_md") or ())
        sources = fm.get("sources")
        if isinstance(sources, list):
            for item in sources:
                if isinstance(item, dict):
                    res = item.get("resource")
                    if isinstance(res, str) and res.strip():
                        raw_refs.append(res.strip())
                elif isinstance(item, str) and item.strip():
                    raw_refs.append(item.strip())

        newer_deps: dict[str, str] = {}
        for ref in raw_refs:
            dep_rel = _resolve_dep_path(ref, rel_path, name_to_rel, graph)
            if not dep_rel or dep_rel == rel_path:
                continue
            dep_fm = (graph.get(dep_rel) or {}).get("frontmatter")
            if not isinstance(dep_fm, dict):
                continue
            dep_upd = _extract_iso_date(dep_fm.get("updated"))
            if dep_upd and dep_upd > synth_date:
                newer_deps[dep_rel] = dep_upd

        if newer_deps:
            stale_syntheses.append(
                {
                    "file": rel_path,
                    "synthesis_date": synth_date,
                    "newer_dependencies": [
                        {"file": dep_rel, "updated": newer_deps[dep_rel]}
                        for dep_rel in sorted(newer_deps)
                    ],
                }
            )
    return stale_syntheses


def _scan_unlinked_mentions(
    all_md_files: dict[str, dict[str, Any]],
    graph: dict[str, dict[str, Any]],
    name_to_rel: dict[str, str],
    scan_meta: dict[str, tuple[int, str, Any, str, str, int]],
) -> list[dict[str, Any]]:
    """Scan living wiki/ prose for plain-text mentions of linkable entities/concepts/patterns."""
    term_map: dict[str, tuple[str, str]] = {}
    for rel_path in sorted(all_md_files):
        if (
            not rel_path.startswith(_LINKABLE_WIKI_PREFIXES)
            or not rel_path.endswith(".md")
            or Path(rel_path).name.lower() in RESERVED_BUNDLE_FILENAMES
        ):
            continue
        candidates: list[str] = [all_md_files[rel_path]["base_name"]]
        fm = (graph.get(rel_path) or {}).get("frontmatter")
        if isinstance(fm, dict):
            title = fm.get("title")
            if isinstance(title, str) and title.strip():
                candidates.append(title.strip())
            aliases = fm.get("aliases")
            if isinstance(aliases, list):
                for alias in aliases:
                    if isinstance(alias, str) and alias.strip():
                        candidates.append(alias.strip())
        for raw_term in candidates:
            term = re.sub(r"\s+", " ", raw_term.strip())
            if len(term) < 4 or term.lower() in _MENTION_STOPWORDS:
                continue
            if any(ch in term for ch in "[]()`\n\r"):
                continue
            term_map.setdefault(term.lower(), (term, rel_path))

    if not term_map:
        return []

    compiled_terms = [
        (
            term,
            target_rel,
            re.compile(
                rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])",
                re.IGNORECASE,
            ),
        )
        for _k, (term, target_rel) in sorted(
            term_map.items(),
            key=lambda kv: (-len(kv[1][0]), kv[1][0].lower(), kv[1][1]),
        )
    ]

    mentions: list[dict[str, Any]] = []
    for rel_path in sorted(all_md_files):
        if (
            not rel_path.startswith("wiki/")
            or not rel_path.endswith(".md")
            or Path(rel_path).name.lower() in RESERVED_BUNDLE_FILENAMES
            or _is_protected_from_lint_fix(rel_path)
        ):
            continue
        meta = scan_meta.get(rel_path)
        if meta is None:
            continue
        fm_line_offset, masked_body, restore_body, open_ch, close_ch, digit_base = meta
        digit_lo = re.escape(chr(digit_base))
        digit_hi = re.escape(chr(digit_base + 15))
        ph_re = re.compile(
            rf"{re.escape(open_ch)}([{digit_lo}-{digit_hi}]+){re.escape(close_ch)}"
        )

        data = graph[rel_path]
        resolved_outbound: set[str] = set()
        for tgt in data["outbound"]:
            resolved = _resolve_dep_path(tgt, rel_path, name_to_rel, graph)
            if resolved:
                resolved_outbound.add(resolved)
        for href in data["outbound_md"]:
            resolved = _resolve_dep_path(href, rel_path, name_to_rel, graph)
            if resolved:
                resolved_outbound.add(resolved)

        extra_newlines = 0
        for b_idx, masked_line in enumerate(masked_body.splitlines(), start=1):
            actual_line = fm_line_offset + extra_newlines + b_idx
            for ph_m in ph_re.finditer(masked_line):
                ph_str = ph_m.group(0)
                extra_newlines += max(
                    0, restore_body(ph_str).count("\n") - ph_str.count("\n")
                )

            if not masked_line.strip() or _HEADING_RE.match(masked_line):
                continue

            # Replace existing wikilinks, markdown links, PUA sentinels, and URLs with spaces
            line_for_scan = _WIKILINK_RE.sub(
                lambda m: " " * len(m.group(0)), masked_line
            )
            line_for_scan = _INLINE_MD_LINK_MASK_RE.sub(
                lambda m: " " * len(m.group(0)), line_for_scan
            )
            line_for_scan = ph_re.sub(
                lambda m: " " * len(m.group(0)), line_for_scan
            )
            line_for_scan = _URL_MASK_RE.sub(
                lambda m: " " * len(m.group(0)), line_for_scan
            )
            if not line_for_scan.strip():
                continue

            occupied_spans: list[tuple[int, int]] = []
            seen_targets_on_line: set[str] = set()
            for _term, target_rel, pattern in compiled_terms:
                if target_rel == rel_path or target_rel in resolved_outbound:
                    continue
                if target_rel in seen_targets_on_line:
                    continue
                for m in pattern.finditer(line_for_scan):
                    s, e = m.span()
                    if any(not (e <= os_s or s >= os_e) for os_s, os_e in occupied_spans):
                        continue
                    occupied_spans.append((s, e))
                    seen_targets_on_line.add(target_rel)
                    mentions.append(
                        {
                            "file": rel_path,
                            "target": target_rel,
                            "matched_term": m.group(0),
                            "line": actual_line,
                        }
                    )
                    break

    mentions.sort(key=lambda item: (item["file"], item["line"], item["target"]))
    return mentions


def _compact_norm(value: str) -> str:
    """Normalize a note stem, title, or alias for collision detection."""
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _semantic_tokens(value: str) -> set[str]:
    """Extract normalized multi-character tokens for similarity comparison."""
    return {
        tok
        for tok in re.split(r"[^a-z0-9]+", (value or "").lower())
        if len(tok) >= 2 and tok not in _MENTION_STOPWORDS
    }


def generate_dedup_manifest(vault_root: Path, out_path: Path | str) -> dict[str, Any]:
    """Read-only scan for duplicate entity/concept/pattern notes; writes review manifest JSON."""
    raw_vault = Path(vault_root)
    if not raw_vault.exists() or not raw_vault.is_dir():
        return {"success": False, "error": f"Vault directory not found: {raw_vault}"}
    v_root = raw_vault.resolve()
    wiki_dir = v_root / "wiki"
    if wiki_dir.is_symlink() or not wiki_dir.is_dir():
        return {"success": False, "error": f"Vault wiki directory not found at {wiki_dir}"}

    dest = Path(out_path)
    if dest.is_symlink():
        return {"success": False, "error": f"Refusing symlink manifest path: {dest}"}
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.parent.is_symlink():
        return {"success": False, "error": f"Refusing symlink manifest parent: {dest.parent}"}

    # Compute inbound reference counts so canonical keep_target selection is deterministic
    inbound_counts: Counter[str] = Counter()
    all_notes_for_links: list[Path] = []
    for root, dirs, files in os.walk(v_root, followlinks=False):
        root_p = Path(root)
        dirs[:] = sorted(
            d for d in dirs if d not in IGNORED_DIR_NAMES and not (root_p / d).is_symlink()
        )
        for fname in sorted(files):
            if fname.endswith(".md"):
                fp = root_p / fname
                if not fp.is_symlink():
                    all_notes_for_links.append(fp)

    records: list[dict[str, Any]] = []
    stem_lookup: dict[str, list[str]] = {}
    for prefix_rel in _LINKABLE_WIKI_PREFIXES:
        base_dir = v_root / prefix_rel.rstrip("/")
        if not base_dir.is_dir() or base_dir.is_symlink():
            continue
        for root, dirs, files in os.walk(base_dir, followlinks=False):
            root_p = Path(root)
            dirs[:] = sorted(
                d for d in dirs if d not in IGNORED_DIR_NAMES and not (root_p / d).is_symlink()
            )
            for fname in sorted(files):
                if not fname.endswith(".md") or fname.lower() in RESERVED_BUNDLE_FILENAMES:
                    continue
                fp = root_p / fname
                if fp.is_symlink():
                    continue
                rel = fp.relative_to(v_root).as_posix()
                if _is_protected_from_lint_fix(rel):
                    continue
                raw_bytes = fp.read_bytes()
                sha256 = hashlib.sha256(raw_bytes).hexdigest()
                text = raw_bytes.decode("utf-8", errors="replace")
                _prefix, yaml_text, raw_body = okf.split_frontmatter(text)
                body = raw_body if yaml_text is not None else text
                fm = okf.parse_frontmatter(yaml_text, strict=False) if yaml_text else {}
                title = str(fm.get("title") or "").strip() if isinstance(fm, dict) else ""
                aliases = (
                    [str(a).strip() for a in (fm.get("aliases") or []) if isinstance(a, str) and str(a).strip()]
                    if isinstance(fm, dict) and isinstance(fm.get("aliases"), list)
                    else []
                )
                masked_body, _restore, _unclosed = _mask_markdown_code(body)
                headings = [m.group(1).strip() for m in _MD_HEADING_12_RE.finditer(masked_body)]
                primary_keys = {
                    k for k in (_compact_norm(fp.stem), _compact_norm(title)) if k
                }
                alias_keys = {_compact_norm(a) for a in aliases if _compact_norm(a)}
                sem_tokens = _semantic_tokens(" ".join([title or fp.stem, *aliases, *headings]))
                records.append(
                    {
                        "rel": rel,
                        "stem": fp.stem,
                        "sha256": sha256,
                        "bytes_len": len(raw_bytes),
                        "primary_keys": primary_keys,
                        "alias_keys": alias_keys,
                        "sem_tokens": sem_tokens,
                    }
                )
                stem_lookup.setdefault(fp.stem.lower(), []).append(rel)

    record_rels = {r["rel"] for r in records}
    for note_fp in all_notes_for_links:
        note_rel = note_fp.relative_to(v_root).as_posix()
        txt, ok_utf8 = _read_text_preserve_eol(note_fp)
        if not ok_utf8:
            continue
        for m in _WIKILINK_RE.finditer(txt):
            tgt = re.split(r"\\?\|", m.group(1).strip())[0].split("#", 1)[0].strip()
            tgt_clean = tgt.removesuffix(".md").lower()
            matched_rel: str | None = None
            cand_paths = [
                f"{tgt_clean}.md",
                f"wiki/{tgt_clean}.md",
            ]
            for cp in cand_paths:
                for rec_rel in record_rels:
                    if rec_rel.lower() == cp:
                        matched_rel = rec_rel
                        break
                if matched_rel:
                    break
            if not matched_rel and len(stem_lookup.get(tgt_clean.split("/")[-1], [])) == 1:
                matched_rel = stem_lookup[tgt_clean.split("/")[-1]][0]
            if matched_rel and matched_rel != note_rel:
                inbound_counts[matched_rel] += 1

    records.sort(key=lambda r: r["rel"])
    raw_proposals: list[dict[str, Any]] = []
    for i in range(len(records)):
        rec_a = records[i]
        for j in range(i + 1, len(records)):
            rec_b = records[j]
            reason = ""
            similarity = 0.0
            if rec_a["primary_keys"] & rec_b["primary_keys"]:
                reason = "normalized_stem_or_title_collision"
                similarity = 1.0
            elif (
                (rec_a["alias_keys"] & rec_b["alias_keys"])
                or (rec_a["alias_keys"] & rec_b["primary_keys"])
                or (rec_b["alias_keys"] & rec_a["primary_keys"])
            ):
                reason = "shared_alias"
                similarity = 1.0
            elif len(rec_a["sem_tokens"]) >= 2 and len(rec_b["sem_tokens"]) >= 2:
                union = rec_a["sem_tokens"] | rec_b["sem_tokens"]
                if union:
                    jaccard = len(rec_a["sem_tokens"] & rec_b["sem_tokens"]) / len(union)
                    if jaccard >= 0.75:
                        reason = "high_title_heading_similarity"
                        similarity = round(jaccard, 4)
            if not reason:
                continue

            score_a = (-inbound_counts[rec_a["rel"]], -rec_a["bytes_len"], rec_a["rel"])
            score_b = (-inbound_counts[rec_b["rel"]], -rec_b["bytes_len"], rec_b["rel"])
            keep_rec, merge_rec = (rec_a, rec_b) if score_a <= score_b else (rec_b, rec_a)
            raw_proposals.append(
                {
                    "keep_target": keep_rec["rel"],
                    "merge_source": merge_rec["rel"],
                    "reason": reason,
                    "similarity": similarity,
                    "approved": False,
                    "keep_sha256": keep_rec["sha256"],
                    "merge_sha256": merge_rec["sha256"],
                }
            )

    raw_proposals.sort(
        key=lambda p: (-float(p["similarity"]), p["keep_target"], p["merge_source"])
    )
    proposals = [
        {"id": f"dedup-{idx:03d}", **prop}
        for idx, prop in enumerate(raw_proposals, start=1)
    ]
    manifest = {
        "version": "1.0",
        "vault_path": str(v_root),
        "proposals": proposals,
    }
    _atomic_write_text(dest, json.dumps(manifest, indent=2) + "\n")
    return {
        "success": True,
        "vault_path": str(v_root),
        "manifest_path": str(dest),
        "proposal_count": len(proposals),
        "proposals": proposals,
    }


def _validate_dedup_note_rel(v_root: Path, wiki_root: Path, rel_str: Any) -> Path | None:
    """Validate that `rel_str` resolves safely inside writable living `wiki/` with zero symlinks."""
    if not isinstance(rel_str, str) or not rel_str.strip():
        return None
    clean = rel_str.replace("\\", "/").strip()
    rel_p = Path(clean)
    if rel_p.is_absolute() or ".." in rel_p.parts:
        return None
    if _is_protected_from_lint_fix(clean):
        return None
    if rel_p.name.lower() in RESERVED_BUNDLE_FILENAMES or rel_p.suffix.lower() != ".md":
        return None
    cand = v_root / rel_p
    if _has_symlink_component(cand, v_root):
        return None
    try:
        resolved = cand.resolve()
        resolved.relative_to(wiki_root)
    except (OSError, ValueError):
        return None
    if not resolved.is_file():
        return None
    return resolved


def _update_merged_frontmatter(
    keep_content: str,
    keep_stem: str,
    merge_content: str,
    merge_stem: str,
) -> str:
    """Merge tags, aliases, sources, updated date, and non-duplicate body content into keep_content."""
    bom = "\ufeff" if keep_content.startswith("\ufeff") else ""
    text = keep_content[len(bom) :]
    match = okf._FRONTMATTER_RE.match(text)
    merge_prefix, merge_yaml, merge_raw_body = okf.split_frontmatter(merge_content)
    merge_fm = (
        okf.parse_frontmatter(merge_yaml, strict=False) if merge_yaml is not None else {}
    )
    if not isinstance(merge_fm, dict):
        merge_fm = {}
    merge_body = (merge_raw_body if merge_yaml is not None else merge_content).strip()
    merge_title = str(merge_fm.get("title") or merge_stem).strip()

    if match:
        nl = match.group(1)
        yaml_text = match.group(2) if match.group(2) is not None else ""
        close_nl = match.group(3)
        keep_body = match.group(4)
        keep_fm = okf.parse_frontmatter(yaml_text, strict=False)
        if not isinstance(keep_fm, dict):
            keep_fm = {}
    else:
        nl = "\r\n" if "\r\n" in keep_content else "\n"
        yaml_text = f"title: {okf._format_yaml_value(keep_stem)}{nl}type: concept{nl}status: draft"
        close_nl = nl
        keep_body = text
        keep_fm = {"title": keep_stem, "type": "concept", "status": "draft"}

    keep_title = str(keep_fm.get("title") or keep_stem).strip()
    keep_ident_lower = {keep_title.lower(), keep_stem.lower()}

    # Merge aliases
    merged_aliases: list[str] = []
    seen_alias_low: set[str] = set()
    raw_alias_candidates: list[Any] = []
    if isinstance(keep_fm.get("aliases"), list):
        raw_alias_candidates.extend(keep_fm["aliases"])
    if isinstance(merge_fm.get("aliases"), list):
        raw_alias_candidates.extend(merge_fm["aliases"])
    raw_alias_candidates.extend([merge_title, merge_stem])
    for item in raw_alias_candidates:
        if not isinstance(item, str):
            continue
        s = item.strip()
        if not s or s.lower() in keep_ident_lower or s.lower() in seen_alias_low:
            continue
        seen_alias_low.add(s.lower())
        merged_aliases.append(s)

    # Merge tags
    merged_tags: list[str] = []
    seen_tag_low: set[str] = set()
    for fm_obj in (keep_fm, merge_fm):
        raw_tags = fm_obj.get("tags")
        if isinstance(raw_tags, list):
            for t in raw_tags:
                if isinstance(t, str) and t.strip() and t.strip().lower() not in seen_tag_low:
                    seen_tag_low.add(t.strip().lower())
                    merged_tags.append(t.strip())

    # Merge sources preserving existing OKF objects/strings
    merged_sources: list[Any] = []
    seen_sources: set[str] = set()
    for fm_obj in (keep_fm, merge_fm):
        raw_sources = fm_obj.get("sources")
        if isinstance(raw_sources, list):
            for src in raw_sources:
                if isinstance(src, dict):
                    key = f"dict:{src.get('resource') or ''}:{src.get('id') or ''}"
                else:
                    key = f"str:{str(src).strip()}"
                if key in seen_sources or not key.rstrip(":"):
                    continue
                seen_sources.add(key)
                merged_sources.append(src)

    new_yaml = yaml_text
    if merged_aliases or isinstance(keep_fm.get("aliases"), list):
        new_yaml = okf._replace_top_level_key_block(
            new_yaml, "aliases", f"aliases: {okf._format_yaml_value(merged_aliases)}", nl
        )
    if merged_tags:
        new_yaml = okf._replace_top_level_key_block(
            new_yaml, "tags", f"tags: {okf._format_yaml_value(merged_tags)}", nl
        )
    if merged_sources:
        src_lines = ["sources:"]
        for entry in merged_sources:
            if isinstance(entry, dict):
                first_kv = True
                ordered = [k for k in ("id", "resource") if k in entry] + [
                    k for k in entry if k not in ("id", "resource")
                ]
                for k in ordered:
                    pfx = "  - " if first_kv else "    "
                    src_lines.append(f"{pfx}{k}: {okf._format_yaml_value(entry[k])}")
                    first_kv = False
            else:
                src_lines.append(f"  - {okf._format_yaml_value(str(entry))}")
        new_yaml = okf._replace_top_level_key_block(
            new_yaml, "sources", nl.join(src_lines), nl
        )

    today_iso = datetime.date.today().isoformat()
    new_yaml = okf._replace_top_level_key_block(
        new_yaml, "updated", f"updated: {okf._format_yaml_value(today_iso)}", nl
    )

    updated_body = keep_body
    if merge_body and merge_body not in keep_body:
        sep = "" if (not updated_body or updated_body.endswith(("\n\n", "\r\n\r\n"))) else (nl + nl)
        if updated_body and not updated_body.endswith(("\n", "\r\n")):
            sep = nl + nl
        updated_body = (
            f"{updated_body}{sep}## Merged from {merge_title}{nl}{nl}{merge_body}{nl}"
        )

    return f"{bom}---{nl}{new_yaml}{nl}---{close_nl}{updated_body}"


def _rewrite_wikilinks_for_merge(
    note_text: str,
    merge_rel: str,
    merge_stem: str,
    merge_title: str,
    keep_rel: str,
    keep_stem: str,
) -> tuple[str, bool]:
    """Rewrite [[merge_source]] wikilinks to [[keep_stem]] outside frontmatter/code blocks."""
    fm_prefix, yaml_text, raw_body = okf.split_frontmatter(note_text)
    body = raw_body if yaml_text is not None else note_text
    masked_body, restore_body, has_unclosed = _mask_markdown_code(body)
    _o, _c, _b, sentinel_clean = _find_pua_sentinel_base(body)
    if has_unclosed or not sentinel_clean:
        return note_text, False

    merge_aliases_lower = {
        merge_stem.lower(),
        merge_rel.lower(),
        merge_rel.removesuffix(".md").lower(),
    }
    if merge_rel.startswith("wiki/"):
        merge_aliases_lower.add(merge_rel[5:].lower())
        merge_aliases_lower.add(merge_rel[5:].removesuffix(".md").lower())
    if merge_title.strip():
        merge_aliases_lower.add(merge_title.strip().lower())

    changed = False

    def _repl(match_obj: re.Match[str]) -> str:
        nonlocal changed
        inner = match_obj.group(1)
        if "|" in inner:
            left, right = inner.split("|", 1)
            alias_part = f"|{right}"
        else:
            left, alias_part = inner, ""
        if "#" in left:
            tgt, sec = left.split("#", 1)
            sec_part = f"#{sec}"
        else:
            tgt, sec_part = left, ""
        tgt_norm = tgt.strip().removesuffix("\\").strip().lower()
        tgt_norm_no_md = tgt_norm.removesuffix(".md")
        if tgt_norm in merge_aliases_lower or tgt_norm_no_md in merge_aliases_lower:
            changed = True
            if tgt_norm.startswith("wiki/"):
                new_ref = keep_rel.removesuffix(".md")
            elif "/" in tgt_norm and keep_rel.startswith("wiki/"):
                new_ref = keep_rel[5:].removesuffix(".md")
            else:
                new_ref = keep_stem
            return f"[[{new_ref}{sec_part}{alias_part}]]"
        return match_obj.group(0)

    rewritten_masked = _WIKILINK_RE.sub(_repl, masked_body)
    if not changed:
        return note_text, False
    rebuilt_body = restore_body(rewritten_masked)
    updated_text = f"{fm_prefix}{rebuilt_body}" if yaml_text is not None else rebuilt_body
    return updated_text, updated_text != note_text


def apply_dedup_manifest(vault_root: Path, manifest_path: Path | str) -> dict[str, Any]:
    """Apply ONLY approved proposals in a dedup manifest using strict SHA-256 CAS checks."""
    raw_vault = Path(vault_root)
    if not raw_vault.exists() or not raw_vault.is_dir():
        return {"success": False, "error": f"Vault directory not found: {raw_vault}"}
    v_root = raw_vault.resolve()
    wiki_dir = v_root / "wiki"
    if wiki_dir.is_symlink() or not wiki_dir.is_dir():
        return {"success": False, "error": f"Vault wiki directory not found at {wiki_dir}"}
    wiki_root = wiki_dir.resolve()

    m_path = Path(manifest_path)
    if m_path.is_symlink() or not m_path.is_file():
        return {"success": False, "error": f"Dedup manifest not found: {m_path}"}
    try:
        manifest_obj = json.loads(m_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"success": False, "error": f"Invalid dedup manifest JSON: {exc}"}
    if not isinstance(manifest_obj, dict) or not isinstance(manifest_obj.get("proposals"), list):
        return {"success": False, "error": "Dedup manifest must contain a 'proposals' list"}

    approved_props = [
        p for p in manifest_obj["proposals"] if isinstance(p, dict) and p.get("approved") is True
    ]
    if not approved_props:
        return {
            "success": True,
            "vault_path": str(v_root),
            "applied_count": 0,
            "skipped_count": len(manifest_obj["proposals"]),
            "applied": [],
        }

    # Pre-verify containment, zero symlinks, and SHA-256 CAS on ALL approved proposals first
    seen_merges: set[str] = set()
    keep_rels: set[str] = set()
    verified_ops: list[tuple[dict[str, Any], Path, Path]] = []
    for prop in approved_props:
        keep_rel = str(prop.get("keep_target") or "").strip()
        merge_rel = str(prop.get("merge_source") or "").strip()
        if not keep_rel or not merge_rel or keep_rel == merge_rel:
            return {"success": False, "error": f"Invalid dedup proposal endpoints: {prop}"}
        if merge_rel in seen_merges:
            return {"success": False, "error": f"Duplicate merge_source in manifest: {merge_rel}"}
        seen_merges.add(merge_rel)
        keep_rels.add(keep_rel)

        keep_resolved = _validate_dedup_note_rel(v_root, wiki_root, keep_rel)
        merge_resolved = _validate_dedup_note_rel(v_root, wiki_root, merge_rel)
        if keep_resolved is None or merge_resolved is None:
            return {
                "success": False,
                "error": f"Proposal escapes writable wiki/ or hits symlink/protected path: {keep_rel} <- {merge_rel}",
            }

        exp_keep_sha = str(prop.get("keep_sha256") or "").strip()
        exp_merge_sha = str(prop.get("merge_sha256") or "").strip()
        cur_keep_sha = hashlib.sha256(keep_resolved.read_bytes()).hexdigest()
        cur_merge_sha = hashlib.sha256(merge_resolved.read_bytes()).hexdigest()
        if not exp_keep_sha or cur_keep_sha != exp_keep_sha:
            return {
                "success": False,
                "cas_conflict": True,
                "error": f"SHA-256 CAS conflict on keep_target '{keep_rel}'",
            }
        if not exp_merge_sha or cur_merge_sha != exp_merge_sha:
            return {
                "success": False,
                "cas_conflict": True,
                "error": f"SHA-256 CAS conflict on merge_source '{merge_rel}'",
            }
        verified_ops.append((prop, keep_resolved, merge_resolved))

    if seen_merges & keep_rels:
        return {
            "success": False,
            "error": f"Conflicting chain where note is both keep_target and merge_source: {sorted(seen_merges & keep_rels)}",
        }

    applied: list[dict[str, Any]] = []
    log_entries: list[str] = []
    today_iso = datetime.date.today().isoformat()

    for prop, keep_resolved, merge_resolved in verified_ops:
        keep_rel = str(prop["keep_target"]).strip()
        merge_rel = str(prop["merge_source"]).strip()
        keep_content, keep_utf8 = _read_text_preserve_eol(keep_resolved)
        merge_content, merge_utf8 = _read_text_preserve_eol(merge_resolved)
        if not keep_utf8 or not merge_utf8:
            return {
                "success": False,
                "error": f"Refusing merge on non-UTF-8 note ({keep_rel} / {merge_rel})",
            }

        _, merge_yaml, _ = okf.split_frontmatter(merge_content)
        merge_fm = okf.parse_frontmatter(merge_yaml, strict=False) if merge_yaml else {}
        merge_title = (
            str(merge_fm.get("title") or "").strip()
            if isinstance(merge_fm, dict)
            else ""
        )

        merged_text = _update_merged_frontmatter(
            keep_content,
            keep_resolved.stem,
            merge_content,
            merge_resolved.stem,
        )
        _atomic_write_text(keep_resolved, merged_text)

        rewritten_files: list[str] = []
        # Rewrite [[merge_source]] across living wiki/ notes and root index.md (never raw/, wiki/sources/, log.md, SKILL.md)
        candidate_files: list[Path] = []
        for root, dirs, files in os.walk(wiki_root, followlinks=False):
            root_p = Path(root)
            dirs[:] = sorted(
                d for d in dirs if d not in IGNORED_DIR_NAMES and not (root_p / d).is_symlink()
            )
            for fname in sorted(files):
                if fname.endswith(".md"):
                    fp = root_p / fname
                    if not fp.is_symlink():
                        candidate_files.append(fp)
        root_index = v_root / "index.md"
        if root_index.is_file() and not root_index.is_symlink():
            candidate_files.append(root_index)

        for target_fp in candidate_files:
            rel_t = target_fp.relative_to(v_root).as_posix()
            if target_fp == merge_resolved:
                continue
            if rel_t != "index.md" and (
                _is_protected_from_lint_fix(rel_t)
                or Path(rel_t).name.lower() in RESERVED_BUNDLE_FILENAMES
            ):
                continue
            orig_t, ok_u8 = _read_text_preserve_eol(target_fp)
            if not ok_u8:
                continue
            new_t, did_rewrite = _rewrite_wikilinks_for_merge(
                orig_t,
                merge_rel,
                merge_resolved.stem,
                merge_title,
                keep_rel,
                keep_resolved.stem,
            )
            if did_rewrite:
                _atomic_write_text(target_fp, new_t)
                rewritten_files.append(rel_t)

        merge_resolved.unlink()
        applied.append(
            {
                "id": prop.get("id", ""),
                "keep_target": keep_rel,
                "merge_source": merge_rel,
                "rewritten_files": rewritten_files,
            }
        )
        log_entries.append(
            f"## [{today_iso}] dedup | Merged [[{merge_resolved.stem}]] into [[{keep_resolved.stem}]]\n"
            f"- Removed `{merge_rel}` into `{keep_rel}` and updated {len(rewritten_files)} referencing file(s).\n"
        )

    log_path = v_root / "log.md"
    if not log_path.is_symlink():
        nl = "\n"
        if log_path.is_file():
            existing_log, _ = _read_text_preserve_eol(log_path)
            if "\r\n" in existing_log:
                nl = "\r\n"
        else:
            existing_log = "# Audit Log\n\n"
        entries_block = nl.join(log_entries).replace("\n", nl)
        lines = existing_log.splitlines(keepends=True)
        if lines and lines[0].lstrip().startswith("# "):
            idx = 1
            while idx < len(lines) and not lines[idx].strip():
                idx += 1
            new_log = "".join(lines[:idx]) + entries_block + nl + "".join(lines[idx:])
        else:
            new_log = f"# Audit Log{nl}{nl}{entries_block}{nl}{existing_log}"
        _atomic_write_text(log_path, new_log)

    return {
        "success": True,
        "vault_path": str(v_root),
        "applied_count": len(applied),
        "skipped_count": len(manifest_obj["proposals"]) - len(approved_props),
        "applied": applied,
    }


_LEGACY_LOG_H2_RE = re.compile(r"^##\s+\[(\d{4}-\d{2}-\d{2})\]\s*(.*)$")
_V03_LOG_H2_RE = re.compile(r"^##\s+(\d{4}-\d{2}-\d{2})\s*$")
_GENERIC_H2_RE = re.compile(r"^##\s+(.+?)\s*$")
_URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def _upgrade_bare_bundle_path(raw_val: Any, vault_root: Path, file_path: Path) -> str | None:
    """Prefix bare v0.2 bundle-root paths with '/' when resolving under OKF v0.3 §6.2."""
    if not isinstance(raw_val, str):
        return None
    val = raw_val.strip()
    if (
        not val
        or val.startswith(("/", "//", "[[", "#"))
        or _URI_SCHEME_RE.match(val)
        or any(ch in val for ch in ("\r", "\n", "\t"))
    ):
        return None
    clean = val.split("#", 1)[0].split("?", 1)[0]
    if not clean:
        return None
    rel_candidate = Path(os.path.normpath(str(file_path.parent / clean)))
    try:
        rel_candidate.resolve().relative_to(vault_root)
        if rel_candidate.exists():
            return None
    except (OSError, ValueError):
        pass
    root_candidate = Path(os.path.normpath(str(vault_root / clean)))
    try:
        root_candidate.resolve().relative_to(vault_root)
        if root_candidate.exists():
            return f"/{val}"
    except (OSError, ValueError):
        pass
    return None


def _render_yaml_mapping_list_block(
    key: str,
    items: list[dict[str, Any]],
    preferred_order: tuple[str, ...],
    nl: str,
) -> str:
    """Format a top-level YAML list of mappings cleanly."""
    lines = [f"{key}:"]
    for entry in items:
        first_kv = True
        ordered: list[str] = [k for k in preferred_order if k in entry]
        for k in entry:
            if k not in ordered:
                ordered.append(k)
        for k in ordered:
            prefix = "  - " if first_kv else "    "
            lines.append(f"{prefix}{k}: {okf._format_yaml_value(entry[k])}")
            first_kv = False
    return nl.join(lines)


def _render_yaml_mapping_block(
    key: str,
    mapping: dict[str, Any],
    preferred_order: tuple[str, ...],
    nl: str,
) -> str:
    """Format a top-level YAML mapping block cleanly."""
    lines = [f"{key}:"]
    ordered: list[str] = [k for k in preferred_order if k in mapping]
    for k in mapping:
        if k not in ordered:
            ordered.append(k)
    for k in ordered:
        lines.append(f"  {k}: {okf._format_yaml_value(mapping[k])}")
    return nl.join(lines)


def _migrate_log_content_to_v03(content: str) -> tuple[str, bool]:
    """Convert a v0.2 log.md (frontmatter and/or `## [YYYY-MM-DD] op | title`) to OKF v0.3 §9.

    Idempotent: returns `(content, False)` if already frontmatter-free with strictly
    newest-first `## YYYY-MM-DD` headings.
    """
    bom = "\ufeff" if content.startswith("\ufeff") else ""
    text = content[len(bom) :]
    nl = "\r\n" if "\r\n" in text else "\n"
    _fm_prefix, yaml_text, body = okf.split_frontmatter(text)
    has_fm = yaml_text is not None
    raw_body = body if has_fm else text

    # Check if already clean OKF v0.3 log.md (no frontmatter, strictly ## YYYY-MM-DD newest-first)
    if not has_fm:
        masked_check, _restore, _unclosed = _mask_markdown_code(raw_body)
        all_v03 = True
        dates_seen: list[str] = []
        for raw_ln in masked_check.splitlines():
            if raw_ln.startswith("## "):
                m_v03 = _V03_LOG_H2_RE.match(raw_ln)
                if not m_v03:
                    all_v03 = False
                    break
                d_str = m_v03.group(1)
                try:
                    datetime.date.fromisoformat(d_str)
                except ValueError:
                    all_v03 = False
                    break
                dates_seen.append(d_str)
        if all_v03 and all(a >= b for a, b in zip(dates_seen, dates_seen[1:])):
            return content, False

    lines = raw_body.splitlines()
    preamble_lines: list[str] = []
    entries_by_date: dict[str, list[str]] = {}
    current_date: str | None = None
    in_fence: str | None = None
    seen_first_h2 = False
    fallback_date = datetime.date.today().isoformat()

    for line in lines:
        stripped = line.lstrip()
        if in_fence is None and stripped.startswith(("```", "~~~")):
            in_fence = stripped[:3]
        elif in_fence is not None:
            if stripped.startswith(in_fence):
                in_fence = None
            if seen_first_h2 and current_date is not None:
                entries_by_date[current_date].append(line)
            else:
                preamble_lines.append(line)
            continue

        if in_fence is None and line.startswith("## "):
            seen_first_h2 = True
            m_v03 = _V03_LOG_H2_RE.match(line)
            m_leg = _LEGACY_LOG_H2_RE.match(line)
            if m_v03:
                d_str = m_v03.group(1)
                current_date = d_str
                entries_by_date.setdefault(current_date, [])
            elif m_leg:
                d_str = m_leg.group(1)
                rest = m_leg.group(2).strip()
                current_date = d_str
                bucket = entries_by_date.setdefault(current_date, [])
                if rest:
                    if " | " in rest:
                        op_part, title_part = rest.split(" | ", 1)
                        bucket.append(f"- **{op_part.strip()}** | {title_part.strip()}")
                    else:
                        bucket.append(f"- {rest}")
            else:
                m_gen = _GENERIC_H2_RE.match(line)
                heading_txt = m_gen.group(1).strip() if m_gen else line[3:].strip()
                current_date = current_date or fallback_date
                entries_by_date.setdefault(current_date, []).append(f"- {heading_txt}")
            continue

        if not seen_first_h2:
            preamble_lines.append(line)
        elif current_date is not None:
            entries_by_date[current_date].append(line)

    # Trim leading/trailing blank lines on preamble
    while preamble_lines and not preamble_lines[0].strip():
        preamble_lines.pop(0)
    while preamble_lines and not preamble_lines[-1].strip():
        preamble_lines.pop()

    out_chunks: list[str] = []
    if preamble_lines:
        out_chunks.append(nl.join(preamble_lines))
    else:
        out_chunks.append("# Audit Log")

    for d_str in sorted(entries_by_date.keys(), reverse=True):
        body_lines = list(entries_by_date[d_str])
        while body_lines and not body_lines[0].strip():
            body_lines.pop(0)
        while body_lines and not body_lines[-1].strip():
            body_lines.pop()
        if body_lines:
            out_chunks.append(f"## {d_str}{nl}{nl}" + nl.join(body_lines))
        else:
            out_chunks.append(f"## {d_str}")

    new_text = bom + f"{nl}{nl}".join(out_chunks) + nl
    return (new_text, new_text != content)


def _rename_top_level_yaml_key(yaml_text: str, old_key: str, new_key: str, nl: str) -> str:
    """Rename a top-level YAML key `old_key:` to `new_key:` while preserving its value block."""
    pattern = re.compile(rf"^{re.escape(old_key)}:(.*)$")
    lines = yaml_text.splitlines()
    changed = False
    out_lines: list[str] = []
    for line in lines:
        if not line.startswith((" ", "\t")):
            m = pattern.match(line)
            if m:
                out_lines.append(f"{new_key}:{m.group(1)}")
                changed = True
                continue
        out_lines.append(line)
    return nl.join(out_lines) if changed else yaml_text


def _encode_md_link_path(rel_posix_path: str) -> str:
    """Percent-encode a POSIX relative path for portable OKF v0.3 / CommonMark links."""
    return urllib.parse.quote(rel_posix_path.replace("\\", "/"), safe="/-._~")


def _is_protected_from_portable_links(rel_path: str) -> bool:
    """Return True if `rel_path` must not be modified by `--portable-links` conversion."""
    rel_norm = rel_path.replace("\\", "/").strip("/")
    parts = [p.lower() for p in Path(rel_norm).parts]
    if not parts:
        return True
    if parts[-1] in _PORTABLE_LINK_PROTECTED_FILENAMES:
        return True
    if any(p in _PROTECTED_LINT_FIX_DIRS or p.startswith(".") for p in parts[:-1]):
        return True
    return False


_SUBDIR_TITLES: dict[str, str] = {
    "sources": "Source Summaries",
    "entities": "Entities",
    "concepts": "Core Concepts",
    "patterns": "Architectural Patterns",
    "synthesis": "Synthesis",
}


def _ensure_wiki_subindexes(vault_root: Path) -> list[str]:
    """Ensure frontmatter-free OKF v0.3 §8 `wiki/index.md` and `wiki/<subdir>/index.md` exist.

    Idempotent: creates missing subdirectory indexes only; never overwrites existing ones.
    """
    v_root = Path(vault_root).resolve()
    wiki_root = v_root / "wiki"
    if not wiki_root.is_dir() or wiki_root.is_symlink():
        return []

    created: list[str] = []
    subdir_entries: list[tuple[str, str, int]] = []

    for child in sorted(wiki_root.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir() or child.is_symlink():
            continue
        if child.name in IGNORED_DIR_NAMES or child.name.startswith("."):
            continue
        notes = sorted(
            (
                p
                for p in child.iterdir()
                if p.is_file()
                and not p.is_symlink()
                and p.name.endswith(".md")
                and p.name.lower() not in RESERVED_BUNDLE_FILENAMES
            ),
            key=lambda p: p.name.lower(),
        )
        if not notes:
            continue

        heading = _SUBDIR_TITLES.get(
            child.name.lower(), child.name.replace("-", " ").replace("_", " ").title()
        )
        subdir_entries.append((child.name, heading, len(notes)))
        sub_index = child / "index.md"
        if sub_index.exists() or sub_index.is_symlink():
            continue

        lines = [
            f"# {heading}",
            "",
            f"OKF v0.3 subdirectory index for `wiki/{child.name}/` (see [Master Index](../../index.md) and [Wiki Index](../index.md)).",
            "",
        ]
        for note_path in notes:
            txt, ok_u8 = _read_text_preserve_eol(note_path)
            title = note_path.stem
            desc = ""
            if ok_u8:
                doc = okf.parse_okf_document(txt, strict=False)
                fm = doc.get("frontmatter") or {}
                if isinstance(fm, dict):
                    raw_t = str(fm.get("title") or "").strip()
                    if raw_t:
                        title = raw_t
                    desc = str(fm.get("description") or "").strip()
            href = _encode_md_link_path(note_path.name)
            if desc:
                lines.append(f"- [{title}]({href}): {desc}")
            else:
                lines.append(f"- [{title}]({href})")
        _atomic_write_text(sub_index, "\n".join(lines) + "\n")
        created.append(sub_index.relative_to(v_root).as_posix())

    wiki_index = wiki_root / "index.md"
    if not wiki_index.exists() and not wiki_index.is_symlink():
        top_notes = sorted(
            (
                p
                for p in wiki_root.iterdir()
                if p.is_file()
                and not p.is_symlink()
                and p.name.endswith(".md")
                and p.name.lower() not in RESERVED_BUNDLE_FILENAMES
            ),
            key=lambda p: p.name.lower(),
        )
        lines = [
            "# Wiki Index",
            "",
            "Compiled knowledge directory for this OKF v0.3 bundle (see [Master Index](../index.md)).",
            "",
        ]
        if subdir_entries:
            lines.append("## Sections")
            lines.append("")
            for dir_name, heading, count in subdir_entries:
                plural = "note" if count == 1 else "notes"
                lines.append(
                    f"- [{heading}]({_encode_md_link_path(dir_name)}/index.md): {count} {plural} in `wiki/{dir_name}/`."
                )
            lines.append("")
        if top_notes:
            lines.append("## Ledgers & Notes")
            lines.append("")
            for note_path in top_notes:
                txt, ok_u8 = _read_text_preserve_eol(note_path)
                title = note_path.stem
                desc = ""
                if ok_u8:
                    doc = okf.parse_okf_document(txt, strict=False)
                    fm = doc.get("frontmatter") or {}
                    if isinstance(fm, dict):
                        raw_t = str(fm.get("title") or "").strip()
                        if raw_t:
                            title = raw_t
                        desc = str(fm.get("description") or "").strip()
                href = _encode_md_link_path(note_path.name)
                if desc:
                    lines.append(f"- [{title}]({href}): {desc}")
                else:
                    lines.append(f"- [{title}]({href})")
            lines.append("")
        _atomic_write_text(wiki_index, "\n".join(lines).rstrip() + "\n")
        created.append("wiki/index.md")

    return created


def convert_wikilinks_to_markdown_links(vault_root: Path) -> dict[str, Any]:
    """Deterministically rewrite resolved Obsidian `[[wikilinks]]` to OKF v0.3 relative Markdown links.

    - Converts resolved `[[Target]]` / `[[Target|Alias]]` in masked Markdown prose (skipping code
      fences, inline code, HTML comments, `![[embeds]]`, unresolved targets, `raw/`, `archive/`,
      `GEMINI.md`, and `log.md`) to RFC 3986 `%20`-encoded relative Markdown links
      `[Label](relative/path.md)`.
    - Converts resolved `[[Target]]` values inside `x-kc-*` / legacy epistemic frontmatter lists to
      canonical OKF v0.3 §6.2 bundle-root paths (`"/wiki/.../Target.md"`).
    - Idempotent: returns empty `converted_files` on re-run.
    """
    v_root = Path(vault_root).resolve()
    all_md_files: dict[str, dict[str, Any]] = {}
    raw_assets: dict[str, dict[str, Any]] = {}

    for root, dirs, files in os.walk(v_root, followlinks=False):
        root_path = Path(root)
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in IGNORED_DIR_NAMES and not (root_path / d).is_symlink()
        )
        try:
            rel_dir = root_path.relative_to(v_root)
        except ValueError:
            continue
        if any(part in IGNORED_DIR_NAMES for part in rel_dir.parts):
            continue
        for f in sorted(files):
            full_path = root_path / f
            if full_path.is_symlink():
                continue
            try:
                full_path.resolve().relative_to(v_root)
            except (OSError, ValueError):
                continue
            rel_path = full_path.relative_to(v_root).as_posix()
            entry = {
                "full_path": full_path,
                "base_name": full_path.stem,
                "rel_path": rel_path,
            }
            if f.endswith(".md"):
                all_md_files[rel_path] = entry
            else:
                raw_assets[rel_path] = entry

    name_to_rel: dict[str, str] = {}
    for rel_path, data in raw_assets.items():
        name_to_rel[data["full_path"].name.lower()] = rel_path
        name_to_rel[data["base_name"].lower()] = rel_path
        name_to_rel[rel_path.lower()] = rel_path
        if rel_path.startswith("raw/"):
            name_to_rel[rel_path[4:].lower()] = rel_path

    def _set_md_alias(key: str, target_rel: str) -> None:
        existing = name_to_rel.get(key)
        if (
            existing is None
            or not existing.endswith(".md")
            or target_rel.count("/") < existing.count("/")
        ):
            name_to_rel[key] = target_rel

    for rel_path, data in all_md_files.items():
        _set_md_alias(data["base_name"].lower(), rel_path)
        name_to_rel[rel_path.lower()] = rel_path
        _set_md_alias(rel_path[:-3].lower(), rel_path)
        if rel_path.startswith("wiki/"):
            _set_md_alias(rel_path[5:].lower(), rel_path)
            _set_md_alias(rel_path[5:-3].lower(), rel_path)
        elif rel_path.startswith("raw/"):
            _set_md_alias(rel_path[4:].lower(), rel_path)
            _set_md_alias(rel_path[4:-3].lower(), rel_path)

    graph_lookup: dict[str, dict[str, Any]] = {}
    for rel_path, data in all_md_files.items():
        txt, ok_u8 = _read_text_preserve_eol(data["full_path"])
        fm_obj: dict[str, Any] | None = None
        if ok_u8:
            doc = okf.parse_okf_document(txt, strict=False)
            if doc.get("has_frontmatter") and isinstance(doc.get("frontmatter"), dict):
                fm_obj = doc["frontmatter"]
        graph_lookup[rel_path] = {"frontmatter": fm_obj}

    converted_files: list[str] = []
    links_converted = 0

    for rel_path in sorted(all_md_files):
        if _is_protected_from_portable_links(rel_path):
            continue
        fp = all_md_files[rel_path]["full_path"]
        orig, ok_u8 = _read_text_preserve_eol(fp)
        if not ok_u8:
            continue

        bom = "\ufeff" if orig.startswith("\ufeff") else ""
        text = orig[len(bom) :]
        fm_match = okf._FRONTMATTER_RE.match(text)

        new_fm_prefix = ""
        body_part = text
        fm_changed = False

        if fm_match:
            fm_nl = fm_match.group(1)
            yaml_text = fm_match.group(2) if fm_match.group(2) is not None else ""
            close_nl = fm_match.group(3)
            body_part = fm_match.group(4)
            updated_yaml = yaml_text
            try:
                fm = okf.parse_frontmatter(yaml_text, strict=True)
            except okf.OKFParseError:
                fm = None

            if isinstance(fm, dict):
                for ep_key in list(fm.keys()):
                    if _epistemic_edge_type_for_key(str(ep_key)) is None:
                        continue
                    raw_val = fm.get(ep_key)
                    if isinstance(raw_val, list):
                        new_items: list[str] = []
                        list_changed = False
                        all_str = True
                        for item in raw_val:
                            if not isinstance(item, str):
                                all_str = False
                                break
                            s_item = item.strip()
                            m_wl = _WIKILINK_RE.fullmatch(s_item)
                            if m_wl:
                                raw_inner = m_wl.group(1).strip()
                                tgt_part = re.split(r"\\?\|", raw_inner)[0].split("#", 1)[0].strip()
                                dst_rel = (
                                    _resolve_target(tgt_part, name_to_rel, graph_lookup)
                                    if tgt_part
                                    else None
                                )
                                if dst_rel:
                                    new_items.append(f"/{dst_rel}")
                                    list_changed = True
                                    links_converted += 1
                                    continue
                            new_items.append(item)
                        if all_str and list_changed:
                            block_lines = [f"{ep_key}:"] + [
                                f'  - "{okf._escape_double_quoted_yaml_str(it)}"'
                                for it in new_items
                            ]
                            updated_yaml = okf._replace_top_level_key_block(
                                updated_yaml, str(ep_key), fm_nl.join(block_lines), fm_nl
                            )
                            fm_changed = True
                    elif isinstance(raw_val, str):
                        m_wl = _WIKILINK_RE.fullmatch(raw_val.strip())
                        if m_wl:
                            raw_inner = m_wl.group(1).strip()
                            tgt_part = re.split(r"\\?\|", raw_inner)[0].split("#", 1)[0].strip()
                            dst_rel = (
                                _resolve_target(tgt_part, name_to_rel, graph_lookup)
                                if tgt_part
                                else None
                            )
                            if dst_rel:
                                replacement_scalar = (
                                    f'{ep_key}: "{okf._escape_double_quoted_yaml_str(f"/{dst_rel}")}"'
                                )
                                updated_yaml = okf._replace_top_level_key_block(
                                    updated_yaml, str(ep_key), replacement_scalar, fm_nl
                                )
                                fm_changed = True
                                links_converted += 1

            new_fm_prefix = f"---{fm_nl}{updated_yaml}{fm_nl}---{close_nl}"

        masked_body, restore_body, _unclosed = _mask_markdown_code(body_part)
        src_dir = posixpath.dirname(rel_path) or "."
        body_links_changed = 0

        def _replace_wl(m: re.Match[str]) -> str:
            nonlocal body_links_changed
            raw_inner = m.group(1).strip()
            parts = re.split(r"\\?\|", raw_inner, maxsplit=1)
            raw_target = parts[0].strip()
            explicit_alias = parts[1].strip() if len(parts) > 1 else ""
            if not raw_target or raw_target.startswith("#"):
                return m.group(0)
            frag = ""
            target_no_frag = raw_target
            if "#" in raw_target:
                target_no_frag, frag = raw_target.split("#", 1)
                target_no_frag = target_no_frag.strip()
                frag = frag.strip()
            if not target_no_frag:
                return m.group(0)
            dst_rel = _resolve_target(target_no_frag, name_to_rel, graph_lookup)
            if not dst_rel:
                return m.group(0)

            rel_href = posixpath.relpath(dst_rel, src_dir)
            encoded_href = _encode_md_link_path(rel_href)
            if frag:
                encoded_href = f"{encoded_href}#{urllib.parse.quote(frag, safe='-._~')}"

            if explicit_alias:
                label = explicit_alias
            else:
                label = target_no_frag.split("/")[-1].removesuffix(".md").strip()
                if not label:
                    label = Path(dst_rel).stem
            safe_label = label.replace("]", r"\]")
            body_links_changed += 1
            return f"[{safe_label}]({encoded_href})"

        converted_masked = _PORTABLE_WIKILINK_RE.sub(_replace_wl, masked_body)
        if body_links_changed > 0 or fm_changed:
            new_body = restore_body(converted_masked) if body_links_changed > 0 else body_part
            new_content = bom + new_fm_prefix + new_body
            if new_content != orig:
                _atomic_write_text(fp, new_content)
                converted_files.append(rel_path)
                links_converted += body_links_changed

    return {
        "converted_files": converted_files,
        "links_converted": links_converted,
    }


def migrate_vault_to_v03(vault_root: Path, portable_links: bool = False) -> dict[str, Any]:
    """Deterministically upgrade a vault to OKF v0.3 conformance (idempotent).

    Performs five safe, deterministic upgrades:
      1. Adds `okf_version: "0.3"` (plus `title` / `description` if missing) to root `index.md`.
      2. Strips YAML frontmatter from `log.md` (and any sub-`index.md`) and normalizes
         `log.md` date headings to newest-first `## YYYY-MM-DD` (OKF v0.3 §8.2, §9).
      3. Prefixes bare v0.2 bundle-root path fields (`sources[].resource`, `superseded_by`,
         `resource`, `computation`, `executor.resource`, `attester.resource`) inside `wiki/`
         with `/` when the target resolves from the vault root (OKF v0.3 §6.2), and namespaces
         bare epistemic frontmatter keys (`corroborates`, `complements`, `extends`,
         `contradicts`, `supersedes`) under `x-kc-*` (OKF v0.3 §4.1).
      4. Ensures frontmatter-free subdirectory `wiki/index.md` and `wiki/<subdir>/index.md`
         files exist for progressive disclosure (OKF v0.3 §8).
      5. When `portable_links=True`, rewrites resolved `[[wikilinks]]` to RFC 3986 `%20`-encoded
         relative Markdown links (`[Label](relative/path.md)`) and `x-kc-*` bundle-root paths.
    """
    v_root = Path(vault_root).resolve()
    migrated_files: list[str] = []
    errors: list[dict[str, str]] = []

    # 1. Root index.md -> okf_version: "0.3", title, description
    root_index = v_root / "index.md"
    if root_index.is_file() and not root_index.is_symlink():
        orig, ok_u8 = _read_text_preserve_eol(root_index)
        if ok_u8:
            bom = "\ufeff" if orig.startswith("\ufeff") else ""
            text = orig[len(bom) :]
            nl = "\r\n" if "\r\n" in text else "\n"
            match = okf._FRONTMATTER_RE.match(text)
            default_title = v_root.name.replace("-", " ").replace("_", " ").strip() or "Knowledge Vault"
            default_desc = "OKF v0.3 Knowledge Compiler vault catalog."
            new_content = orig
            if not match:
                fm_block = (
                    f"---{nl}"
                    f'okf_version: "0.3"{nl}'
                    f"title: {okf._format_yaml_scalar(default_title)}{nl}"
                    f"description: {okf._format_yaml_scalar(default_desc)}{nl}"
                    f"---{nl}{nl}"
                )
                new_content = bom + fm_block + text.lstrip("\r\n")
            else:
                fm_nl = match.group(1)
                yaml_text = match.group(2) if match.group(2) is not None else ""
                close_nl = match.group(3)
                body = match.group(4)
                fm = okf.parse_frontmatter(yaml_text, strict=False)
                updated_yaml = yaml_text
                if str(fm.get("okf_version") or "").strip() != "0.3" or not isinstance(
                    fm.get("okf_version"), str
                ):
                    updated_yaml = okf._replace_top_level_key_block(
                        updated_yaml, "okf_version", 'okf_version: "0.3"', fm_nl
                    )
                if not str(fm.get("title") or "").strip():
                    updated_yaml = okf._replace_top_level_key_block(
                        updated_yaml,
                        "title",
                        f"title: {okf._format_yaml_scalar(default_title)}",
                        fm_nl,
                    )
                if not str(fm.get("description") or "").strip():
                    updated_yaml = okf._replace_top_level_key_block(
                        updated_yaml,
                        "description",
                        f"description: {okf._format_yaml_scalar(default_desc)}",
                        fm_nl,
                    )
                if updated_yaml != yaml_text:
                    new_content = f"{bom}---{fm_nl}{updated_yaml}{fm_nl}---{close_nl}{body}"
            if new_content != orig:
                _atomic_write_text(root_index, new_content)
                migrated_files.append("index.md")

    # 2. Root log.md (and wiki/log.md if present) -> frontmatter-free ## YYYY-MM-DD newest-first
    for log_cand in (v_root / "log.md", v_root / "wiki" / "log.md"):
        if log_cand.is_file() and not log_cand.is_symlink():
            orig, ok_u8 = _read_text_preserve_eol(log_cand)
            if ok_u8:
                new_log, changed = _migrate_log_content_to_v03(orig)
                if changed:
                    _atomic_write_text(log_cand, new_log)
                    migrated_files.append(log_cand.relative_to(v_root).as_posix())

    # 3. Walk wiki/ for sub-index.md frontmatter stripping & bare bundle-root path prefixing
    wiki_root = v_root / "wiki"
    if wiki_root.is_dir() and not wiki_root.is_symlink():
        for root, dirs, files in os.walk(wiki_root, followlinks=False):
            root_p = Path(root)
            dirs[:] = sorted(
                d for d in dirs if d not in IGNORED_DIR_NAMES and not (root_p / d).is_symlink()
            )
            for fname in sorted(files):
                if not fname.endswith(".md"):
                    continue
                fp = root_p / fname
                if fp.is_symlink():
                    continue
                rel_posix = fp.relative_to(v_root).as_posix()
                orig, ok_u8 = _read_text_preserve_eol(fp)
                if not ok_u8:
                    continue

                if fname.lower() == "index.md":
                    bom = "\ufeff" if orig.startswith("\ufeff") else ""
                    text = orig[len(bom) :]
                    _p, y_txt, b_txt = okf.split_frontmatter(text)
                    if y_txt is not None:
                        cleaned_sub = bom + b_txt.lstrip("\r\n")
                        if cleaned_sub != orig:
                            _atomic_write_text(fp, cleaned_sub)
                            migrated_files.append(rel_posix)
                    continue

                if fname.lower() == "log.md" or _is_protected_from_migrate_sources(rel_posix):
                    continue

                bom = "\ufeff" if orig.startswith("\ufeff") else ""
                text = orig[len(bom) :]
                match = okf._FRONTMATTER_RE.match(text)
                if not match:
                    continue
                fm_nl = match.group(1)
                yaml_text = match.group(2) if match.group(2) is not None else ""
                close_nl = match.group(3)
                body = match.group(4)
                try:
                    fm = okf.parse_frontmatter(yaml_text, strict=True)
                except okf.OKFParseError:
                    continue

                updated_yaml = yaml_text
                # Scalar path fields
                for scalar_key in ("superseded_by", "resource", "computation"):
                    upgraded = _upgrade_bare_bundle_path(fm.get(scalar_key), v_root, fp)
                    if upgraded is not None:
                        updated_yaml = okf._replace_top_level_key_block(
                            updated_yaml,
                            scalar_key,
                            f"{scalar_key}: {okf._format_yaml_scalar(upgraded)}",
                            fm_nl,
                        )

                # sources[].resource
                raw_sources = fm.get("sources")
                if isinstance(raw_sources, (list, dict)):
                    src_items = raw_sources if isinstance(raw_sources, list) else [raw_sources]
                    new_sources: list[dict[str, Any]] = []
                    sources_changed = False
                    all_dicts = True
                    for item in src_items:
                        if not isinstance(item, dict):
                            all_dicts = False
                            break
                        entry = dict(item)
                        upgraded_res = _upgrade_bare_bundle_path(entry.get("resource"), v_root, fp)
                        if upgraded_res is not None:
                            entry["resource"] = upgraded_res
                            sources_changed = True
                        new_sources.append(entry)
                    if all_dicts and sources_changed:
                        block = _render_yaml_mapping_list_block(
                            "sources", new_sources, ("id", "resource"), fm_nl
                        )
                        updated_yaml = okf._replace_top_level_key_block(
                            updated_yaml, "sources", block, fm_nl
                        )

                # executor.resource / attester.resource
                for map_key in ("executor", "attester"):
                    m_val = fm.get(map_key)
                    if isinstance(m_val, dict):
                        upgraded_res = _upgrade_bare_bundle_path(m_val.get("resource"), v_root, fp)
                        if upgraded_res is not None:
                            new_map = dict(m_val)
                            new_map["resource"] = upgraded_res
                            block = _render_yaml_mapping_block(
                                map_key, new_map, ("resource", "receipt"), fm_nl
                            )
                            updated_yaml = okf._replace_top_level_key_block(
                                updated_yaml, map_key, block, fm_nl
                            )

                # OKF v0.3 §4.1: namespace bare epistemic keys under `x-kc-*`
                fm_keys_lower = {str(k).lower(): str(k) for k in fm}
                for bare_key in EPISTEMIC_EDGE_CANONICAL_TYPES:
                    x_key = f"{EPISTEMIC_EDGE_X_PREFIX}{bare_key}"
                    if bare_key in fm_keys_lower and x_key not in fm_keys_lower:
                        orig_key_name = fm_keys_lower[bare_key]
                        updated_yaml = _rename_top_level_yaml_key(
                            updated_yaml, orig_key_name, x_key, fm_nl
                        )

                if updated_yaml != yaml_text:
                    new_content = f"{bom}---{fm_nl}{updated_yaml}{fm_nl}---{close_nl}{body}"
                    if new_content != orig:
                        _atomic_write_text(fp, new_content)
                        migrated_files.append(rel_posix)

    # 4. Ensure frontmatter-free wiki/index.md and wiki/<subdir>/index.md (OKF v0.3 §8)
    for sub_idx_rel in _ensure_wiki_subindexes(v_root):
        if sub_idx_rel not in migrated_files:
            migrated_files.append(sub_idx_rel)

    # 5. Optional: convert resolved [[wikilinks]] to OKF v0.3 relative Markdown links
    portable_converted: list[str] = []
    if portable_links:
        p_res = convert_wikilinks_to_markdown_links(v_root)
        portable_converted = list(p_res.get("converted_files", []))
        for conv_rel in portable_converted:
            if conv_rel not in migrated_files:
                migrated_files.append(conv_rel)

    return {
        "migrated_files": migrated_files,
        "portable_links_files": portable_converted,
        "errors": errors,
    }


def run_vault_lint(
    vault_root: Path,
    auto_fix: bool = False,
    as_json: bool = False,
    check_okf_upstream: bool = False,
    strict: bool = False,
    migrate_sources: bool = False,
    migrate_v03: bool = False,
    portable_links: bool = False,
    strict_drift: bool = False,
    include_mentions: bool = False,
) -> dict[str, Any]:
    """Audit a Knowledge Compiler vault against OKF v0.3/v0.2 conformance and graph invariants."""
    raw_vault = Path(vault_root)
    if not raw_vault.exists() or not raw_vault.is_dir():
        err_res: dict[str, Any] = {
            "success": False,
            "error": f"Vault directory not found: {raw_vault}",
            "vault_path": str(raw_vault),
            "is_healthy": False,
        }
        if as_json:
            print(json.dumps(err_res, indent=2))
        else:
            print(f"❌ Error: {err_res['error']}", file=sys.stderr)
        return err_res

    vault_root = raw_vault.resolve()
    wiki_dir = vault_root / "wiki"
    if wiki_dir.is_symlink() or not wiki_dir.is_dir():
        err_res = {
            "success": False,
            "error": f"Vault wiki directory not found at {wiki_dir}",
            "vault_path": str(vault_root),
            "is_healthy": False,
        }
        if as_json:
            print(json.dumps(err_res, indent=2))
        else:
            print(f"❌ Error: {err_res['error']}", file=sys.stderr)
        return err_res

    migrated_v03_files: list[str] = []
    portable_links_files: list[str] = []
    if auto_fix and migrate_v03:
        mig_res = migrate_vault_to_v03(vault_root, portable_links=portable_links)
        migrated_v03_files = list(mig_res.get("migrated_files", []))
        portable_links_files = list(mig_res.get("portable_links_files", []))
    elif auto_fix and portable_links:
        p_res = convert_wikilinks_to_markdown_links(vault_root)
        portable_links_files = list(p_res.get("converted_files", []))

    bundle_okf_version: str | None = None
    root_idx_path = vault_root / "index.md"
    if root_idx_path.is_file() and not root_idx_path.is_symlink():
        try:
            root_idx_txt, root_idx_u8 = _read_text_preserve_eol(root_idx_path)
            if root_idx_u8:
                root_idx_doc = okf.parse_okf_document(root_idx_txt, strict=False)
                if root_idx_doc.get("has_frontmatter"):
                    raw_ver = (root_idx_doc.get("frontmatter") or {}).get("okf_version")
                    if raw_ver is not None and str(raw_ver).strip():
                        bundle_okf_version = str(raw_ver).strip()
        except OSError:
            pass
    bundle_ver_tuple = okf._parse_okf_version_tuple(bundle_okf_version)
    is_v03_bundle = bundle_ver_tuple is not None and bundle_ver_tuple >= (0, 3)

    all_md_files: dict[str, dict[str, Any]] = {}
    raw_assets: dict[str, dict[str, Any]] = {}
    walk_errors: list[OSError] = []

    def _on_walk_error(err: OSError) -> None:
        walk_errors.append(err)

    for root, dirs, files in os.walk(
        vault_root, followlinks=False, onerror=_on_walk_error
    ):
        root_path = Path(root)
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in IGNORED_DIR_NAMES and not (root_path / d).is_symlink()
        )
        try:
            rel_dir = root_path.relative_to(vault_root)
        except ValueError:
            continue
        if any(part in IGNORED_DIR_NAMES for part in rel_dir.parts):
            continue

        for f in sorted(files):
            full_path = root_path / f
            if full_path.is_symlink():
                continue
            try:
                resolved_file = full_path.resolve()
                resolved_file.relative_to(vault_root)
            except (OSError, ValueError):
                continue

            rel_obj = full_path.relative_to(vault_root)
            if any(part in IGNORED_DIR_NAMES for part in rel_obj.parts):
                continue
            rel_path = rel_obj.as_posix()
            base_name = full_path.stem
            entry = {
                "full_path": full_path,
                "base_name": base_name,
                "rel_path": rel_path,
            }
            if f.endswith(".md"):
                all_md_files[rel_path] = entry
            else:
                raw_assets[rel_path] = entry

    if walk_errors:
        err_res = {
            "success": False,
            "error": f"Failed to traverse vault directory: {walk_errors[0]}",
            "vault_path": str(vault_root),
            "is_healthy": False,
        }
        if as_json:
            print(json.dumps(err_res, indent=2))
        else:
            print(f"❌ Error: {err_res['error']}", file=sys.stderr)
        return err_res

    # Build lookup index (populate assets first so .md notes win on stem collisions)
    name_to_rel: dict[str, str] = {}
    for rel_path, data in raw_assets.items():
        name_to_rel[data["full_path"].name.lower()] = rel_path
        name_to_rel[data["base_name"].lower()] = rel_path
        name_to_rel[rel_path.lower()] = rel_path
        if rel_path.startswith("raw/"):
            name_to_rel[rel_path[4:].lower()] = rel_path

    def _set_md_alias(key: str, target_rel: str) -> None:
        existing = name_to_rel.get(key)
        if (
            existing is None
            or not existing.endswith(".md")
            or target_rel.count("/") < existing.count("/")
        ):
            name_to_rel[key] = target_rel

    for rel_path, data in all_md_files.items():
        _set_md_alias(data["base_name"].lower(), rel_path)
        name_to_rel[rel_path.lower()] = rel_path
        _set_md_alias(rel_path[:-3].lower(), rel_path)
        if rel_path.startswith("wiki/"):
            _set_md_alias(rel_path[5:].lower(), rel_path)
            _set_md_alias(rel_path[5:-3].lower(), rel_path)
        elif rel_path.startswith("raw/"):
            _set_md_alias(rel_path[4:].lower(), rel_path)
            _set_md_alias(rel_path[4:-3].lower(), rel_path)

    graph: dict[str, dict[str, Any]] = {
        k: {
            "outbound": set(),
            "outbound_md": set(),
            "inbound": set(),
            "frontmatter": None,
            "has_fm": False,
        }
        for k in all_md_files
    }

    table_invariant_violations: list[dict[str, str]] = []
    fixed_files: list[str] = list(dict.fromkeys(migrated_v03_files + portable_links_files))
    migrated_sources_files: list[str] = []
    conformance_errors: list[dict[str, str]] = []
    missing_frontmatter: list[str] = []
    legacy_sources_notes: list[str] = []
    dangling_footnotes: list[dict[str, str]] = []
    stale_notes: list[dict[str, str]] = []
    stale_verification_notes: list[str] = []
    workspace_profile_warnings: list[dict[str, str]] = []
    scan_meta: dict[str, tuple[int, str, Any, str, str, int]] = {}
    trust_tier_counts = {
        "unverified": 0,
        "machine-confirmed": 0,
        "human-reviewed": 0,
    }

    for rel_path, data in all_md_files.items():
        try:
            orig_content, valid_utf8 = _read_text_preserve_eol(data["full_path"])
        except OSError as exc:
            err_res = {
                "success": False,
                "error": f"Failed to read vault note '{rel_path}': {exc}",
                "vault_path": str(vault_root),
                "is_healthy": False,
            }
            if as_json:
                print(json.dumps(err_res, indent=2))
            else:
                print(f"❌ Error: {err_res['error']}", file=sys.stderr)
            return err_res
        content = orig_content
        is_wiki_note = rel_path.startswith("wiki/")
        note_filename_lower = Path(rel_path).name.lower()
        is_reserved_wiki = is_wiki_note and note_filename_lower in RESERVED_BUNDLE_FILENAMES

        if not valid_utf8:
            conformance_errors.append(
                {
                    "file": rel_path,
                    "rule": "utf8_encoding",
                    "message": f"Invalid UTF-8 byte sequence in {rel_path}; skipping auto-fix writes.",
                }
            )

        fm_prefix, yaml_text, raw_body = okf.split_frontmatter(content)
        body_to_scan = raw_body if yaml_text is not None else content
        pua_open, pua_close, pua_digit_base, sentinel_clean = _find_pua_sentinel_base(body_to_scan)
        masked_body, restore_body, has_unclosed_fence = _mask_markdown_code(body_to_scan)
        fm_line_offset = fm_prefix.count("\n") if yaml_text is not None else 0

        if has_unclosed_fence:
            workspace_profile_warnings.append(
                {
                    "file": rel_path,
                    "rule": "unclosed_code_fence",
                    "message": f"Unclosed code fence detected in {rel_path}; skipping auto-fix writes.",
                }
            )
        if not sentinel_clean:
            workspace_profile_warnings.append(
                {
                    "file": rel_path,
                    "rule": "sentinel_collision",
                    "message": f"No collision-free sentinel alphabet for {rel_path}; skipping body auto-fix writes.",
                }
            )

        is_protected_fix = _is_protected_from_lint_fix(rel_path)
        can_fix_body = valid_utf8 and not has_unclosed_fence and not is_protected_fix and sentinel_clean
        can_migrate_sources = (
            valid_utf8
            and not has_unclosed_fence
            and not _is_protected_from_migrate_sources(rel_path)
        )
        can_write_note = can_fix_body or (migrate_sources and can_migrate_sources)

        # 1. Check escaped pipes inside [[...|...]] outside code blocks/spans
        escaped_matches = _TABLE_ESCAPED_PIPE_RE.findall(masked_body)
        if escaped_matches and not is_protected_fix:
            for m in escaped_matches:
                fix_snippet = m.replace(r"\|", "|")
                table_invariant_violations.append(
                    {
                        "file": rel_path,
                        "snippet": f"[[{m}]]",
                        "fix": f"[[{fix_snippet}]]",
                    }
                )
            if auto_fix and can_fix_body:
                fixed_masked = _TABLE_ESCAPED_PIPE_RE.sub(
                    lambda m_obj: "[[" + m_obj.group(1).replace(r"\|", "|") + "]]",
                    masked_body,
                )
                repaired_body = restore_body(fixed_masked)
                candidate_content = (
                    f"{fm_prefix}{repaired_body}" if yaml_text is not None else repaired_body
                )
                try:
                    hash_changed = (
                        candidate_content != content
                        and okf.canonical_content_hash(candidate_content)
                        != okf.canonical_content_hash(content)
                    )
                except Exception:
                    hash_changed = candidate_content != content
                if hash_changed:
                    content = candidate_content
                    fm_prefix, yaml_text, raw_body = okf.split_frontmatter(content)
                    body_to_scan = raw_body if yaml_text is not None else content
                    pua_open, pua_close, pua_digit_base, _ = _find_pua_sentinel_base(body_to_scan)
                    masked_body, restore_body, _ = _mask_markdown_code(body_to_scan)
                    fm_line_offset = fm_prefix.count("\n") if yaml_text is not None else 0

        # 2. Opt-in deterministic migration of legacy string `sources:` inside wiki/
        if (
            auto_fix
            and migrate_sources
            and is_wiki_note
            and not is_reserved_wiki
            and can_migrate_sources
        ):
            try:
                migrated_content, did_migrate = okf.migrate_legacy_sources_in_frontmatter(
                    content
                )
                if did_migrate and (
                    okf.canonical_content_hash(migrated_content)
                    != okf.canonical_content_hash(content)
                ):
                    content = migrated_content
                    migrated_sources_files.append(rel_path)
            except Exception as exc:
                conformance_errors.append(
                    {
                        "file": rel_path,
                        "rule": "okf_migrate_sources",
                        "message": f"Failed to migrate sources in {rel_path}: {exc}",
                    }
                )

        # Write atomically once if substantive content changed (never churn updated: on no-op)
        if auto_fix and can_write_note and content != orig_content:
            try:
                write_needed = (
                    okf.canonical_content_hash(content)
                    != okf.canonical_content_hash(orig_content)
                )
            except Exception:
                write_needed = content != orig_content
            if write_needed:
                _atomic_write_text(data["full_path"], content)
                if rel_path not in fixed_files:
                    fixed_files.append(rel_path)

        # 3. Validate OKF v0.3/v0.2 Bundle Root (`wiki/`) vs Workspace Profile root files
        val: dict[str, Any] | None = None
        if is_wiki_note and not is_reserved_wiki:
            try:
                val = okf.validate_okf_concept(
                    content,
                    is_reserved=False,
                    bundle_root=vault_root,
                    file_path=data["full_path"],
                    okf_version=bundle_okf_version,
                )
            except Exception as exc:
                val = None
                try:
                    doc_info = okf.parse_okf_document(content, strict=False)
                except Exception:
                    doc_info = {"has_frontmatter": False, "frontmatter": {}, "errors": []}
                if not doc_info["has_frontmatter"]:
                    missing_frontmatter.append(rel_path)
                conformance_errors.append(
                    {
                        "file": rel_path,
                        "rule": "okf_v03",
                        "message": f"Unexpected validation error: {exc}",
                    }
                )
                tier = "unverified"
                trust_tier_counts[tier] = trust_tier_counts.get(tier, 0) + 1
            else:
                if not val["errors"] and val["has_frontmatter"]:
                    doc_info = {
                        "has_frontmatter": True,
                        "frontmatter": val["frontmatter"],
                        "errors": [],
                    }
                else:
                    try:
                        doc_info = okf.parse_okf_document(content, strict=False)
                    except Exception as exc:
                        doc_info = {
                            "has_frontmatter": False,
                            "frontmatter": {},
                            "errors": [f"Unexpected frontmatter parse error: {exc}"],
                        }
        else:
            try:
                doc_info = okf.parse_okf_document(content, strict=False)
            except Exception as exc:
                doc_info = {
                    "has_frontmatter": False,
                    "frontmatter": {},
                    "errors": [f"Unexpected frontmatter parse error: {exc}"],
                }
        fm = doc_info["frontmatter"] if doc_info["has_frontmatter"] else {}
        graph[rel_path]["frontmatter"] = fm if doc_info["has_frontmatter"] else None
        graph[rel_path]["has_fm"] = bool(doc_info["has_frontmatter"])
        scan_meta[rel_path] = (
            fm_line_offset,
            masked_body,
            restore_body,
            pua_open,
            pua_close,
            pua_digit_base,
        )

        if is_wiki_note:
            if is_reserved_wiki:
                if note_filename_lower == "log.md":
                    if yaml_text is not None and is_v03_bundle:
                        fm_issue = {
                            "file": rel_path,
                            "rule": "okf_log_frontmatter",
                            "message": "log.md must not have YAML frontmatter (OKF v0.3 §9); run 'vault-lint --fix --migrate-v03'",
                        }
                        workspace_profile_warnings.append(fm_issue)
                        conformance_errors.append(fm_issue)
                    log_issues = _validate_log_headings(
                        body_to_scan, rel_path, check_date_order=is_v03_bundle
                    )
                    workspace_profile_warnings.extend(log_issues)
                    conformance_errors.extend(
                        i for i in log_issues if i.get("rule") != "okf_log_date_order"
                    )
                elif note_filename_lower == "index.md" and yaml_text is not None and is_v03_bundle:
                    sub_idx_issue = {
                        "file": rel_path,
                        "rule": "okf_subindex_frontmatter",
                        "message": "Subdirectory index.md must not have YAML frontmatter (OKF v0.3 §8.2); run 'vault-lint --fix --migrate-v03'",
                    }
                    workspace_profile_warnings.append(sub_idx_issue)
                    conformance_errors.append(sub_idx_issue)
            else:
                if val is not None:
                    if not val["has_frontmatter"]:
                        missing_frontmatter.append(rel_path)

                    raw_sources = (
                        val["frontmatter"].get("sources")
                        if isinstance(val["frontmatter"], dict)
                        else None
                    )
                    has_source_ids = isinstance(raw_sources, list) and any(
                        isinstance(s, dict) and str(s.get("id") or "").strip()
                        for s in raw_sources
                    )
                    body_defs = {
                        m.group(1).strip() for m in _FOOTNOTE_DEF_RE.finditer(masked_body)
                    }
                    source_ids = (
                        {
                            str(s["id"]).strip()
                            for s in raw_sources
                            if isinstance(s, dict) and str(s.get("id") or "").strip()
                        }
                        if isinstance(raw_sources, list)
                        else set()
                    )
                    valid_fn_targets = source_ids | body_defs
                    seen_dangling: list[str] = []
                    for fn_m in _FOOTNOTE_REF_RE.finditer(masked_body):
                        lbl = fn_m.group(1).strip()
                        if lbl and lbl not in valid_fn_targets and lbl not in seen_dangling:
                            seen_dangling.append(lbl)

                    enforce_footnotes = has_source_ids or bool(body_defs)
                    if enforce_footnotes and seen_dangling:
                        for lbl in seen_dangling:
                            dangling_footnotes.append({"file": rel_path, "label": lbl})
                        conformance_errors.append(
                            {
                                "file": rel_path,
                                "rule": "okf_v03",
                                "message": (
                                    "Unresolved footnote citation(s) in body matching neither "
                                    f"sources[].id nor [^id]: definitions: {', '.join(seen_dangling)}"
                                ),
                            }
                        )

                    for err_msg in val["errors"]:
                        if err_msg.startswith("Unresolved footnote citation(s)"):
                            continue
                        conformance_errors.append(
                            {"file": rel_path, "rule": "okf_v03", "message": err_msg}
                        )

                    if val["legacy_sources"]:
                        legacy_sources_notes.append(rel_path)

                    if val.get("stale_verifications"):
                        stale_verification_notes.append(rel_path)

                    tier = val["trust_tier"]
                    trust_tier_counts[tier] = trust_tier_counts.get(tier, 0) + 1

                    if val["is_stale"]:
                        stale_notes.append(
                            {
                                "file": rel_path,
                                "stale_after": str(val.get("stale_after") or ""),
                            }
                        )
        else:
            # Workspace Profile root files (`index.md`, `log.md`, `GEMINI.md`, etc.)
            if rel_path == "log.md":
                if yaml_text is not None and is_v03_bundle:
                    workspace_profile_warnings.append(
                        {
                            "file": rel_path,
                            "rule": "okf_log_frontmatter",
                            "message": "log.md should not have YAML frontmatter (OKF v0.3 §9); run 'vault-lint --fix --migrate-v03'",
                        }
                    )
                workspace_profile_warnings.extend(
                    _validate_log_headings(
                        body_to_scan, rel_path, check_date_order=is_v03_bundle
                    )
                )

        # 4. Extract outbound [[wikilinks]] and local .md links from masked prose
        for match in _WIKILINK_RE.finditer(masked_body):
            raw_link = match.group(1).strip()
            target = re.split(r"\\?\|", raw_link)[0].strip()
            if target.startswith("#"):
                continue
            if "#" in target:
                target = target.split("#", 1)[0].strip()
            if target:
                graph[rel_path]["outbound"].add(target)

        if isinstance(fm, dict):
            for ep_target in _extract_epistemic_wikilinks(fm):
                graph[rel_path]["outbound"].add(ep_target)

        for md_m in _MD_LINK_RE.finditer(masked_body):
            raw_href = md_m.group(1).strip()
            if (
                not raw_href
                or raw_href.startswith(("#", "//"))
                or _URI_SCHEME_RE.match(raw_href)
            ):
                continue
            href_clean = raw_href.split("#", 1)[0].split("?", 1)[0].strip()
            if not href_clean:
                continue
            href_decoded = urllib.parse.unquote(href_clean).replace("\\", "/")
            if href_decoded.lower().endswith(".md"):
                graph[rel_path]["outbound_md"].add(href_clean)

    # Resolve wikilinks and relative Markdown links; build inbound edges
    exact_path_to_rel: dict[str, str] = {rel.lower(): rel for rel in all_md_files}
    broken_links: list[dict[str, str]] = []
    for src in sorted(graph):
        data = graph[src]
        for target in sorted(data["outbound"]):
            resolved_dst = _resolve_target(target, name_to_rel, graph)
            if resolved_dst:
                if resolved_dst in graph:
                    graph[resolved_dst]["inbound"].add(src)
            else:
                broken_links.append({"source": src, "target": target})

        for md_href in sorted(data["outbound_md"]):
            decoded_href = urllib.parse.unquote(md_href).replace("\\", "/")
            if decoded_href.startswith("/"):
                candidate_rel = posixpath.normpath(decoded_href.lstrip("/"))
            else:
                src_parent = posixpath.dirname(src.replace("\\", "/"))
                joined = (
                    posixpath.join(src_parent, decoded_href)
                    if src_parent
                    else decoded_href
                )
                candidate_rel = posixpath.normpath(joined)
            if not candidate_rel or candidate_rel == "." or candidate_rel.startswith(".."):
                continue
            resolved_md = exact_path_to_rel.get(candidate_rel.lower())
            if resolved_md and resolved_md in graph:
                graph[resolved_md]["inbound"].add(src)
            elif not src.startswith("raw/"):
                broken_links.append({"source": src, "target": decoded_href})

    wanted_pages = _build_wanted_pages(broken_links)

    # Find orphan notes in wiki/ (excluding reserved index.md / log.md)
    orphan_notes: list[str] = []
    for rel_path, data in graph.items():
        if (
            rel_path.startswith("wiki/")
            and rel_path.endswith(".md")
            and Path(rel_path).name.lower() not in RESERVED_BUNDLE_FILENAMES
        ):
            if len(data["inbound"]) == 0:
                orphan_notes.append(rel_path)

    # Check index.md coverage for wiki/ concept notes
    missing_from_index: list[str] = []
    index_file = vault_root / "index.md"
    if index_file.is_file() and not index_file.is_symlink():
        index_content, _idx_utf8 = _read_text_preserve_eol(index_file)
        idx_lower = urllib.parse.unquote(index_content).lower()
        for rel_path in all_md_files:
            if (
                rel_path.startswith("wiki/")
                and rel_path.endswith(".md")
                and Path(rel_path).name.lower() not in RESERVED_BUNDLE_FILENAMES
            ):
                note_base = all_md_files[rel_path]["base_name"]
                rel_no_wiki = rel_path[5:]
                if (
                    note_base.lower() not in idx_lower
                    and f"[[{note_base}" not in index_content
                    and rel_path.lower() not in idx_lower
                    and rel_no_wiki.lower() not in idx_lower
                ):
                    missing_from_index.append(rel_path)

    # Count 5-way typed epistemic edges across wiki notes (both `x-kc-*` and legacy keys)
    epistemic_edge_counts = {
        "CORROBORATES": 0,
        "COMPLEMENTS": 0,
        "EXTENDS": 0,
        "CONTRADICTS": 0,
        "SUPERSEDES": 0,
    }
    for rel_path, data in graph.items():
        if rel_path.startswith("wiki/") and rel_path.endswith(".md") and data["has_fm"]:
            fm = data.get("frontmatter") or {}
            fm_lower = {str(k).lower(): v for k, v in fm.items()}
            seen_ep_note: set[tuple[str, str]] = set()
            for ep_k in EPISTEMIC_EDGE_KEYS:
                edge_type = _epistemic_edge_type_for_key(ep_k)
                if not edge_type:
                    continue
                val = fm_lower.get(ep_k)
                items = (
                    val
                    if isinstance(val, list)
                    else ([val] if isinstance(val, str) and val.strip() else [])
                )
                for item in items:
                    key_tok = str(item).strip().lower()
                    if not key_tok:
                        continue
                    pair = (edge_type, key_tok)
                    if pair not in seen_ep_note:
                        seen_ep_note.add(pair)
                        epistemic_edge_counts[edge_type] += 1

    stale_syntheses = _detect_stale_syntheses(all_md_files, graph, name_to_rel)
    unlinked_mentions = (
        _scan_unlinked_mentions(all_md_files, graph, name_to_rel, scan_meta)
        if include_mentions
        else []
    )

    is_healthy = (
        len(broken_links) == 0
        and len(table_invariant_violations) == 0
        and len(missing_frontmatter) == 0
        and len(conformance_errors) == 0
    )
    has_strict_warnings = bool(
        stale_notes
        or orphan_notes
        or missing_from_index
        or legacy_sources_notes
        or dangling_footnotes
        or workspace_profile_warnings
    )
    strict_passed = is_healthy and (not has_strict_warnings)
    strict_drift_passed = strict_passed and (not stale_syntheses)

    okf_upstream_report = check_upstream_okf_version() if check_okf_upstream else None

    total_wiki_notes = len(
        [
            k
            for k in all_md_files
            if k.startswith("wiki/")
            and Path(k).name.lower() not in RESERVED_BUNDLE_FILENAMES
        ]
    )

    results: dict[str, Any] = {
        "success": True,
        "vault_path": str(vault_root),
        "bundle_root": ".",
        "concepts_dir": "wiki",
        "supported_okf_version": SUPPORTED_OKF_VERSION,
        "bundle_okf_version": bundle_okf_version,
        "total_markdown_files": len(all_md_files),
        "total_wiki_notes": total_wiki_notes,
        "broken_links": broken_links,
        "wanted_pages": wanted_pages,
        "table_invariant_violations": table_invariant_violations,
        "fixed_files": fixed_files,
        "migrated_sources_files": migrated_sources_files,
        "migrated_v03_files": migrated_v03_files,
        "portable_links_files": portable_links_files,
        "orphan_notes": orphan_notes,
        "missing_from_index": missing_from_index,
        "missing_frontmatter": missing_frontmatter,
        "conformance_errors": conformance_errors,
        "legacy_sources_notes": legacy_sources_notes,
        "dangling_footnotes": dangling_footnotes,
        "stale_notes": stale_notes,
        "stale_verification_notes": stale_verification_notes,
        "stale_syntheses": stale_syntheses,
        "unlinked_mentions": unlinked_mentions,
        "workspace_profile_warnings": workspace_profile_warnings,
        "trust_tier_counts": trust_tier_counts,
        "epistemic_edge_counts": epistemic_edge_counts,
        "is_healthy": is_healthy,
        "strict": strict,
        "strict_drift": strict_drift,
        "strict_passed": strict_passed,
        "strict_drift_passed": strict_drift_passed,
    }
    if okf_upstream_report is not None:
        results["okf_upstream"] = okf_upstream_report

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        _print_lint_report(results, auto_fix=auto_fix, strict=strict)

    return results


def _print_lint_report(results: dict[str, Any], *, auto_fix: bool, strict: bool) -> None:
    """Print human-readable OKF v0.3 vault audit report."""
    ep = results["epistemic_edge_counts"]
    tt = results["trust_tier_counts"]
    total_ep = sum(ep.values())

    print("=" * 60)
    print("🔍 OKF v0.3 Knowledge Compiler Vault Audit Report")
    print("=" * 60)
    bver = results.get("bundle_okf_version") or "legacy/0.2"
    broot = results.get("bundle_root", ".")
    cdir = results.get("concepts_dir", "wiki")
    print(
        f"📁 Vault Path: {results['vault_path']} "
        f"(OKF Bundle Root: {broot}, Concepts: {cdir}/, Spec: {bver})"
    )
    print(f"📄 Total Markdown Files: {results['total_markdown_files']}")
    print(f"📚 Total Wiki Concepts: {results['total_wiki_notes']}")
    print(
        f"🛡️ Trust Tiers (OKF §5.3): "
        f"human-reviewed={tt['human-reviewed']}, "
        f"machine-confirmed={tt['machine-confirmed']}, "
        f"unverified={tt['unverified']}"
    )
    print(
        f"🧭 Explicit 5-Way Epistemic Frontmatter Edges: {total_ep} "
        f"(CORROBORATES={ep['CORROBORATES']}, "
        f"COMPLEMENTS={ep['COMPLEMENTS']}, "
        f"EXTENDS={ep['EXTENDS']}, "
        f"CONTRADICTS={ep['CONTRADICTS']}, "
        f"SUPERSEDES={ep['SUPERSEDES']})"
    )
    print("-" * 60)

    if results.get("migrated_v03_files"):
        print(
            f"🚀 Migrated Vault Files to OKF v0.3 ({len(results['migrated_v03_files'])}):"
        )
        for mv in results["migrated_v03_files"]:
            print(f"   • {mv}")

    if results.get("portable_links_files"):
        print(
            f"🔗 Converted Links to Portable OKF Markdown ({len(results['portable_links_files'])}):"
        )
        for plf in results["portable_links_files"]:
            print(f"   • {plf}")

    if results["migrated_sources_files"]:
        print(
            f"🔄 Migrated Legacy String Sources to {{id, resource}} ({len(results['migrated_sources_files'])}):"
        )
        for mf in results["migrated_sources_files"]:
            print(f"   • {mf}")

    if results["strict_passed"]:
        print(
            "✨ 100% HEALTHY! All links resolve, OKF conformance passes, and index is synchronized."
        )
    else:
        if results["conformance_errors"]:
            print(f"❌ OKF v0.3 Conformance Errors ({len(results['conformance_errors'])}):")
            for err in results["conformance_errors"]:
                print(f"   • [{err['file']}] {err['message']}")

        if results["broken_links"]:
            print(f"❌ Broken Links ({len(results['broken_links'])}):")
            for b in results["broken_links"]:
                tgt = b["target"]
                formatted_tgt = tgt if tgt.lower().endswith(".md") else f"[[{tgt}]]"
                print(f"   • [{b['source']}] -> {formatted_tgt}")

        if results["wanted_pages"]:
            print(f"📌 Wanted Pages (Ranked by Inbound Refs, {len(results['wanted_pages'])}):")
            for wp in results["wanted_pages"]:
                srcs_preview = ", ".join(wp["sources"][:5])
                if len(wp["sources"]) > 5:
                    srcs_preview += f", +{len(wp['sources']) - 5} more"
                print(
                    f"   • [[{wp['target']}]] ({wp['inbound_count']} inbound: {srcs_preview})"
                )

        if results["table_invariant_violations"]:
            print(
                f"⚠️ Table Wikilink Pipe Invariant Violations ({len(results['table_invariant_violations'])}):"
            )
            for v in results["table_invariant_violations"]:
                print(f"   • [{v['file']}] {v['snippet']}  (Should be: {v['fix']})")
            if auto_fix and results["fixed_files"]:
                print(f"   ⚡ Automatically fixed in {len(results['fixed_files'])} files!")

        if results["stale_notes"]:
            label = "❌" if strict else "⚠️"
            print(f"{label} Stale Notes (now >= stale_after, {len(results['stale_notes'])}):")
            for sn in results["stale_notes"]:
                print(f"   • {sn['file']} (stale_after: {sn['stale_after']})")

        if results["legacy_sources_notes"]:
            print(
                f"ℹ️ Legacy String `sources:` Notice (use --fix --migrate-sources, {len(results['legacy_sources_notes'])}):"
            )
            for ln in results["legacy_sources_notes"]:
                print(f"   • {ln}")

        if results["dangling_footnotes"]:
            print(f"⚠️ Dangling Footnote Citations ({len(results['dangling_footnotes'])}):")
            for df in results["dangling_footnotes"]:
                print(f"   • [{df['file']}] [^{df['label']}]")

        if results["workspace_profile_warnings"]:
            print(f"⚠️ Workspace Profile Warnings ({len(results['workspace_profile_warnings'])}):")
            for ww in results["workspace_profile_warnings"]:
                print(f"   • [{ww['file']}] {ww['message']}")

        if results["orphan_notes"]:
            print(f"ℹ️ Orphan Notes (0 inbound links, {len(results['orphan_notes'])}):")
            for o in results["orphan_notes"]:
                print(f"   • {o}")

        if results["missing_from_index"]:
            print(f"ℹ️ Notes not mentioned in index.md ({len(results['missing_from_index'])}):")
            for mi in results["missing_from_index"]:
                print(f"   • {mi}")

    if results.get("stale_verification_notes"):
        print(
            f"ℹ️ Stale Verifications (verified.at < generated.at, OKF v0.3 §5.3, {len(results['stale_verification_notes'])}):"
        )
        for sv in results["stale_verification_notes"]:
            print(f"   • {sv}")

    if results.get("stale_syntheses"):
        label = "❌" if results.get("strict_drift") else "⚠️"
        print(f"{label} Synthesis Drift Detected ({len(results['stale_syntheses'])}):")
        for ss in results["stale_syntheses"]:
            deps = ", ".join(
                f"{d['file']} (updated {d['updated']})" for d in ss.get("newer_dependencies", [])
            )
            print(f"   • {ss['file']} (synthesis date {ss['synthesis_date']}): {deps}")

    if results.get("unlinked_mentions"):
        print(f"🔗 Unlinked Plain-Text Mentions ({len(results['unlinked_mentions'])}):")
        for um in results["unlinked_mentions"][:50]:
            print(
                f"   • [{um['file']}:{um['line']}] '{um['matched_term']}' -> [[{Path(um['target']).stem}]]"
            )
        if len(results["unlinked_mentions"]) > 50:
            print(f"   • ... and {len(results['unlinked_mentions']) - 50} more")

    if results.get("okf_upstream") is not None:
        print("-" * 60)
        _print_okf_upstream_report(results["okf_upstream"])

    print("=" * 60)


def _print_okf_upstream_report(report: dict[str, Any]) -> None:
    """Print human-readable upstream Open Knowledge Format (OKF) version status."""
    status = report.get("status", "unknown")
    sup_v = report.get("supported_version", SUPPORTED_OKF_VERSION)
    up_v = report.get("upstream_version")
    sha = report.get("latest_commit_sha")
    c_date = report.get("latest_commit_date")
    c_msg = report.get("latest_commit_message")

    print("🌐 Upstream Open Knowledge Format (OKF) Specification Check:")
    print(f"   • Official Repo:     {report.get('repo_url')}")
    print(f"   • Compiler Version:  v{sup_v}")
    if status == "up_to_date":
        print(f"   • Upstream SPEC.md:  v{up_v} (✅ Up to date with official spec)")
    elif status == "update_available":
        print(
            f"   • Upstream SPEC.md:  v{up_v} (🚀 NEW VERSION AVAILABLE! Upgrade from v{sup_v} -> v{up_v})"
        )
        print(f"   • Spec Changelog:    {report.get('spec_url')}")
    elif status == "ahead_of_upstream":
        print(f"   • Upstream SPEC.md:  v{up_v} (ℹ️ Compiler v{sup_v} is ahead of upstream)")
    elif status == "offline":
        print(f"   • Upstream Status:   ⚠️ Offline / unreachable ({report.get('error')})")
    else:
        print(f"   • Upstream Status:   ⚠️ Could not parse version ({status})")

    if sha:
        commit_line = f"{sha}"
        if c_date:
            commit_line += f" ({c_date})"
        if c_msg:
            commit_line += f" — {c_msg}"
        print(f"   • Latest main Commit: {commit_line}")


def _resolve_vault_arg_for_approve(vault_arg: str | None, note_arg: str) -> Path:
    """Resolve vault root when `--approve-human` is called with or without positional `vault`."""
    if vault_arg:
        return Path(vault_arg)
    raw_note = Path(note_arg)
    if raw_note.is_absolute() and not raw_note.is_symlink():
        curr = raw_note.parent
        while curr != curr.parent:
            if (curr / "wiki").is_dir():
                return curr
            curr = curr.parent
    return find_vault_root(Path.cwd())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Audit and lint an OKF v0.3/v0.2 Knowledge Compiler Obsidian Vault."
    )
    parser.add_argument(
        "vault",
        nargs="?",
        default=None,
        help="Path to vault root (default: current directory or auto-detected).",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Automatically fix table pipe escaping invariants.",
    )
    parser.add_argument(
        "--migrate-sources",
        action="store_true",
        help="With --fix, deterministically convert legacy string `sources:` entries in wiki/ to `{id, resource}`.",
    )
    parser.add_argument(
        "--migrate-v03",
        action="store_true",
        help="With --fix, deterministically upgrade index.md (okf_version: '0.3'), log.md (frontmatter-free ## YYYY-MM-DD), bare bundle-root path fields, bare epistemic keys (-> x-kc-*), and missing wiki/**/index.md files to OKF v0.3.",
    )
    parser.add_argument(
        "--portable-links",
        action="store_true",
        help="With --fix, deterministically rewrite resolved Obsidian [[wikilinks]] in living notes to OKF v0.3 RFC 3986 relative Markdown links and x-kc-* bundle-root paths.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail with exit code 1 on stale_notes, orphan_notes, missing_from_index, or legacy_sources_notes.",
    )
    parser.add_argument(
        "--strict-drift",
        action="store_true",
        help="Fail with exit code 1 if stale_syntheses or strict warnings are present.",
    )
    parser.add_argument(
        "--mentions",
        action="store_true",
        help="Scan living wiki/ prose for plain-text mentions of entities/concepts not yet [[wikilinked]].",
    )
    parser.add_argument(
        "--dedup-manifest",
        default=None,
        metavar="OUT_JSON",
        help="Read-only scan for duplicate entities/concepts; write review manifest JSON without modifying vault files.",
    )
    parser.add_argument(
        "--apply-manifest",
        default=None,
        metavar="IN_JSON",
        help="Apply ONLY approved entries in a dedup manifest using SHA-256 CAS verification.",
    )
    parser.add_argument(
        "--approve-human",
        default=None,
        metavar="NOTE_PATH",
        help="Stamp human verification (`verified: [{by: human:<id>, at: ...}]`) onto a wiki/ note.",
    )
    parser.add_argument(
        "--actor",
        default=None,
        help="Human actor for --approve-human (default: human:<USER>).",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output audit results in JSON format."
    )
    parser.add_argument(
        "--check-okf-upstream",
        action="store_true",
        help="Check https://github.com/open-knowledge-format/open-knowledge-format for a newer OKF spec version.",
    )
    args = parser.parse_args(argv)

    if args.approve_human is not None:
        v_root = _resolve_vault_arg_for_approve(args.vault, args.approve_human)
        res = approve_human_note(v_root, args.approve_human, actor=args.actor)
        if args.json:
            print(json.dumps(res, indent=2))
        elif res.get("success"):
            print(
                f"✅ Approved human review on {res['file']} as {res['actor']} "
                f"(trust_tier={res['trust_tier']})"
            )
        else:
            print(f"❌ Error: {res.get('error', 'Approval failed')}", file=sys.stderr)
        if not res.get("success"):
            sys.exit(2)
        return

    v_root = Path(args.vault) if args.vault else find_vault_root(Path.cwd())
    if args.dedup_manifest is not None:
        res = generate_dedup_manifest(v_root, Path(args.dedup_manifest))
        if args.json:
            print(json.dumps(res, indent=2))
        elif res.get("success"):
            print(
                f"📋 Wrote {res['proposal_count']} dedup proposal(s) to {res['manifest_path']}"
            )
        else:
            print(f"❌ Error: {res.get('error', 'Dedup scan failed')}", file=sys.stderr)
        if not res.get("success"):
            sys.exit(2)
        return

    if args.apply_manifest is not None:
        res = apply_dedup_manifest(v_root, Path(args.apply_manifest))
        if args.json:
            print(json.dumps(res, indent=2))
        elif res.get("success"):
            print(
                f"✅ Applied {res['applied_count']} approved dedup merge(s) "
                f"(skipped {res['skipped_count']})."
            )
        else:
            print(f"❌ Error: {res.get('error', 'Dedup apply failed')}", file=sys.stderr)
        if not res.get("success"):
            sys.exit(2)
        return

    if args.check_okf_upstream and not (v_root / "wiki").exists() and not args.vault:
        report = check_upstream_okf_version()
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("=" * 60)
            _print_okf_upstream_report(report)
            print("=" * 60)
        return

    res = run_vault_lint(
        v_root,
        auto_fix=args.fix,
        as_json=args.json,
        check_okf_upstream=args.check_okf_upstream,
        strict=args.strict,
        migrate_sources=args.migrate_sources,
        migrate_v03=args.migrate_v03,
        portable_links=args.portable_links,
        strict_drift=args.strict_drift,
        include_mentions=args.mentions,
    )

    if not res.get("success", False):
        sys.exit(2)

    if not res.get("is_healthy", False):
        sys.exit(1)

    if args.strict and not res.get("strict_passed", False):
        sys.exit(1)

    if args.strict_drift and not res.get("strict_drift_passed", False):
        sys.exit(1)


if __name__ == "__main__":
    main()
