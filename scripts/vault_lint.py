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
OKF v0.2 Knowledge Compiler Vault Linter & Conformance Auditor.
Validates OKF v0.2 bundle conformance inside `wiki/`, wikilink integrity,
table formatting invariants, orphan notes, ranked `wanted_pages`, trust-tier
breakdown, freshness (`stale_after`), and Workspace Profile root files.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime
import getpass
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any
import urllib.error
import urllib.request

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import okf  # noqa: E402

SUPPORTED_OKF_VERSION = okf.SUPPORTED_OKF_VERSION
UPSTREAM_OKF_REPO_URL = "https://github.com/GoogleCloudPlatform/open-knowledge-format"
UPSTREAM_OKF_SPEC_RAW_URL = (
    "https://raw.githubusercontent.com/GoogleCloudPlatform/open-knowledge-format/main/SPEC.md"
)
UPSTREAM_OKF_COMMITS_API_URL = (
    "https://api.github.com/repos/GoogleCloudPlatform/open-knowledge-format/commits/main"
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
EPISTEMIC_EDGE_KEYS = (
    "corroborates",
    "complements",
    "extends",
    "contradicts",
    "supersedes",
)

_HEADING_RE = re.compile(r"^[ \t]{0,3}#{1,6}(?:[ \t]|$)")
_BQ_PREFIX_RE = re.compile(r"^((?:[ \t]*>[ \t]?)*)([\s\S]*)$")
_LIST_MARKER_RE = re.compile(r"^([ \t]*(?:[-*+]|\d+[.)])[ \t]+(?:\[[ xX]\][ \t]+)?)")
_OPEN_FENCE_LINE_RE = re.compile(r"^([ \t]*)(`{3,}|~{3,})([^\r\n]*)$")
_WIKILINK_RE = re.compile(r"\[\[([^\]\n]+)\]\]")
_MD_LINK_RE = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
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
    """Check upstream GoogleCloudPlatform/open-knowledge-format SPEC.md version."""
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
        "User-Agent": "knowledge-compiler-okf-checker/1.0.0",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        req = urllib.request.Request(UPSTREAM_OKF_SPEC_RAW_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            spec_text = resp.read().decode("utf-8", errors="replace")

        header_chunk = "\n".join(spec_text.splitlines()[:40])
        m = re.search(
            r"(?:\*\*Version\s+([0-9]+(?:\.[0-9]+)+)\*\*|Version[:\s]+([0-9]+(?:\.[0-9]+)+))",
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


def _validate_log_headings(body: str, rel_path: str) -> list[dict[str, str]]:
    """Verify `log.md` level-2 headings match `## [YYYY-MM-DD]` or `## YYYY-MM-DD`."""
    masked_body, _restore, _unclosed = _mask_markdown_code(body)
    issues: list[dict[str, str]] = []
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
                        "'## [YYYY-MM-DD]' or '## YYYY-MM-DD'"
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
    """Extract `[[wikilink]]` targets from frontmatter epistemic edge keys."""
    targets: list[str] = []
    for ep_k in EPISTEMIC_EDGE_KEYS:
        val = fm.get(ep_k)
        items = val if isinstance(val, list) else ([val] if isinstance(val, str) else [])
        for item in items:
            if not isinstance(item, str):
                continue
            for m in _WIKILINK_RE.finditer(item):
                raw_link = m.group(1).strip()
                tgt = re.split(r"\\?\|", raw_link)[0].strip()
                if tgt and not tgt.startswith("#"):
                    tgt = tgt.split("#", 1)[0].strip()
                    if tgt:
                        targets.append(tgt)
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


def run_vault_lint(
    vault_root: Path,
    auto_fix: bool = False,
    as_json: bool = False,
    check_okf_upstream: bool = False,
    strict: bool = False,
    migrate_sources: bool = False,
) -> dict[str, Any]:
    """Audit a Knowledge Compiler vault against OKF v0.2 conformance and graph invariants."""
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

    for rel_path, data in all_md_files.items():
        name_to_rel[data["base_name"].lower()] = rel_path
        name_to_rel[rel_path.lower()] = rel_path
        name_to_rel[rel_path[:-3].lower()] = rel_path
        if rel_path.startswith("wiki/"):
            name_to_rel[rel_path[5:].lower()] = rel_path
            name_to_rel[rel_path[5:-3].lower()] = rel_path
        elif rel_path.startswith("raw/"):
            name_to_rel[rel_path[4:].lower()] = rel_path
            name_to_rel[rel_path[4:-3].lower()] = rel_path

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
    fixed_files: list[str] = []
    migrated_sources_files: list[str] = []
    conformance_errors: list[dict[str, str]] = []
    missing_frontmatter: list[str] = []
    legacy_sources_notes: list[str] = []
    dangling_footnotes: list[dict[str, str]] = []
    stale_notes: list[dict[str, str]] = []
    workspace_profile_warnings: list[dict[str, str]] = []
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
        sentinel_clean = _find_pua_sentinel_base(body_to_scan)[3]
        masked_body, restore_body, has_unclosed_fence = _mask_markdown_code(body_to_scan)

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
                    masked_body, restore_body, _ = _mask_markdown_code(body_to_scan)

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

        # 3. Validate OKF v0.2 Bundle Root (`wiki/`) vs Workspace Profile root files
        val: dict[str, Any] | None = None
        if is_wiki_note and not is_reserved_wiki:
            try:
                val = okf.validate_okf_concept(content, is_reserved=False)
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
                        "rule": "okf_v02",
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

        if is_wiki_note:
            if is_reserved_wiki:
                if note_filename_lower == "log.md":
                    log_issues = _validate_log_headings(body_to_scan, rel_path)
                    workspace_profile_warnings.extend(log_issues)
                    conformance_errors.extend(log_issues)
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
                                "rule": "okf_v02",
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
                            {"file": rel_path, "rule": "okf_v02", "message": err_msg}
                        )

                    if val["legacy_sources"]:
                        legacy_sources_notes.append(rel_path)

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
                workspace_profile_warnings.extend(
                    _validate_log_headings(body_to_scan, rel_path)
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
            if not raw_href or raw_href.startswith(("#", "http://", "https://", "mailto:")):
                continue
            href_clean = raw_href.split("#", 1)[0].split("?", 1)[0].strip()
            if href_clean.lower().endswith(".md"):
                graph[rel_path]["outbound_md"].add(href_clean)

    # Resolve wikilinks and build inbound edges
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
            candidate_rel = md_href.lstrip("/")
            if not md_href.startswith("/"):
                src_parent = Path(src).parent
                joined = os.path.normpath(str(src_parent / md_href)).replace("\\", "/")
                if not joined.startswith(".."):
                    candidate_rel = joined
            resolved_md = _resolve_target(candidate_rel, name_to_rel, graph)
            if resolved_md and resolved_md in graph:
                graph[resolved_md]["inbound"].add(src)

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
        idx_lower = index_content.lower()
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

    # Count 5-way typed epistemic edges across wiki notes
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
            for ep_k in EPISTEMIC_EDGE_KEYS:
                val = fm.get(ep_k)
                if isinstance(val, list):
                    epistemic_edge_counts[ep_k.upper()] += len(val)
                elif isinstance(val, str) and val.strip():
                    epistemic_edge_counts[ep_k.upper()] += 1

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
        "bundle_root": "wiki",
        "supported_okf_version": SUPPORTED_OKF_VERSION,
        "total_markdown_files": len(all_md_files),
        "total_wiki_notes": total_wiki_notes,
        "broken_links": broken_links,
        "wanted_pages": wanted_pages,
        "table_invariant_violations": table_invariant_violations,
        "fixed_files": fixed_files,
        "migrated_sources_files": migrated_sources_files,
        "orphan_notes": orphan_notes,
        "missing_from_index": missing_from_index,
        "missing_frontmatter": missing_frontmatter,
        "conformance_errors": conformance_errors,
        "legacy_sources_notes": legacy_sources_notes,
        "dangling_footnotes": dangling_footnotes,
        "stale_notes": stale_notes,
        "workspace_profile_warnings": workspace_profile_warnings,
        "trust_tier_counts": trust_tier_counts,
        "epistemic_edge_counts": epistemic_edge_counts,
        "is_healthy": is_healthy,
        "strict": strict,
        "strict_passed": strict_passed,
    }
    if okf_upstream_report is not None:
        results["okf_upstream"] = okf_upstream_report

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        _print_lint_report(results, auto_fix=auto_fix, strict=strict)

    return results


def _print_lint_report(results: dict[str, Any], *, auto_fix: bool, strict: bool) -> None:
    """Print human-readable OKF v0.2 vault audit report."""
    ep = results["epistemic_edge_counts"]
    tt = results["trust_tier_counts"]
    total_ep = sum(ep.values())

    print("=" * 60)
    print("🔍 OKF v0.2 Knowledge Compiler Vault Audit Report")
    print("=" * 60)
    print(f"📁 Vault Path: {results['vault_path']} (OKF Bundle Root: wiki/)")
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

    if results["strict_passed"]:
        print(
            "✨ 100% HEALTHY! All links resolve, OKF conformance passes, and index is synchronized."
        )
    else:
        if results["conformance_errors"]:
            print(f"❌ OKF v0.2 Conformance Errors ({len(results['conformance_errors'])}):")
            for err in results["conformance_errors"]:
                print(f"   • [{err['file']}] {err['message']}")

        if results["broken_links"]:
            print(f"❌ Broken Wikilinks ({len(results['broken_links'])}):")
            for b in results["broken_links"]:
                print(f"   • [{b['source']}] -> [[{b['target']}]]")

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

        if results["migrated_sources_files"]:
            print(
                f"🔄 Migrated Legacy String Sources to {{id, resource}} ({len(results['migrated_sources_files'])}):"
            )
            for mf in results["migrated_sources_files"]:
                print(f"   • {mf}")

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
        description="Audit and lint an OKF v0.2 Knowledge Compiler Obsidian Vault."
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
        "--strict",
        action="store_true",
        help="Fail with exit code 1 on stale_notes, orphan_notes, missing_from_index, or legacy_sources_notes.",
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
        help="Check https://github.com/GoogleCloudPlatform/open-knowledge-format for a newer OKF spec version.",
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
    )

    if not res.get("success", False):
        sys.exit(2)

    if not res.get("is_healthy", False):
        sys.exit(1)

    if args.strict and not res.get("strict_passed", False):
        sys.exit(1)


if __name__ == "__main__":
    main()
