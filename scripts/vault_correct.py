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
OKF v0.2 Knowledge Compiler Vault Correction Engine (vault_correct.py).

Implements the Write-Correctness Laws:
1. Sweep corrected facts through the vault upon discovery or distillation.
2. Tri-state classification:
   - AUTHORITATIVE: The single canonical note where the fact is updated.
   - RESTATEMENT: Living notes asserting the claim; assertion is refactored into a wikilink.
   - HISTORICAL: Notes recording what was believed at the time (raw/, dated notes, status: superseded/archived).
     STRICTLY PRESERVED.
3. Preserves frontmatter, code blocks, inline code, existing wikilinks, and reserved/instruction files.
4. Enforces SHA-256 Compare-and-Swap (CAS) + atomic writes (temp + fsync + os.replace).
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

try:
    import okf  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    from . import okf  # type: ignore[import-not-found]

_FRONTMATTER_RE = re.compile(
    r"\A---[ \t]*(\r?\n)(?:([\s\S]*?)\r?\n)?---[ \t]*(\r?\n|\Z)([\s\S]*)\Z"
)
_HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")
_INLINE_CODE_RE = re.compile(r"(?<!`)(`+)(?!`)[^\n]*?(?<!`)\1(?!`)")
_LINKS_AND_URLS_RE = re.compile(
    r"\[\[[^\]\n]+\]\]|(?<=\])\([^)\n]+\)|https?://[^\s<>\[\]()\"']+"
)
_YAML_ANCHOR_RE = re.compile(r"(?:^|[:\[,\s])&[A-Za-z_][A-Za-z0-9_-]*(?:\s|$)", re.MULTILINE)
_YAML_ALIAS_RE = re.compile(r"(?:^|[:\[,\s])\*[A-Za-z_][A-Za-z0-9_-]*(?:\s|$)", re.MULTILINE)
_MAX_FRONTMATTER_CHARS = 65536

RESERVED_FILENAMES = frozenset(
    {
        "gemini.md",
        "agents.md",
        "claude.md",
        "skill.md",
        "hooks.json",
        "plugin.json",
        "index.md",
        "purpose.md",
    }
)
RESERVED_DIRS = frozenset(
    {
        ".git",
        ".obsidian",
        ".agents",
        ".gemini",
        "rules",
        "skills",
        "__pycache__",
        ".venv",
    }
)
HISTORICAL_DIRS = frozenset(
    {
        "raw",
        "archive",
        "meetings",
        "1-1",
        "journal",
        "incidents",
    }
)
HISTORICAL_STATUSES = frozenset(
    {"superseded", "archived", "completed", "deprecated", "done"}
)


class CASConflictError(RuntimeError):
    """Raised when a target file changes concurrently before atomic replacement."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _has_symlink_component(file_path: Path, vault_root: Path) -> bool:
    """Return True if `file_path` or any component under `vault_root` is a symlink or escapes `vault_root`."""
    try:
        resolved_root = vault_root.resolve()
        rel = file_path.relative_to(vault_root)
    except (OSError, ValueError):
        return True

    curr = vault_root
    for part in rel.parts:
        curr = curr / part
        if curr.is_symlink():
            return True

    try:
        resolved_file = file_path.resolve()
        if not resolved_file.is_relative_to(resolved_root):
            return True
    except OSError:
        return True

    return False


def _fallback_parse_simple_yaml(fm_text: str) -> Dict[str, Any]:
    """Parse YAML frontmatter via okf pure-stdlib fallback parser."""
    return okf.parse_frontmatter(fm_text, strict=False, use_pyyaml=False)


def _parse_frontmatter_yaml(fm_text: str) -> Dict[str, Any]:
    """Parse YAML frontmatter via okf.parse_frontmatter (with PyYAML + stdlib parity)."""
    return okf.parse_frontmatter(
        fm_text, strict=False, use_pyyaml=(yaml is not None)
    )


def _split_frontmatter(content: str) -> Tuple[str, Optional[str], str]:
    """Split markdown into (raw_frontmatter_with_fences, yaml_text, body)."""
    bom = "\ufeff" if content.startswith("\ufeff") else ""
    text = content[len(bom) :]
    if not text.startswith("---"):
        return "", None, content
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return "", None, content
    yaml_text = match.group(2) if match.group(2) is not None else ""
    body = match.group(4)
    fm_prefix = bom + text[: match.start(4)]
    return fm_prefix, yaml_text, body


def find_vault_root(start_path: Optional[Path] = None) -> Path:
    """Locates the active Knowledge Compiler vault root."""
    if start_path is not None:
        return Path(start_path).expanduser().resolve()

    cwd = Path.cwd().resolve()
    for parent in [cwd] + list(cwd.parents):
        if (
            (parent / "GEMINI.md").exists()
            or (parent / "wiki").exists()
            or (parent / "raw").exists()
        ):
            return parent

    vault_env = os.environ.get("OBSIDIAN_VAULT_PATH") or os.environ.get("KC_VAULT_PATH")
    default_vault = (
        Path(vault_env).expanduser().resolve()
        if vault_env
        else (Path.home() / "ObsidianVault")
    )
    if (default_vault / "wiki").is_dir():
        return default_vault

    return cwd


def parse_frontmatter(content: str) -> Tuple[Dict[str, Any], str]:
    """Extracts YAML frontmatter via okf.parse_frontmatter (with stdlib fallback) and body."""
    _fm_prefix, fm_text, body = _split_frontmatter(content)
    if fm_text is None:
        return {}, content
    if not fm_text.strip():
        return {}, body
    return _parse_frontmatter_yaml(fm_text), body


def update_frontmatter_date(content: str, new_date: Optional[str] = None) -> str:
    """Updates the top-level 'updated: YYYY-MM-DD' field in frontmatter."""
    if new_date is None:
        new_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    bom = "\ufeff" if content.startswith("\ufeff") else ""
    text = content[len(bom) :]
    if not text.startswith("---"):
        return content

    match = _FRONTMATTER_RE.match(text)
    if not match:
        return content

    nl = match.group(1)
    fm_text = match.group(2) if match.group(2) is not None else ""
    close_nl = match.group(3)
    body = match.group(4)

    if re.search(r"^updated:[ \t]*[^\r\n]*(?=\r?$)", fm_text, re.MULTILINE):
        new_fm = re.sub(
            r"^updated:[ \t]*[^\r\n]*(?=\r?$)",
            lambda _m: f"updated: {new_date}",
            fm_text,
            count=1,
            flags=re.MULTILINE,
        )
    elif fm_text.strip():
        new_fm = fm_text.rstrip("\r\n") + f"{nl}updated: {new_date}"
    else:
        new_fm = f"updated: {new_date}"

    return f"{bom}---{nl}{new_fm}{nl}---{close_nl}{body}"


def is_reserved_or_instruction_path(
    file_path: Path, vault_root: Path
) -> Tuple[bool, str]:
    """Return True if path is a symlink or reserved instruction/config/index file."""
    if _has_symlink_component(file_path, vault_root):
        return True, "Symlink or out-of-vault path excluded from mutation"

    try:
        rel = file_path.relative_to(vault_root)
    except ValueError:
        return True, "Path escapes vault root"

    parts_lower = tuple(part.lower() for part in rel.parts)
    if not parts_lower:
        return True, "Invalid empty relative path"

    for dir_part in parts_lower[:-1]:
        if dir_part in RESERVED_DIRS:
            return True, f"Located in reserved directory '{dir_part}/'"

    if parts_lower[-1] in RESERVED_FILENAMES:
        return True, f"Reserved instruction/config/index file '{rel.as_posix()}'"

    return False, ""


def is_historical_note(
    file_path: Path, vault_root: Path, frontmatter: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Determines if a note is historical and MUST be preserved without rewriting.

    A note is historical if ANY one holds:
    1. It is a symlink or escapes `vault_root`.
    2. It sits under an immutable or record directory (raw/, archive/, meetings/, 1-1/, journal/, incidents/).
    3. It is in wiki/sources/ (immutable source extraction summaries).
    4. It is the operations ledger 'log.md' or 'wiki/skill-impact.md'.
    5. Its filename carries a date pattern (e.g. YYYY-MM-DD or (YYYY-MM)).
    6. Its frontmatter status is 'superseded', 'archived', 'completed', 'deprecated', or 'done'.
    """
    if _has_symlink_component(file_path, vault_root):
        return True, "Symlink path excluded from mutation"

    try:
        rel = file_path.relative_to(vault_root)
    except ValueError:
        return True, "Path escapes vault root"

    rel_posix = rel.as_posix()
    rel_lower = rel_posix.lower()
    parts_lower = tuple(part.lower() for part in rel.parts)

    if rel_lower == "log.md":
        return True, "Operations audit log is immutable ledger"

    if rel_lower == "wiki/skill-impact.md":
        return True, "Skill impact ledger wiki/skill-impact.md is immutable ledger"

    for dir_part in parts_lower[:-1]:
        if dir_part in HISTORICAL_DIRS:
            return True, f"Located in record directory '{dir_part}/'"

    if len(parts_lower) >= 2 and parts_lower[0] == "wiki" and parts_lower[1] == "sources":
        return (
            True,
            "Source summaries in wiki/sources/ represent historical ingest snapshots",
        )

    stem = file_path.stem
    if re.search(r"\b\d{4}-\d{2}-\d{2}\b", stem) or re.search(
        r"\(\d{4}-\d{2}\)", stem
    ):
        return True, f"Filename contains explicit date provenance '{stem}'"

    status = str(frontmatter.get("status", "")).lower().strip()
    if status in HISTORICAL_STATUSES:
        return True, f"Frontmatter status is '{status}'"

    return False, ""


def find_candidate_notes(
    vault_root: Path,
    terms: List[str],
    exclude_patterns: Optional[List[str]] = None,
) -> List[Path]:
    """Finds markdown files in the vault matching any of the given search terms."""
    matched: List[Path] = []
    excluded_dirs = set(RESERVED_DIRS)
    if exclude_patterns:
        excluded_dirs.update(p.lower() for p in exclude_patterns)

    for root, dirs, files in os.walk(vault_root, followlinks=False):
        root_path = Path(root)
        dirs[:] = sorted(
            d
            for d in dirs
            if d.lower() not in excluded_dirs and not (root_path / d).is_symlink()
        )
        for f in sorted(files):
            if not f.endswith(".md"):
                continue
            full_path = root_path / f
            is_reserved, _ = is_reserved_or_instruction_path(full_path, vault_root)
            if is_reserved:
                continue
            try:
                text = full_path.read_text(encoding="utf-8", errors="ignore")
                for term in terms:
                    if term and re.search(re.escape(term), text, re.IGNORECASE):
                        matched.append(full_path)
                        break
            except Exception:
                continue

    return matched


def classify_notes(
    matched_files: List[Path],
    vault_root: Path,
    target_authoritative: Optional[str] = None,
    fact: str = "",
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Classifies candidate notes into AUTHORITATIVE, RESTATEMENT, and HISTORICAL.
    """
    classified: Dict[str, List[Dict[str, Any]]] = {
        "authoritative": [],
        "restatement": [],
        "historical": [],
        "unclassified": [],
        "excluded": [],
    }

    target_stem: Optional[str] = None
    target_norm: Optional[str] = None
    if target_authoritative:
        target_norm = str(target_authoritative).replace("\\", "/").strip().lower()
        target_stem = Path(target_authoritative).stem.lower()

    for f in matched_files:
        is_reserved, res_reason = is_reserved_or_instruction_path(f, vault_root)
        if is_reserved:
            try:
                rel_exc = f.relative_to(vault_root).as_posix()
            except ValueError:
                rel_exc = str(f)
            classified["excluded"].append(
                {
                    "path": f,
                    "rel_path": rel_exc,
                    "title": f.stem,
                    "reason": res_reason,
                }
            )
            continue

        rel = f.relative_to(vault_root).as_posix()
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        fm, _body = parse_frontmatter(content)
        raw_title = fm.get("title")
        title = str(raw_title).strip() if raw_title is not None and str(raw_title).strip() else f.stem

        # 1. Check Historical first (Preservation Rail)
        is_hist, reason = is_historical_note(f, vault_root, fm)
        if is_hist:
            classified["historical"].append(
                {
                    "path": f,
                    "rel_path": rel,
                    "title": title,
                    "reason": reason,
                    "frontmatter": fm,
                }
            )
            continue

        # 2. Check if this is the designated or inferred Authoritative note
        is_auth = False
        if target_stem is not None and target_norm is not None:
            if (
                rel.lower() == target_norm
                or f.stem.lower() == target_stem
                or title.lower() == target_stem
                or title.lower() == target_norm
            ):
                is_auth = True
        elif rel.startswith(("wiki/entities/", "wiki/concepts/")):
            if f.stem.lower() in fact.lower():
                is_auth = True

        if is_auth:
            classified["authoritative"].append(
                {
                    "path": f,
                    "rel_path": rel,
                    "title": title,
                    "frontmatter": fm,
                }
            )
        else:
            classified["restatement"].append(
                {
                    "path": f,
                    "rel_path": rel,
                    "title": title,
                    "frontmatter": fm,
                }
            )

    return classified


def _build_boundary_pattern(pat: str) -> str:
    """Build case-insensitive regex pattern with word-boundary guards on alphanumeric edges."""
    escaped = re.escape(pat)
    if pat and (pat[0].isalnum() or pat[0] == "_"):
        escaped = r"(?<![\w.])" + escaped
    if pat and (pat[-1].isalnum() or pat[-1] == "_"):
        escaped = escaped + r"(?![\w]|\.\d)"
    return escaped


def _select_pua_sentinel_base(text: str) -> Tuple[str, str, int]:
    """Select an unused Private Use Area marker alphabet so stale terms can never collide."""
    for base in (0xE000, 0xE200, 0xE400, 0xF0000):
        open_ch = chr(base)
        close_ch = chr(base + 1)
        digit_base = base + 0x10
        used = any(
            (ord(ch) == base or ord(ch) == base + 1 or digit_base <= ord(ch) <= digit_base + 15)
            for ch in text
        )
        if not used:
            return open_ch, close_ch, digit_base
    return "\U0010f000", "\U0010f001", 0x10F010


_LIST_MARKER_RE = re.compile(r"^([ \t]*(?:[-*+]|\d+[.)])[ \t]+(?:\[[ xX]\][ \t]+)?)")
_HEADING_RE = re.compile(r"^[ \t]{0,3}#{1,6}(?:[ \t]|$)")
_BQ_PREFIX_RE = re.compile(r"^((?:[ \t]*>[ \t]?)*)([\s\S]*)$")
_OPEN_FENCE_LINE_RE = re.compile(r"^([ \t]*)(`{3,}|~{3,})([^\r\n]*)$")


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


def _split_line_ending(line: str) -> Tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    return line, ""


def _mask_fenced_code_blocks(
    body: str,
    encode_token: Callable[[str], str],
) -> Tuple[str, set[str], List[str]]:
    """Mask top-level, list-indented, and blockquote/callout fenced code blocks."""
    lines = body.splitlines(keepends=True)
    out: List[str] = []
    fence_placeholders: set[str] = set()
    warnings: List[str] = []
    i = 0

    while i < len(lines):
        line_no_nl, _ = _split_line_ending(lines[i])
        m_bq = _BQ_PREFIX_RE.match(line_no_nl)
        bq_prefix = m_bq.group(1) if m_bq else ""
        bq_depth = bq_prefix.count(">")
        inner = m_bq.group(2) if m_bq else line_no_nl

        m_open = _OPEN_FENCE_LINE_RE.match(inner)
        list_prefix = ""
        if not m_open:
            m_list = _LIST_MARKER_RE.match(inner)
            if m_list:
                list_prefix = m_list.group(0)
                m_open = _OPEN_FENCE_LINE_RE.match(inner[len(list_prefix) :])

        if m_open:
            open_indent, fence_seq, info = m_open.group(1), m_open.group(2), m_open.group(3)
            fence_char = fence_seq[0]
            fence_len = len(fence_seq)
            if fence_char == "`" and "`" in info:
                out.append(lines[i])
                i += 1
                continue

            close_re = re.compile(rf"^[ \t]*{re.escape(fence_char)}{{{fence_len},}}[ \t]*$")
            closed_idx: Optional[int] = None

            for j in range(i + 1, len(lines)):
                j_no_nl, _ = _split_line_ending(lines[j])
                j_bq = _BQ_PREFIX_RE.match(j_no_nl)
                j_bq_depth = (j_bq.group(1) if j_bq else "").count(">")
                j_inner = j_bq.group(2) if j_bq else j_no_nl

                if j_bq_depth < bq_depth:
                    break
                if close_re.match(j_inner):
                    closed_idx = j
                    break

            if closed_idx is None:
                warnings.append(
                    f"Unclosed {fence_seq} code fence at body line {i + 1}; skipping note edits to avoid corrupting unclosed code."
                )
                return body, set(), warnings

            end_exclusive = closed_idx + 1
            mask_prefix = bq_prefix + list_prefix + open_indent
            block_text = "".join(lines[i:end_exclusive])
            _last_no_nl, last_nl = _split_line_ending(lines[end_exclusive - 1])
            raw_inner_block = block_text[len(mask_prefix) :]
            if last_nl and raw_inner_block.endswith(last_nl):
                raw_inner_block = raw_inner_block[: -len(last_nl)]

            placeholder = encode_token(raw_inner_block)
            if not mask_prefix:
                fence_placeholders.add(placeholder)
            out.append(mask_prefix + placeholder + last_nl)
            i = end_exclusive
            continue

        out.append(lines[i])
        i += 1

    return "".join(out), fence_placeholders, warnings


def _mask_indented_code_blocks(
    text: str,
    mask_fn: Callable[[str], str],
    fence_placeholders: Optional[set[str]] = None,
) -> str:
    """Mask indented code blocks while preserving tight and loose list children/continuations."""
    lines = text.splitlines(keepends=True)
    out: List[str] = []
    idx = 0
    can_start_indented = True
    list_code_threshold: Optional[int] = None
    f_placeholders = fence_placeholders or set()

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
        if list_match and indent < (list_code_threshold if list_code_threshold is not None else 4):
            list_code_threshold = len(list_match.group(0).expandtabs(4)) + 4
            can_start_indented = False
            out.append(line)
            idx += 1
            continue

        min_code_indent = list_code_threshold if list_code_threshold is not None else 4
        if can_start_indented and indent >= min_code_indent and not list_match:
            block_lines: List[str] = [line]
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
            trailing_blanks: List[str] = []
            while block_lines and not block_lines[-1].rstrip("\r\n").strip():
                trailing_blanks.append(block_lines.pop())
            out.append(mask_fn("".join(block_lines)))
            for tb in reversed(trailing_blanks):
                out.append(tb)
            can_start_indented = True
            continue

        # Reset list context on non-indented non-list prose/heading/fence lines
        if indent == 0 and not list_match:
            list_code_threshold = None

        out.append(line)
        is_fence_or_heading = bool(
            _HEADING_RE.match(stripped_no_nl) or stripped in f_placeholders
        )
        can_start_indented = is_fence_or_heading
        idx += 1

    return "".join(out)


def _mask_body_protected_spans(
    body: str,
    warnings_out: Optional[List[str]] = None,
) -> Tuple[str, Callable[[str], str]]:
    """Mask fenced/indented code, HTML comments, inline code, [[wikilinks]], and URLs."""
    tokens: List[str] = []
    open_ch, close_ch, digit_base = _select_pua_sentinel_base(body)
    placeholders: List[str] = []

    def _encode_token(raw: str) -> str:
        idx = len(tokens)
        tokens.append(raw)
        hex_digits = format(idx, "x")
        encoded = "".join(chr(digit_base + int(ch, 16)) for ch in hex_digits)
        placeholder = f"{open_ch}{encoded}{close_ch}"
        placeholders.append(placeholder)
        return placeholder

    def _mask_match(match: re.Match[str]) -> str:
        return _encode_token(match.group(0))

    # Mask HTML comments BEFORE scanning fences so lone ``` inside <!-- --> cannot open a fence
    masked = _HTML_COMMENT_RE.sub(_mask_match, body)
    local_warnings: List[str] = []
    masked, fence_placeholders, fence_warnings = _mask_fenced_code_blocks(
        masked, _encode_token
    )
    if fence_warnings:
        local_warnings.extend(fence_warnings)
    if warnings_out is not None and local_warnings:
        warnings_out.extend(local_warnings)
    masked = _INLINE_CODE_RE.sub(_mask_match, masked)
    masked = _mask_indented_code_blocks(
        masked, _encode_token, fence_placeholders=fence_placeholders
    )
    masked = _LINKS_AND_URLS_RE.sub(_mask_match, masked)

    def _restore(text: str) -> str:
        out = text
        # Restore strictly in LIFO order so outer spans expose nested inner tokens
        for placeholder, original in reversed(list(zip(placeholders, tokens))):
            if out.count(placeholder) != 1:
                raise ValueError(
                    "Protected span sentinel corrupted during replacement; aborting write."
                )
            out = out.replace(placeholder, original, 1)
        if open_ch in out or close_ch in out:
            raise ValueError(
                "Unrestored protected span sentinel detected after replacement."
            )
        return out

    return masked, _restore


def replace_restatements_with_link(
    content: str,
    stale_patterns: List[str],
    authoritative_title: str,
    warnings_out: Optional[List[str]] = None,
) -> Tuple[str, int]:
    """
    Replaces stale pattern occurrences in body outside code blocks, inline code,
    HTML comments, URLs, and existing [[wikilinks]] with a clean [[Authoritative Title]] link.
    Frontmatter is never modified.
    """
    valid_patterns = sorted(
        {p.strip() for p in stale_patterns if p and p.strip()},
        key=len,
        reverse=True,
    )
    if not valid_patterns:
        return content, 0

    fm_prefix, _fm_yaml, body = _split_frontmatter(content)
    local_warnings: List[str] = []
    masked_body, restore_masks = _mask_body_protected_spans(
        body, warnings_out=local_warnings
    )
    if warnings_out is not None and local_warnings:
        warnings_out.extend(local_warnings)
    if local_warnings:
        return content, 0

    link_target = f"[[{authoritative_title}]]"
    combined_regex = re.compile(
        "|".join(_build_boundary_pattern(pat) for pat in valid_patterns),
        re.IGNORECASE,
    )
    new_masked_body, replacements_made = combined_regex.subn(
        lambda _m: link_target, masked_body
    )

    if replacements_made == 0:
        return content, 0

    new_body = restore_masks(new_masked_body)
    return fm_prefix + new_body, replacements_made


def _trim_fact_overlap(fact: str, before: str, after: str) -> str:
    """Strip overlapping prefix/suffix from `fact` already present on that line."""
    rem = fact
    if before and rem:
        max_k = min(len(before), len(rem))
        best_prefix = 0
        for k in range(max_k, 0, -1):
            candidate = rem[:k]
            if not candidate.strip():
                continue
            if before[-k:].lower() != candidate.lower():
                continue
            # Require word boundary at overlap start in `before`
            start_idx = len(before) - k
            if start_idx > 0 and before[start_idx - 1].isalnum() and candidate[0].isalnum():
                continue
            # Require word boundary at overlap end in `rem`
            if k < len(rem) and candidate[-1].isalnum() and rem[k].isalnum():
                continue
            best_prefix = k
            break
        if best_prefix > 0 and rem[best_prefix:].strip():
            rem = rem[best_prefix:]

    if after and rem:
        max_k = min(len(after), len(rem))
        best_suffix = 0
        for k in range(max_k, 0, -1):
            candidate = rem[-k:]
            if not candidate.strip():
                continue
            if after[:k].lower() != candidate.lower():
                continue
            # Require word boundary at overlap start in `rem`
            if k < len(rem) and rem[-k - 1].isalnum() and candidate[0].isalnum():
                continue
            # Require word boundary at overlap end in `after`
            if k < len(after) and candidate[-1].isalnum() and after[k].isalnum():
                continue
            best_suffix = k
            break
        if best_suffix > 0 and rem[:-best_suffix].strip():
            rem = rem[:-best_suffix]

    return rem


def _replace_stale_in_authoritative_body(
    body: str,
    stale_claim: str,
    fact: str,
    replacement: Optional[str] = None,
    warnings_out: Optional[List[str]] = None,
) -> Tuple[str, int]:
    """Replace `stale_claim` in authoritative note body while preserving code & links."""
    local_warnings: List[str] = []
    masked_body, restore_masks = _mask_body_protected_spans(
        body, warnings_out=local_warnings
    )
    if warnings_out is not None and local_warnings:
        warnings_out.extend(local_warnings)
    if local_warnings:
        return body, 0
    regex = re.compile(_build_boundary_pattern(stale_claim), re.IGNORECASE)
    if not regex.search(masked_body):
        return body, 0

    total_replacements = 0
    new_lines: List[str] = []
    for raw_line in masked_body.splitlines(keepends=True):
        if raw_line.endswith("\r\n"):
            line_text, line_end = raw_line[:-2], "\r\n"
        elif raw_line.endswith("\n"):
            line_text, line_end = raw_line[:-1], "\n"
        else:
            line_text, line_end = raw_line, ""

        if regex.search(line_text):
            def _sub_fn(
                m: re.Match[str],
                _line: str = line_text,
            ) -> str:
                if replacement is not None:
                    return replacement
                return _trim_fact_overlap(
                    fact,
                    _line[: m.start()],
                    _line[m.end() :],
                )

            updated_line, count = regex.subn(_sub_fn, line_text)
            total_replacements += count
            new_lines.append(updated_line + line_end)
        else:
            new_lines.append(raw_line)

    if total_replacements == 0:
        return body, 0

    return restore_masks("".join(new_lines)), total_replacements


def _atomic_write_text(
    target_path: Path,
    new_content: str,
    expected_sha256: Optional[str] = None,
) -> None:
    """Verify SHA-256 CAS and write `new_content` atomically via temp + fsync + os.replace."""
    if target_path.is_symlink():
        raise OSError(f"Refusing to write symlink: {target_path}")

    if expected_sha256 is not None:
        try:
            current_bytes = target_path.read_bytes()
        except FileNotFoundError as exc:
            raise CASConflictError(
                f"CAS conflict: '{target_path}' was removed before write"
            ) from exc
        current_sha = _sha256_bytes(current_bytes)
        if current_sha != expected_sha256:
            raise CASConflictError(
                f"CAS conflict on '{target_path}': expected {expected_sha256[:12]}, got {current_sha[:12]}"
            )

    orig_mode: Optional[int] = None
    try:
        orig_mode = stat.S_IMODE(target_path.stat().st_mode)
    except OSError:
        orig_mode = None

    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=str(target_path.parent),
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(new_content.encode("utf-8"))
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        if orig_mode is not None:
            try:
                os.chmod(tmp_path, orig_mode)
            except OSError:
                pass
        os.replace(tmp_path, target_path)
        tmp_path = None
    finally:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _resolve_target_authoritative_direct(
    vault_root: Path, target_authoritative: str
) -> Tuple[Optional[Path], Optional[str]]:
    """Directly locate a target note inside `vault_root` if it did not match search terms."""
    target_norm = str(target_authoritative).replace("\\", "/").strip()
    target_lower = target_norm.lower()
    target_stem = Path(target_norm).stem.lower()
    if target_stem in {name.removesuffix(".md") for name in RESERVED_FILENAMES} or target_lower in RESERVED_FILENAMES:
        return None, f"Reserved instruction/config/index file '{target_authoritative}'"

    for direct_cand in (vault_root / target_norm, vault_root / f"{target_norm}.md"):
        if direct_cand.is_file() or direct_cand.is_symlink():
            is_res, reason = is_reserved_or_instruction_path(direct_cand, vault_root)
            if is_res:
                return None, reason
            return direct_cand, None

    for root, dirs, files in os.walk(vault_root, followlinks=False):
        root_path = Path(root)
        dirs[:] = sorted(
            d
            for d in dirs
            if d.lower() not in RESERVED_DIRS and not (root_path / d).is_symlink()
        )
        for f in sorted(files):
            if not f.endswith(".md"):
                continue
            cand = root_path / f
            is_res, _ = is_reserved_or_instruction_path(cand, vault_root)
            if is_res:
                continue
            rel = cand.relative_to(vault_root).as_posix()
            if rel.lower() == target_lower or cand.stem.lower() == target_stem:
                return cand, None
            try:
                fm, _ = parse_frontmatter(cand.read_text(encoding="utf-8", errors="ignore"))
                title = str(fm.get("title") or "").strip().lower()
                if title and (title == target_stem or title == target_lower):
                    return cand, None
            except Exception:
                continue

    return None, None


def _build_unified_diff(rel_path: str, old_text: str, new_text: str) -> str:
    return "".join(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
    )


def execute_vault_correction(
    vault_root: Path,
    fact: str,
    stale_claim: Optional[str] = None,
    target_authoritative: Optional[str] = None,
    dry_run: bool = False,
    auto: bool = False,
    replacement: Optional[str] = None,
    apply: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Runs the complete tri-state vault correction sweep with CAS + atomic writes.
    """
    vault_root = Path(vault_root).expanduser().resolve()
    if apply is not None:
        effective_dry_run = bool(dry_run) or (not bool(apply))
    else:
        effective_dry_run = bool(dry_run)

    results: Dict[str, Any] = {
        "vault_path": str(vault_root),
        "fact": fact,
        "stale_claim": stale_claim,
        "replacement": replacement,
        "dry_run": effective_dry_run,
        "applied": False,
        "cas_conflict": False,
        "cas_conflicts": [],
        "authoritative_updated": [],
        "restatements_refactored": [],
        "historical_preserved": [],
        "diffs": [],
        "warnings": [],
        "errors": [],
    }

    if not vault_root.exists() or not vault_root.is_dir():
        results["errors"].append(f"Vault path does not exist: {vault_root}")
        return results

    if not stale_claim or not stale_claim.strip():
        results["errors"].append(
            "Explicit stale_claim (--stale) is required to refactor restatements or perform in-place replacement."
        )
        return results

    clean_stale = stale_claim.strip()
    search_terms: List[str] = [clean_stale]
    keywords = re.findall(
        r"\b[A-Z][a-zA-Z0-9_\-\.]+\b|\$\d+[\d,]*|\bv\d+[\d\.]*\b|\b\d+[\d,]*\b",
        fact,
    )
    for kw in keywords:
        if len(kw) > 2 and kw not in {"The", "And", "For", "With", "Not"}:
            if kw not in search_terms:
                search_terms.append(kw)

    # 1. Sweep files (reserved/instruction files & symlinks excluded)
    candidates = find_candidate_notes(vault_root, search_terms)

    # 2. Tri-state classification
    classified = classify_notes(
        matched_files=candidates,
        vault_root=vault_root,
        target_authoritative=target_authoritative,
        fact=fact,
    )

    # Record historical preservations
    for hist in classified["historical"]:
        results["historical_preserved"].append(
            {
                "rel_path": hist["rel_path"],
                "title": hist["title"],
                "reason": hist["reason"],
            }
        )

    # Fallback direct lookup if --target was explicitly named but lacked keywords
    if not classified["authoritative"] and target_authoritative:
        direct_path, blocked_reason = _resolve_target_authoritative_direct(
            vault_root, target_authoritative
        )
        if blocked_reason:
            results["errors"].append(
                f"Cannot target protected/reserved path '{target_authoritative}': {blocked_reason}"
            )
            return results
        if direct_path is not None and direct_path not in candidates:
            direct_cls = classify_notes(
                matched_files=[direct_path],
                vault_root=vault_root,
                target_authoritative=target_authoritative,
                fact=fact,
            )
            if direct_cls["historical"]:
                h0 = direct_cls["historical"][0]
                results["historical_preserved"].append(
                    {
                        "rel_path": h0["rel_path"],
                        "title": h0["title"],
                        "reason": h0["reason"],
                    }
                )
                results["errors"].append(
                    f"Target '{h0['rel_path']}' is historical and cannot be mutated ({h0['reason']})."
                )
                return results
            classified["authoritative"].extend(direct_cls["authoritative"])

    # Validate authoritative note identification
    auth_list = classified["authoritative"]
    if not auth_list:
        if not auto:
            results["errors"].append(
                "No authoritative note identified. Provide --target <note> or name an entity/concept."
            )
        else:
            results["errors"].append(
                "Skipping edits: authoritative single-source note could not be resolved."
            )
        return results

    auth_entry = auth_list[0]
    auth_path: Path = auth_entry["path"]
    auth_title: str = auth_entry["title"]

    # Double-check defense-in-depth on authoritative path before planning writes
    is_res_auth, res_reason_auth = is_reserved_or_instruction_path(auth_path, vault_root)
    if is_res_auth:
        results["errors"].append(
            f"Refusing to mutate reserved path {auth_entry['rel_path']}: {res_reason_auth}"
        )
        return results

    planned_writes: List[Dict[str, Any]] = []

    # 3. Plan Authoritative Note Update (body-only replacement, frontmatter protected)
    try:
        auth_bytes = auth_path.read_bytes()
        auth_sha = _sha256_bytes(auth_bytes)
        auth_content = auth_bytes.decode("utf-8")
        fm_prefix, _fm_yaml, orig_body = _split_frontmatter(auth_content)

        auth_warnings: List[str] = []
        new_body, auth_replacements = _replace_stale_in_authoritative_body(
            orig_body,
            stale_claim=clean_stale,
            fact=fact,
            replacement=replacement,
            warnings_out=auth_warnings,
        )
        for aw in auth_warnings:
            results["warnings"].append(f"{auth_entry['rel_path']}: {aw}")
        if auth_warnings:
            results["authoritative_updated"].append(
                {
                    "rel_path": auth_entry["rel_path"],
                    "title": auth_title,
                    "replacements": 0,
                    "status": "skipped_unclosed_fence",
                }
            )
            results["errors"].append(
                f"Authoritative note '{auth_entry['rel_path']}' skipped due to unclosed code fence; aborting sweep with 0 writes."
            )
            return results

        if auth_replacements == 0:
            insert_text = replacement if replacement is not None else fact
            if insert_text not in orig_body and fact not in orig_body:
                nl = "\r\n" if "\r\n" in auth_content else "\n"
                new_body = (
                    orig_body.rstrip()
                    + f"{nl}{nl}> [!NOTE] Architectural Specification Update{nl}> {insert_text}{nl}"
                )

        if new_body != orig_body:
            updated_auth = update_frontmatter_date(fm_prefix + new_body)
            diff_text = _build_unified_diff(
                auth_entry["rel_path"], auth_content, updated_auth
            )
            planned_writes.append(
                {
                    "path": auth_path,
                    "rel_path": auth_entry["rel_path"],
                    "expected_sha256": auth_sha,
                    "new_content": updated_auth,
                }
            )
            results["diffs"].append({"rel_path": auth_entry["rel_path"], "diff": diff_text})
            results["authoritative_updated"].append(
                {
                    "rel_path": auth_entry["rel_path"],
                    "title": auth_title,
                    "replacements": auth_replacements,
                    "status": "planned" if effective_dry_run else "updated",
                }
            )
        else:
            results["authoritative_updated"].append(
                {
                    "rel_path": auth_entry["rel_path"],
                    "title": auth_title,
                    "replacements": 0,
                    "status": "unchanged",
                }
            )
    except Exception as e:
        results["errors"].append(
            f"Failed to prepare update for authoritative note {auth_path}: {e}"
        )
        return results

    # 4. Plan Restatement Refactoring (explicit stale_claim ONLY — zero keyword fallback)
    stale_patterns = [clean_stale]
    for rest in classified["restatement"]:
        r_path: Path = rest["path"]
        is_res_r, _ = is_reserved_or_instruction_path(r_path, vault_root)
        if is_res_r:
            continue
        try:
            r_bytes = r_path.read_bytes()
            r_sha = _sha256_bytes(r_bytes)
            r_content = r_bytes.decode("utf-8")
            rest_warnings: List[str] = []
            new_content, count = replace_restatements_with_link(
                r_content,
                stale_patterns=stale_patterns,
                authoritative_title=auth_title,
                warnings_out=rest_warnings,
            )
            for rw in rest_warnings:
                results["warnings"].append(f"{rest['rel_path']}: {rw}")
            if count > 0 and new_content != r_content:
                new_content = update_frontmatter_date(new_content)
                diff_text = _build_unified_diff(rest["rel_path"], r_content, new_content)
                planned_writes.append(
                    {
                        "path": r_path,
                        "rel_path": rest["rel_path"],
                        "expected_sha256": r_sha,
                        "new_content": new_content,
                    }
                )
                results["diffs"].append({"rel_path": rest["rel_path"], "diff": diff_text})
                results["restatements_refactored"].append(
                    {
                        "rel_path": rest["rel_path"],
                        "title": rest["title"],
                        "replacements": count,
                        "status": "planned" if effective_dry_run else "refactored_to_wikilink",
                    }
                )
        except Exception as e:
            results["errors"].append(f"Failed to prepare restatement {r_path}: {e}")
            return results

    # 5. Plan log.md audit entry if any note changes are planned
    log_file = vault_root / "log.md"
    if (
        planned_writes
        and log_file.exists()
        and not _has_symlink_component(log_file, vault_root)
    ):
        try:
            log_bytes = log_file.read_bytes()
            log_sha = _sha256_bytes(log_bytes)
            cur_log = log_bytes.decode("utf-8")
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            log_entry = [
                f"\n## [{today_str}] correct | {auth_title}",
                f"- **Fact**: {fact}",
                f"- **Authoritative**: `[[{auth_entry['rel_path']}]]` (updated)",
            ]
            if results["restatements_refactored"]:
                log_entry.append("- **Refactored Restatements**:")
                for rf in results["restatements_refactored"]:
                    log_entry.append(
                        f"  - `[[{rf['rel_path']}]]` ({rf['replacements']} occurrence(s) linked)"
                    )
            if results["historical_preserved"]:
                log_entry.append(
                    f"- **Preserved Historical Records**: {len(results['historical_preserved'])} notes preserved"
                )
            log_entry.append("")

            if "## [" in cur_log:
                first_idx = cur_log.index("## [")
                new_log = (
                    cur_log[:first_idx]
                    + "\n".join(log_entry).lstrip("\n")
                    + "\n"
                    + cur_log[first_idx:]
                )
            else:
                new_log = cur_log + "\n" + "\n".join(log_entry)

            planned_writes.append(
                {
                    "path": log_file,
                    "rel_path": "log.md",
                    "expected_sha256": log_sha,
                    "new_content": new_log,
                }
            )
        except Exception as e:
            results["errors"].append(f"Failed to prepare log.md update: {e}")
            return results

    if effective_dry_run:
        return results

    # 6. Pre-write all-or-nothing CAS check across every planned target
    for item in planned_writes:
        p: Path = item["path"]
        try:
            if p.is_symlink():
                results["errors"].append(f"Refusing to write symlink: {item['rel_path']}")
                return results
            cur_sha = _sha256_bytes(p.read_bytes())
            if cur_sha != item["expected_sha256"]:
                results["cas_conflict"] = True
                results["cas_conflicts"].append(item["rel_path"])
                results["errors"].append(
                    f"CAS conflict on '{item['rel_path']}': file modified concurrently since read."
                )
        except FileNotFoundError:
            results["cas_conflict"] = True
            results["cas_conflicts"].append(item["rel_path"])
            results["errors"].append(
                f"CAS conflict on '{item['rel_path']}': file no longer exists."
            )
        except Exception as e:
            results["errors"].append(f"Failed pre-write verification on {item['rel_path']}: {e}")

    if results["errors"] or results["cas_conflict"]:
        return results

    # 7. Execute atomic writes (temp + fsync + os.replace)
    for item in planned_writes:
        try:
            _atomic_write_text(
                item["path"],
                item["new_content"],
                expected_sha256=item["expected_sha256"],
            )
        except CASConflictError as e:
            results["cas_conflict"] = True
            results["cas_conflicts"].append(item["rel_path"])
            results["errors"].append(str(e))
            return results
        except Exception as e:
            results["errors"].append(f"Failed atomic write on {item['rel_path']}: {e}")
            return results

    results["applied"] = True
    return results


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Sweep a corrected fact through the OKF v0.2 Knowledge Compiler vault (Plan/Diff preview by default; pass --apply to write)."
    )
    parser.add_argument(
        "fact", nargs="?", help="The corrected fact, stated as it is now true."
    )
    parser.add_argument(
        "--stale", "-s", help="Exact stale claim or phrase to find and replace (required)."
    )
    parser.add_argument(
        "--target", "-t", help="Authoritative note title or path to update."
    )
    parser.add_argument(
        "--replacement",
        "-r",
        default=None,
        help="Optional explicit replacement text for authoritative body matches.",
    )
    parser.add_argument("--vault-path", "-p", help="Root path of the knowledge vault.")
    parser.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help="Apply planned changes atomically with SHA-256 CAS checks.",
    )
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        default=False,
        help="Preview planned changes without modifying files (default).",
    )
    parser.add_argument(
        "--auto", action="store_true", help="Autonomous mode for agent pipelines."
    )
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON."
    )

    args = parser.parse_args(argv)

    if not args.fact or not str(args.fact).strip():
        parser.print_help()
        sys.exit(2)

    if args.vault_path:
        vault_root = Path(args.vault_path).expanduser().resolve()
    else:
        vault_root = find_vault_root(None)

    if not vault_root.exists() or not vault_root.is_dir() or not (vault_root / "wiki").is_dir():
        err_payload = {
            "vault_path": str(vault_root),
            "fact": args.fact,
            "stale_claim": args.stale,
            "dry_run": True,
            "applied": False,
            "errors": [f"Vault path does not exist or is missing wiki/ directory: {vault_root}"],
        }
        if args.json:
            print(json.dumps(err_payload, indent=2))
        else:
            print(
                f"Error: Vault path does not exist or is missing wiki/ directory: {vault_root}",
                file=sys.stderr,
            )
        sys.exit(2)

    is_apply = bool(args.apply and not args.dry_run)
    if is_apply and (not args.stale or not str(args.stale).strip()):
        err_payload = {
            "vault_path": str(vault_root),
            "fact": args.fact,
            "stale_claim": args.stale,
            "dry_run": False,
            "applied": False,
            "errors": [
                "Explicit stale_claim (--stale) is required when passing --apply."
            ],
        }
        if args.json:
            print(json.dumps(err_payload, indent=2))
        else:
            print(
                "Error: Explicit stale_claim (--stale) is required when passing --apply.",
                file=sys.stderr,
            )
        sys.exit(2)
    results = execute_vault_correction(
        vault_root=vault_root,
        fact=args.fact,
        stale_claim=args.stale,
        target_authoritative=args.target,
        dry_run=not is_apply,
        auto=args.auto,
        replacement=args.replacement,
        apply=is_apply,
    )

    exit_code = 0
    if results.get("cas_conflict"):
        exit_code = 2
    elif results.get("errors"):
        exit_code = 1

    if args.json:
        print(json.dumps(results, indent=2))
        sys.exit(exit_code)

    mode_label = "APPLIED" if is_apply and exit_code == 0 else "PLAN / DIFF PREVIEW"
    print(f"\n🔍 OKF v0.2 Vault Correction Sweep ({mode_label})")
    print(f"📁 Vault: {vault_root}")
    print(f'📌 Corrected Fact: "{args.fact}"\n')

    if results["authoritative_updated"]:
        print("  AUTHORITATIVE (Source of Truth):")
        for au in results["authoritative_updated"]:
            print(f"    ✓ {au['rel_path']}  ← {au['status']}")

    if results["restatements_refactored"]:
        print("\n  RESTATEMENTS (Refactored to Wikilinks):")
        for rf in results["restatements_refactored"]:
            print(
                f"    🔗 {rf['rel_path']}  → {rf['replacements']} assertion(s) ({rf['status']})"
            )

    if results["historical_preserved"]:
        print(
            f"\n  HISTORICAL RECORDS ({len(results['historical_preserved'])} notes preserved):"
        )
        for hp in results["historical_preserved"][:5]:
            print(f"    ✋ {hp['rel_path']}  ({hp['reason']})")
        if len(results["historical_preserved"]) > 5:
            print(
                f"    ... and {len(results['historical_preserved']) - 5} more historical notes."
            )

    if results.get("diffs") and not is_apply:
        print("\n  PLANNED DIFFS:")
        for d in results["diffs"]:
            if d["diff"]:
                print(d["diff"].rstrip())

    if results.get("warnings"):
        print("\n  ⚠️ WARNINGS:")
        for w in results["warnings"]:
            print(f"    • {w}")

    if results["errors"]:
        print("\n  ❌ ERRORS:")
        for err in results["errors"]:
            print(f"    • {err}")

    summary_counts = (
        f"{len(results['authoritative_updated'])} authoritative, "
        f"{len(results['restatements_refactored'])} restatements, "
        f"{len(results['historical_preserved'])} historical notes preserved."
    )
    print(f"\n📊 Summary: {summary_counts}")
    if not is_apply and exit_code == 0:
        print("Plan preview completed (0 files modified). Re-run with --apply to write changes.")

    if exit_code != 0:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
