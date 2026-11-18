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
"""Stateless Pure-Stdlib Multi-Field Okapi BM25 Vault Search & Duplicate Checker.

Implements an in-memory, single-pass Okapi BM25 (`k1=1.5`, `b=0.75`) search and
pre-ingest duplicate detection engine for Open Knowledge Format (OKF v0.2)
Markdown vaults:
- Zero index files, zero `.sqlite` databases, and zero mutations inside `$VAULT/`.
- Linear `O(N)` identifier-aware tokenizer splitting `CamelCase`, `ACRONYMBoundary`,
  and `-`/`_`/`/`/`.`, while stripping stray boolean operators and punctuation.
- Multi-field weighted BM25 scoring across `title` (3.0x), `aliases` (2.5x),
  `tags` (2.0x), `headings` (1.5x), and `body` (1.0x), with folder/type boosts
  (`1.2x` for `wiki/concepts/` and `wiki/patterns/`) and lifecycle demotion
  (`0.4x` for `deprecated`, `archived`, or `superseded` notes).
- Excludes `raw/` by default; when `--include-raw` is passed, applies a `0.7x`
  weight and fences every `raw/` excerpt inside `<untrusted-snippet source="...">`.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any
import unicodedata

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import okf  # noqa: E402
from vault_lint import find_vault_root  # noqa: E402

BM25_K1: float = 1.5
BM25_B: float = 0.75

FIELD_WEIGHT_TITLE: float = 3.0
FIELD_WEIGHT_ALIASES: float = 2.5
FIELD_WEIGHT_TAGS: float = 2.0
FIELD_WEIGHT_HEADINGS: float = 1.5
FIELD_WEIGHT_BODY: float = 1.0

CONCEPT_OR_PATTERN_BOOST: float = 1.2
DEPRECATED_OR_ARCHIVED_DEMOTION: float = 0.4
RAW_NOTE_WEIGHT: float = 0.7

IGNORED_PATH_PARTS: frozenset[str] = frozenset(
    {".obsidian", ".git", "__pycache__", ".venv", ".agents", ".gemini"}
)

_STOP_OPERATORS: frozenset[str] = frozenset({"and", "or", "not", "near"})
_DEMOTED_STATUSES: frozenset[str] = frozenset(
    {"deprecated", "archived", "superseded"}
)
_BOOSTED_TYPES: frozenset[str] = frozenset({"concept", "pattern"})

_INVISIBLE_FORMAT_RE = re.compile(
    r"[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\U000e0000-\U000e007f]"
)
_ALNUM_WORD_RE = re.compile(r"[^\W_]+")
_HEADING_LINE_RE = re.compile(r"^[ \t]{0,3}#{1,6}[ \t]+(.+)$")
_WIKILINK_ALIASED_RE = re.compile(
    r"\[\[([^\[\]|\n]{1,512})\\?\|([^\[\]\n]{1,512})\]\]"
)
_WIKILINK_PLAIN_RE = re.compile(r"\[\[([^\[\]\n]{1,512})\]\]")
_MD_LINK_LABEL_RE = re.compile(r"(?<!!)\[([^\[\]\n]{1,512})\]\([^()\n]{1,512}\)")
_BLOCKQUOTE_LINE_RE = re.compile(r"(?m)^[ \t]*>+[ \t]*")
_MD_SYNTAX_CHARS_RE = re.compile(r"[*_`|#~]+")
_WHITESPACE_RUN_RE = re.compile(r"\s+")

_PROTECTED_QUERY_TECH_WORDS: frozenset[str] = frozenset(
    {
        "cloud",
        "google",
        "aws",
        "azure",
        "gcp",
        "spanner",
        "cloud spanner",
        "alloydb",
        "alloydb for postgresql",
        "bigquery",
        "cloud sql",
        "cloud run",
        "cloud storage",
        "cloud kms",
        "cloud workstations",
        "cloud pub/sub",
        "pub/sub",
        "vertex",
        "vertex ai",
        "gemini",
        "apigee",
        "apigee api management",
        "memorystore",
        "kubernetes",
        "google kubernetes engine",
        "database migration service",
        "migration center",
        "security command center",
        "model armor",
        "gke",
        "gce",
        "gcs",
        "adk",
        "mcp",
        "a2a",
        "okf",
        "kafka",
        "spark",
        "redis",
        "postgres",
        "postgresql",
        "mysql",
        "oracle",
        "sap",
        "enterprise",
        "global",
        "national",
        "regional",
        "general",
        "united",
        "american",
        "northern",
        "southern",
        "eastern",
        "western",
        "central",
        "federal",
        "public",
        "private",
        "digital",
        "modern",
        "open",
        "core",
        "bank",
        "banking",
        "financial",
        "finance",
        "insurance",
        "retail",
        "health",
        "healthcare",
        "energy",
        "utility",
        "telecom",
        "media",
        "group",
        "corp",
        "corporation",
        "inc",
        "llc",
        "ltd",
        "company",
        "industries",
        "holdings",
        "partners",
        "solutions",
        "technologies",
        "system",
        "systems",
        "service",
        "services",
        "platform",
        "data",
        "security",
        "network",
        "server",
        "database",
        "storage",
        "compute",
        "agent",
        "agents",
        "model",
        "armor",
        "migration",
        "center",
        "workstations",
    }
)


def _strip_invisible_and_normalize(text: str) -> str:
    """Strip invisible format/bidi/tag characters and NFKC-normalize in O(N) time."""
    if not text:
        return ""
    if text.isascii():
        return text
    cleaned = _INVISIBLE_FORMAT_RE.sub("", text)
    return unicodedata.normalize("NFKC", cleaned)


def _fold_diacritics(word: str) -> str:
    """Fold combining diacritical marks on Latin characters while preserving non-combining scripts (CJK, Cyrillic)."""
    if word.isascii():
        return word
    decomposed = unicodedata.normalize("NFKD", word)
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return unicodedata.normalize("NFKC", stripped)


def _is_valid_bm25_token(tok: str) -> bool:
    if not tok or tok in _STOP_OPERATORS:
        return False
    if len(tok) >= 2 or tok.isdigit():
        return True
    return not tok.isascii()


def _is_cjk_char(ch: str) -> bool:
    cp = ord(ch)
    return cp >= 0x2E80


def _append_token_with_folded(tokens: list[str], low_tok: str) -> None:
    if _is_valid_bm25_token(low_tok):
        tokens.append(low_tok)
    if not low_tok.isascii():
        folded = _fold_diacritics(low_tok).lower()
        if folded != low_tok and _is_valid_bm25_token(folded):
            tokens.append(folded)
        # Emit overlapping 2-character CJK/Kana bigrams for sub-phrase CJK matching
        cjk_runs: list[str] = []
        curr: list[str] = []
        for ch in low_tok:
            if _is_cjk_char(ch):
                curr.append(ch)
            else:
                if len(curr) >= 2:
                    cjk_runs.append("".join(curr))
                curr = []
        if len(curr) >= 2:
            cjk_runs.append("".join(curr))
        for run in cjk_runs:
            if len(run) > 2:
                for i in range(len(run) - 1):
                    bg = run[i : i + 2]
                    tokens.append(bg)


def _split_camel_and_acronym(word: str) -> list[str]:
    """Split an alphanumeric identifier on CamelCase and ACRONYMBoundary in O(N) time.

    Examples:
      - "BigQueryTable" -> ["Big", "Query", "Table"]
      - "HTTPServerV2" -> ["HTTP", "Server", "V2"]
      - "bm25" -> ["bm25"]
    """
    n = len(word)
    if n <= 1 or word.islower() or word.isdigit() or word.isupper():
        return [word]
    parts: list[str] = []
    start = 0
    for i in range(1, n):
        prev_c = word[i - 1]
        curr_c = word[i]
        if (
            (prev_c.islower() and curr_c.isupper())
            or (prev_c.isdigit() and curr_c.isupper())
            or (
                prev_c.isupper()
                and curr_c.isupper()
                and i + 1 < n
                and word[i + 1].islower()
            )
        ):
            parts.append(word[start:i])
            start = i
    parts.append(word[start:])
    return parts


def tokenize_for_bm25(text: str) -> list[str]:
    """Tokenize text or query into lowercase BM25 terms in linear O(N) time.

    - Safely ignores boolean operators (`AND`, `OR`, `NOT`, `NEAR`) and punctuation
      (`*`, `"`, `(`, `)`, `:`, `^`, `~`, `\\`, `[`, `]`, null bytes).
    - Splits compound identifiers on `-`, `_`, `/`, `.` as well as `CamelCase`
      and `ACRONYMBoundary`, preserving compound CamelCase tokens alongside their
      sub-parts (`BigQueryTable` -> `["bigquerytable", "big", "query", "table"]`,
      `HTTPServerV2` -> `["httpserverv2", "http", "server", "v2"]`).
    """
    if not text:
        return []
    norm = _strip_invisible_and_normalize(text)
    tokens: list[str] = []
    for raw_word in _ALNUM_WORD_RE.findall(norm):
        low_word = raw_word.lower()
        if low_word in _STOP_OPERATORS:
            continue
        if raw_word.islower() or raw_word.isdigit() or raw_word.isupper():
            _append_token_with_folded(tokens, low_word)
            continue
        sub_parts = _split_camel_and_acronym(raw_word)
        if len(sub_parts) <= 1:
            _append_token_with_folded(tokens, low_word)
            continue
        _append_token_with_folded(tokens, low_word)
        for part in sub_parts:
            low_part = part.lower()
            if low_part in _STOP_OPERATORS:
                continue
            _append_token_with_folded(tokens, low_part)
    return tokens


def _tokenize_atomic_leaves(text: str) -> list[str]:
    """Tokenize text into atomic leaf tokens (without compound CamelCase wrapper tokens)."""
    if not text:
        return []
    norm = _strip_invisible_and_normalize(text)
    leaves: list[str] = []
    for raw_word in _ALNUM_WORD_RE.findall(norm):
        low_word = raw_word.lower()
        if low_word in _STOP_OPERATORS:
            continue
        sub_parts = _split_camel_and_acronym(raw_word)
        for part in sub_parts:
            low_part = part.lower()
            if low_part in _STOP_OPERATORS:
                continue
            _append_token_with_folded(leaves, low_part)
    return leaves


def expand_customer_anonymization_variants(
    anonymizations: dict[str, str],
) -> dict[str, str]:
    """Expand customer entity names with hyphen, underscore, concatenated, and distinctive-brand variants."""
    expanded: dict[str, str] = {}
    for cust_name, archetype in list(anonymizations.items()):
        if cust_name.strip().lower() in _PROTECTED_QUERY_TECH_WORDS:
            continue
        expanded[cust_name] = archetype

    for cust_name, archetype in list(expanded.items()):
        words = _ALNUM_WORD_RE.findall(cust_name)
        parts = (
            _split_camel_and_acronym(words[0])
            if len(words) == 1
            else words
        )
        if len(parts) >= 2:
            for joined in (
                "-".join(parts),
                "_".join(parts),
                "".join(parts),
                " ".join(parts),
            ):
                if (
                    len(joined) >= 2
                    and joined.lower() not in _PROTECTED_QUERY_TECH_WORDS
                    and joined not in expanded
                ):
                    expanded[joined] = archetype
            first_part = parts[0]
            if (
                len(first_part) >= 4
                and first_part.lower() not in _PROTECTED_QUERY_TECH_WORDS
                and first_part not in expanded
            ):
                expanded[first_part] = archetype
    return expanded


def normalize_query_for_dlp(query: str) -> str:
    """Normalize invisible characters, fullwidth NFKC characters, and Latin diacritics for query DLP matching."""
    norm = _strip_invisible_and_normalize(query)
    if norm.isascii():
        return norm
    out_chars: list[str] = []
    for ch in norm:
        if ord(ch) < 0x0250:
            folded = _fold_diacritics(ch)
            out_chars.append(folded if folded else ch)
        else:
            out_chars.append(ch)
    return "".join(out_chars)


def compute_bm25_idf(n_docs: int, df: int) -> float:
    """Compute standard positive Okapi BM25 IDF: ln(1 + (N - df + 0.5) / (df + 0.5))."""
    if n_docs <= 0 or df <= 0:
        return 0.0
    capped_df = min(df, n_docs)
    return math.log(1.0 + (n_docs - capped_df + 0.5) / (capped_df + 0.5))


def _escape_xml_text(s: str) -> str:
    """Escape `&`, `<`, and `>` so untrusted text cannot close or open XML/HTML tags."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_xml_attr(s: str) -> str:
    """Escape `&`, `<`, `>`, `\"`, and `'` for safe XML attribute emission."""
    return (
        _escape_xml_text(s)
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def format_untrusted_raw_snippet(rel_path: str, snippet_text: str) -> str:
    """Wrap an excerpt from `raw/` inside `<untrusted-snippet source=\"raw/...\">...</untrusted-snippet>`.

    Escapes all `<` and `>` characters inside `snippet_text` and `rel_path` so
    malicious raw content containing literal `</untrusted-snippet>` can never
    break out of the tag fence.
    """
    clean_chars = [
        ch if (ord(ch) >= 32 or ch in ("\t", "\n")) else " "
        for ch in snippet_text
    ]
    collapsed = _WHITESPACE_RUN_RE.sub(" ", "".join(clean_chars)).strip()
    safe_source = _escape_xml_attr(rel_path)
    safe_body = _escape_xml_text(collapsed)
    return f'<untrusted-snippet source="{safe_source}">{safe_body}</untrusted-snippet>'


def _coerce_string_list(val: Any) -> list[str]:
    if isinstance(val, list):
        return [
            str(item).strip()
            for item in val
            if item is not None and str(item).strip()
        ]
    if isinstance(val, str) and val.strip():
        return [val.strip()]
    return []


def _build_plain_excerpt(text: str, max_chars: int = 240) -> str:
    """Convert markdown body prose into a clean single-line excerpt in O(1) bounded time."""
    sample = text[:8192]
    if "<!--" in sample:
        sample = okf._strip_html_comments_linear(sample)
    if "```" in sample or "~~~" in sample:
        sample = okf._strip_fenced_code_linear(sample)
    sample = sample[:4096]
    unwrapped = _WIKILINK_ALIASED_RE.sub(r"\2", sample)
    unwrapped = _WIKILINK_PLAIN_RE.sub(r"\1", unwrapped)
    unwrapped = _MD_LINK_LABEL_RE.sub(r"\1", unwrapped)
    unwrapped = _BLOCKQUOTE_LINE_RE.sub(" ", unwrapped)
    cleaned = _MD_SYNTAX_CHARS_RE.sub(" ", unwrapped)
    collapsed = _WHITESPACE_RUN_RE.sub(" ", cleaned).strip()
    if len(collapsed) <= max_chars:
        return collapsed
    return collapsed[:max_chars] + "..."


def extract_note_fields(
    content_or_path: str | Path,
    stem: str = "",
) -> dict[str, Any]:
    """Parse an OKF Markdown note into separate fields for multi-field BM25 indexing."""
    if isinstance(content_or_path, Path):
        try:
            content = content_or_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            content = ""
        note_stem = content_or_path.stem
    else:
        content = content_or_path
        if "/" in stem or stem.endswith(".md"):
            note_stem = Path(stem).stem
        else:
            note_stem = stem or "Untitled"

    _fm_prefix, yaml_text, body = okf.split_frontmatter(content)
    if len(body) > 262_144:
        body = body[:262_144]
    fm: dict[str, Any] = {}
    yaml_within_cap = (
        yaml_text is not None
        and len(yaml_text) <= okf.MAX_FRONTMATTER_BYTES
        and not okf._DEEP_BRACKET_RE.search(yaml_text)
    )
    if yaml_text and yaml_within_cap:
        try:
            parsed_fm = okf.parse_frontmatter(
                yaml_text, strict=False, use_pyyaml=False
            )
            if isinstance(parsed_fm, dict):
                fm = parsed_fm
        except Exception:
            fm = {}

    raw_title = fm.get("title")
    fm_title = (
        str(raw_title).strip()
        if raw_title is not None and str(raw_title).strip()
        else ""
    )
    title = fm_title or note_stem
    if fm_title and fm_title.lower() != note_stem.lower():
        title_index_text = f"{fm_title} {note_stem}"
    else:
        title_index_text = title

    aliases = _coerce_string_list(fm.get("aliases"))
    if not aliases and yaml_text and yaml_within_cap and "alias" in yaml_text.lower():
        aliases = okf.extract_string_list(yaml_text, "aliases")

    tags = _coerce_string_list(fm.get("tags"))
    if not tags and yaml_text and yaml_within_cap and "tag" in yaml_text.lower():
        tags = okf.extract_string_list(yaml_text, "tags")

    raw_type = fm.get("type")
    note_type = str(raw_type).strip() if raw_type is not None else ""
    raw_status = fm.get("status")
    status = (
        str(raw_status).strip()
        if raw_status is not None and str(raw_status).strip()
        else "stable"
    )

    body_no_comments = (
        okf._strip_html_comments_linear(body) if "<!--" in body else body
    )
    has_fences = "```" in body_no_comments or "~~~" in body_no_comments
    body_no_fences = (
        okf._strip_fenced_code_linear(body_no_comments)
        if has_fences
        else body_no_comments
    )

    heading_lines: list[str] = []
    prose_lines: list[str] = []
    for line in body_no_fences.splitlines():
        if line.lstrip().startswith("#"):
            m_h = _HEADING_LINE_RE.match(line)
            if m_h:
                heading_lines.append(m_h.group(1).strip())
                continue
        prose_lines.append(line)

    headings_text = " ".join(heading_lines)
    non_heading_prose = "\n".join(prose_lines)

    # Also include code identifiers from fenced blocks in body indexing without polluting headings or excerpt
    body_index_text = non_heading_prose
    if has_fences:
        full_non_heading_lines = [
            ln
            for ln in body_no_comments.splitlines()
            if not (ln.lstrip().startswith("#") and _HEADING_LINE_RE.match(ln))
        ]
        body_index_text = "\n".join(full_non_heading_lines)

    excerpt_source = non_heading_prose.strip() or headings_text.strip() or title

    return {
        "frontmatter": fm,
        "title": title,
        "stem": note_stem,
        "title_index_text": title_index_text,
        "aliases": aliases,
        "tags": tags,
        "type": note_type,
        "status": status,
        "headings_text": headings_text,
        "body": non_heading_prose,
        "body_index_text": body_index_text,
        "excerpt_source": excerpt_source,
    }


def _compute_document_multiplier(
    rel_path: str,
    note_type: str,
    status: str,
    is_raw: bool,
) -> float:
    """Compute document-level folder/type, lifecycle, and raw multipliers."""
    mult = 1.0
    rel_parts = tuple(p.lower() for p in Path(rel_path).parts)
    is_concept_or_pattern_path = (
        (len(rel_parts) >= 2 and rel_parts[0] == "wiki" and rel_parts[1] in ("concepts", "patterns"))
        or (len(rel_parts) >= 1 and rel_parts[0] in ("concepts", "patterns"))
    )
    if is_concept_or_pattern_path or note_type.lower() in _BOOSTED_TYPES:
        mult *= CONCEPT_OR_PATTERN_BOOST

    is_archive_path = "archive" in rel_parts
    if status.lower() in _DEMOTED_STATUSES or is_archive_path:
        mult *= DEPRECATED_OR_ARCHIVED_DEMOTION

    if is_raw:
        mult *= RAW_NOTE_WEIGHT

    return mult


def iter_vault_markdown_files(
    root_dir: Path,
    *,
    subdirs: tuple[str, ...] | None = None,
    include_raw: bool = False,
) -> list[tuple[Path, str, bool]]:
    """Collect markdown files under `root_dir`, skipping ignored directories and symlinks.

    Returns a sorted list of `(full_path, rel_path, is_raw)` tuples.
    Never modifies any file or directory.
    """
    if not root_dir.exists() or root_dir.is_symlink() or not root_dir.is_dir():
        return []

    try:
        resolved_root = root_dir.resolve()
    except OSError:
        return []

    scan_targets: list[tuple[Path, bool]] = []
    if subdirs is not None:
        for sub in subdirs:
            sub_clean = sub.strip("/")
            is_raw_sub = sub_clean == "raw" or sub_clean.startswith("raw/")
            if is_raw_sub and not include_raw:
                continue
            target = (root_dir / sub_clean) if sub_clean else root_dir
            scan_targets.append((target, is_raw_sub))
    else:
        wiki_dir = root_dir / "wiki"
        if wiki_dir.exists():
            scan_targets.append((wiki_dir, False))
        if include_raw:
            raw_dir = root_dir / "raw"
            if raw_dir.exists():
                scan_targets.append((raw_dir, True))

    collected: dict[str, tuple[Path, str, bool]] = {}
    for target_dir, default_raw in scan_targets:
        if not target_dir.exists() or target_dir.is_symlink() or not target_dir.is_dir():
            continue
        try:
            target_resolved = target_dir.resolve()
            target_resolved.relative_to(resolved_root)
        except (OSError, ValueError):
            continue

        for walk_root, dirnames, filenames in os.walk(target_dir, followlinks=False):
            walk_path = Path(walk_root)
            if walk_path.is_symlink():
                dirnames[:] = []
                continue
            try:
                rel_walk = walk_path.relative_to(root_dir)
            except ValueError:
                dirnames[:] = []
                continue
            if any(part in IGNORED_PATH_PARTS for part in rel_walk.parts):
                dirnames[:] = []
                continue

            # Prune ignored directories, raw/ (when not include_raw), and symlinked directories in-place
            kept_dirs: list[str] = []
            for d in sorted(dirnames):
                if d in IGNORED_PATH_PARTS:
                    continue
                d_path = walk_path / d
                if d_path.is_symlink():
                    continue
                rel_d_parts = (*rel_walk.parts, d)
                if not include_raw and rel_d_parts and rel_d_parts[0] == "raw":
                    continue
                kept_dirs.append(d)
            dirnames[:] = kept_dirs

            for fname in sorted(filenames):
                if not fname.endswith(".md") or fname in IGNORED_PATH_PARTS:
                    continue
                f_path = walk_path / fname
                if f_path.is_symlink() or not f_path.is_file():
                    continue
                try:
                    f_resolved = f_path.resolve()
                    f_resolved.relative_to(resolved_root)
                    rel_file = f_path.relative_to(root_dir)
                except (OSError, ValueError):
                    continue
                if any(part in IGNORED_PATH_PARTS for part in rel_file.parts):
                    continue
                rel_str = rel_file.as_posix()
                is_raw_file = default_raw or (
                    len(rel_file.parts) > 0 and rel_file.parts[0] == "raw"
                )
                if is_raw_file and not include_raw:
                    continue
                if rel_str not in collected:
                    collected[rel_str] = (f_path, rel_str, is_raw_file)

    return [collected[k] for k in sorted(collected)]


def score_notes_bm25(
    root_dir: Path,
    query: str,
    *,
    subdirs: tuple[str, ...] | None = None,
    include_raw: bool = False,
    limit: int = 10,
    k1: float = BM25_K1,
    b: float = BM25_B,
) -> list[dict[str, Any]]:
    """Score markdown notes under `root_dir` using multi-field weighted Okapi BM25."""
    query_tokens = tokenize_for_bm25(query)
    if not query_tokens:
        return []
    unique_q_tokens = list(dict.fromkeys(query_tokens))
    q_token_set = frozenset(unique_q_tokens)

    files = iter_vault_markdown_files(
        root_dir, subdirs=subdirs, include_raw=include_raw
    )
    if not files:
        return []

    docs: list[dict[str, Any]] = []
    df_counts: Counter[str] = Counter()
    total_doc_len = 0

    for full_path, rel_path, is_raw in files:
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        fields = extract_note_fields(content, full_path.stem)
        title_toks = tokenize_for_bm25(fields["title_index_text"])
        alias_toks = tokenize_for_bm25(" ".join(fields["aliases"]))
        tag_toks = tokenize_for_bm25(" ".join(fields["tags"]))
        heading_toks = tokenize_for_bm25(fields["headings_text"])
        body_toks = tokenize_for_bm25(fields["body_index_text"])

        doc_len = max(
            1,
            len(title_toks)
            + len(alias_toks)
            + len(tag_toks)
            + len(heading_toks)
            + len(body_toks),
        )
        total_doc_len += doc_len

        # Only build per-field frequency maps for tokens present in the query
        title_tf: Counter[str] = Counter(t for t in title_toks if t in q_token_set)
        alias_tf: Counter[str] = Counter(t for t in alias_toks if t in q_token_set)
        tag_tf: Counter[str] = Counter(t for t in tag_toks if t in q_token_set)
        heading_tf: Counter[str] = Counter(t for t in heading_toks if t in q_token_set)
        body_tf: Counter[str] = Counter(t for t in body_toks if t in q_token_set)

        matched_q_terms = (
            set(title_tf)
            | set(alias_tf)
            | set(tag_tf)
            | set(heading_tf)
            | set(body_tf)
        )
        for qt in matched_q_terms:
            df_counts[qt] += 1

        docs.append(
            {
                "rel_path": rel_path,
                "is_raw": is_raw,
                "fields": fields,
                "doc_len": doc_len,
                "matched_q_terms": matched_q_terms,
                "field_tfs": (
                    (FIELD_WEIGHT_TITLE, title_tf),
                    (FIELD_WEIGHT_ALIASES, alias_tf),
                    (FIELD_WEIGHT_TAGS, tag_tf),
                    (FIELD_WEIGHT_HEADINGS, heading_tf),
                    (FIELD_WEIGHT_BODY, body_tf),
                ),
            }
        )

    n_docs = len(docs)
    if n_docs == 0:
        return []
    avgdl = max(1.0, total_doc_len / n_docs)

    idfs: dict[str, float] = {
        qt: compute_bm25_idf(n_docs, df_counts[qt])
        for qt in unique_q_tokens
        if df_counts[qt] > 0
    }
    if not idfs:
        return []

    scored_results: list[dict[str, Any]] = []
    for doc in docs:
        if not doc["matched_q_terms"]:
            continue

        norm_denom_factor = k1 * (1.0 - b + b * (doc["doc_len"] / avgdl))
        raw_bm25 = 0.0
        for qt in unique_q_tokens:
            idf = idfs.get(qt, 0.0)
            if idf <= 0.0:
                continue
            term_field_sum = 0.0
            for weight, tf_map in doc["field_tfs"]:
                tf = tf_map.get(qt, 0)
                if tf > 0:
                    term_field_sum += weight * ((tf * (k1 + 1.0)) / (tf + norm_denom_factor))
            raw_bm25 += idf * term_field_sum

        if raw_bm25 <= 0.0:
            continue

        fields = doc["fields"]
        is_raw = doc["is_raw"]
        rel_path = doc["rel_path"]
        mult = _compute_document_multiplier(
            rel_path=rel_path,
            note_type=fields["type"],
            status=fields["status"],
            is_raw=is_raw,
        )
        final_score = round(raw_bm25 * mult, 4)
        plain_excerpt = _build_plain_excerpt(fields["excerpt_source"], max_chars=240)
        if is_raw:
            raw_title = fields["title"]
            snippet_payload = (
                f"[{raw_title}] {plain_excerpt}"
                if raw_title and raw_title != plain_excerpt
                else plain_excerpt
            )
            excerpt = format_untrusted_raw_snippet(rel_path, snippet_payload)
            out_id = _escape_xml_attr(rel_path)
            out_title = _escape_xml_text(raw_title)
            out_type = _escape_xml_text(fields["type"] or "raw")
            out_status = _escape_xml_text(fields["status"])
            out_tags = [_escape_xml_text(t) for t in fields["tags"]]
            out_aliases = [_escape_xml_text(a) for a in fields["aliases"]]
        else:
            excerpt = plain_excerpt
            out_id = rel_path
            out_title = fields["title"]
            out_type = fields["type"] or "concept"
            out_status = fields["status"]
            out_tags = fields["tags"]
            out_aliases = fields["aliases"]

        fm = fields["frontmatter"]
        scored_results.append(
            {
                "id": out_id,
                "rel_path": out_id,
                "title": out_title,
                "label": out_title,
                "type": out_type,
                "status": out_status,
                "score": final_score,
                "bm25_score": final_score,
                "trust_tier": okf.derive_trust_tier(fm),
                "is_stale": okf.is_stale(fm),
                "tags": out_tags,
                "aliases": out_aliases,
                "excerpt": excerpt,
                "untrusted": is_raw,
            }
        )

    scored_results.sort(
        key=lambda r: (-float(r["score"]), str(r["id"]))
    )
    return scored_results[: max(1, limit)] if limit > 0 else scored_results


def search_vault(
    vault_root: Path | str,
    query: str,
    *,
    limit: int = 10,
    include_raw: bool = False,
    subdirs: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Execute a stateless multi-field Okapi BM25 search across `vault_root`."""
    v_root = Path(vault_root).expanduser().resolve()
    q_tokens = tokenize_for_bm25(query)
    hits = score_notes_bm25(
        v_root,
        query,
        subdirs=subdirs,
        include_raw=include_raw,
        limit=limit,
    )
    return {
        "query": query,
        "tokens": q_tokens,
        "vault": str(v_root),
        "include_raw": include_raw,
        "total_results": len(hits),
        "results": hits,
    }


query_vault = search_vault


def _normalize_exact_key(text: str) -> str:
    """Normalize a title, stem, or alias for exact duplicate matching (including Unicode scripts)."""
    norm = _strip_invisible_and_normalize(text).removesuffix(".md").strip().lower()
    if not norm:
        return ""
    words = [
        _fold_diacritics(w).lower()
        for w in _ALNUM_WORD_RE.findall(norm)
        if w not in _STOP_OPERATORS
    ]
    return " ".join(w for w in words if w)


def _jaccard_similarity(set_a: set[str], set_b: set[str]) -> float:
    if not set_a or not set_b:
        return 0.0
    inter = len(set_a & set_b)
    if inter == 0:
        return 0.0
    union = len(set_a | set_b)
    return inter / union if union > 0 else 0.0


def check_duplicate(
    vault_root: Path | str,
    candidate_text: str,
    *,
    limit: int = 5,
) -> dict[str, Any]:
    """Evaluate candidate title/topic against `wiki/` notes before creating a new note.

    Returns:
      {
          "query": candidate_text,
          "create_safety": "exists" | "probable" | "unknown",
          "matches": [{"id": rel_path, "title": title, "similarity": float, "bm25_score": float, "reason": str}, ...],
      }
    """
    v_root = Path(vault_root).expanduser().resolve()
    cand_norm = _normalize_exact_key(candidate_text)
    cand_full_set = set(tokenize_for_bm25(candidate_text))
    cand_leaf_set = set(_tokenize_atomic_leaves(candidate_text))

    if not cand_norm and not cand_full_set:
        return {
            "query": candidate_text,
            "create_safety": "unknown",
            "matches": [],
        }

    bm25_hits = score_notes_bm25(
        v_root,
        candidate_text,
        include_raw=False,
        limit=0,
    )
    bm25_by_id: dict[str, float] = {
        str(h["id"]): float(h["bm25_score"]) for h in bm25_hits
    }

    files = iter_vault_markdown_files(v_root, include_raw=False)
    evaluated: list[dict[str, Any]] = []

    for full_path, rel_path, _is_raw in files:
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        fields = extract_note_fields(content, full_path.stem)
        title = fields["title"]
        stem = fields["stem"]
        aliases = fields["aliases"]

        candidates_for_note = [title, stem, *aliases]
        exact_matched = False
        best_title_sim = 0.0

        for cand_target in candidates_for_note:
            t_norm = _normalize_exact_key(cand_target)
            if cand_norm and t_norm and cand_norm == t_norm:
                exact_matched = True
                best_title_sim = 1.0
                break
            t_leaf_set = set(_tokenize_atomic_leaves(cand_target))
            t_full_set = set(tokenize_for_bm25(cand_target))
            sim = max(
                _jaccard_similarity(cand_leaf_set, t_leaf_set),
                _jaccard_similarity(cand_full_set, t_full_set),
            )
            if sim > best_title_sim:
                best_title_sim = sim

        # Also check combined title + aliases token overlap
        combined_title_alias = f"{title} {stem} {' '.join(aliases)}"
        combined_leaf_set = set(_tokenize_atomic_leaves(combined_title_alias))
        combined_sim = _jaccard_similarity(cand_leaf_set, combined_leaf_set)
        if combined_sim > best_title_sim:
            best_title_sim = combined_sim

        # Compute query-token coverage across title + headings + aliases
        structural_leaf_set = combined_leaf_set | set(
            _tokenize_atomic_leaves(fields["headings_text"])
        )
        coverage = (
            len(cand_leaf_set & structural_leaf_set) / len(cand_leaf_set)
            if cand_leaf_set
            else 0.0
        )

        bm25_score = bm25_by_id.get(rel_path, 0.0)
        if not exact_matched and best_title_sim == 0.0 and bm25_score <= 0.0:
            continue

        tier = "unknown"
        reason = "low token overlap in wiki/"
        if exact_matched:
            tier = "exists"
            reason = "exact normalized title/stem/alias match"
        elif best_title_sim >= 0.85:
            tier = "exists"
            reason = f"high title/alias token overlap ({best_title_sim:.2f} >= 0.85)"
        elif best_title_sim >= 0.45:
            tier = "probable"
            reason = f"partial title/alias token overlap ({best_title_sim:.2f} >= 0.45)"
        elif bm25_score > 0.0 and coverage >= 0.60:
            tier = "probable"
            reason = (
                f"strong BM25 hit ({bm25_score:.2f}) with {coverage:.0%} query-token "
                "coverage in title/headings/aliases"
            )

        similarity_out = round(max(best_title_sim, coverage * 0.85), 4)
        if exact_matched:
            similarity_out = 1.0

        tier_rank = 2 if tier == "exists" else (1 if tier == "probable" else 0)
        evaluated.append(
            {
                "id": rel_path,
                "title": title,
                "similarity": similarity_out,
                "bm25_score": round(bm25_score, 4),
                "reason": reason,
                "_tier": tier,
                "_tier_rank": tier_rank,
            }
        )

    evaluated.sort(
        key=lambda m: (
            -int(m["_tier_rank"]),
            -float(m["similarity"]),
            -float(m["bm25_score"]),
            str(m["id"]),
        )
    )

    overall_safety = "unknown"
    if evaluated:
        top_tier = evaluated[0]["_tier"]
        if top_tier in ("exists", "probable"):
            overall_safety = top_tier

    clean_matches = [
        {
            "id": m["id"],
            "title": m["title"],
            "similarity": m["similarity"],
            "bm25_score": m["bm25_score"],
            "reason": m["reason"],
        }
        for m in evaluated[: max(1, limit)]
    ]

    return {
        "query": candidate_text,
        "create_safety": overall_safety,
        "matches": clean_matches,
    }


def _resolve_cli_vault_root(explicit_vault: str | None) -> Path:
    """Resolve `--vault` path without creating or modifying any files on disk."""
    if explicit_vault is not None:
        raw = explicit_vault.strip()
        if not raw:
            return Path("/nonexistent_invalid_vault_path")
        return Path(raw).expanduser().resolve()
    env_vault = os.environ.get("KC_VAULT_PATH") or os.environ.get("OBSIDIAN_VAULT_PATH")
    if env_vault and env_vault.strip():
        return Path(env_vault.strip()).expanduser().resolve()
    return find_vault_root(Path.cwd())


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `vault_query.py`."""
    parser = argparse.ArgumentParser(
        prog="vault_query.py",
        description="Stateless Pure-Stdlib Okapi BM25 Vault Search & Pre-Ingest Duplicate Checker.",
    )
    parser.add_argument(
        "query",
        nargs="?",
        default=None,
        help="Search query string or candidate note title.",
    )
    parser.add_argument(
        "--vault",
        default=None,
        help="Path to the OKF v0.2 vault root (must contain a wiki/ directory).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of results to return (default: 10).",
    )
    parser.add_argument(
        "--include-raw",
        action="store_true",
        help="Also search raw/**/*.md notes with 0.7x weight and <untrusted-snippet> fencing.",
    )
    parser.add_argument(
        "--federated",
        action="store_true",
        help="Query both the local vault and the shared OKF patterns repository.",
    )
    parser.add_argument(
        "--patterns-path",
        default=None,
        help="Optional path to the shared OKF patterns repository for --federated.",
    )
    parser.add_argument(
        "--check-duplicate",
        action="store_true",
        help="Run pre-ingest duplicate check against wiki/ notes (exists | probable | unknown).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON output.",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2

    if args.query is None or not str(args.query).strip():
        err_msg = "Missing or empty search query."
        if args.json:
            print(json.dumps({"error": err_msg}))
        else:
            sys.stderr.write(f"Error: {err_msg}\n")
        return 2

    vault_root = _resolve_cli_vault_root(args.vault)
    if not vault_root.is_dir() or not (vault_root / "wiki").is_dir():
        err_msg = f"Invalid or nonexistent vault root (missing wiki/ directory): {vault_root}"
        if args.json:
            print(json.dumps({"error": err_msg, "vault": str(vault_root)}))
        else:
            sys.stderr.write(f"Error: {err_msg}\n")
        return 2

    limit = max(1, int(args.limit)) if args.limit is not None else 10

    if args.check_duplicate:
        payload = check_duplicate(vault_root, args.query, limit=limit)
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(
                f"Duplicate Check for {args.query!r}: create_safety={payload['create_safety']}"
            )
            for item in payload["matches"]:
                print(
                    f"  - [{item['id']}] {item['title']} "
                    f"(similarity={item['similarity']:.2f}, bm25={item['bm25_score']:.2f}: {item['reason']})"
                )
        return 0

    if args.federated:
        from federation_provider import run_portable_federated_query

        pat_root = (
            Path(args.patterns_path).expanduser().resolve()
            if args.patterns_path
            else None
        )
        payload = run_portable_federated_query(
            query=args.query,
            obsidian_vault_root=vault_root,
            ce_patterns_root=pat_root,
            limit=limit,
        )
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(
                f"Federated Query {args.query!r}: {payload['total_results']} result(s)"
            )
            for item in payload["results"][:limit]:
                print(
                    f"  - [{item.get('source_plane', '')}] {item.get('title', item.get('id', ''))} "
                    f"(score={item.get('score', 0.0):.4f})"
                )
        return 0

    payload = search_vault(
        vault_root,
        args.query,
        limit=limit,
        include_raw=bool(args.include_raw),
    )
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(
            f"Vault Query {args.query!r}: {payload['total_results']} result(s)"
        )
        for item in payload["results"]:
            if item.get("untrusted"):
                print(
                    f"  - [UNTRUSTED RAW] (score={item['score']:.4f}) {item['excerpt']}"
                )
            else:
                print(
                    f"  - [{item['id']}] {item['title']} (score={item['score']:.4f})\n"
                    f"    {item['excerpt']}"
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
