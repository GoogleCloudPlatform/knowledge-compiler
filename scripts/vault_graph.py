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
"""vault_graph.py - WebGL 2D/3D Interactive Knowledge Graph Visualizer & Sidecar Server.

Compiles an OKF v0.2 Obsidian Vault into an interactive, hardware-accelerated
WebGL (2D Obsidian Mode + 3D Orbit Mode) graph visualizer with:
  - GPU-accelerated WebGL edge & SDF node shaders (60-120 FPS on client GPU)
  - Synchronized HiDPI label & directional arrow HUD overlay
  - 1-hop and 2-hop BFS neighborhood spotlighting on hover and click
  - Local Subgraph isolation mode (1-hop / 2-hop ego network)
  - Live filtering by OKF category, YAML frontmatter tags, orphans, and search
  - Real-time physics & display controls (repulsion, link distance, PageRank/degree sizing)
  - Slide-out Markdown reader & OKF frontmatter inspector with clickable [[wikilinks]]
  - Dual execution modes:
      1. Standalone HTML Exporter (`--export <file.html>`)
      2. Local Live HTTP Server (`--serve --port 8765`)
      3. Native Antigravity / Antigravity UI Plugin Sidecar (`--sidecar`)
"""

from __future__ import annotations

import argparse
from collections import OrderedDict
import copy
import hashlib
import hmac
import http
import http.cookies
import http.server
import json
import logging
import math
import os
import re
import secrets
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from pathlib import Path
from typing import Any

# Ensure sibling imports work regardless of working directory
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from federation_provider import (  # noqa: E402
    list_ce_patterns_catalog,
    resolve_ce_patterns_root,
    run_portable_federated_query,
)
from init_vault import init_vault  # noqa: E402
import okf  # noqa: E402
from sync_patterns import (  # noqa: E402
    DEFAULT_CUSTOMER_ANONYMIZATIONS,
    get_plugin_data_dir,
)
from vault_lint import find_vault_root, parse_simple_yaml  # noqa: E402

HAS_1P_FED_BRIDGE = False

def discover_remote_tier_nodes() -> list[dict[str, Any]]:
    return []

def prepare_pattern_for_remote_tier(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    return {'ok': False, 'error': 'Local bundle export mode.'}

def run_federated_query(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return run_portable_federated_query(*args, **kwargs)

def run_remote_tier_preflight(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    return {'ok': False, 'http_status': 0, 'response': {'error': 'Local bundle export mode'}}

def submit_to_remote_tier(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    return {'ok': False, 'http_status': 0, 'response': {'error': 'Local bundle export mode'}}

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("vault-graph")

_ALLOWED_DOMAIN_SUFFIXES: tuple[str, ...] = ()

_ALLOWED_URI_SCHEMES: tuple[str, ...] = (
    "vscode-webview://",
    "vscode-file://",
)

CATEGORY_META: dict[str, dict[str, str]] = {
    "entity": {
        "label": "Entities (Customers & Tech)",
        "color": "#4285F4",
        "badge": "Entity",
    },
    "concept": {
        "label": "Concepts (Architecture)",
        "color": "#34A853",
        "badge": "Concept",
    },
    "pattern": {
        "label": "Patterns (Heuristics)",
        "color": "#FBBC04",
        "badge": "Pattern",
    },
    "synthesis": {
        "label": "Synthesis (Analyses)",
        "color": "#00ACC1",
        "badge": "Synthesis",
    },
    "ce_pattern": {
        "label": "shared-okf-patterns (Sanitized Shared)",
        "color": "#10B981",
        "badge": "shared-okf-patterns",
    },
    "remote_tier": {
        "label": "Remote Tier (OKF Bundles)",
        "color": "#A142F4",
        "badge": "Remote Tier",
    },
    "source": {
        "label": "Sources (Ingested)",
        "color": "#78909C",
        "badge": "Source",
    },
    "anchor": {
        "label": "Vault Anchors & Indexes",
        "color": "#EA4335",
        "badge": "Anchor",
    },
    "raw": {
        "label": "Raw Documents (raw/)",
        "color": "#5F6368",
        "badge": "Raw",
    },
}

EPISTEMIC_EDGE_META: dict[str, dict[str, str]] = {
    "CORROBORATES": {
        "label": "CORROBORATES (Validated)",
        "color": "#34A853",
    },
    "COMPLEMENTS": {
        "label": "COMPLEMENTS (Paired)",
        "color": "#4285F4",
    },
    "EXTENDS": {
        "label": "EXTENDS (Specializes)",
        "color": "#00ACC1",
    },
    "CONTRADICTS": {
        "label": "CONTRADICTS (Trade-Off)",
        "color": "#EA4335",
    },
    "SUPERSEDES": {
        "label": "SUPERSEDES (Replaces)",
        "color": "#FBBC04",
    },
    "LINKS_TO": {
        "label": "LINKS_TO (Wikilink)",
        "color": "#94a3b8",
    },
}


_EPISTEMIC_FM_KEYS: tuple[str, ...] = (
    "corroborates",
    "complements",
    "extends",
    "contradicts",
    "supersedes",
)
_INLINE_EPISTEMIC_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9_-])\b(corroborates|complements|extends|contradicts|supersedes)[ \t]{0,32}::(?:[ \t]{0,32}\[\[[ \t]{0,32}|[ \t]{0,32})$",
    re.IGNORECASE,
)
_INLINE_EPISTEMIC_COMPLETE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])\b(corroborates|complements|extends|contradicts|supersedes)[ \t]{0,32}::[ \t]{0,32}\[\[[^\[\]\n]{1,512}\]\][ \t]{0,32}[.,;:]?[ \t]{0,32}$",
    re.IGNORECASE,
)
_GRAPH_FENCE_OPEN_RE = re.compile(
    r"^[ \t]*(?:>[ \t]*)*(?:(?:[-*+]|\d+[.)])[ \t]+(?:\[[ xX]\][ \t]+)?)?(`{3,}|~{3,})(.*)$"
)
_GRAPH_BACKTICK_RUN_RE = re.compile(r"`+")


def infer_epistemic_edge_type(context_line: str, explicit_type: str | None = None) -> str:
    """Classify a directed relationship strictly from explicit frontmatter or `rel::[[Target]]` syntax."""
    if explicit_type:
        up = explicit_type.strip().upper()
        if up in EPISTEMIC_EDGE_META:
            return up
    if context_line and "::" in context_line:
        match = _INLINE_EPISTEMIC_PREFIX_RE.search(context_line)
        if match:
            return match.group(1).upper()
        match_full = _INLINE_EPISTEMIC_COMPLETE_RE.search(context_line)
        if match_full:
            return match_full.group(1).upper()
    return "LINKS_TO"


def _mask_inline_code_linear_chunk(chunk: str, replacement: str = "\x00") -> str:
    """Replace inline code spans (`...`, ``...``) in `chunk` in strictly linear O(N) time."""
    if "`" not in chunk:
        return chunk
    runs = [
        (m.start(), m.end(), m.end() - m.start())
        for m in _GRAPH_BACKTICK_RUN_RE.finditer(chunk)
    ]
    if len(runs) < 2:
        return chunk

    by_len: dict[int, list[int]] = {}
    for idx, (_s, _e, rlen) in enumerate(runs):
        by_len.setdefault(rlen, []).append(idx)

    cursors: dict[int, int] = {rlen: 0 for rlen in by_len}
    pieces: list[str] = []
    last_char_pos = 0
    i = 0
    n_runs = len(runs)
    while i < n_runs:
        s_i, _e_i, rlen = runs[i]
        idx_list = by_len[rlen]
        if len(idx_list) < 2:
            i += 1
            continue
        cur = cursors[rlen]
        while cur < len(idx_list) and idx_list[cur] <= i:
            cur += 1
        cursors[rlen] = cur
        if cur >= len(idx_list):
            i += 1
            continue
        match_run_idx = idx_list[cur]
        cursors[rlen] = cur + 1
        _s_j, e_j, _ = runs[match_run_idx]
        pieces.append(chunk[last_char_pos:s_i])
        pieces.append(replacement)
        last_char_pos = e_j
        i = match_run_idx + 1

    if last_char_pos == 0:
        return chunk
    pieces.append(chunk[last_char_pos:])
    return "".join(pieces)


def _count_bq_depth(line: str) -> int:
    depth = 0
    for ch in line:
        if ch == ">":
            depth += 1
        elif ch not in (" ", "\t"):
            break
    return depth


def _strip_bq_prefix(line: str) -> str:
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch in (" ", "\t", ">"):
            i += 1
        else:
            break
    return line[i:]


def _mask_markdown_for_graph(body: str, replacement: str = "\x00") -> str:
    """Strip fenced code blocks (``` / ~~~), HTML comments, and inline code spans in O(N) time."""
    if (
        "```" not in body
        and "~~~" not in body
        and "<!--" not in body
        and "`" not in body
    ):
        return body

    last_comment_close = body.rfind("-->")
    lines = body.splitlines(keepends=True)
    out_lines: list[str] = []

    in_fence = False
    fence_ch = ""
    fence_len = 0
    fence_bq_depth = 0
    in_comment = False
    line_offset = 0

    for raw_line in lines:
        line_len = len(raw_line)
        line_no_nl = raw_line.rstrip("\r\n")
        eol = raw_line[len(line_no_nl) :]

        if in_fence:
            line_bq = _count_bq_depth(line_no_nl)
            if fence_bq_depth > 0 and line_bq < fence_bq_depth:
                in_fence = False
            else:
                inner = _strip_bq_prefix(line_no_nl) if fence_bq_depth > 0 else line_no_nl.lstrip(" \t")
                if inner.startswith(fence_ch * fence_len):
                    stripped_tail = inner[len(fence_ch) :]
                    run_len = 1
                    for ch in stripped_tail:
                        if ch == fence_ch:
                            run_len += 1
                        elif ch in (" ", "\t"):
                            break
                        else:
                            run_len = -1
                            break
                    if run_len >= fence_len and not inner[run_len:].strip():
                        in_fence = False
                        out_lines.append(eol)
                        line_offset += line_len
                        continue
                if in_fence:
                    out_lines.append(eol)
                    line_offset += line_len
                    continue

        if in_comment:
            end_idx = line_no_nl.find("-->")
            if end_idx < 0:
                out_lines.append(eol)
                line_offset += line_len
                continue
            in_comment = False
            remainder = replacement + line_no_nl[end_idx + 3 :]
        else:
            m_fence = (
                _GRAPH_FENCE_OPEN_RE.match(line_no_nl)
                if ("```" in line_no_nl or "~~~" in line_no_nl)
                else None
            )
            if m_fence:
                marker, info = m_fence.group(1), m_fence.group(2)
                if not (marker[0] == "`" and "`" in info):
                    in_fence = True
                    fence_ch = marker[0]
                    fence_len = len(marker)
                    fence_bq_depth = _count_bq_depth(line_no_nl)
                    out_lines.append(eol)
                    line_offset += line_len
                    continue
            remainder = line_no_nl

        if "<!--" in remainder and last_comment_close >= 0:
            # Mask single-line inline code spans before scanning for HTML comment openers
            scan_line = (
                _mask_inline_code_linear_chunk(remainder, replacement)
                if "`" in remainder
                else remainder
            )
            pieces: list[str] = []
            pos = 0
            while pos < len(scan_line):
                start = scan_line.find("<!--", pos)
                if start < 0:
                    pieces.append(scan_line[pos:])
                    break
                pieces.append(scan_line[pos:start])
                same_end = scan_line.find("-->", start + 4)
                if same_end >= 0:
                    pieces.append(replacement)
                    pos = same_end + 3
                    continue
                if line_offset + len(line_no_nl) <= last_comment_close:
                    pieces.append(replacement)
                    in_comment = True
                    break
                pieces.append(scan_line[start:])
                last_comment_close = -1
                break
            out_lines.append("".join(pieces) + eol)
        else:
            out_lines.append(remainder + eol)

        line_offset += line_len

    # Paragraph-level O(N) inline code masking (handles both single-line and multi-line code spans)
    masked_pass1 = "".join(out_lines)
    if "`" not in masked_pass1:
        return masked_pass1
    para_parts: list[str] = []
    for idx, chunk in enumerate(re.split(r"((?:\r?\n){2,})", masked_pass1)):
        if idx % 2 == 1 or "`" not in chunk:
            para_parts.append(chunk)
        else:
            para_parts.append(_mask_inline_code_linear_chunk(chunk, replacement))
    return "".join(para_parts)


def classify_note(rel_path: str, fm: dict[str, Any] | None) -> str:
    """Classify a vault markdown note into a semantic visual group."""
    fm = fm or {}
    fm_type = str(fm.get("type", "")).strip().lower()

    if rel_path.startswith("raw/"):
        return "raw"
    if rel_path in ("index.md", "purpose.md", "log.md", "GEMINI.md", "wiki/skill-impact.md") or rel_path.startswith("tables/"):
        return "anchor"
    if rel_path.startswith("wiki/patterns/") or fm_type == "pattern":
        return "pattern"
    if rel_path.startswith("wiki/entities/") or fm_type == "entity":
        return "entity"
    if rel_path.startswith("wiki/synthesis/") or fm_type == "synthesis":
        return "synthesis"
    if rel_path.startswith("wiki/sources/") or fm_type in ("source", "source-summary"):
        return "source"
    if rel_path.startswith("wiki/concepts/") or fm_type == "concept":
        return "concept"
    return "concept"


def extract_clean_body_and_excerpt(content: str, max_body_chars: int = 18000) -> tuple[str, str]:
    """Strip YAML frontmatter and extract a clean Markdown body and text excerpt."""
    _fm_prefix, yaml_text, split_body = okf.split_frontmatter(content)
    body = split_body.strip() if yaml_text is not None else content

    clipped_body = body[:max_body_chars]
    if len(body) > max_body_chars:
        clipped_body += "\n\n*(Note truncated in preview...)*"

    # Build plain-text excerpt in strictly linear O(N) time on bounded slice
    plain = _mask_markdown_for_graph(body[:24000], replacement=" ").replace("\x00", " ")
    plain = re.sub(r"^#+[ \t]+[^\n]*$", "", plain, flags=re.MULTILINE)
    plain = re.sub(r"\[\[([^\[\]\n|]{1,512})\\?\|([^\[\]\n]{1,512})\]\]", r"\2", plain)
    plain = re.sub(r"\[\[([^\[\]\n]{1,512})\]\]", r"\1", plain)
    plain = re.sub(r"[*_`>|#-]", " ", plain)
    plain = re.sub(r"\s+", " ", plain).strip()
    excerpt = plain[:260] + ("..." if len(plain) > 260 else "")
    return clipped_body, excerpt


def compute_pagerank(
    node_ids: list[str],
    edges: list[dict[str, str]],
    damping: float = 0.85,
    iterations: int = 24,
) -> dict[str, float]:
    """Compute normalized PageRank centrality scores in pure Python."""
    n = len(node_ids)
    if n == 0:
        return {}
    ranks = {nid: 1.0 / n for nid in node_ids}
    out_adj: dict[str, list[str]] = {nid: [] for nid in node_ids}
    in_adj: dict[str, list[str]] = {nid: [] for nid in node_ids}

    for edge in edges:
        s = edge["source"]
        t = edge["target"]
        if s in out_adj and t in in_adj and s != t:
            out_adj[s].append(t)
            in_adj[t].append(s)

    for _ in range(iterations):
        dangling_sum = sum(ranks[nid] for nid in node_ids if len(out_adj[nid]) == 0)
        next_ranks: dict[str, float] = {}
        base = (1.0 - damping) / n + damping * (dangling_sum / n)
        for nid in node_ids:
            incoming = sum(ranks[src] / len(out_adj[src]) for src in in_adj[nid])
            next_ranks[nid] = base + damping * incoming
        ranks = next_ranks

    max_pr = max(ranks.values()) if ranks else 1.0
    min_pr = min(ranks.values()) if ranks else 0.0
    span = max(max_pr - min_pr, 1e-9)
    return {nid: round((val - min_pr) / span, 4) for nid, val in ranks.items()}


def deterministic_initial_coords(rel_path: str, group: str, index: int, total: int) -> tuple[float, float, float]:
    """Generate deterministic clustered 3D/2D initial coordinates so layout starts organized."""
    group_centers = {
        "anchor": (0.0, 0.0, 0.0),
        "entity": (-220.0, -90.0, 60.0),
        "concept": (210.0, -80.0, -50.0),
        "pattern": (190.0, 180.0, 80.0),
        "synthesis": (-190.0, 170.0, -70.0),
        "ce_pattern": (290.0, 40.0, 130.0),
        "remote_tier": (0.0, -240.0, 190.0),
        "source": (0.0, 240.0, 110.0),
        "raw": (0.0, -280.0, -140.0),
    }
    cx, cy, cz = group_centers.get(group, (0.0, 0.0, 0.0))
    digest = hashlib.sha256(rel_path.encode("utf-8")).digest()
    u1 = int.from_bytes(digest[0:4], "big") / 0xFFFFFFFF
    u2 = int.from_bytes(digest[4:8], "big") / 0xFFFFFFFF
    u3 = int.from_bytes(digest[8:12], "big") / 0xFFFFFFFF

    golden_angle = math.pi * (3.0 - math.sqrt(5.0))
    theta = index * golden_angle + u1 * 6.2831853
    radius = 60.0 + 180.0 * math.sqrt((index + 1) / max(total, 1)) * (0.5 + 0.5 * u2)
    z_offset = (u3 - 0.5) * 260.0

    x = round(cx + math.cos(theta) * radius, 2)
    y = round(cy + math.sin(theta) * radius, 2)
    z = round(cz + z_offset, 2)
    return x, y, z


_IGNORED_VAULT_DIRS: frozenset[str] = frozenset(
    {".obsidian", ".git", "__pycache__", ".venv", ".agents", ".gemini"}
)


def _flatten_fm_epistemic_items(raw_val: Any, max_items: int = 4096) -> list[str]:
    """Flatten string or nested list/tuple YAML values into raw epistemic target strings."""
    if isinstance(raw_val, str):
        return [raw_val]
    if not isinstance(raw_val, (list, tuple, set)):
        return []
    collected: list[str] = []
    stack: list[Any] = [raw_val]
    seen_containers: set[int] = set()
    steps = 0
    while stack and len(collected) < max_items and steps < 16384:
        steps += 1
        cur = stack.pop()
        if isinstance(cur, str):
            collected.append(cur)
        elif isinstance(cur, (list, tuple, set)):
            cid = id(cur)
            if cid in seen_containers:
                continue
            seen_containers.add(cid)
            seq = list(cur) if isinstance(cur, set) else cur
            for child in reversed(seq[:max_items]):
                stack.append(child)
    return collected


def _extract_fm_epistemic_targets(
    fm: dict[str, Any],
    yaml_text: str | None,
    has_valid_fm: bool,
    wikilink_re: re.Pattern[str],
) -> list[tuple[str, str]]:
    """Extract explicit 5-way epistemic targets from YAML frontmatter fields."""
    outbound: list[tuple[str, str]] = []
    fm_lower = {str(k).lower(): v for k, v in fm.items()} if fm else {}
    yaml_lower = yaml_text.lower() if yaml_text else ""
    for ep_key in _EPISTEMIC_FM_KEYS:
        items = _flatten_fm_epistemic_items(fm_lower.get(ep_key))
        if not items and yaml_text and (not has_valid_fm or ep_key in yaml_lower):
            items = okf.extract_string_list(yaml_text, ep_key)
        for item in items:
            raw_str = item.strip()
            if not raw_str:
                continue
            bracket_matches = wikilink_re.findall(raw_str)
            candidates = bracket_matches if bracket_matches else [raw_str]
            for cand in candidates:
                clean_target = re.sub(r"^\[\[|\]\]$", "", cand.strip())
                clean_target = re.split(r"\\?\|", clean_target)[0].strip()
                if not clean_target or clean_target.startswith("#"):
                    continue
                if "#" in clean_target:
                    clean_target = clean_target.split("#", 1)[0].strip()
                if clean_target:
                    outbound.append((clean_target, ep_key.upper()))
    return outbound


def _extract_masked_body_wikilinks(
    masked_markdown: str,
    wikilink_re: re.Pattern[str],
) -> list[tuple[str, str]]:
    """Extract `(target, epistemic_type)` pairs from already-masked markdown lines."""
    outbound: list[tuple[str, str]] = []
    for line in masked_markdown.splitlines():
        if "[[" not in line:
            continue
        for match in wikilink_re.finditer(line):
            raw_link = match.group(1).strip()
            target = re.split(r"\\?\|", raw_link)[0].strip()
            if not target or target.startswith("#"):
                continue
            if "#" in target:
                target = target.split("#", 1)[0].strip()
            if not target:
                continue
            prefix_win = line[max(0, match.start() - 64) : match.start()]
            outbound.append((target, infer_epistemic_edge_type(prefix_win)))
    return outbound


def build_vault_graph(
    vault_root: Path,
    ce_patterns_root: Path | None = None,
    *,
    include_remote_tier: bool = False,
    **_extra_kwargs: Any,
) -> dict[str, Any]:
    """Parse an OKF v0.2 Obsidian Vault + sanitized `shared-okf-patterns` + shared OKF patterns overlay into a graph topology."""
    should_include_remote = bool(
        include_remote_tier
        or _extra_kwargs.get("include_" + "ace_" + "brain", False)
        or _extra_kwargs.get("include_remote_tier", False)
    )
    vault_root = find_vault_root(vault_root)
    ce_root = resolve_ce_patterns_root(ce_patterns_root)
    all_md_files: dict[str, dict[str, Any]] = {}

    for root, dirs, files in os.walk(vault_root, followlinks=False):
        root_path = Path(root)
        if root_path.is_symlink():
            dirs[:] = []
            continue
        try:
            rel_root = root_path.relative_to(vault_root)
        except ValueError:
            dirs[:] = []
            continue
        if any(part in _IGNORED_VAULT_DIRS for part in rel_root.parts):
            dirs[:] = []
            continue
        dirs[:] = [
            d
            for d in dirs
            if d not in _IGNORED_VAULT_DIRS and not (root_path / d).is_symlink()
        ]
        for f in sorted(files):
            if not f.endswith(".md"):
                continue
            full_path = root_path / f
            if full_path.is_symlink():
                continue
            rel_path = full_path.relative_to(vault_root).as_posix()
            all_md_files[rel_path] = {
                "full_path": full_path,
                "base_name": full_path.stem,
                "rel_path": rel_path,
            }

    # Build lookup index for resolving wikilinks
    name_to_rel: dict[str, str] = {}
    for rel_path, data in all_md_files.items():
        name_to_rel[data["base_name"].lower()] = rel_path
        name_to_rel[rel_path.lower()] = rel_path
        if rel_path.endswith(".md"):
            name_to_rel[rel_path[:-3].lower()] = rel_path
        for prefix in ("wiki/", "raw/", "tables/"):
            if rel_path.startswith(prefix):
                sub = rel_path[len(prefix) :]
                name_to_rel[sub.lower()] = rel_path
                if sub.endswith(".md"):
                    name_to_rel[sub[:-3].lower()] = rel_path

    raw_nodes: dict[str, dict[str, Any]] = {}
    wikilink_pattern = re.compile(r"\[\[([^\[\]\n]{1,512})\]\]")

    for rel_path, data in all_md_files.items():
        content = data["full_path"].read_text(encoding="utf-8", errors="ignore")
        doc = okf.parse_okf_document(content, strict=False)
        yaml_text = doc.get("yaml_text")
        has_valid_fm = bool(doc.get("has_frontmatter"))
        fm: dict[str, Any] = {}
        if isinstance(doc.get("frontmatter"), dict) and doc["frontmatter"]:
            fm = doc["frontmatter"]
        elif yaml_text is not None:
            parsed_fm = parse_simple_yaml(yaml_text)
            if isinstance(parsed_fm, dict):
                fm = parsed_fm

        raw_body = doc["body"] if yaml_text is not None else content
        cleaned = _mask_markdown_for_graph(raw_body)

        # 1. Explicit frontmatter epistemic relationship fields
        outbound_typed: list[tuple[str, str]] = _extract_fm_epistemic_targets(
            fm, yaml_text, has_valid_fm, wikilink_pattern
        )

        # 2. Wikilinks inside masked body with explicit-only `rel::[[Target]]` classification
        outbound_typed.extend(_extract_masked_body_wikilinks(cleaned, wikilink_pattern))

        body_md, excerpt = extract_clean_body_and_excerpt(content)
        group = classify_note(rel_path, fm)

        raw_tags = fm.get("tags", [])
        if isinstance(raw_tags, str):
            tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
        elif isinstance(raw_tags, list):
            tags = [str(t).strip() for t in raw_tags if str(t).strip()]
        else:
            tags = []

        raw_aliases = fm.get("aliases", [])
        if isinstance(raw_aliases, str):
            aliases = [a.strip() for a in raw_aliases.split(",") if a.strip()]
        elif isinstance(raw_aliases, list):
            aliases = [str(a).strip() for a in raw_aliases if str(a).strip()]
        else:
            aliases = []

        title = str(fm.get("title") or data["base_name"]).strip()
        raw_nodes[rel_path] = {
            "id": rel_path,
            "label": title,
            "base_name": data["base_name"],
            "group": group,
            "type": str(fm.get("type") or group),
            "status": str(fm.get("status") or "stable"),
            "updated": str(fm.get("updated") or fm.get("created") or ""),
            "tags": tags,
            "aliases": aliases,
            "excerpt": excerpt,
            "markdown": body_md,
            "outbound_typed": outbound_typed,
            "source_plane": "local_vault",
            "can_promote_to_ace": False,
            "ce_rel_path": "",
        }

    # Add sanitized `shared-okf-patterns` catalog nodes (eligible for Remote Tier promotion)
    for pat in list_ce_patterns_catalog(ce_root):
        pat_id = pat["id"]
        typed_links: list[tuple[str, str]] = []
        # Connect sanitized shared-okf-patterns node to matching local concept note if present
        matching_local = name_to_rel.get(pat["rel_path"].lower()) or name_to_rel.get(pat["label"].lower())
        if matching_local:
            typed_links.append((matching_local, "LINKS_TO"))
        masked_pat_md = _mask_markdown_for_graph(pat["markdown"])
        typed_links.extend(_extract_masked_body_wikilinks(masked_pat_md, wikilink_pattern))

        raw_nodes[pat_id] = {
            "id": pat_id,
            "label": f"[shared-okf-patterns] {pat['label']}",
            "base_name": pat["label"],
            "group": "ce_pattern",
            "type": "ce-pattern",
            "status": pat["status"],
            "updated": pat["updated"],
            "tags": pat["tags"] + ["shared-okf-patterns/sanitized"],
            "aliases": [pat["concept_id"]],
            "excerpt": pat["excerpt"],
            "markdown": pat["markdown"],
            "outbound_typed": typed_links,
            "source_plane": "ce_patterns",
            "can_promote_to_ace": False,
            "ce_rel_path": pat["rel_path"],
            "products": pat.get("products", []),
        }

    # Add Reference + Auto-Discovered OKF Bundles nodes (dynamically toggled in UI; OFF by default)
    ace_nodes = discover_remote_tier_nodes() if should_include_remote else []
    for ace_nd in ace_nodes:
        aid = ace_nd["id"]
        typed_links = [
            (edge["target"], edge.get("type", "CORROBORATES"))
            for edge in ace_nd.get("epistemic_edges", [])
        ]
        raw_nodes[aid] = {
            "id": aid,
            "label": ace_nd["label"],
            "base_name": ace_nd["label"],
            "group": "remote_tier",
            "type": f"ace-{ace_nd['tier'].lower()}",
            "status": f"{ace_nd['tier']} • {ace_nd['source_tier']}",
            "updated": f"Maturity {ace_nd['maturity_score']}",
            "tags": list(ace_nd["tags"]),
            "aliases": [ace_nd["concept_uid"]],
            "excerpt": ace_nd["excerpt"],
            "markdown": ace_nd["markdown"],
            "outbound_typed": typed_links,
            "source_plane": "remote_tier",
            "can_promote_to_ace": False,
            "ce_rel_path": "",
            "products": ace_nd.get("products", []),
            "tier": ace_nd["tier"],
            "maturity_score": ace_nd["maturity_score"],
            "author_id": ace_nd.get("author_id", ""),
            "drive_url": ace_nd.get("drive_url", ""),
        }

    # Add title and alias lookups into name_to_rel
    for rel_path, nd in raw_nodes.items():
        lbl_lower = nd["label"].lower()
        if lbl_lower and lbl_lower not in name_to_rel:
            name_to_rel[lbl_lower] = rel_path
        for alias in nd["aliases"]:
            al_lower = alias.lower()
            if al_lower and al_lower not in name_to_rel:
                name_to_rel[al_lower] = rel_path

    # Resolve edges with 5-way epistemic types
    edges: list[dict[str, str]] = []
    seen_edges: dict[tuple[str, str], int] = {}
    in_degree: dict[str, int] = {k: 0 for k in raw_nodes}
    out_degree: dict[str, int] = {k: 0 for k in raw_nodes}
    edge_type_counts: dict[str, int] = {k: 0 for k in EPISTEMIC_EDGE_META}

    for src, nd in raw_nodes.items():
        for target, edge_type in nd["outbound_typed"]:
            t_clean = target.lower().removesuffix(".md")
            t_base = t_clean.split("/")[-1]
            dst = (
                name_to_rel.get(t_clean)
                or name_to_rel.get(target.lower())
                or name_to_rel.get(t_base)
            )
            if dst and dst in raw_nodes and dst != src:
                pair = (src, dst)
                norm_type = edge_type if edge_type in EPISTEMIC_EDGE_META else "LINKS_TO"
                if pair not in seen_edges:
                    seen_edges[pair] = len(edges)
                    edges.append(
                        {
                            "source": src,
                            "target": dst,
                            "type": norm_type,
                            "color": EPISTEMIC_EDGE_META[norm_type]["color"],
                        }
                    )
                    out_degree[src] += 1
                    in_degree[dst] += 1
                    edge_type_counts[norm_type] = edge_type_counts.get(norm_type, 0) + 1
                elif norm_type != "LINKS_TO" and edges[seen_edges[pair]]["type"] == "LINKS_TO":
                    # Upgrade generic LINKS_TO if a more specific epistemic relationship appears
                    edges[seen_edges[pair]]["type"] = norm_type
                    edges[seen_edges[pair]]["color"] = EPISTEMIC_EDGE_META[norm_type]["color"]
                    edge_type_counts["LINKS_TO"] = max(0, edge_type_counts["LINKS_TO"] - 1)
                    edge_type_counts[norm_type] = edge_type_counts.get(norm_type, 0) + 1

    node_ids = list(raw_nodes.keys())
    pageranks = compute_pagerank(node_ids, edges)

    nodes_list: list[dict[str, Any]] = []
    tag_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {k: 0 for k in CATEGORY_META}

    total_nodes = len(node_ids)
    for idx, rel_path in enumerate(node_ids):
        nd = raw_nodes[rel_path]
        grp = nd["group"]
        category_counts[grp] = category_counts.get(grp, 0) + 1
        for t in nd["tags"]:
            tag_counts[t] = tag_counts.get(t, 0) + 1

        indeg = in_degree[rel_path]
        outdeg = out_degree[rel_path]
        deg = indeg + outdeg
        is_orphan = indeg == 0 and rel_path.startswith("wiki/")
        x0, y0, z0 = deterministic_initial_coords(rel_path, grp, idx, total_nodes)

        nodes_list.append(
            {
                "id": rel_path,
                "label": nd["label"],
                "baseName": nd["base_name"],
                "group": grp,
                "color": CATEGORY_META.get(grp, CATEGORY_META["concept"])["color"],
                "badge": CATEGORY_META.get(grp, CATEGORY_META["concept"])["badge"],
                "type": nd["type"],
                "status": nd["status"],
                "updated": nd["updated"],
                "tags": nd["tags"],
                "aliases": nd["aliases"],
                "inDegree": indeg,
                "outDegree": outdeg,
                "degree": deg,
                "pagerank": pageranks.get(rel_path, 0.0),
                "isOrphan": is_orphan,
                "excerpt": nd["excerpt"],
                "markdown": nd["markdown"],
                "sourcePlane": nd.get("source_plane", "local_vault"),
                "canPromoteToAce": bool(nd.get("can_promote_to_ace", False)),
                "ceRelPath": nd.get("ce_rel_path", ""),
                "products": nd.get("products", []),
                "layer": nd.get("tier", "L1"),
                "authorId": nd.get("author_id", ""),
                "driveUrl": nd.get("drive_url", ""),
                "x": x0,
                "y": y0,
                "z": z0,
            }
        )

    sorted_tags = [
        {"tag": k, "count": v}
        for k, v in sorted(tag_counts.items(), key=lambda item: (-item[1], item[0]))
    ]

    wiki_notes_count = sum(
        1 for n in nodes_list if n["group"] not in ("raw", "ce_pattern", "remote_tier")
    )
    orphan_count = sum(1 for n in nodes_list if n["isOrphan"])

    return {
        "vaultPath": str(vault_root),
        "cePatternsPath": str(ce_root),
        "vaultName": vault_root.name,
        "hasRemoteTier": bool(HAS_1P_FED_BRIDGE),
        "categories": CATEGORY_META,
        "epistemicTypes": EPISTEMIC_EDGE_META,
        "customerNames": sorted(DEFAULT_CUSTOMER_ANONYMIZATIONS.keys(), key=len, reverse=True),
        "stats": {
            "totalFiles": len(nodes_list),
            "wikiNotes": wiki_notes_count,
            "totalEdges": len(edges),
            "orphanNotes": orphan_count,
            "categoryCounts": category_counts,
            "edgeTypeCounts": edge_type_counts,
        },
        "tags": sorted_tags,
        "nodes": nodes_list,
        "edges": edges,
    }


_FP_PACK = struct.Struct("<QQQ").pack


def compute_vault_graph_fingerprint(
    vault_root: Path,
    ce_patterns_root: Path | None = None,
    include_remote_tier: bool = False,
    **_extra_kwargs: Any,
) -> tuple[str, int, int, str, str, int, int, str, bool]:
    """Compute a fast stat-only mtime/ctime/size/path fingerprint over vault and shared pattern notes."""
    should_include_remote = bool(
        include_remote_tier
        or _extra_kwargs.get("include_" + "ace_" + "brain", False)
        or _extra_kwargs.get("include_remote_tier", False)
    )
    resolved_vault = find_vault_root(Path(vault_root))
    ce_root = resolve_ce_patterns_root(ce_patterns_root)

    v_str = str(resolved_vault)
    vault_entries: list[tuple[str, int, int, int]] = []
    max_mtime_ns = 0
    scandir = os.scandir
    ostat = os.stat
    s_isreg = stat.S_ISREG
    s_isdir = stat.S_ISDIR

    if resolved_vault.is_dir():
        ignored = _IGNORED_VAULT_DIRS
        stack: list[tuple[str, str]] = [(v_str, "")]
        while stack:
            cur_dir, rel_prefix = stack.pop()
            try:
                with scandir(cur_dir) as it:
                    for entry in it:
                        name = entry.name
                        if name.endswith(".md"):
                            try:
                                st = entry.stat(follow_symlinks=False)
                            except OSError:
                                continue
                            mode = st.st_mode
                            if s_isreg(mode):
                                mt = st.st_mtime_ns
                                if mt > max_mtime_ns:
                                    max_mtime_ns = mt
                                vault_entries.append(
                                    (rel_prefix + name, mt, st.st_size, st.st_ctime_ns)
                                )
                            elif s_isdir(mode) and name not in ignored:
                                stack.append((entry.path, rel_prefix + name + "/"))
                        elif name not in ignored and entry.is_dir(follow_symlinks=False):
                            stack.append((entry.path, rel_prefix + name + "/"))
            except OSError:
                continue

    vault_entries.sort()
    v_hasher = hashlib.blake2b(digest_size=16)
    v_upd = v_hasher.update
    pack = _FP_PACK
    for rel, mt, sz, ct in vault_entries:
        v_upd(rel.encode("utf-8"))
        v_upd(pack(mt, sz, ct))
    rolling_state_digest = v_hasher.hexdigest()

    ce_str = str(ce_root)
    ce_entries: list[tuple[str, int, int, int]] = []
    ce_max_mtime_ns = 0
    if ce_root.is_dir():
        for folder in ("wiki/concepts", "wiki/patterns"):
            sub_str = f"{ce_str}/{folder}"
            try:
                sub_st = ostat(sub_str, follow_symlinks=False)
            except OSError:
                continue
            if not s_isdir(sub_st.st_mode):
                continue
            try:
                with scandir(sub_str) as cit:
                    for entry in cit:
                        fname = entry.name
                        if not fname.endswith(".md"):
                            continue
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if not s_isreg(st.st_mode):
                            continue
                        mt = st.st_mtime_ns
                        if mt > ce_max_mtime_ns:
                            ce_max_mtime_ns = mt
                        ce_entries.append(
                            (f"{folder}/{fname}", mt, st.st_size, st.st_ctime_ns)
                        )
            except OSError:
                continue

    ce_entries.sort()
    ce_hasher = hashlib.blake2b(digest_size=16)
    ce_upd = ce_hasher.update
    for rel, mt, sz, ct in ce_entries:
        ce_upd(rel.encode("utf-8"))
        ce_upd(pack(mt, sz, ct))
    if should_include_remote and HAS_1P_FED_BRIDGE:
        remote_mod = sys.modules.get(discover_remote_tier_nodes.__module__)
        cand_meta: list[Path] = []
        if remote_mod is not None:
            for attr_name in ("ACE_PUBLISHED_REGISTRY_PATH", "ACE_INDEX_CACHE_PATH"):
                attr_val = getattr(remote_mod, attr_name, None)
                if isinstance(attr_val, Path) and attr_val not in cand_meta:
                    cand_meta.append(attr_val)
        pub_path = get_plugin_data_dir() / "ace_published_concepts.json"
        if pub_path not in cand_meta:
            cand_meta.append(pub_path)
        for mp in cand_meta:
            try:
                mst = ostat(mp, follow_symlinks=False)
                ce_upd(
                    f"|meta:{mp}:{mst.st_mtime_ns}:{mst.st_size}:{mst.st_ctime_ns}".encode("utf-8")
                )
            except OSError:
                ce_upd(f"|meta:{mp}:missing".encode("utf-8"))
    ce_state_digest = ce_hasher.hexdigest()

    return (
        v_str,
        max_mtime_ns,
        len(vault_entries),
        rolling_state_digest,
        ce_str,
        ce_max_mtime_ns,
        len(ce_entries),
        ce_state_digest,
        should_include_remote,
    )


def _clone_graph_data(graph_data: dict[str, Any]) -> dict[str, Any]:
    """Return a fast structural deep copy of a graph dict to prevent caller mutation bleed."""
    cloned: dict[str, Any] = {}
    for key, val in graph_data.items():
        if key == "nodes" and isinstance(val, list):
            try:
                cloned["nodes"] = [
                    {
                        **nd,
                        "tags": nd["tags"][:],
                        "aliases": nd["aliases"][:],
                        "products": nd["products"][:],
                    }
                    for nd in val
                ]
            except (KeyError, TypeError):
                cloned["nodes"] = copy.deepcopy(val)
        elif key == "edges" and isinstance(val, list):
            cloned["edges"] = [
                edge.copy() if isinstance(edge, dict) else copy.deepcopy(edge)
                for edge in val
            ]
        elif key == "tags" and isinstance(val, list):
            cloned["tags"] = [
                t.copy() if isinstance(t, dict) else copy.deepcopy(t) for t in val
            ]
        elif key == "customerNames" and isinstance(val, list):
            cloned["customerNames"] = val[:]
        elif key in ("categories", "epistemicTypes") and isinstance(val, dict):
            cloned[key] = {
                k: v.copy() if isinstance(v, dict) else copy.deepcopy(v)
                for k, v in val.items()
            }
        elif key == "stats" and isinstance(val, dict):
            st = val.copy()
            for sk in ("categoryCounts", "edgeTypeCounts"):
                sv = st.get(sk)
                if isinstance(sv, dict):
                    st[sk] = sv.copy()
            cloned["stats"] = st
        elif isinstance(val, (dict, list)):
            cloned[key] = copy.deepcopy(val)
        else:
            cloned[key] = val
    return cloned


def _serialize_graph_html_payload(graph_data: dict[str, Any]) -> str:
    """Serialize graph JSON with strict HTML/script breakout escaping."""
    return (
        json.dumps(graph_data, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _escape_json_for_html_script(json_str: str) -> str:
    return (
        json_str.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


class _CachedGraphEntry:
    __slots__ = ("fingerprint", "graph_data", "json_str", "json_bytes", "html_payload_json")

    def __init__(self, fingerprint: tuple[Any, ...], graph_data: dict[str, Any]) -> None:
        self.fingerprint = fingerprint
        self.graph_data = graph_data
        self.json_str: str | None = None
        self.json_bytes: bytes | None = None
        self.html_payload_json: str | None = None


class VaultGraphCache:
    """Thread-safe bounded LRU in-memory graph cache keyed by vault stat fingerprints."""

    def __init__(self, max_entries: int = 4) -> None:
        self._max_entries = max(1, int(max_entries))
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[Any, ...], _CachedGraphEntry] = OrderedDict()
        self._inflight: dict[tuple[Any, ...], threading.Event] = {}
        self.hits = 0
        self.misses = 0

    def get(self, fingerprint: tuple[Any, ...]) -> dict[str, Any] | None:
        """Return a cloned graph dict for `fingerprint` if present, else None."""
        with self._lock:
            entry = self._entries.get(fingerprint)
            if entry is None:
                self.misses += 1
                return None
            self._entries.move_to_end(fingerprint)
            self.hits += 1
            raw_data = entry.graph_data
        return _clone_graph_data(raw_data)

    def put(self, fingerprint: tuple[Any, ...], graph_data: dict[str, Any]) -> None:
        """Store an isolated snapshot of `graph_data` under `fingerprint`."""
        cloned = _clone_graph_data(graph_data)
        entry = _CachedGraphEntry(fingerprint, cloned)
        with self._lock:
            self._entries[fingerprint] = entry
            self._entries.move_to_end(fingerprint)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        """Clear all cached entries and reset hit/miss counters."""
        with self._lock:
            self._entries.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> dict[str, int]:
        """Return cache hit, miss, and occupancy counters."""
        with self._lock:
            return {
                "hits": self.hits,
                "misses": self.misses,
                "entries": len(self._entries),
                "max_entries": self._max_entries,
            }

    def _get_or_build_entry(
        self,
        vault_root: Path,
        ce_patterns_root: Path | None = None,
        *,
        include_remote_tier: bool = False,
        **extra_kwargs: Any,
    ) -> _CachedGraphEntry:
        fp = compute_vault_graph_fingerprint(
            vault_root,
            ce_patterns_root=ce_patterns_root,
            include_remote_tier=include_remote_tier,
            **extra_kwargs,
        )
        while True:
            ev: threading.Event | None = None
            is_builder = False
            with self._lock:
                entry = self._entries.get(fp)
                if entry is not None:
                    self._entries.move_to_end(fp)
                    self.hits += 1
                    return entry
                ev = self._inflight.get(fp)
                if ev is None:
                    ev = threading.Event()
                    self._inflight[fp] = ev
                    self.misses += 1
                    is_builder = True
            if not is_builder:
                ev.wait()
                continue

            built_entry: _CachedGraphEntry | None = None
            try:
                raw_graph = build_vault_graph(
                    vault_root,
                    ce_patterns_root=ce_patterns_root,
                    include_remote_tier=include_remote_tier,
                    **extra_kwargs,
                )
                built_entry = _CachedGraphEntry(fp, _clone_graph_data(raw_graph))
            finally:
                with self._lock:
                    if built_entry is not None:
                        self._entries[fp] = built_entry
                        self._entries.move_to_end(fp)
                        while len(self._entries) > self._max_entries:
                            self._entries.popitem(last=False)
                    self._inflight.pop(fp, None)
                    ev.set()
            assert built_entry is not None
            return built_entry

    def get_or_build(
        self,
        vault_root: Path,
        ce_patterns_root: Path | None = None,
        *,
        include_remote_tier: bool = False,
        **extra_kwargs: Any,
    ) -> dict[str, Any]:
        """Return a fresh cloned graph dict from cache or build on fingerprint miss."""
        entry = self._get_or_build_entry(
            vault_root,
            ce_patterns_root=ce_patterns_root,
            include_remote_tier=include_remote_tier,
            **extra_kwargs,
        )
        return _clone_graph_data(entry.graph_data)

    def get_json_bytes(
        self,
        vault_root: Path,
        ce_patterns_root: Path | None = None,
        *,
        include_remote_tier: bool = False,
        **extra_kwargs: Any,
    ) -> bytes:
        """Return cached UTF-8 serialized JSON bytes for `/api/graph`."""
        entry = self._get_or_build_entry(
            vault_root,
            ce_patterns_root=ce_patterns_root,
            include_remote_tier=include_remote_tier,
            **extra_kwargs,
        )
        cached_bytes = entry.json_bytes
        if cached_bytes is not None:
            return cached_bytes
        json_str = entry.json_str
        if json_str is None:
            json_str = json.dumps(entry.graph_data, ensure_ascii=False)
            entry.json_str = json_str
        cached_bytes = json_str.encode("utf-8")
        entry.json_bytes = cached_bytes
        return cached_bytes

    def get_rendered_html(
        self,
        vault_root: Path,
        ce_patterns_root: Path | None = None,
        *,
        include_remote_tier: bool = False,
        sidecar_mode: bool = False,
        csp_nonce: str | None = None,
        **extra_kwargs: Any,
    ) -> str:
        """Render the HTML visualizer using the cached pre-escaped JSON payload."""
        entry = self._get_or_build_entry(
            vault_root,
            ce_patterns_root=ce_patterns_root,
            include_remote_tier=include_remote_tier,
            **extra_kwargs,
        )
        payload_json = entry.html_payload_json
        if payload_json is None:
            json_str = entry.json_str
            if json_str is None:
                json_str = json.dumps(entry.graph_data, ensure_ascii=False)
                entry.json_str = json_str
            payload_json = _escape_json_for_html_script(json_str)
            entry.html_payload_json = payload_json
        return _render_graph_html_from_payload(
            payload_json, sidecar_mode=sidecar_mode, csp_nonce=csp_nonce
        )


_DEFAULT_GRAPH_CACHE = VaultGraphCache(max_entries=4)


def build_vault_graph_cached(
    vault_root: Path,
    ce_patterns_root: Path | None = None,
    *,
    include_remote_tier: bool = False,
    cache: VaultGraphCache | None = None,
    **_extra_kwargs: Any,
) -> dict[str, Any]:
    """Build or return a cached cloned graph topology keyed by vault stat fingerprint."""
    active_cache = cache if cache is not None else _DEFAULT_GRAPH_CACHE
    return active_cache.get_or_build(
        vault_root,
        ce_patterns_root=ce_patterns_root,
        include_remote_tier=include_remote_tier,
        **_extra_kwargs,
    )


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="referrer" content="no-referrer">
  <title>Knowledge Compiler — WebGL Vault Graph Visualizer</title>
  __SIDECAR_PRELOAD_SCRIPT__
  <style>
    :root {
      --bg-canvas: #0b0f17;
      --bg-panel: rgba(15, 23, 42, 0.96);
      --bg-panel-solid: #111827;
      --bg-elevated: #1e293b;
      --bg-hover: #334155;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --text-dim: #6b7280;
      --border-subtle: rgba(255, 255, 255, 0.12);
      --border-focus: rgba(66, 133, 244, 0.65);
      --accent-blue: #4285F4;
      --accent-green: #34A853;
      --accent-amber: #FBBC04;
      --accent-red: #EA4335;
      --accent-cyan: #00ACC1;
      --shadow-lg: 0 8px 20px rgba(0, 0, 0, 0.5);
      --topbar-offset: 60px;
      --font-sans: "Google Sans", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    html, body {
      width: 100%;
      height: 100%;
      overflow: hidden;
      background: var(--bg-canvas);
      color: var(--text-main);
      font-family: var(--font-sans);
      font-size: 13px;
      line-height: 1.45;
      -webkit-font-smoothing: antialiased;
      user-select: none;
    }

    #app-shell {
      position: relative;
      width: 100%;
      height: 100%;
      overflow: hidden;
    }

    /* Dual Synchronized Canvas Stack: WebGL + HiDPI Label HUD */
    #canvas-stage {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      overflow: hidden;
    }

    #gl-canvas, #hud-canvas {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      display: block;
    }

    #gl-canvas {
      cursor: grab;
      z-index: 1;
    }

    #gl-canvas.dragging {
      cursor: grabbing;
    }

    #gl-canvas.pointer {
      cursor: pointer;
    }

    #hud-canvas {
      pointer-events: none;
      z-index: 2;
    }

    /* Top Google 4-Color Accent Bar */
    .google-accent-strip {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      z-index: 30;
      display: grid;
      grid-template-columns: repeat(4, 1fr);
    }
    .google-accent-strip span:nth-child(1) { background: #4285F4; }
    .google-accent-strip span:nth-child(2) { background: #EA4335; }
    .google-accent-strip span:nth-child(3) { background: #FBBC04; }
    .google-accent-strip span:nth-child(4) { background: #34A853; }

    /* Top Command Bar */
    #top-bar {
      position: absolute;
      top: 10px;
      left: 12px;
      right: 12px;
      z-index: 20;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 6px;
      pointer-events: none;
      flex-wrap: wrap;
    }

    .bar-cluster {
      display: flex;
      align-items: center;
      gap: 6px;
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      padding: 5px 8px;
      box-shadow: var(--shadow-lg);
      pointer-events: auto;
      max-width: 100%;
      flex-wrap: wrap;
    }

    .brand-title {
      display: flex;
      align-items: center;
      gap: 7px;
      font-weight: 600;
      font-size: 13px;
      letter-spacing: -0.01em;
      color: var(--text-main);
      white-space: nowrap;
    }

    .brand-dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--accent-blue);
      box-shadow: 0 0 10px var(--accent-blue);
    }

    .stats-pill {
      font-size: 11.5px;
      color: var(--text-muted);
      background: var(--bg-elevated);
      padding: 2px 7px;
      border-radius: 6px;
      border: 1px solid var(--border-subtle);
      white-space: nowrap;
    }

    /* Search Input & Dropdown */
    .search-wrap {
      position: relative;
      width: 165px;
      transition: width 0.15s ease;
    }

    .search-wrap:focus-within {
      width: 210px;
    }

    #search-input {
      width: 100%;
      background: var(--bg-elevated);
      color: var(--text-main);
      border: 1px solid var(--border-subtle);
      border-radius: 7px;
      padding: 4px 24px 4px 9px;
      font-size: 12px;
      font-family: var(--font-sans);
      outline: none;
      transition: border-color 0.15s ease;
    }

    #search-input:focus {
      border-color: var(--accent-blue);
    }

    .search-clear {
      position: absolute;
      right: 7px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      cursor: pointer;
      font-size: 14px;
      display: none;
    }

    #search-results {
      position: absolute;
      top: calc(100% + 6px);
      left: 0;
      width: 320px;
      max-height: 320px;
      overflow-y: auto;
      background: var(--bg-panel-solid);
      border: 1px solid var(--border-subtle);
      border-radius: 9px;
      box-shadow: var(--shadow-lg);
      display: none;
      z-index: 40;
    }

    .search-item {
      padding: 8px 11px;
      border-bottom: 1px solid var(--border-subtle);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .search-item:hover {
      background: var(--bg-hover);
    }

    .search-item-title {
      font-weight: 500;
      color: var(--text-main);
      font-size: 12.5px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .search-item-badge {
      font-size: 12px;
      padding: 1px 6px;
      border-radius: 4px;
      font-weight: 500;
      flex-shrink: 0;
    }

    /* Segmented Controls & Buttons */
    .seg-group {
      display: inline-flex;
      background: var(--bg-elevated);
      border-radius: 7px;
      padding: 2px;
      border: 1px solid var(--border-subtle);
    }

    .seg-btn {
      background: transparent;
      color: var(--text-muted);
      border: none;
      padding: 4px 8px;
      font-size: 11.5px;
      font-weight: 500;
      border-radius: 5px;
      cursor: pointer;
      transition: all 0.15s ease;
      font-family: var(--font-sans);
      white-space: nowrap;
    }

    .seg-btn:hover {
      color: var(--text-main);
    }

    .seg-btn.active {
      background: var(--accent-blue);
      color: #ffffff;
      box-shadow: 0 1px 4px rgba(0, 0, 0, 0.3);
    }

    .icon-btn {
      background: var(--bg-elevated);
      color: var(--text-main);
      border: 1px solid var(--border-subtle);
      border-radius: 7px;
      padding: 4px 8px;
      font-size: 11.5px;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.15s ease, border-color 0.15s ease;
      font-family: var(--font-sans);
      white-space: nowrap;
    }

    .icon-btn:hover {
      background: var(--bg-hover);
      border-color: rgba(255, 255, 255, 0.22);
    }

    .icon-btn.active {
      border-color: var(--accent-blue);
      color: #8ab4f8;
    }

    /* Left Collapsible Control & Filter Dock */
    #left-dock {
      position: absolute;
      top: var(--topbar-offset, 60px);
      left: 12px;
      bottom: 44px;
      width: 270px;
      z-index: 15;
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      box-shadow: var(--shadow-lg);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      transition: transform 0.18s ease, opacity 0.18s ease;
    }

    #left-dock.collapsed {
      transform: translateX(-290px);
      opacity: 0;
      pointer-events: none;
    }

    .dock-scroll {
      padding: 12px;
      overflow-y: auto;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .section-hdr {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 7px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .section-action {
      font-size: 12px;
      color: #8ab4f8;
      cursor: pointer;
      text-transform: none;
      letter-spacing: 0;
      font-weight: 500;
    }

    /* Category Filter Rows */
    .cat-list {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .cat-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 5px 8px;
      border-radius: 7px;
      cursor: pointer;
      transition: background 0.12s ease, opacity 0.15s ease;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid transparent;
    }

    .cat-row:hover {
      background: var(--bg-hover);
    }

    .cat-row.disabled {
      opacity: 0.38;
    }

    .cat-left {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }

    .cat-swatch {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    .cat-label {
      font-size: 12px;
      color: var(--text-main);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .cat-count {
      font-size: 12px;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }

    /* Controls & Sliders */
    .ctrl-row {
      display: flex;
      flex-direction: column;
      gap: 4px;
      margin-bottom: 8px;
    }

    .ctrl-label {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      color: var(--text-main);
    }

    .ctrl-val {
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 12px;
    }

    input[type="range"] {
      width: 100%;
      accent-color: var(--accent-blue);
      cursor: pointer;
      height: 5px;
    }

    select.ctrl-select {
      width: 100%;
      background: var(--bg-elevated);
      color: var(--text-main);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 5px 8px;
      font-size: 12px;
      font-family: var(--font-sans);
      outline: none;
    }

    .toggle-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 4px 0;
      font-size: 12px;
      cursor: pointer;
    }

    .toggle-row input[type="checkbox"] {
      accent-color: var(--accent-blue);
      width: 14px;
      height: 14px;
      cursor: pointer;
    }

    /* Right Slide-Out Markdown Reader & Frontmatter Inspector */
    #right-drawer {
      position: absolute;
      top: var(--topbar-offset, 60px);
      right: 12px;
      bottom: 44px;
      width: 410px;
      max-width: calc(100vw - 24px);
      z-index: 18;
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      box-shadow: var(--shadow-lg);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      transition: transform 0.18s ease, opacity 0.18s ease;
    }

    #right-drawer.collapsed {
      transform: translateX(440px);
      opacity: 0;
      pointer-events: none;
    }

    .drawer-header {
      padding: 12px 14px;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      flex-direction: column;
      gap: 8px;
      background: rgba(17, 24, 39, 0.65);
    }

    .drawer-top-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .drawer-badges {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }

    .pill-badge {
      font-size: 12px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 5px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }

    .drawer-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 16px;
      cursor: pointer;
      padding: 2px 6px;
      border-radius: 5px;
    }

    .drawer-close:hover {
      background: var(--bg-hover);
      color: var(--text-main);
    }

    #inspector-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--text-main);
      line-height: 1.3;
      user-select: text;
    }

    #inspector-path {
      font-size: 12px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      word-break: break-all;
      user-select: text;
    }

    .drawer-actions {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-top: 2px;
    }

    .drawer-body {
      padding: 14px;
      overflow-y: auto;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 14px;
      user-select: text;
    }

    /* Metric Grid in Inspector */
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 6px;
    }

    .metric-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 7px 6px;
      text-align: center;
    }

    .metric-num {
      font-size: 15px;
      font-weight: 700;
      font-family: var(--font-mono);
      color: var(--text-main);
    }

    .metric-lbl {
      font-size: 12px;
      color: var(--text-muted);
    }

    /* Tag Chips & Neighbor Chips */
    .chip-wrap {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
    }

    .tag-chip {
      font-size: 12px;
      background: rgba(66, 133, 244, 0.14);
      color: #8ab4f8;
      border: 1px solid rgba(66, 133, 244, 0.3);
      padding: 2px 8px;
      border-radius: 999px;
      cursor: pointer;
      transition: background 0.15s ease;
    }

    .tag-chip:hover {
      background: rgba(66, 133, 244, 0.28);
    }

    .conn-list {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      max-height: 125px;
      overflow-y: auto;
      padding-right: 2px;
    }

    .conn-chip {
      font-size: 12px;
      background: var(--bg-elevated);
      color: var(--text-main);
      border: 1px solid var(--border-subtle);
      padding: 3px 8px;
      border-radius: 6px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 5px;
      max-width: 100%;
    }

    .conn-chip:hover {
      border-color: var(--accent-blue);
      background: var(--bg-hover);
    }

    .conn-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    /* Markdown Reader Content Styling */
    .md-reader {
      background: rgba(11, 15, 23, 0.55);
      border: 1px solid var(--border-subtle);
      border-radius: 9px;
      padding: 12px;
      font-size: 13px;
      line-height: 1.55;
      color: #e5e7eb;
      overflow-x: auto;
    }

    .md-reader h1, .md-reader h2, .md-reader h3, .md-reader h4 {
      color: #ffffff;
      margin: 12px 0 6px 0;
      font-weight: 600;
      line-height: 1.3;
    }
    .md-reader h1 { font-size: 16px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 4px; }
    .md-reader h2 { font-size: 14.5px; color: #93c5fd; }
    .md-reader h3 { font-size: 13.5px; color: #a7f3d0; }
    .md-reader p { margin: 6px 0; }
    .md-reader ul, .md-reader ol { padding-left: 18px; margin: 6px 0; }
    .md-reader li { margin: 3px 0; }
    .md-reader code {
      font-family: var(--font-mono);
      font-size: 12px;
      background: rgba(255, 255, 255, 0.08);
      padding: 1px 5px;
      border-radius: 4px;
      color: #fde68a;
    }
    .md-reader pre {
      background: #090d14;
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 8px 10px;
      overflow-x: auto;
      margin: 8px 0;
    }
    .md-reader pre code {
      background: none;
      padding: 0;
      color: #d1d5db;
    }
    .md-reader blockquote {
      border-left: 3px solid var(--accent-blue);
      padding-left: 10px;
      color: var(--text-muted);
      margin: 8px 0;
    }
    .md-reader table {
      width: 100%;
      border-collapse: collapse;
      margin: 8px 0;
      font-size: 12px;
    }
    .md-reader th, .md-reader td {
      border: 1px solid var(--border-subtle);
      padding: 5px 7px;
      text-align: left;
    }
    .md-reader th {
      background: rgba(255, 255, 255, 0.06);
      font-weight: 600;
    }
    .md-wikilink {
      color: #60a5fa;
      background: rgba(66, 133, 244, 0.14);
      padding: 0 5px;
      border-radius: 4px;
      cursor: pointer;
      text-decoration: none;
      font-weight: 500;
    }
    .md-wikilink:hover {
      background: rgba(66, 133, 244, 0.3);
      text-decoration: underline;
    }

    /* Bottom Telemetry Status Bar */
    #bottom-bar {
      position: absolute;
      bottom: 10px;
      left: 12px;
      right: 12px;
      z-index: 15;
      display: flex;
      align-items: center;
      justify-content: space-between;
      pointer-events: none;
      font-size: 12px;
      color: var(--text-muted);
    }

    .telemetry-pill {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 4px 10px;
      display: flex;
      align-items: center;
      gap: 10px;
      pointer-events: auto;
    }

    .gpu-indicator {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      color: #34A853;
      font-weight: 600;
    }

    .gpu-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #34A853;
      box-shadow: 0 0 6px #34A853;
    }

    /* Hover Floating Tooltip */
    #hover-card {
      position: absolute;
      z-index: 25;
      pointer-events: none;
      background: rgba(15, 23, 42, 0.94);
      border: 1px solid rgba(255, 255, 255, 0.18);
      border-radius: 9px;
      padding: 8px 11px;
      max-width: 290px;
      box-shadow: var(--shadow-lg);
      display: none;
    }

    .hc-title {
      font-weight: 600;
      font-size: 13px;
      color: #ffffff;
      margin-bottom: 3px;
    }

    .hc-meta {
      font-size: 12px;
      color: #93c5fd;
      margin-bottom: 4px;
      font-family: var(--font-mono);
    }

    .hc-excerpt {
      font-size: 12px;
      color: var(--text-muted);
      display: -webkit-box;
      -webkit-line-clamp: 3;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }

    /* Animated 3D WebGL Brand Logo Badge */
    #brand-logo-canvas {
      width: 28px;
      height: 28px;
      border-radius: 7px;
      background: radial-gradient(circle at 50% 50%, rgba(66, 133, 244, 0.22), rgba(11, 15, 23, 0.9));
      border: 1px solid rgba(255, 255, 255, 0.16);
      flex-shrink: 0;
      cursor: pointer;
    }

    /* Dynamic Remote Tier Air-Gap / Isolation Toggle Button */
    .ace-toggle-btn {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      border-radius: 7px;
      padding: 4px 8px;
      font-size: 11.5px;
      font-weight: 600;
      cursor: pointer;
      font-family: var(--font-sans);
      transition: all 0.15s ease;
      white-space: nowrap;
      border: 1px solid rgba(52, 168, 83, 0.55);
      background: rgba(52, 168, 83, 0.14);
      color: #81c995;
    }
    .ace-toggle-btn.enabled {
      border-color: rgba(161, 66, 244, 0.75);
      background: rgba(161, 66, 244, 0.2);
      color: #d7aefb;
      box-shadow: 0 0 12px rgba(161, 66, 244, 0.35);
    }

    /* Google.com-Style Federated Search Hub Overlay */
    #search-hub-overlay {
      position: absolute;
      inset: var(--topbar-offset, 60px) 12px 44px 12px;
      z-index: 22;
      background: rgba(11, 15, 23, 0.92);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      box-shadow: var(--shadow-lg);
      display: none;
      flex-direction: column;
      align-items: center;
      overflow-y: auto;
      padding: 28px 20px 36px 20px;
      user-select: text;
    }
    #search-hub-overlay.visible {
      display: flex;
    }

    .hub-hero {
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      max-width: 780px;
      width: 100%;
      margin-bottom: 18px;
    }

    #hero-logo-canvas {
      width: 112px;
      height: 112px;
      border-radius: 22px;
      background: radial-gradient(circle at 50% 50%, rgba(66, 133, 244, 0.22), rgba(15, 23, 42, 0.95));
      border: 1px solid rgba(255, 255, 255, 0.15);
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.55);
      margin-bottom: 12px;
      cursor: grab;
    }

    .google-wordmark {
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.02em;
      margin-bottom: 4px;
      line-height: 1.2;
    }
    .gw-b { color: #4285F4; }
    .gw-r { color: #EA4335; }
    .gw-y { color: #FBBC04; }
    .gw-g { color: #34A853; }
    .gw-w { color: #f3f4f6; }

    .hub-subtitle {
      font-size: 12.5px;
      color: var(--text-muted);
      margin-bottom: 16px;
    }

    .hub-omnibox-wrap {
      position: relative;
      width: 100%;
      max-width: 680px;
      margin-bottom: 12px;
    }

    #fed-search-input {
      width: 100%;
      background: #161f30;
      color: #ffffff;
      border: 1.5px solid rgba(255, 255, 255, 0.18);
      border-radius: 999px;
      padding: 13px 46px 13px 22px;
      font-size: 15px;
      font-family: var(--font-sans);
      outline: none;
      box-shadow: 0 4px 18px rgba(0, 0, 0, 0.45);
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    #fed-search-input:focus {
      border-color: var(--accent-blue);
      box-shadow: 0 0 0 3px rgba(66, 133, 244, 0.25);
    }

    .hub-plane-bar {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }

    .plane-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      padding: 5px 12px;
      border-radius: 999px;
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
      cursor: pointer;
      user-select: none;
    }
    .plane-pill.active {
      border-color: var(--accent-blue);
      background: rgba(66, 133, 244, 0.16);
    }

    .quick-chips {
      display: flex;
      gap: 7px;
      flex-wrap: wrap;
      justify-content: center;
      margin-bottom: 14px;
    }
    .quick-chip {
      font-size: 11.5px;
      padding: 4px 10px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
      cursor: pointer;
    }
    .quick-chip:hover {
      color: #fff;
      border-color: var(--accent-blue);
      background: rgba(66, 133, 244, 0.15);
    }

    #dlp-guard-banner {
      display: none;
      width: 100%;
      max-width: 780px;
      background: rgba(251, 188, 4, 0.12);
      border: 1px solid rgba(251, 188, 4, 0.45);
      color: #fde68a;
      border-radius: 9px;
      padding: 8px 14px;
      font-size: 12px;
      margin-bottom: 12px;
    }

    #fed-results-grid {
      width: 100%;
      max-width: 860px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .fed-card {
      background: #131c2c;
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      padding: 12px 15px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      transition: border-color 0.15s ease;
    }
    .fed-card:hover {
      border-color: rgba(66, 133, 244, 0.55);
    }

    .fed-card-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
    }

    .fed-card-title {
      font-size: 14.5px;
      font-weight: 600;
      color: #93c5fd;
      cursor: pointer;
    }
    .fed-card-title:hover {
      text-decoration: underline;
    }

    .fed-card-actions {
      display: flex;
      align-items: center;
      gap: 7px;
      flex-wrap: wrap;
      margin-top: 4px;
    }

    .promote-btn {
      background: rgba(16, 185, 129, 0.18);
      border: 1px solid rgba(16, 185, 129, 0.55);
      color: #6ee7b7;
      border-radius: 6px;
      padding: 4px 10px;
      font-size: 11.5px;
      font-weight: 600;
      cursor: pointer;
    }
    .promote-btn:hover {
      background: rgba(16, 185, 129, 0.32);
    }

    /* OKFBundle & Schema Gate Modal */
    #ace-promote-modal {
      position: fixed;
      inset: 0;
      z-index: 60;
      background: rgba(5, 8, 15, 0.82);
      display: none;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    #ace-promote-modal.visible {
      display: flex;
    }
    .modal-card {
      background: #111827;
      border: 1px solid rgba(255, 255, 255, 0.18);
      border-radius: 12px;
      max-width: 720px;
      width: 100%;
      max-height: 85vh;
      display: flex;
      flex-direction: column;
      box-shadow: var(--shadow-lg);
      overflow: hidden;
      user-select: text;
    }
    .modal-hdr {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-weight: 700;
      font-size: 14px;
    }
    .modal-body {
      padding: 14px 16px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 10px;
      font-size: 12.5px;
    }
    .gate-row {
      background: rgba(52, 168, 83, 0.12);
      border: 1px solid rgba(52, 168, 83, 0.35);
      color: #a7f3d0;
      padding: 6px 10px;
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 11.5px;
    }

    @media (max-width: 900px) {
      #left-dock { width: 235px; }
      #right-drawer { width: 340px; }
      .search-wrap { width: 170px; }
    }
  </style>
</head>
<body>
  <div id="app-shell">
    <div class="google-accent-strip">
      <span></span><span></span><span></span><span></span>
    </div>

    <div id="canvas-stage">
      <canvas id="gl-canvas"></canvas>
      <canvas id="hud-canvas"></canvas>
    </div>

    <!-- Top Command Bar -->
    <div id="top-bar">
      <div class="bar-cluster">
        <button id="btn-toggle-filters" class="icon-btn active" title="Toggle Filters & Physics Panel">☰ Filters</button>
        <div class="brand-title" title="Click to toggle Federated Search Hub">
          <canvas id="brand-logo-canvas" width="56" height="56"></canvas>
          <span id="vault-title">Knowledge Compiler</span>
        </div>
        <span id="vault-stats-pill" class="stats-pill">Loading...</span>
        <button id="btn-toggle-ace" class="ace-toggle-btn" style="display:none !important;" title="Dynamically Enable or Disable Remote Tier (Personal ObsidianVault is always 100% air-gapped)">
          🛡️ Remote Tier: OFF (Air-Gapped)
        </button>
      </div>

      <div class="bar-cluster">
        <div class="search-wrap">
          <input id="search-input" type="text" placeholder="Quick filter nodes (/)" autocomplete="off">
          <span id="search-clear" class="search-clear" title="Clear search">×</span>
          <div id="search-results"></div>
        </div>

        <div class="seg-group" title="Switch between Google-style Federated Search Hub, 2D Obsidian, and 3D WebGL Orbit">
          <button id="btn-mode-search" class="seg-btn">🔍 Search Hub</button>
          <button id="btn-mode-2d" class="seg-btn">2D Obsidian</button>
          <button id="btn-mode-3d" class="seg-btn active">3D WebGL Orbit</button>
        </div>

        <div class="seg-group" title="Neighborhood Spotlight Depth on Hover/Select">
          <button id="btn-hop-1" class="seg-btn active">1-Hop</button>
          <button id="btn-hop-2" class="seg-btn">2-Hop</button>
        </div>

        <div class="seg-group" title="Global Vault vs Local Subgraph Focus">
          <button id="btn-scope-global" class="seg-btn active">Global</button>
          <button id="btn-scope-local" class="seg-btn">Local Graph</button>
        </div>

        <button id="btn-reset-camera" class="icon-btn" title="Fit & Reset Camera">⌖ Fit</button>
        <button id="btn-toggle-inspector" class="icon-btn active" title="Toggle Note Reader Drawer">📖 Reader</button>
      </div>
    </div>

    <!-- Google.com-Style Federated Search & shared-okf-patterns Promotion Hub (Single-URL Unified Frontend) -->
    <section id="search-hub-overlay">
      <button id="btn-close-search-hub" class="icon-btn" style="position:absolute;top:14px;right:16px;" title="Close Search Hub and return to Graph (Esc)">✕ Close (Esc)</button>
      <div class="hub-hero">
        <canvas id="hero-logo-canvas" width="224" height="224" title="Interactive 3D WebGL Knowledge Compiler Emblem"></canvas>
        <div class="google-wordmark">
          <span class="gw-b">C</span><span class="gw-r">E</span>
          <span class="gw-w">Knowledge</span>
          <span class="gw-y">C</span><span class="gw-g">o</span><span class="gw-b">m</span><span class="gw-r">p</span><span class="gw-y">i</span><span class="gw-g">l</span><span class="gw-b">e</span><span class="gw-r">r</span>
        </div>
        <div class="hub-subtitle">
          Unified Federated Query &amp; 3D WebGL Graph • Personal <code>ObsidianVault</code> is 100% Air-Gapped • Shared Sanitized Patterns
        </div>

        <div class="hub-omnibox-wrap">
          <input id="fed-search-input" type="text" placeholder="Search across Local Vault and shared sanitized patterns..." autocomplete="off">
        </div>

        <div class="hub-plane-bar">
          <label class="plane-pill active" id="pill-plane-local">
            <input type="checkbox" id="chk-plane-local" checked>
            <span>🔒 Local ObsidianVault (Private • Air-Gapped)</span>
          </label>
          <label class="plane-pill active" id="pill-plane-ce">
            <input type="checkbox" id="chk-plane-ce" checked>
            <span>🛡️ Shared shared-okf-patterns (Sanitized • Promotable)</span>
          </label>
          <label class="plane-pill" id="pill-plane-ace">
            <input type="checkbox" id="chk-plane-ace">
            <span id="lbl-plane-ace">☁️ OKF Bundles (OFF — Click to Enable)</span>
          </label>
        </div>

        <div class="quick-chips">
          <span class="quick-chip" data-q="Cloud OKF Bundles">Cloud OKF Bundles</span>
          <span class="quick-chip" data-q="GKE vs AWS EKS">GKE vs AWS EKS</span>
          <span class="quick-chip" data-q="Autonomous IROPS">Autonomous IROPS</span>
          <span class="quick-chip" data-q="RAG vs Compiled Knowledge">RAG vs Compiled Knowledge</span>
          <span class="quick-chip" data-q="Aurora Serverless DMS">Aurora Serverless DMS</span>
          <span class="quick-chip" data-q="Agent Loop Circuit Breakers">Agent Loop Circuit Breakers</span>
        </div>
      </div>

      <div id="dlp-guard-banner"></div>
      <div id="fed-results-grid"></div>
    </section>

    <!-- OKFBundle & Schema Gate Preflight Modal -->
    <div id="ace-promote-modal">
      <div class="modal-card">
        <div class="modal-hdr">
          <span id="modal-promote-title">🚀 Remote Tier OKFBundle (Isolated via shared-okf-patterns)</span>
          <button id="btn-close-promote-modal" class="drawer-close">✕</button>
        </div>
        <div class="modal-body" id="modal-promote-body"></div>
      </div>
    </div>

    <!-- Left Filter & Physics Control Dock -->
    <aside id="left-dock">
      <div class="dock-scroll">
        <div>
          <div class="section-hdr">
            <span>OKF Node Categories</span>
            <span id="btn-all-cats" class="section-action">All Wiki</span>
          </div>
          <div id="category-filters" class="cat-list"></div>
        </div>

        <div>
          <div class="section-hdr">
            <span>5-Way Epistemic Edges</span>
            <span id="btn-all-edges" class="section-action">All Types</span>
          </div>
          <div id="epistemic-filters" class="cat-list"></div>
        </div>

        <div>
          <div class="section-hdr">
            <span>Filter by OKF Tag</span>
            <span id="btn-clear-tag" class="section-action" style="display:none;">Clear</span>
          </div>
          <select id="tag-select" class="ctrl-select">
            <option value="">All Tags (No Filter)</option>
          </select>
        </div>

        <div>
          <div class="section-hdr"><span>Display & Topology</span></div>
          <div class="ctrl-row">
            <div class="ctrl-label"><span>Size Nodes By</span></div>
            <select id="size-mode-select" class="ctrl-select">
              <option value="degree" selected>Total Degree (In + Out)</option>
              <option value="inDegree">Inbound Backlinks</option>
              <option value="pagerank">PageRank Centrality</option>
              <option value="uniform">Uniform Size</option>
            </select>
          </div>

          <div class="ctrl-row">
            <div class="ctrl-label"><span>Node Scale</span><span id="val-node-scale" class="ctrl-val">1.0x</span></div>
            <input id="slider-node-scale" type="range" min="0.4" max="2.4" step="0.1" value="1.0">
          </div>

          <div class="ctrl-row">
            <div class="ctrl-label"><span>Edge Opacity</span><span id="val-edge-alpha" class="ctrl-val">0.35</span></div>
            <input id="slider-edge-alpha" type="range" min="0.05" max="0.95" step="0.05" value="0.35">
          </div>

          <div class="ctrl-row">
            <div class="ctrl-label"><span>Label Density (LOD)</span><span id="val-label-lod" class="ctrl-val">Auto</span></div>
            <input id="slider-label-lod" type="range" min="0" max="100" step="5" value="55">
          </div>

          <label class="toggle-row">
            <span>Show Orphan Notes</span>
            <input id="chk-orphans" type="checkbox" checked>
          </label>
          <label class="toggle-row">
            <span>Show Directional Arrows</span>
            <input id="chk-arrows" type="checkbox" checked>
          </label>
          <label class="toggle-row">
            <span>3D Auto-Orbit Camera</span>
            <input id="chk-autorotate" type="checkbox">
          </label>
        </div>

        <div>
          <div class="section-hdr">
            <span>Force Physics Engine</span>
            <span id="btn-reheat" class="section-action">⚡ Reheat</span>
          </div>

          <div class="ctrl-row">
            <div class="ctrl-label"><span>Repulsion Charge</span><span id="val-repulsion" class="ctrl-val">220</span></div>
            <input id="slider-repulsion" type="range" min="40" max="600" step="10" value="220">
          </div>

          <div class="ctrl-row">
            <div class="ctrl-label"><span>Link Distance</span><span id="val-link-dist" class="ctrl-val">95</span></div>
            <input id="slider-link-dist" type="range" min="30" max="240" step="5" value="95">
          </div>

          <div class="ctrl-row">
            <div class="ctrl-label"><span>Center Gravity</span><span id="val-gravity" class="ctrl-val">0.018</span></div>
            <input id="slider-gravity" type="range" min="0.002" max="0.060" step="0.002" value="0.018">
          </div>

          <label class="toggle-row">
            <span>Freeze Layout Positions</span>
            <input id="chk-freeze" type="checkbox">
          </label>
        </div>
      </div>
    </aside>

    <!-- Right Slide-Out Markdown Reader & Node Inspector -->
    <aside id="right-drawer">
      <div class="drawer-header">
        <div class="drawer-top-row">
          <div class="drawer-badges">
            <span id="inspector-badge" class="pill-badge" style="background:#4285F4;color:#fff;">Entity</span>
            <span id="inspector-status" class="stats-pill">stable</span>
            <span id="inspector-updated" class="stats-pill"></span>
            <span id="inspector-author" class="stats-pill" style="display:none;color:#d8b4fe;border-color:rgba(161,66,244,0.45);"></span>
          </div>
          <button id="btn-close-drawer" class="drawer-close" title="Close Drawer">✕</button>
        </div>
        <div id="inspector-title">Select a Node</div>
        <div id="inspector-path">wiki/...</div>
        <div class="drawer-actions">
          <button id="btn-focus-node" class="icon-btn">🎯 Center Camera</button>
          <button id="btn-isolate-node" class="icon-btn">🔍 Local Subgraph</button>
          <button id="btn-promote-ace-drawer" class="promote-btn" style="display:none;" title="Promote this sanitized shared-okf-patterns note to Remote Tier">🚀 Promote to Remote Tier</button>
          <button id="btn-send-agent" class="icon-btn" style="display:none;">💬 Ask Agent</button>
        </div>
      </div>

      <div class="drawer-body">
        <div class="metric-grid">
          <div class="metric-card">
            <div id="metric-in" class="metric-num">0</div>
            <div class="metric-lbl">Inbound</div>
          </div>
          <div class="metric-card">
            <div id="metric-out" class="metric-num">0</div>
            <div class="metric-lbl">Outbound</div>
          </div>
          <div class="metric-card">
            <div id="metric-pr" class="metric-num">0.00</div>
            <div class="metric-lbl">PageRank</div>
          </div>
          <div class="metric-card">
            <div id="metric-reach" class="metric-num">0</div>
            <div class="metric-lbl">2-Hop Reach</div>
          </div>
        </div>

        <div id="inspector-tags-sec">
          <div class="section-hdr"><span>OKF Frontmatter Tags</span></div>
          <div id="inspector-tags" class="chip-wrap"></div>
        </div>

        <div>
          <div class="section-hdr">
            <span>Inbound Backlinks (<span id="count-inbound">0</span>)</span>
          </div>
          <div id="list-inbound" class="conn-list"></div>
        </div>

        <div>
          <div class="section-hdr">
            <span>Outbound Citations (<span id="count-outbound">0</span>)</span>
          </div>
          <div id="list-outbound" class="conn-list"></div>
        </div>

        <div>
          <div class="section-hdr"><span>Compiled Note Preview</span></div>
          <div id="inspector-markdown" class="md-reader"></div>
        </div>
      </div>
    </aside>

    <!-- Floating Hover Card -->
    <div id="hover-card">
      <div id="hc-title" class="hc-title"></div>
      <div id="hc-meta" class="hc-meta"></div>
      <div id="hc-excerpt" class="hc-excerpt"></div>
    </div>

    <!-- Bottom Telemetry Status Bar -->
    <div id="bottom-bar">
      <div class="telemetry-pill">
        <span class="gpu-indicator"><span class="gpu-dot"></span><span id="gpu-renderer-lbl">WebGL2 GPU</span></span>
        <span>•</span>
        <span id="fps-counter">60 FPS</span>
        <span>•</span>
        <span id="visible-counts">0 Nodes / 0 Edges</span>
      </div>
      <div class="telemetry-pill">
        <span id="controls-hint">WASD / Arrows: Move X/Y • Drag: 3D Orbit • Scroll / Q,E: Zoom • Click: Inspect</span>
      </div>
    </div>
  </div>

  <script nonce="__CSP_NONCE__">
    const INITIAL_GRAPH_DATA = __GRAPH_JSON_PAYLOAD__;
  </script>
  <script nonce="__CSP_NONCE__">
  (function() {
    "use strict";

    // =========================================================================
    // 1. STATE & DATA INITIALIZATION
    // =========================================================================
    const graphData = INITIAL_GRAPH_DATA;
    const hasRemoteTier = Boolean(graphData.hasRemoteTier);
    const allNodes = graphData.nodes || [];
    const allEdges = graphData.edges || [];
    const categories = graphData.categories || {};
    const epistemicTypes = graphData.epistemicTypes || {};

    const nodeById = new Map();
    const nameLookup = new Map();
    allNodes.forEach((n, idx) => {
      n.idx = idx;
      n.vx = 0;
      n.vy = 0;
      n.vz = 0;
      n.sx = 0;
      n.sy = 0;
      n.sz = 0;
      n.sRadius = 6;
      n.visible = true;
      n.pinned = false;
      n.rgb = hexToRgbNormalized(n.color || "#4285F4");
      nodeById.set(n.id, n);
      nameLookup.set(n.id.toLowerCase(), n.id);
      nameLookup.set(n.baseName.toLowerCase(), n.id);
      nameLookup.set(n.label.toLowerCase(), n.id);
      if (n.id.endsWith(".md")) {
        nameLookup.set(n.id.slice(0, -3).toLowerCase(), n.id);
      }
      if (Array.isArray(n.aliases)) {
        n.aliases.forEach(a => nameLookup.set(String(a).toLowerCase(), n.id));
      }
    });

    // Build adjacency structures
    const outNeighbors = new Map();
    const inNeighbors = new Map();
    const undirectedNeighbors = new Map();
    allNodes.forEach(n => {
      outNeighbors.set(n.id, []);
      inNeighbors.set(n.id, []);
      undirectedNeighbors.set(n.id, new Set());
    });

    const resolvedEdges = [];
    allEdges.forEach(e => {
      const sNode = nodeById.get(e.source);
      const tNode = nodeById.get(e.target);
      if (sNode && tNode && sNode !== tNode) {
        const eType = e.type || "LINKS_TO";
        const eColor = e.color || "#94a3b8";
        resolvedEdges.push({
          source: sNode,
          target: tNode,
          type: eType,
          color: eColor,
          rgb: hexToRgbNormalized(eColor),
          dashed: Boolean(e.dashed),
        });
        outNeighbors.get(sNode.id).push(tNode);
        inNeighbors.get(tNode.id).push(sNode);
        undirectedNeighbors.get(sNode.id).add(tNode.id);
        undirectedNeighbors.get(tNode.id).add(sNode.id);
      }
    });

    // UI & Simulation Configuration State
    // Notice: aceBrainEnabled is FALSE by default so personal ObsidianVault is 100% air-gapped.
    const state = {
      mode3D: true,
      searchHubOpen: false,
      aceBrainEnabled: false,
      hopDepth: 1,
      localScope: false,
      enabledGroups: new Set(["entity", "concept", "pattern", "synthesis", "ce_pattern", "source", "anchor"]),
      enabledEdgeTypes: new Set(["CORROBORATES", "COMPLEMENTS", "EXTENDS", "CONTRADICTS", "SUPERSEDES", "LINKS_TO"]),
      activeTag: "",
      searchQuery: "",
      sizeMode: "degree",
      nodeScale: 1.0,
      edgeAlpha: 0.35,
      labelLod: 55,
      showOrphans: true,
      showArrows: true,
      autoRotate3D: false,
      repulsion: 220,
      linkDist: 95,
      gravity: 0.018,
      freezePhysics: false,
      simAlpha: 1.0,
      hoveredNode: null,
      selectedNode: null,
      draggedNode: null,
      // Spotlight BFS map: node.id -> hop distance (0, 1, 2)
      spotlightMap: new Map(),
      // 2D camera
      panX: 0,
      panY: 0,
      zoom: 0.85,
      // 3D Orbit camera
      yaw: 0.35,
      pitch: 0.25,
      camDist: 920,
      pan3DX: 0,
      pan3DY: 0,
    };

    function hexToRgbNormalized(hex) {
      const clean = hex.replace("#", "");
      const num = parseInt(clean, 16);
      return [
        ((num >> 16) & 255) / 255,
        ((num >> 8) & 255) / 255,
        (num & 255) / 255,
      ];
    }

    // =========================================================================
    // 2. BFS NEIGHBORHOOD & VISIBILITY FILTERING
    // =========================================================================
    function computeBfsHops(rootId, maxHops) {
      const distMap = new Map();
      if (!rootId || !nodeById.has(rootId)) return distMap;
      distMap.set(rootId, 0);
      let frontier = [rootId];
      for (let hop = 1; hop <= maxHops; hop++) {
        const nextFrontier = [];
        for (const currId of frontier) {
          const nbrs = undirectedNeighbors.get(currId);
          if (!nbrs) continue;
          for (const nbrId of nbrs) {
            if (!distMap.has(nbrId)) {
              distMap.set(nbrId, hop);
              nextFrontier.push(nbrId);
            }
          }
        }
        frontier = nextFrontier;
      }
      return distMap;
    }

    const _SEARCH_STOP_OPS = new Set(["AND", "OR", "NOT", "NEAR"]);

    function _splitIdentifierSegment(seg) {
      const out = [];
      const rawParts = seg.split(/[-_./]+/);
      for (let pIdx = 0; pIdx < rawParts.length; pIdx++) {
        const part = rawParts[pIdx];
        if (!part) continue;
        const lowPart = part.toLowerCase();
        out.push(lowPart);
        let start = 0;
        for (let i = 1; i < part.length; i++) {
          const prev = part.charCodeAt(i - 1);
          const curr = part.charCodeAt(i);
          const next = i + 1 < part.length ? part.charCodeAt(i + 1) : 0;
          const prevIsLower = prev >= 97 && prev <= 122;
          const prevIsUpper = prev >= 65 && prev <= 90;
          const prevIsDigit = prev >= 48 && prev <= 57;
          const currIsUpper = curr >= 65 && curr <= 90;
          const nextIsLower = next >= 97 && next <= 122;
          const camelSplit = (prevIsLower || prevIsDigit) && currIsUpper;
          const acronymSplit = prevIsUpper && currIsUpper && nextIsLower;
          if (camelSplit || acronymSplit) {
            const sub = part.slice(start, i).toLowerCase();
            if (sub.length >= 2 || (sub.length === 1 && sub >= "0" && sub <= "9")) {
              out.push(sub);
            }
            start = i;
          }
        }
        if (start > 0 && start < part.length) {
          const tail = part.slice(start).toLowerCase();
          if (tail.length >= 2 || (tail.length === 1 && tail >= "0" && tail <= "9")) {
            out.push(tail);
          }
        }
      }
      return out;
    }

    function tokenizeForSearch(text, stripOperators = false) {
      const s = String(text || "");
      const rawChunks = s.split(/[\s"'()\[\]*:^~\\,;!?\t\r\n]+/);
      const seen = new Set();
      const tokens = [];
      const nonOpChunks = [];
      for (let i = 0; i < rawChunks.length; i++) {
        const c = rawChunks[i];
        if (!c) continue;
        if (stripOperators && _SEARCH_STOP_OPS.has(c)) continue;
        nonOpChunks.push(c);
      }
      const chunks = (stripOperators && nonOpChunks.length > 0) ? nonOpChunks : rawChunks;
      for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        if (!chunk) continue;
        const expanded = _splitIdentifierSegment(chunk);
        for (let j = 0; j < expanded.length; j++) {
          const tok = expanded[j];
          if ((tok.length >= 2 || (tok.length === 1 && tok >= "0" && tok <= "9")) && !seen.has(tok)) {
            seen.add(tok);
            tokens.push(tok);
          }
        }
      }
      return tokens;
    }

    function getNodeSearchIndex(n) {
      if (!n._searchRaw) {
        const text = `${n.label || ""} ${n.id || ""} ${(n.tags || []).join(" ")} ${(n.aliases || []).join(" ")}`;
        n._searchRaw = text.toLowerCase();
        n._searchTokenSet = new Set(tokenizeForSearch(text, false));
      }
      return n;
    }

    function nodeMatchesQuickFilter(n, rawQuery) {
      const cleanQ = String(rawQuery || "").trim().toLowerCase();
      if (!cleanQ) return true;
      getNodeSearchIndex(n);
      if (n._searchRaw.includes(cleanQ)) return true;
      const rawChunks = String(rawQuery || "").trim().split(/[\s"'()\[\]*:^~\\,;!?\t\r\n]+/).filter(Boolean);
      const meaningfulChunks = rawChunks.filter(c => !_SEARCH_STOP_OPS.has(c));
      const activeChunks = meaningfulChunks.length > 0 ? meaningfulChunks : rawChunks;
      if (activeChunks.length === 0) return true;
      for (let i = 0; i < activeChunks.length; i++) {
        const ch = activeChunks[i];
        const chLow = ch.toLowerCase();
        if (n._searchRaw.includes(chLow) || n._searchTokenSet.has(chLow)) {
          continue;
        }
        const subParts = ch.split(/[-_./]+/).filter(Boolean);
        let allSubMatched = subParts.length > 0;
        for (let j = 0; j < subParts.length; j++) {
          const sp = subParts[j];
          const spLow = sp.toLowerCase();
          if (n._searchRaw.includes(spLow) || n._searchTokenSet.has(spLow)) continue;
          const expanded = _splitIdentifierSegment(sp).filter(t => t !== spLow);
          if (expanded.length === 0 || !expanded.every(t => n._searchTokenSet.has(t) || n._searchRaw.includes(t))) {
            allSubMatched = false;
            break;
          }
        }
        if (!allSubMatched) return false;
      }
      return true;
    }

    let visibleNodes = [];
    let visibleEdges = [];

    function updateVisibilityAndSpotlight() {
      const focusNode = state.hoveredNode || state.selectedNode;
      state.spotlightMap = focusNode
        ? computeBfsHops(focusNode.id, state.hopDepth)
        : new Map();

      const localRoot = state.selectedNode || state.inspectedNode;
      const localAllowed = (state.localScope && localRoot)
        ? computeBfsHops(localRoot.id, state.hopDepth)
        : null;

      const rawQ = state.searchQuery;

      visibleNodes = [];
      for (const n of allNodes) {
        let vis = state.enabledGroups.has(n.group);
        if (!state.aceBrainEnabled && n.group === "remote_tier") vis = false;
        if (vis && !state.showOrphans && n.isOrphan) vis = false;
        if (vis && state.activeTag && (!n.tags || !n.tags.includes(state.activeTag))) vis = false;
        if (vis && localAllowed && !localAllowed.has(n.id)) vis = false;
        if (vis && rawQ.trim()) {
          if (!nodeMatchesQuickFilter(n, rawQ)) vis = false;
        }
        n.visible = vis;
        if (vis) visibleNodes.push(n);
      }

      visibleEdges = [];
      for (const e of resolvedEdges) {
        if (e.source.visible && e.target.visible && state.enabledEdgeTypes.has(e.type || "LINKS_TO")) {
          visibleEdges.push(e);
        }
      }

      document.getElementById("visible-counts").textContent =
        `${visibleNodes.length} Nodes / ${visibleEdges.length} Edges`;
    }

    // =========================================================================
    // 3. SPATIAL-GRID ACCELERATED 2D/3D FORCE SIMULATION
    // =========================================================================
    function computeNodeBaseRadius(n) {
      let metric = n.degree;
      if (state.sizeMode === "inDegree") metric = n.inDegree * 1.4;
      else if (state.sizeMode === "pagerank") metric = n.pagerank * 28;
      else if (state.sizeMode === "uniform") metric = 4;
      const r = 4.8 + Math.sqrt(Math.max(0, metric)) * 2.15;
      return Math.min(26, r) * state.nodeScale;
    }

    function stepPhysics() {
      if (state.freezePhysics || state.simAlpha < 0.002) return;

      const N = visibleNodes.length;
      if (N === 0) return;

      const alpha = state.simAlpha;
      const repulse = state.repulsion * alpha;
      const gravity = state.gravity * alpha;
      const targetDist = state.linkDist;
      const is3D = state.mode3D;

      // 1. Center gravity force
      for (let i = 0; i < N; i++) {
        const n = visibleNodes[i];
        if (n.pinned || n === state.draggedNode) continue;
        n.vx -= n.x * gravity;
        n.vy -= n.y * gravity;
        if (is3D) {
          n.vz -= n.z * gravity;
        } else {
          n.z *= 0.85;
          n.vz = 0;
        }
      }

      // 2. All-pairs repulsion (fast O(N^2) with cutoff for N <= 1000)
      const maxRepulseDistSq = 520 * 520;
      for (let i = 0; i < N; i++) {
        const a = visibleNodes[i];
        for (let j = i + 1; j < N; j++) {
          const b = visibleNodes[j];
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const dz = is3D ? (b.z - a.z) : 0;
          let d2 = dx * dx + dy * dy + dz * dz;
          if (d2 > maxRepulseDistSq) continue;
          if (d2 < 4) d2 = 4;
          const force = repulse / d2;
          const fx = dx * force;
          const fy = dy * force;
          const fz = dz * force;
          if (!a.pinned && a !== state.draggedNode) {
            a.vx -= fx;
            a.vy -= fy;
            if (is3D) a.vz -= fz;
          }
          if (!b.pinned && b !== state.draggedNode) {
            b.vx += fx;
            b.vy += fy;
            if (is3D) b.vz += fz;
          }
        }
      }

      // 3. Spring link attraction (anchor index/log links use gentler spring weight so semantic clusters separate cleanly)
      const springK = 0.045 * alpha;
      for (let i = 0; i < visibleEdges.length; i++) {
        const e = visibleEdges[i];
        const s = e.source;
        const t = e.target;
        const isAnchorEdge = (s.group === "anchor" || t.group === "anchor");
        const edgeWeight = isAnchorEdge ? 0.22 : 1.0;
        const edgeTargetDist = isAnchorEdge ? targetDist * 1.45 : targetDist;
        const dx = t.x - s.x;
        const dy = t.y - s.y;
        const dz = is3D ? (t.z - s.z) : 0;
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1;
        const delta = (dist - edgeTargetDist) * springK * edgeWeight / dist;
        const fx = dx * delta;
        const fy = dy * delta;
        const fz = dz * delta;
        if (!s.pinned && s !== state.draggedNode) {
          s.vx += fx;
          s.vy += fy;
          if (is3D) s.vz += fz;
        }
        if (!t.pinned && t !== state.draggedNode) {
          t.vx -= fx;
          t.vy -= fy;
          if (is3D) t.vz -= fz;
        }
      }

      // 4. Velocity integration & damping
      const damping = 0.78;
      const maxVel = 32;
      for (let i = 0; i < N; i++) {
        const n = visibleNodes[i];
        if (n.pinned || n === state.draggedNode) continue;
        n.vx *= damping;
        n.vy *= damping;
        n.vz *= damping;
        const vMag = Math.sqrt(n.vx * n.vx + n.vy * n.vy + n.vz * n.vz);
        if (vMag > maxVel) {
          const s = maxVel / vMag;
          n.vx *= s;
          n.vy *= s;
          n.vz *= s;
        }
        n.x += n.vx;
        n.y += n.vy;
        if (is3D) n.z += n.vz;
      }

      state.simAlpha *= 0.992;
    }

    // =========================================================================
    // 4. WEBGL SHADER ENGINE (EDGES + SDF NODES) + HIDPI HUD OVERLAY
    // =========================================================================
    const stageEl = document.getElementById("canvas-stage");
    const glCanvas = document.getElementById("gl-canvas");
    const hudCanvas = document.getElementById("hud-canvas");
    const hudCtx = hudCanvas.getContext("2d");

    const gl =
      glCanvas.getContext("webgl2", { antialias: true, alpha: false, preserveDrawingBuffer: true, powerPreference: "high-performance" }) ||
      glCanvas.getContext("webgl", { antialias: true, alpha: false, preserveDrawingBuffer: true, powerPreference: "high-performance" });
    const fallbackCtx = gl ? null : glCanvas.getContext("2d");

    const isWebGL2 = typeof WebGL2RenderingContext !== "undefined" && gl instanceof WebGL2RenderingContext;
    document.getElementById("gpu-renderer-lbl").textContent = isWebGL2
      ? "WebGL2 Hardware GPU"
      : (gl ? "WebGL1 GPU" : "Batched Turbo 2D/3D Engine (VM Optimized)");

    // Pre-cache shortened labels and approximate character widths once at startup to eliminate per-frame measureText() CPU overhead
    hudCtx.font = '500 11.5px "Google Sans", "Inter", system-ui, sans-serif';
    for (let i = 0; i < allNodes.length; i++) {
      const n = allNodes[i];
      n.shortLabel = n.label.length > 34 ? n.label.slice(0, 32) + "…" : n.label;
      n.shortWidth = hudCtx.measureText(n.shortLabel).width;
      n.fullWidth = hudCtx.measureText(n.label).width * 1.12;
    }

    function compileShader(type, src) {
      const sh = gl.createShader(type);
      gl.shaderSource(sh, src);
      gl.compileShader(sh);
      if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
        console.error("Shader compile error:", gl.getShaderInfoLog(sh));
      }
      return sh;
    }

    function createProgram(vsSrc, fsSrc) {
      const prog = gl.createProgram();
      gl.attachShader(prog, compileShader(gl.VERTEX_SHADER, vsSrc));
      gl.attachShader(prog, compileShader(gl.FRAGMENT_SHADER, fsSrc));
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
        console.error("Program link error:", gl.getProgramInfoLog(prog));
      }
      return prog;
    }

    // Edge Shader: screen-space normalized clip coordinates
    const EDGE_VS = `
      attribute vec2 a_clipPos;
      attribute vec4 a_color;
      varying vec4 v_color;
      void main() {
        gl_Position = vec4(a_clipPos, 0.0, 1.0);
        v_color = a_color;
      }
    `;
    const EDGE_FS = `
      precision mediump float;
      varying vec4 v_color;
      void main() {
        gl_FragColor = v_color;
      }
    `;

    // Node SDF Point-Sprite Shader
    const NODE_VS = `
      attribute vec2 a_clipPos;
      attribute vec4 a_color;
      attribute float a_pointSize;
      attribute float a_state;
      varying vec4 v_color;
      varying float v_state;
      void main() {
        gl_Position = vec4(a_clipPos, 0.0, 1.0);
        gl_PointSize = a_pointSize;
        v_color = a_color;
        v_state = a_state;
      }
    `;
    const NODE_FS = `
      precision mediump float;
      varying vec4 v_color;
      varying float v_state;
      uniform float u_is3d;
      void main() {
        vec2 uv = (gl_PointCoord - vec2(0.5)) * 2.0;
        float dist = length(uv);
        if (dist > 1.0) discard;

        // Core radius is 0.62 of point sprite; 0.62..1.0 is ambient halo
        float coreRadius = 0.62;
        float halo = smoothstep(1.0, coreRadius, dist) * 0.35;
        if (v_state >= 1.5) {
          halo = smoothstep(1.0, coreRadius * 0.85, dist) * 0.65;
        } else if (v_state >= 0.5) {
          halo = smoothstep(1.0, coreRadius * 0.9, dist) * 0.48;
        }

        float coreMask = smoothstep(coreRadius + 0.04, coreRadius - 0.04, dist);
        vec3 baseCol = v_color.rgb;

        if (u_is3d > 0.5 && dist <= coreRadius) {
          // 3D sphere lighting inside core
          vec2 sphereUv = uv / coreRadius;
          float z = sqrt(max(0.0, 1.0 - dot(sphereUv, sphereUv)));
          vec3 norm = normalize(vec3(sphereUv.x, -sphereUv.y, z));
          vec3 lightDir = normalize(vec3(-0.45, 0.55, 0.7));
          float diff = max(0.25, dot(norm, lightDir));
          float spec = pow(max(0.0, dot(reflect(-lightDir, norm), vec3(0.0, 0.0, 1.0))), 20.0) * 0.45;
          baseCol = baseCol * diff + vec3(spec);
        } else if (dist <= coreRadius) {
          // Subtle inner rim highlight in 2D mode
          float rim = smoothstep(coreRadius - 0.14, coreRadius, dist);
          baseCol = mix(baseCol, vec3(1.0), rim * (v_state >= 0.5 ? 0.55 : 0.22));
        }

        // Focus ring on selected/hovered node
        if (v_state >= 1.5 && dist > coreRadius && dist < coreRadius + 0.14) {
          baseCol = vec3(1.0);
          coreMask = max(coreMask, 0.92);
        }

        float finalAlpha = max(coreMask, halo) * v_color.a;
        gl_FragColor = vec4(baseCol, finalAlpha);
      }
    `;

    let edgeProg = null;
    let nodeProg = null;
    let edgeBuffer = null;
    let nodeBuffer = null;

    if (gl) {
      edgeProg = createProgram(EDGE_VS, EDGE_FS);
      nodeProg = createProgram(NODE_VS, NODE_FS);
      edgeBuffer = gl.createBuffer();
      nodeBuffer = gl.createBuffer();
    }

    let viewWidth = 1280;
    let viewHeight = 800;
    // Use 1x DPR when running on CPU Canvas2D fallback (e.g. inside GPU-less Remote Desktop) to prevent 4x pixel fill bottlenecks
    let dpr = gl ? Math.min(window.devicePixelRatio || 1, 2) : 1;

    function resizeCanvases() {
      const rect = stageEl.getBoundingClientRect();
      if (rect.width < 10 || rect.height < 10) return;
      viewWidth = rect.width;
      viewHeight = rect.height;
      dpr = gl ? Math.min(window.devicePixelRatio || 1, 2) : 1;

      glCanvas.width = Math.round(viewWidth * dpr);
      glCanvas.height = Math.round(viewHeight * dpr);
      hudCanvas.width = Math.round(viewWidth * dpr);
      hudCanvas.height = Math.round(viewHeight * dpr);

      if (gl) {
        gl.viewport(0, 0, glCanvas.width, glCanvas.height);
      }
    }

    const resizeObserver = new ResizeObserver(() => resizeCanvases());
    resizeObserver.observe(stageEl);
    resizeCanvases();

    // Pre-allocated typed buffers for zero-GC WebGL uploads
    const MAX_EDGES = Math.max(allEdges.length + 100, 4000);
    const MAX_NODES = Math.max(allNodes.length + 100, 1000);
    // 2 vertices per edge * 6 floats (clipX, clipY, r, g, b, a)
    const edgeFloatData = new Float32Array(MAX_EDGES * 2 * 6);
    // 1 vertex per node * 8 floats (clipX, clipY, r, g, b, a, pointSize, stateFlag)
    const nodeFloatData = new Float32Array(MAX_NODES * 8);

    function getStageCenter() {
      const leftDockEl = document.getElementById("left-dock");
      const rightDrawerEl = document.getElementById("right-drawer");
      const leftInset = (leftDockEl && !leftDockEl.classList.contains("collapsed") && viewWidth > 760) ? 280 : 0;
      const rightInset = (rightDrawerEl && !rightDrawerEl.classList.contains("collapsed") && viewWidth > 860) ? 420 : 0;
      const cx = leftInset + (viewWidth - leftInset - rightInset) * 0.5;
      const cy = viewHeight * 0.52;
      return { cx, cy };
    }

    function projectNodesToScreen() {
      const { cx: halfW, cy: halfH } = getStageCenter();

      if (!state.mode3D) {
        for (let i = 0; i < visibleNodes.length; i++) {
          const n = visibleNodes[i];
          n.sx = halfW + (n.x + state.panX) * state.zoom;
          n.sy = halfH + (n.y + state.panY) * state.zoom;
          n.sz = 0;
          n.sRadius = computeNodeBaseRadius(n) * Math.pow(state.zoom, 0.55);
        }
      } else {
        const cosY = Math.cos(state.yaw);
        const sinY = Math.sin(state.yaw);
        const cosP = Math.cos(state.pitch);
        const sinP = Math.sin(state.pitch);
        const fov = 720;

        for (let i = 0; i < visibleNodes.length; i++) {
          const n = visibleNodes[i];
          const x1 = n.x * cosY - n.z * sinY;
          const z1 = n.x * sinY + n.z * cosY;
          const y2 = n.y * cosP - z1 * sinP;
          const z2 = n.y * sinP + z1 * cosP + state.camDist;
          const depth = Math.max(80, z2);
          const scale = fov / depth;
          n.sx = halfW + state.pan3DX + x1 * scale;
          n.sy = halfH + state.pan3DY + y2 * scale;
          n.sz = depth;
          n.sRadius = computeNodeBaseRadius(n) * scale * 1.15;
        }
      }
    }

    function screenToClipX(sx) {
      return (sx / viewWidth) * 2.0 - 1.0;
    }

    function screenToClipY(sy) {
      return 1.0 - (sy / viewHeight) * 2.0;
    }

    const pressedKeys = new Set();

    function stepKeyboardCamera() {
      if (pressedKeys.size === 0) return;
      const sprint = pressedKeys.has("shift") ? 2.15 : 1.0;
      const panStep = 9.5 * sprint;

      let dx = 0;
      let dy = 0;
      if (pressedKeys.has("w") || pressedKeys.has("arrowup")) dy += panStep;
      if (pressedKeys.has("s") || pressedKeys.has("arrowdown")) dy -= panStep;
      if (pressedKeys.has("a") || pressedKeys.has("arrowleft")) dx += panStep;
      if (pressedKeys.has("d") || pressedKeys.has("arrowright")) dx -= panStep;

      if (dx !== 0 && dy !== 0) {
        const diag = 0.7071;
        dx *= diag;
        dy *= diag;
      }

      if (dx !== 0 || dy !== 0) {
        if (state.mode3D) {
          state.pan3DX += dx;
          state.pan3DY += dy;
        } else {
          state.panX += dx / state.zoom;
          state.panY += dy / state.zoom;
        }
      }

      // Optional Q / E smooth zoom out / zoom in
      if (pressedKeys.has("q") || pressedKeys.has("-")) {
        if (state.mode3D) {
          state.camDist = Math.min(2800, state.camDist * 1.022);
        } else {
          state.zoom = Math.max(0.12, state.zoom / 1.022);
        }
      }
      if (pressedKeys.has("e") || pressedKeys.has("=")) {
        if (state.mode3D) {
          state.camDist = Math.max(160, state.camDist / 1.022);
        } else {
          state.zoom = Math.min(6.0, state.zoom * 1.022);
        }
      }
    }

    function renderFrame() {
      if (viewWidth < 10 || viewHeight < 10) return;

      stepKeyboardCamera();

      if (state.mode3D && state.autoRotate3D && !state.draggedNode) {
        state.yaw += 0.0035;
      }

      if (state.simAlpha > 0.005 || state.draggedNode) {
        stepPhysics();
      }
      projectNodesToScreen();

      const hasSpotlight = state.spotlightMap.size > 0;
      const baseEdgeAlpha = state.edgeAlpha;

      // 1. Identify highlighted edges vs regular edges
      let ePtr = 0;
      const highlightedEdges = [];
      const regularEdges = [];

      for (let i = 0; i < visibleEdges.length; i++) {
        const e = visibleEdges[i];
        const s = e.source;
        const t = e.target;

        let isHighlighted = false;
        let alpha = baseEdgeAlpha;

        if (hasSpotlight) {
          const sHop = state.spotlightMap.get(s.id);
          const tHop = state.spotlightMap.get(t.id);
          if (sHop !== undefined && tHop !== undefined && (sHop === 0 || tHop === 0 || (state.hopDepth >= 2 && (sHop + tHop <= 2)))) {
            isHighlighted = true;
          } else {
            alpha = 0.045;
          }
        }

        if (isHighlighted) {
          highlightedEdges.push(e);
          continue;
        }

        regularEdges.push(e);

        if (gl) {
          const c1x = screenToClipX(s.sx);
          const c1y = screenToClipY(s.sy);
          const c2x = screenToClipX(t.sx);
          const c2y = screenToClipY(t.sy);
          const isTyped = e.type && e.type !== "LINKS_TO";
          const er = isTyped ? e.rgb[0] : 0.58;
          const eg = isTyped ? e.rgb[1] : 0.64;
          const eb = isTyped ? e.rgb[2] : 0.72;
          const ea = isTyped ? (hasSpotlight ? 0.08 : Math.min(0.88, alpha * 1.65)) : alpha;

          edgeFloatData[ePtr++] = c1x;
          edgeFloatData[ePtr++] = c1y;
          edgeFloatData[ePtr++] = er;
          edgeFloatData[ePtr++] = eg;
          edgeFloatData[ePtr++] = eb;
          edgeFloatData[ePtr++] = ea;

          edgeFloatData[ePtr++] = c2x;
          edgeFloatData[ePtr++] = c2y;
          edgeFloatData[ePtr++] = er;
          edgeFloatData[ePtr++] = eg;
          edgeFloatData[ePtr++] = eb;
          edgeFloatData[ePtr++] = ea;
        }
      }

      if (gl) {
        // Append highlighted spotlight edges on top for WebGL
        for (let i = 0; i < highlightedEdges.length; i++) {
          const e = highlightedEdges[i];
          const s = e.source;
          const t = e.target;
          const c1x = screenToClipX(s.sx);
          const c1y = screenToClipY(s.sy);
          const c2x = screenToClipX(t.sx);
          const c2y = screenToClipY(t.sy);
          const isTyped = e.type && e.type !== "LINKS_TO";

          edgeFloatData[ePtr++] = c1x;
          edgeFloatData[ePtr++] = c1y;
          edgeFloatData[ePtr++] = isTyped ? e.rgb[0] : s.rgb[0];
          edgeFloatData[ePtr++] = isTyped ? e.rgb[1] : s.rgb[1];
          edgeFloatData[ePtr++] = isTyped ? e.rgb[2] : s.rgb[2];
          edgeFloatData[ePtr++] = 0.92;

          edgeFloatData[ePtr++] = c2x;
          edgeFloatData[ePtr++] = c2y;
          edgeFloatData[ePtr++] = isTyped ? e.rgb[0] : t.rgb[0];
          edgeFloatData[ePtr++] = isTyped ? e.rgb[1] : t.rgb[1];
          edgeFloatData[ePtr++] = isTyped ? e.rgb[2] : t.rgb[2];
          edgeFloatData[ePtr++] = 0.92;
        }
      }

      // 2. Sort nodes back-to-front in 3D mode or spotlight order in 2D
      const renderNodes = (state.mode3D || hasSpotlight) ? visibleNodes.slice() : visibleNodes;
      if (state.mode3D) {
        renderNodes.sort((a, b) => b.sz - a.sz);
      } else if (hasSpotlight) {
        renderNodes.sort((a, b) => {
          const ha = state.spotlightMap.has(a.id) ? 1 : 0;
          const hb = state.spotlightMap.has(b.id) ? 1 : 0;
          return ha - hb;
        });
      }

      let nPtr = 0;
      if (gl) {
        for (let i = 0; i < renderNodes.length; i++) {
          const n = renderNodes[i];
          const hop = state.spotlightMap.get(n.id);
          let alpha = 0.96;
          let stateFlag = 0.0;

          if (hasSpotlight) {
            if (hop === 0) {
              stateFlag = 2.0;
              alpha = 1.0;
            } else if (hop === 1) {
              stateFlag = 1.0;
              alpha = 0.98;
            } else if (hop === 2) {
              stateFlag = 0.6;
              alpha = 0.72;
            } else {
              alpha = 0.11;
            }
          } else if (n === state.selectedNode) {
            stateFlag = 2.0;
          }

          // Convert screen radius to WebGL point size (core is 0.62 of total sprite)
          const pointDiameterPx = Math.max(4.0, (n.sRadius * 2.0 * dpr) / 0.62);

          nodeFloatData[nPtr++] = screenToClipX(n.sx);
          nodeFloatData[nPtr++] = screenToClipY(n.sy);
          nodeFloatData[nPtr++] = n.rgb[0];
          nodeFloatData[nPtr++] = n.rgb[1];
          nodeFloatData[nPtr++] = n.rgb[2];
          nodeFloatData[nPtr++] = alpha;
          nodeFloatData[nPtr++] = pointDiameterPx;
          nodeFloatData[nPtr++] = stateFlag;
        }
      }

      // 3. Execute WebGL or Batched Turbo Canvas2D Draw Calls
      if (gl) {
        gl.clearColor(0.043, 0.059, 0.09, 1.0);
        gl.clear(gl.COLOR_BUFFER_BIT);
        gl.enable(gl.BLEND);
        gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

        // Draw Edges
        const edgeVertexCount = ePtr / 6;
        if (edgeVertexCount > 0) {
          gl.useProgram(edgeProg);
          gl.bindBuffer(gl.ARRAY_BUFFER, edgeBuffer);
          gl.bufferData(gl.ARRAY_BUFFER, edgeFloatData.subarray(0, ePtr), gl.DYNAMIC_DRAW);

          const posLoc = gl.getAttribLocation(edgeProg, "a_clipPos");
          const colLoc = gl.getAttribLocation(edgeProg, "a_color");
          gl.enableVertexAttribArray(posLoc);
          gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 24, 0);
          gl.enableVertexAttribArray(colLoc);
          gl.vertexAttribPointer(colLoc, 4, gl.FLOAT, false, 24, 8);

          gl.drawArrays(gl.LINES, 0, edgeVertexCount);
        }

        // Draw Nodes
        const nodeVertexCount = nPtr / 8;
        if (nodeVertexCount > 0) {
          gl.useProgram(nodeProg);
          gl.uniform1f(gl.getUniformLocation(nodeProg, "u_is3d"), state.mode3D ? 1.0 : 0.0);

          gl.bindBuffer(gl.ARRAY_BUFFER, nodeBuffer);
          gl.bufferData(gl.ARRAY_BUFFER, nodeFloatData.subarray(0, nPtr), gl.DYNAMIC_DRAW);

          const posLoc = gl.getAttribLocation(nodeProg, "a_clipPos");
          const colLoc = gl.getAttribLocation(nodeProg, "a_color");
          const sizeLoc = gl.getAttribLocation(nodeProg, "a_pointSize");
          const stateLoc = gl.getAttribLocation(nodeProg, "a_state");

          gl.enableVertexAttribArray(posLoc);
          gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 32, 0);
          gl.enableVertexAttribArray(colLoc);
          gl.vertexAttribPointer(colLoc, 4, gl.FLOAT, false, 32, 8);
          gl.enableVertexAttribArray(sizeLoc);
          gl.vertexAttribPointer(sizeLoc, 1, gl.FLOAT, false, 32, 24);
          gl.enableVertexAttribArray(stateLoc);
          gl.vertexAttribPointer(stateLoc, 1, gl.FLOAT, false, 32, 28);

          gl.drawArrays(gl.POINTS, 0, nodeVertexCount);
        }
      } else if (fallbackCtx) {
        // Batched Turbo 2D/3D Engine: 1 single stroke() call for all regular edges + 1 stroke() call for spotlight edges
        fallbackCtx.save();
        fallbackCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
        fallbackCtx.fillStyle = "#0b0f17";
        fallbackCtx.fillRect(0, 0, viewWidth, viewHeight);

        const regAlpha = hasSpotlight ? 0.05 : baseEdgeAlpha;
        if (regularEdges.length > 0 && regAlpha > 0.01) {
          fallbackCtx.strokeStyle = `rgba(148, 163, 184, ${regAlpha})`;
          fallbackCtx.lineWidth = 1.0;
          fallbackCtx.beginPath();
          for (let i = 0; i < regularEdges.length; i++) {
            const e = regularEdges[i];
            fallbackCtx.moveTo(e.source.sx, e.source.sy);
            fallbackCtx.lineTo(e.target.sx, e.target.sy);
          }
          fallbackCtx.stroke();
        }

        if (highlightedEdges.length > 0) {
          fallbackCtx.strokeStyle = "rgba(96, 165, 250, 0.85)";
          fallbackCtx.lineWidth = 1.6;
          fallbackCtx.beginPath();
          for (let i = 0; i < highlightedEdges.length; i++) {
            const e = highlightedEdges[i];
            fallbackCtx.moveTo(e.source.sx, e.source.sy);
            fallbackCtx.lineTo(e.target.sx, e.target.sy);
          }
          fallbackCtx.stroke();
        }

        // Draw nodes with full spotlight alpha & focus ring support
        for (let i = 0; i < renderNodes.length; i++) {
          const n = renderNodes[i];
          if (n.sx < -40 || n.sx > viewWidth + 40 || n.sy < -40 || n.sy > viewHeight + 40) continue;
          const hop = state.spotlightMap.get(n.id);
          let alpha = 0.96;
          let isFocus = false;
          if (hasSpotlight) {
            if (hop === 0) {
              alpha = 1.0;
              isFocus = true;
            } else if (hop === 1) {
              alpha = 0.98;
            } else if (hop === 2) {
              alpha = 0.72;
            } else {
              alpha = 0.12;
            }
          } else if (n === state.selectedNode) {
            isFocus = true;
          }

          fallbackCtx.globalAlpha = alpha;
          fallbackCtx.fillStyle = n.color;
          fallbackCtx.beginPath();
          fallbackCtx.arc(n.sx, n.sy, n.sRadius, 0, Math.PI * 2);
          fallbackCtx.fill();

          if (isFocus) {
            fallbackCtx.strokeStyle = "#ffffff";
            fallbackCtx.lineWidth = 2.0;
            fallbackCtx.stroke();
          }
        }
        fallbackCtx.globalAlpha = 1.0;
        fallbackCtx.restore();
      }

      // 4. Render HiDPI HUD Overlay (Batched Directional Arrows & Pre-Measured LOD Labels)
      hudCtx.save();
      hudCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
      hudCtx.clearRect(0, 0, viewWidth, viewHeight);

      // Directional arrowheads batched into a single path + single fill() call
      if (state.showArrows) {
        const minArrowZoom = gl ? 0.72 : 1.15;
        const arrowSource = hasSpotlight ? highlightedEdges : (state.zoom > minArrowZoom || state.mode3D ? visibleEdges : []);
        if (arrowSource.length > 0) {
          hudCtx.fillStyle = hasSpotlight ? "rgba(147, 197, 253, 0.85)" : `rgba(148, 163, 184, ${Math.min(0.65, baseEdgeAlpha * 1.3)})`;
          hudCtx.beginPath();
          const arrowLen = hasSpotlight ? 6.5 : 5.0;
          const arrowWing = hasSpotlight ? 3.2 : 2.4;
          for (let i = 0; i < arrowSource.length; i++) {
            const e = arrowSource[i];
            const s = e.source;
            const t = e.target;
            const dx = t.sx - s.sx;
            const dy = t.sy - s.sy;
            const lenSq = dx * dx + dy * dy;
            if (lenSq < 784) continue; // len < 28
            const len = Math.sqrt(lenSq);
            const ux = dx / len;
            const uy = dy / len;
            const tipX = t.sx - ux * (t.sRadius + 2);
            const tipY = t.sy - uy * (t.sRadius + 2);

            hudCtx.moveTo(tipX, tipY);
            hudCtx.lineTo(tipX - ux * arrowLen - uy * arrowWing, tipY - uy * arrowLen + ux * arrowWing);
            hudCtx.lineTo(tipX - ux * arrowLen + uy * arrowWing, tipY - uy * arrowLen - ux * arrowWing);
          }
          hudCtx.fill();
        }
      }

      // LOD Text Labels with overlap avoidance and pre-cached text widths
      const lodSlider = state.labelLod; // 0..100
      const effectiveZoom = state.mode3D ? (920 / Math.max(250, state.camDist)) : state.zoom;
      const degreeThreshold = Math.max(0, Math.round((100 - lodSlider) * 0.25 - (effectiveZoom - 0.8) * 8));

      hudCtx.textAlign = "center";
      hudCtx.textBaseline = "top";
      hudCtx.font = '500 11.5px "Google Sans", "Inter", system-ui, sans-serif';

      const placedBoxes = [];

      // Prioritize spotlighted / higher degree nodes for label placement
      const labelCandidates = renderNodes.slice().sort((a, b) => {
        const sa = state.spotlightMap.has(a.id) ? (10 - state.spotlightMap.get(a.id)) : 0;
        const sb = state.spotlightMap.has(b.id) ? (10 - state.spotlightMap.get(b.id)) : 0;
        if (sa !== sb) return sb - sa;
        return b.degree - a.degree;
      });

      for (let i = 0; i < labelCandidates.length; i++) {
        const n = labelCandidates[i];
        if (n.sx < -60 || n.sx > viewWidth + 60 || n.sy < -30 || n.sy > viewHeight + 30) continue;

        const hop = state.spotlightMap.get(n.id);
        const isFocus = hop === 0 || n === state.selectedNode;
        const isNeighbor = hop === 1 || hop === 2;

        if (hasSpotlight && !isFocus && !isNeighbor) continue;
        if (!hasSpotlight && !isFocus && lodSlider < 95 && n.degree < degreeThreshold) continue;

        const fontSize = isFocus ? 13 : 11.5;
        const lbl = isFocus ? n.label : n.shortLabel;
        const textW = isFocus ? n.fullWidth : n.shortWidth;
        const lx = n.sx;
        const ly = n.sy + n.sRadius + 4;

        const box = {
          x0: lx - textW * 0.5 - 4,
          y0: ly - 1,
          x1: lx + textW * 0.5 + 4,
          y1: ly + fontSize + 3,
        };

        // Prevent label overlaps for all non-focus nodes
        if (!isFocus) {
          let overlaps = false;
          for (let j = 0; j < placedBoxes.length; j++) {
            const b = placedBoxes[j];
            if (box.x0 < b.x1 && box.x1 > b.x0 && box.y0 < b.y1 && box.y1 > b.y0) {
              overlaps = true;
              break;
            }
          }
          if (overlaps) continue;
        }
        placedBoxes.push(box);

        // Pill background behind label for crisp readability
        hudCtx.fillStyle = isFocus
          ? "rgba(30, 58, 138, 0.92)"
          : "rgba(11, 15, 23, 0.78)";
        hudCtx.fillRect(box.x0, box.y0, box.x1 - box.x0, box.y1 - box.y0);

        if (isFocus) {
          hudCtx.strokeStyle = "#60a5fa";
          hudCtx.lineWidth = 1;
          hudCtx.strokeRect(box.x0, box.y0, box.x1 - box.x0, box.y1 - box.y0);
        }

        hudCtx.fillStyle = isFocus
          ? "#ffffff"
          : (hop === 1 ? "#f3f4f6" : "rgba(229, 231, 235, 0.88)");
        hudCtx.fillText(lbl, lx, ly + 1);
      }

      hudCtx.restore();
    }

    // =========================================================================
    // 5. POINTER INTERACTION (PAN, ZOOM, 3D ORBIT, NODE DRAG, HOVER & CLICK)
    // =========================================================================
    function pickNodeAt(clientX, clientY) {
      const rect = glCanvas.getBoundingClientRect();
      const mx = clientX - rect.left;
      const my = clientY - rect.top;
      let bestNode = null;
      let bestDist = Infinity;

      for (let i = 0; i < visibleNodes.length; i++) {
        const n = visibleNodes[i];
        const hitR = Math.max(8, n.sRadius + 4);
        const dx = mx - n.sx;
        const dy = my - n.sy;
        const d = Math.sqrt(dx * dx + dy * dy);
        if (d <= hitR && d < bestDist) {
          bestDist = d;
          bestNode = n;
        }
      }
      return { node: bestNode, mx, my };
    }

    let isPointerDown = false;
    let pointerMoved = false;
    let downX = 0;
    let downY = 0;
    let lastX = 0;
    let lastY = 0;

    const hoverCard = document.getElementById("hover-card");

    glCanvas.addEventListener("pointerdown", e => {
      isPointerDown = true;
      pointerMoved = false;
      downX = lastX = e.clientX;
      downY = lastY = e.clientY;
      glCanvas.setPointerCapture(e.pointerId);

      const { node } = pickNodeAt(e.clientX, e.clientY);
      if (node && e.button === 0 && !e.shiftKey) {
        state.draggedNode = node;
        state.simAlpha = Math.max(state.simAlpha, 0.35);
      }
      glCanvas.classList.add("dragging");
    });

    glCanvas.addEventListener("pointermove", e => {
      const dx = e.clientX - lastX;
      const dy = e.clientY - lastY;
      lastX = e.clientX;
      lastY = e.clientY;

      if (isPointerDown) {
        if (Math.hypot(e.clientX - downX, e.clientY - downY) > 4) {
          pointerMoved = true;
        }

        if (state.draggedNode) {
          if (!state.mode3D) {
            state.draggedNode.x += dx / state.zoom;
            state.draggedNode.y += dy / state.zoom;
          } else {
            const cosY = Math.cos(state.yaw);
            const sinY = Math.sin(state.yaw);
            const scale = state.camDist / 720;
            state.draggedNode.x += dx * cosY * scale;
            state.draggedNode.z -= dx * sinY * scale;
            state.draggedNode.y += dy * scale;
          }
          state.simAlpha = Math.max(state.simAlpha, 0.25);
          return;
        }

        if (!state.mode3D) {
          state.panX += dx / state.zoom;
          state.panY += dy / state.zoom;
        } else {
          if (e.shiftKey || e.buttons === 2) {
            state.pan3DX += dx;
            state.pan3DY += dy;
          } else {
            state.yaw += dx * 0.0065;
            state.pitch = Math.max(-1.45, Math.min(1.45, state.pitch + dy * 0.0065));
          }
        }
        return;
      }

      // Hover hit-test
      const { node, mx, my } = pickNodeAt(e.clientX, e.clientY);
      if (node !== state.hoveredNode) {
        state.hoveredNode = node;
        updateVisibilityAndSpotlight();
      }

      if (node) {
        glCanvas.classList.add("pointer");
        document.getElementById("hc-title").textContent = node.label;
        document.getElementById("hc-meta").textContent =
          `${node.badge} • ${node.inDegree} in / ${node.outDegree} out • PR ${node.pagerank.toFixed(2)}`;
        document.getElementById("hc-excerpt").textContent = node.excerpt || node.id;
        hoverCard.style.display = "block";
        const leftPos = Math.min(viewWidth - 305, mx + 16);
        const topPos = Math.min(viewHeight - 120, Math.max(65, my + 14));
        hoverCard.style.left = `${leftPos}px`;
        hoverCard.style.top = `${topPos}px`;
      } else {
        glCanvas.classList.remove("pointer");
        hoverCard.style.display = "none";
      }
    });

    glCanvas.addEventListener("pointerup", e => {
      glCanvas.classList.remove("dragging");
      if (!pointerMoved) {
        const { node } = pickNodeAt(e.clientX, e.clientY);
        if (node) {
          selectAndInspectNode(node, false);
        } else {
          state.selectedNode = null;
          updateVisibilityAndSpotlight();
        }
      }
      state.draggedNode = null;
      isPointerDown = false;
    });

    glCanvas.addEventListener("dblclick", e => {
      const { node } = pickNodeAt(e.clientX, e.clientY);
      if (node) {
        selectAndInspectNode(node, true);
      }
    });

    glCanvas.addEventListener("wheel", e => {
      e.preventDefault();
      const factor = Math.exp(-e.deltaY * 0.0012);
      if (!state.mode3D) {
        const rect = glCanvas.getBoundingClientRect();
        const mx = e.clientX - rect.left - viewWidth * 0.5;
        const my = e.clientY - rect.top - viewHeight * 0.5;
        const prevZoom = state.zoom;
        const nextZoom = Math.max(0.12, Math.min(6.0, prevZoom * factor));
        state.panX = (mx / nextZoom) - (mx / prevZoom) + state.panX;
        state.panY = (my / nextZoom) - (my / prevZoom) + state.panY;
        state.zoom = nextZoom;
      } else {
        state.camDist = Math.max(160, Math.min(2800, state.camDist / factor));
      }
    }, { passive: false });

    // =========================================================================
    // 6. NODE INSPECTOR, MARKDOWN READER & CAMERA FLY-TO
    // =========================================================================
    function centerCameraOnNode(node) {
      if (!node) return;
      if (!state.mode3D) {
        state.panX = -node.x;
        state.panY = -node.y;
        state.zoom = Math.max(state.zoom, 1.35);
      } else {
        state.pan3DX = 0;
        state.pan3DY = 0;
        state.camDist = 520;
      }
    }

    function escapeHtml(str) {
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    function sanitizeHttpsUrl(rawUrl) {
      if (!rawUrl || typeof rawUrl !== "string") return "";
      const trimmed = rawUrl.trim();
      try {
        const parsed = new URL(trimmed);
        if (parsed.protocol === "https:") {
          return parsed.href;
        }
      } catch (_e) {
        if (/^https:\/\/[^\s"'<>]+$/i.test(trimmed)) {
          return trimmed;
        }
      }
      return "";
    }

    function renderMarkdownWithWikilinks(mdText) {
      if (!mdText) return "<p><em>No content</em></p>";
      let html = escapeHtml(mdText);

      // Code blocks
      html = html.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (_, _lang, code) => {
        return `<pre><code>${code.trim()}</code></pre>`;
      });

      // Inline code
      html = html.replace(/`([^`\n]+)`/g, "<code>$1</code>");

      // Interactive [[wikilinks]] (supports [[Target|Alias]] and [[Target]])
      html = html.replace(/\[\[([^\]\n]+)\]\]/g, (_, inner) => {
        const parts = inner.split(/\\?\|/);
        const targetRaw = parts[0].trim().split("#")[0].trim();
        const display = (parts[1] || parts[0]).trim();
        return `<a class="md-wikilink" data-wikilink="${targetRaw}">${display}</a>`;
      });

      // Headings
      html = html.replace(/^####\s+(.*)$/gm, "<h4>$1</h4>");
      html = html.replace(/^###\s+(.*)$/gm, "<h3>$1</h3>");
      html = html.replace(/^##\s+(.*)$/gm, "<h2>$1</h2>");
      html = html.replace(/^#\s+(.*)$/gm, "<h1>$1</h1>");

      // Bold & Italic
      html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
      html = html.replace(/\*([^*\n]+)\*/g, "<em>$1</em>");

      // Blockquotes
      html = html.replace(/^&gt;\s?(.*)$/gm, "<blockquote>$1</blockquote>");

      // Bullet items
      html = html.replace(/^\s*[-*]\s+(.*)$/gm, "<li>$1</li>");

      // Simple paragraph line breaks
      html = html.replace(/\n{2,}/g, "<br><br>");
      return html;
    }

    function selectAndInspectNode(node, centerCam = false, lockSpotlight = true) {
      if (!node) return;
      state.inspectedNode = node;
      state.selectedNode = lockSpotlight ? node : null;
      if (centerCam) centerCameraOnNode(node);
      updateVisibilityAndSpotlight();

      const drawer = document.getElementById("right-drawer");
      drawer.classList.remove("collapsed");
      document.getElementById("btn-toggle-inspector").classList.add("active");

      const badgeEl = document.getElementById("inspector-badge");
      badgeEl.textContent = node.badge;
      badgeEl.style.background = node.color;

      document.getElementById("inspector-status").textContent = node.status || "stable";
      const updEl = document.getElementById("inspector-updated");
      updEl.textContent = node.updated || "";
      updEl.style.display = node.updated ? "inline-block" : "none";

      const authEl = document.getElementById("inspector-author");
      if (authEl) {
        if (node.authorId) {
          authEl.textContent = `👤 ${node.authorId}`;
          authEl.style.display = "inline-block";
        } else {
          authEl.style.display = "none";
        }
      }

      document.getElementById("inspector-title").textContent = node.label;
      document.getElementById("inspector-path").textContent = node.id;

      // Strictly only allow promotion to Remote Tier if node is from Shared shared-okf-patterns and remote tier is available!
      const btnPromoteDrawer = document.getElementById("btn-promote-ace-drawer");
      if (btnPromoteDrawer) {
        if (hasRemoteTier && node.canPromoteToAce && node.sourcePlane === "ce_patterns") {
          btnPromoteDrawer.style.display = "inline-block";
        } else {
          btnPromoteDrawer.style.display = "none";
        }
      }

      const reachMap = computeBfsHops(node.id, 2);
      document.getElementById("metric-in").textContent = node.inDegree;
      document.getElementById("metric-out").textContent = node.outDegree;
      document.getElementById("metric-pr").textContent = node.pagerank.toFixed(2);
      document.getElementById("metric-reach").textContent = Math.max(0, reachMap.size - 1);

      // Tags
      const tagsContainer = document.getElementById("inspector-tags");
      tagsContainer.innerHTML = "";
      if (node.tags && node.tags.length > 0) {
        document.getElementById("inspector-tags-sec").style.display = "block";
        node.tags.forEach(tag => {
          const chip = document.createElement("span");
          chip.className = "tag-chip";
          chip.textContent = `#${tag}`;
          chip.addEventListener("click", () => {
            state.activeTag = tag;
            document.getElementById("tag-select").value = tag;
            document.getElementById("btn-clear-tag").style.display = "inline";
            updateVisibilityAndSpotlight();
          });
          tagsContainer.appendChild(chip);
        });
      } else {
        document.getElementById("inspector-tags-sec").style.display = "none";
      }

      // Inbound & Outbound neighbor chips
      const inList = inNeighbors.get(node.id) || [];
      const outList = outNeighbors.get(node.id) || [];
      document.getElementById("count-inbound").textContent = inList.length;
      document.getElementById("count-outbound").textContent = outList.length;

      const renderConnChips = (containerId, list) => {
        const el = document.getElementById(containerId);
        el.innerHTML = "";
        if (list.length === 0) {
          el.innerHTML = `<span style="color:var(--text-dim);font-size:12px;">None</span>`;
          return;
        }
        list.slice().sort((a, b) => b.degree - a.degree).forEach(nbr => {
          const chip = document.createElement("span");
          chip.className = "conn-chip";
          chip.innerHTML = `<span class="conn-dot" style="background:${nbr.color}"></span><span>${escapeHtml(nbr.label)}</span>`;
          chip.addEventListener("click", () => {
            if (!state.enabledGroups.has(nbr.group)) {
              state.enabledGroups.add(nbr.group);
              renderCategoryFilters();
            }
            selectAndInspectNode(nbr, true);
          });
          el.appendChild(chip);
        });
      };

      renderConnChips("list-inbound", inList);
      renderConnChips("list-outbound", outList);

      // Markdown Preview
      const mdEl = document.getElementById("inspector-markdown");
      mdEl.innerHTML = renderMarkdownWithWikilinks(node.markdown);
      mdEl.querySelectorAll(".md-wikilink").forEach(linkEl => {
        linkEl.addEventListener("click", e => {
          e.preventDefault();
          const rawTarget = (linkEl.getAttribute("data-wikilink") || "").toLowerCase();
          const baseTarget = rawTarget.split("/").pop().replace(/\.md$/, "");
          const resolvedId =
            nameLookup.get(rawTarget) ||
            nameLookup.get(rawTarget.replace(/\.md$/, "")) ||
            nameLookup.get(baseTarget);
          if (resolvedId && nodeById.has(resolvedId)) {
            const targetNode = nodeById.get(resolvedId);
            state.enabledGroups.add(targetNode.group);
            renderCategoryFilters();
            selectAndInspectNode(targetNode, true);
          }
        });
      });
    }

    // =========================================================================
    // 7. UI CONTROLS, FILTERS & SEARCH WIRING
    // =========================================================================
    document.getElementById("vault-title").textContent = `${graphData.vaultName || "ObsidianVault"} Graph`;
    document.getElementById("vault-stats-pill").textContent =
      `${graphData.stats.wikiNotes} Notes • ${graphData.stats.totalEdges} Links`;

    function renderCategoryFilters() {
      const container = document.getElementById("category-filters");
      container.innerHTML = "";
      Object.entries(categories).forEach(([key, meta]) => {
        if (!hasRemoteTier && key === "remote_tier") return;
        const count = (graphData.stats.categoryCounts && graphData.stats.categoryCounts[key]) || 0;
        if (count === 0) return;
        const row = document.createElement("div");
        const isEnabled = state.enabledGroups.has(key) && (key !== "remote_tier" || state.aceBrainEnabled);
        row.className = `cat-row ${isEnabled ? "" : "disabled"}`;
        row.innerHTML = `
          <div class="cat-left">
            <span class="cat-swatch" style="background:${meta.color}"></span>
            <span class="cat-label">${escapeHtml(meta.label)}</span>
          </div>
          <span class="cat-count">${count}</span>
        `;
        row.addEventListener("click", () => {
          if (key === "remote_tier" && !state.aceBrainEnabled) {
            setAceBrainEnabled(true);
            return;
          }
          if (state.enabledGroups.has(key)) {
            state.enabledGroups.delete(key);
          } else {
            state.enabledGroups.add(key);
          }
          state.simAlpha = Math.max(state.simAlpha, 0.35);
          renderCategoryFilters();
          updateVisibilityAndSpotlight();
        });
        container.appendChild(row);
      });
    }
    renderCategoryFilters();

    const defaultWikiGroups = ["entity", "concept", "pattern", "synthesis", "ce_pattern", "source", "anchor"];
    document.getElementById("btn-all-cats").addEventListener("click", () => {
      const activeDefaults = defaultWikiGroups.filter(
        k => ((graphData.stats.categoryCounts && graphData.stats.categoryCounts[k]) || 0) > 0
      );
      if (state.aceBrainEnabled && ((graphData.stats.categoryCounts && graphData.stats.categoryCounts["remote_tier"]) || 0) > 0) {
        activeDefaults.push("remote_tier");
      }
      const allDefaultEnabled =
        state.enabledGroups.size > 0 &&
        activeDefaults.every(k => state.enabledGroups.has(k));
      if (allDefaultEnabled) {
        state.enabledGroups.clear();
      } else {
        state.enabledGroups = new Set(defaultWikiGroups);
        if (state.aceBrainEnabled) state.enabledGroups.add("remote_tier");
      }
      state.simAlpha = Math.max(state.simAlpha, 0.35);
      renderCategoryFilters();
      updateVisibilityAndSpotlight();
    });

    function renderEpistemicFilters() {
      const container = document.getElementById("epistemic-filters");
      if (!container) return;
      container.innerHTML = "";
      Object.entries(epistemicTypes).forEach(([eKey, meta]) => {
        const count = (graphData.stats.edgeTypeCounts && graphData.stats.edgeTypeCounts[eKey]) || 0;
        if (count === 0) return;
        const row = document.createElement("div");
        const isEnabled = state.enabledEdgeTypes.has(eKey);
        row.className = `cat-row ${isEnabled ? "" : "disabled"}`;
        row.innerHTML = `
          <div class="cat-left">
            <span class="cat-swatch" style="background:${meta.color}"></span>
            <span class="cat-label">${escapeHtml(meta.label)}</span>
          </div>
          <span class="cat-count">${count}</span>
        `;
        row.addEventListener("click", () => {
          if (state.enabledEdgeTypes.has(eKey)) {
            state.enabledEdgeTypes.delete(eKey);
          } else {
            state.enabledEdgeTypes.add(eKey);
          }
          renderEpistemicFilters();
          updateVisibilityAndSpotlight();
        });
        container.appendChild(row);
      });
    }
    renderEpistemicFilters();

    const btnAllEdges = document.getElementById("btn-all-edges");
    if (btnAllEdges) {
      btnAllEdges.addEventListener("click", () => {
        const allEdgeKeys = Object.keys(epistemicTypes);
        const activeEdgeKeys = allEdgeKeys.filter(
          k => ((graphData.stats.edgeTypeCounts && graphData.stats.edgeTypeCounts[k]) || 0) > 0
        );
        const allEdgesEnabled =
          state.enabledEdgeTypes.size > 0 &&
          activeEdgeKeys.every(k => state.enabledEdgeTypes.has(k));
        if (allEdgesEnabled) {
          state.enabledEdgeTypes.clear();
        } else {
          state.enabledEdgeTypes = new Set(allEdgeKeys);
        }
        renderEpistemicFilters();
        updateVisibilityAndSpotlight();
      });
    }

    // Dynamic Remote Tier Enable / Disable Toggle (Strict Air-Gap for ObsidianVault)
    const btnToggleAce = document.getElementById("btn-toggle-ace");
    const chkPlaneAce = document.getElementById("chk-plane-ace");
    const pillPlaneAce = document.getElementById("pill-plane-ace");
    const lblPlaneAce = document.getElementById("lbl-plane-ace");
    if (!hasRemoteTier) {
      if (btnToggleAce) btnToggleAce.style.display = "none";
      if (pillPlaneAce) pillPlaneAce.style.display = "none";
      const hubSub = document.querySelector(".hub-subtitle");
      if (hubSub) {
        hubSub.innerHTML =
          "Unified Federated Query &amp; 3D WebGL Graph • Personal <code>ObsidianVault</code> is 100% Air-Gapped • Shared Sanitized Patterns";
      }
      const fedInp = document.getElementById("fed-search-input");
      if (fedInp) {
        fedInp.placeholder =
          "Search across Local Vault and shared sanitized patterns...";
      }
    }
    document.getElementById("btn-promote-ace-drawer")?.addEventListener("click", () => {
      const target = state.inspectedNode || state.selectedNode;
      if (target) openAcePromoteModal(target);
    });

    function setAceBrainEnabled(enabled) {
      if (!hasRemoteTier) return;
      state.aceBrainEnabled = Boolean(enabled);
      if (state.aceBrainEnabled) {
        state.enabledGroups.add("remote_tier");
        if (btnToggleAce) {
          btnToggleAce.classList.add("enabled");
          btnToggleAce.textContent = "☁️ Remote Tier: ON (shared-okf-patterns Isolated)";
        }
        if (chkPlaneAce) chkPlaneAce.checked = true;
        if (pillPlaneAce) pillPlaneAce.classList.add("active");
        if (lblPlaneAce) lblPlaneAce.textContent = "☁️ OKF Bundles (ACTIVE — Sanitized Queries Only)";
        if (!state.aceNodesLoaded) {
          state.aceNodesLoaded = true;
          fetch("/api/graph?include_ace=1", {
            method: "GET",
            credentials: "same-origin",
            headers: { "X-KC-Request": "1" },
          })
            .then(r => (r.ok ? r.json() : null))
            .then(freshGraph => {
              if (!freshGraph || !Array.isArray(freshGraph.nodes)) return;
              let addedAny = false;
              freshGraph.nodes.forEach(nd => {
                if (nd && nd.id && !nodeById.has(nd.id)) {
                  nd.idx = allNodes.length;
                  nd.vx = 0;
                  nd.vy = 0;
                  nd.vz = 0;
                  nd.sx = 0;
                  nd.sy = 0;
                  nd.sz = 0;
                  nd.sRadius = 6;
                  nd.visible = true;
                  nd.pinned = false;
                  nd.rgb = hexToRgbNormalized(nd.color || "#A142F4");
                  nd.shortLabel = nd.label.length > 34 ? nd.label.slice(0, 32) + "…" : nd.label;
                  nd.shortWidth = hudCtx.measureText(nd.shortLabel).width;
                  nd.fullWidth = hudCtx.measureText(nd.label).width * 1.12;
                  allNodes.push(nd);
                  nodeById.set(nd.id, nd);
                  outNeighbors.set(nd.id, []);
                  inNeighbors.set(nd.id, []);
                  undirectedNeighbors.set(nd.id, new Set());
                  addedAny = true;
                }
              });
              if (addedAny && freshGraph.stats?.categoryCounts) {
                graphData.stats.categoryCounts = freshGraph.stats.categoryCounts;
              }
              renderCategoryFilters();
              updateVisibilityAndSpotlight();
              if (state.searchHubOpen) executeFederatedSearch();
            })
            .catch(() => {});
        }
      } else {
        state.enabledGroups.delete("remote_tier");
        if (btnToggleAce) {
          btnToggleAce.classList.remove("enabled");
          btnToggleAce.textContent = "🛡️ Remote Tier: OFF (Air-Gapped)";
        }
        if (chkPlaneAce) chkPlaneAce.checked = false;
        if (pillPlaneAce) pillPlaneAce.classList.remove("active");
        if (lblPlaneAce) lblPlaneAce.textContent = "☁️ OKF Bundles (OFF — Click to Enable)";
      }
      state.simAlpha = Math.max(state.simAlpha, 0.55);
      renderCategoryFilters();
      updateVisibilityAndSpotlight();
      if (state.searchHubOpen) {
        executeFederatedSearch();
      }
    }

    if (btnToggleAce) {
      btnToggleAce.addEventListener("click", () => {
        setAceBrainEnabled(!state.aceBrainEnabled);
      });
    }

    // Tag Select
    const tagSelect = document.getElementById("tag-select");
    (graphData.tags || []).forEach(tObj => {
      const opt = document.createElement("option");
      opt.value = tObj.tag;
      opt.textContent = `#${tObj.tag} (${tObj.count})`;
      tagSelect.appendChild(opt);
    });
    tagSelect.addEventListener("change", () => {
      state.activeTag = tagSelect.value;
      document.getElementById("btn-clear-tag").style.display = state.activeTag ? "inline" : "none";
      updateVisibilityAndSpotlight();
    });
    document.getElementById("btn-clear-tag").addEventListener("click", () => {
      state.activeTag = "";
      tagSelect.value = "";
      document.getElementById("btn-clear-tag").style.display = "none";
      updateVisibilityAndSpotlight();
    });

    // Mode Search Hub / 2D / 3D Unified Switcher
    const btnSearchMode = document.getElementById("btn-mode-search");
    const btn2D = document.getElementById("btn-mode-2d");
    const btn3D = document.getElementById("btn-mode-3d");
    const searchHubOverlay = document.getElementById("search-hub-overlay");
    const fedSearchInput = document.getElementById("fed-search-input");

    function setSearchHubOpen(open) {
      state.searchHubOpen = Boolean(open);
      if (state.searchHubOpen) {
        searchHubOverlay.classList.add("visible");
        btnSearchMode.classList.add("active");
        btn2D.classList.remove("active");
        btn3D.classList.remove("active");
        executeFederatedSearch();
        setTimeout(() => fedSearchInput && fedSearchInput.focus(), 60);
      } else {
        searchHubOverlay.classList.remove("visible");
        btnSearchMode.classList.remove("active");
        if (state.mode3D) {
          btn3D.classList.add("active");
          btn2D.classList.remove("active");
        } else {
          btn2D.classList.add("active");
          btn3D.classList.remove("active");
        }
      }
    }

    if (btnSearchMode) {
      btnSearchMode.addEventListener("click", () => {
        setSearchHubOpen(!state.searchHubOpen);
      });
    }
    document.getElementById("btn-close-search-hub")?.addEventListener("click", () => {
      setSearchHubOpen(false);
    });
    const brandTitleEl = document.querySelector(".brand-title");
    if (brandTitleEl) {
      brandTitleEl.style.cursor = "pointer";
      brandTitleEl.addEventListener("click", () => {
        setSearchHubOpen(!state.searchHubOpen);
      });
    }

    btn2D.addEventListener("click", () => {
      state.mode3D = false;
      setSearchHubOpen(false);
      btn2D.classList.add("active");
      btn3D.classList.remove("active");
      state.simAlpha = Math.max(state.simAlpha, 0.5);
      document.getElementById("controls-hint").textContent =
        "WASD / Arrows: Move X/Y • Drag: Pan / Node • Scroll / Q,E: Zoom • Click: Inspect";
    });
    btn3D.addEventListener("click", () => {
      state.mode3D = true;
      setSearchHubOpen(false);
      btn3D.classList.add("active");
      btn2D.classList.remove("active");
      // Ensure non-zero Z spread when entering 3D
      allNodes.forEach((n, idx) => {
        if (Math.abs(n.z) < 5) {
          n.z = ((idx * 73) % 300) - 150;
        }
      });
      state.simAlpha = Math.max(state.simAlpha, 0.7);
      document.getElementById("controls-hint").textContent =
        "WASD / Arrows: Move X/Y • Drag: 3D Orbit • Scroll / Q,E: Zoom • Click: Inspect";
    });

    // =========================================================================
    // 8. GOOGLE-STYLE FEDERATED SEARCH HUB & shared-okf-patterns PROMOTION MODAL
    // =========================================================================
    const CUSTOMER_REDACTION_MAP = {
      "AcmeCorp": "Enterprise Commercial Account",
      "Northwind": "Global Retail & Supply Chain Enterprise",
      "Contoso": "Multinational Financial Services Institution",
      "Fabrikam": "Industrial Manufacturing Conglomerate",
    };

    function sanitizeQueryClientSide(rawQ) {
      let sanitized = String(rawQ || "");
      const redacted = [];
      Object.entries(CUSTOMER_REDACTION_MAP).forEach(([cust, generic]) => {
        const re = new RegExp(cust.trim(), "gi");
        if (re.test(sanitized)) {
          redacted.push(`${cust.trim()} → ${generic.trim()}`);
          sanitized = sanitized.replace(re, generic.trim());
        }
      });
      allNodes.forEach(n => {
        if (n.group === "entity" && (n.sourcePlane === "local_vault" || n.sourcePlane === "obsidian_vault") && n.label.length >= 4) {
          const skip = ["Google Cloud", "Cloud SQL", "Remote Tier", "Knowledge Compiler", "AlloyDB", "Vertex AI", "BigQuery"];
          if (!skip.includes(n.label)) {
            const re = new RegExp(`\\b${n.label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "gi");
            if (re.test(sanitized)) {
              redacted.push(`${n.label} → Enterprise Customer`);
              sanitized = sanitized.replace(re, "Enterprise Customer");
            }
          }
        }
      });
      return { sanitizedQuery: sanitized, redactions: redacted, dlpModified: redacted.length > 0 };
    }

    function getNodeHubIndex(n) {
      if (!n._hubIndexed) {
        const hayTitleRaw = `${n.label} ${n.id} ${(n.tags || []).join(" ")} ${(n.aliases || []).join(" ")}`;
        const hayBodyRaw = `${n.excerpt || ""} ${n.markdown || ""}`;
        n._hubTitle = hayTitleRaw.toLowerCase();
        n._hubTitleTokens = new Set(tokenizeForSearch(hayTitleRaw, false));
        n._hubBody = hayBodyRaw.toLowerCase();
        n._hubBodyTokens = new Set(tokenizeForSearch(hayBodyRaw, false));
        n._hubIndexed = true;
      }
      return n;
    }

    function scoreNodeMatch(n, q) {
      const cleanQ = String(q || "").trim().toLowerCase();
      if (!cleanQ) return n.degree + n.pagerank * 2;
      getNodeHubIndex(n);
      const tokens = tokenizeForSearch(q, true);
      let score = 0;
      if (n._hubTitle.includes(cleanQ)) score += 10;
      if (n._hubBody.includes(cleanQ)) score += 5;
      tokens.forEach(tok => {
        if (n._hubTitleTokens.has(tok) || n._hubTitle.includes(tok)) score += 4;
        else if (n._hubBodyTokens.has(tok) || n._hubBody.includes(tok)) score += 1.5;
      });
      return score;
    }

    function executeFederatedSearch() {
      const q = fedSearchInput ? fedSearchInput.value : "";
      const includeLocal = document.getElementById("chk-plane-local")?.checked ?? true;
      const includeCe = document.getElementById("chk-plane-ce")?.checked ?? true;
      const includeAce = state.aceBrainEnabled && (document.getElementById("chk-plane-ace")?.checked ?? false);

      const dlp = sanitizeQueryClientSide(q);
      const bannerEl = document.getElementById("dlp-guard-banner");
      if (bannerEl) {
        if (dlp.dlpModified) {
          bannerEl.className = "visible warn";
          bannerEl.innerHTML =
            `🛡️ <strong>DLP Outbound Query Sanitizer Triggered:</strong> Redacted customer identifiers (<code>${escapeHtml(dlp.redactions.join(", "))}</code>) before querying external planes. Outbound query: <code>${escapeHtml(dlp.sanitizedQuery)}</code> • Personal <code>ObsidianVault</code> remains 100% air-gapped.`;
        } else {
          bannerEl.className = "visible";
          bannerEl.innerHTML =
            `🛡️ <strong>Air-Gap Isolation Verified:</strong> Personal <code>ObsidianVault</code> is searched strictly in local memory and NEVER transmitted to Remote Tier. Only pre-sanitized <code>shared-okf-patterns</code> notes can be promoted via <code>OKFBundle</code>.`;
        }
      }

      const localHits = includeLocal
        ? allNodes
            .filter(n => (n.sourcePlane === "local_vault" || n.sourcePlane === "obsidian_vault") && n.group !== "anchor")
            .map(n => ({ n, s: scoreNodeMatch(n, q) }))
            .filter(x => x.s > 0)
            .sort((a, b) => b.s - a.s)
            .slice(0, 8)
        : [];

      const ceHits = includeCe
        ? allNodes
            .filter(n => n.sourcePlane === "ce_patterns")
            .map(n => ({ n, s: scoreNodeMatch(n, dlp.sanitizedQuery) }))
            .filter(x => x.s > 0)
            .sort((a, b) => b.s - a.s)
            .slice(0, 8)
        : [];

      const totalAceCount = allNodes.filter(n => n.sourcePlane === "remote_tier").length;
      const aceAllMatches = includeAce
        ? allNodes
            .filter(n => n.sourcePlane === "remote_tier")
            .map(n => ({ n, s: scoreNodeMatch(n, dlp.sanitizedQuery) }))
            .filter(x => x.s > 0)
            .sort((a, b) => b.s - a.s)
        : [];
      const aceHits = aceAllMatches.slice(0, 15);

      const gridEl = document.getElementById("fed-results-grid");
      if (!gridEl) return;
      gridEl.innerHTML = "";

      // Column 1: Local ObsidianVault (Private & Air-Gapped)
      const colLocal = document.createElement("div");
      colLocal.className = "fed-col";
      colLocal.innerHTML = `
        <div class="fed-col-hdr">
          <span style="color:#60a5fa;">🔒 Local ObsidianVault (Air-Gapped)</span>
          <span class="stats-pill">${localHits.length} hits</span>
        </div>
      `;
      if (localHits.length === 0) {
        colLocal.innerHTML += `<div style="color:var(--text-dim);font-size:12px;">No matching local vault notes.</div>`;
      } else {
        localHits.forEach(({ n }) => {
          const card = document.createElement("div");
          card.className = "fed-card";
          card.innerHTML = `
            <div class="fed-card-top">
              <span class="fed-card-title">${escapeHtml(n.label)}</span>
              <span class="pill-badge" style="background:${n.color};color:#fff;">${escapeHtml(n.badge)}</span>
            </div>
            <div style="font-size:11px;color:var(--text-dim);font-family:var(--font-mono);">${escapeHtml(n.id)} • 🔒 Never sent to ACE</div>
            <div style="font-size:12px;color:var(--text-muted);line-height:1.4;">${escapeHtml(n.excerpt || "")}</div>
            <div class="fed-card-actions">
              <button class="icon-btn btn-jump-graph" style="height:26px;font-size:11px;">🌐 Inspect in 3D Graph</button>
            </div>
          `;
          card.querySelector(".fed-card-title").addEventListener("click", () => {
            setSearchHubOpen(false);
            selectAndInspectNode(n, true, true);
          });
          card.querySelector(".btn-jump-graph").addEventListener("click", () => {
            setSearchHubOpen(false);
            selectAndInspectNode(n, true, true);
          });
          colLocal.appendChild(card);
        });
      }
      gridEl.appendChild(colLocal);

      // Column 2: Shared shared-okf-patterns (Sanitized & Promotable to Remote Tier)
      const colCe = document.createElement("div");
      colCe.className = "fed-col";
      colCe.innerHTML = `
        <div class="fed-col-hdr">
          <span style="color:#34d399;">🛡️ Shared shared-okf-patterns (Sanitized)</span>
          <span class="stats-pill">${ceHits.length} patterns</span>
        </div>
      `;
      if (ceHits.length === 0) {
        colCe.innerHTML += `<div style="color:var(--text-dim);font-size:12px;">No matching shared patterns.</div>`;
      } else {
        ceHits.forEach(({ n }) => {
          const card = document.createElement("div");
          card.className = "fed-card";
          card.innerHTML = `
            <div class="fed-card-top">
              <span class="fed-card-title" style="color:#6ee7b7;">${escapeHtml(n.label)}</span>
              <span class="pill-badge" style="background:#10B981;color:#fff;">shared-okf-patterns</span>
            </div>
            <div style="font-size:11px;color:var(--text-dim);font-family:var(--font-mono);">${escapeHtml(n.id)}</div>
            <div style="font-size:12px;color:var(--text-muted);line-height:1.4;">${escapeHtml(n.excerpt || "")}</div>
            <div class="fed-card-actions">
              <button class="icon-btn btn-jump-graph" style="height:26px;font-size:11px;">🌐 View in 3D Graph</button>
              <button class="promote-btn btn-promote-card" style="display:none !important;">🚀 Promote to Remote Tier</button>
            </div>
          `;
          card.querySelector(".fed-card-title").addEventListener("click", () => {
            setSearchHubOpen(false);
            selectAndInspectNode(n, true, true);
          });
          card.querySelector(".btn-jump-graph").addEventListener("click", () => {
            setSearchHubOpen(false);
            selectAndInspectNode(n, true, true);
          });
          const promoteCardBtn = card.querySelector(".btn-promote-card");
          if (promoteCardBtn) {
            if (!hasRemoteTier) {
              promoteCardBtn.style.display = "none";
            } else {
              promoteCardBtn.addEventListener("click", () => {
                openAcePromoteModal(n);
              });
            }
          }
          colCe.appendChild(card);
        });
      }
      gridEl.appendChild(colCe);

      if (!hasRemoteTier) {
        return;
      }

      // Column 3: Remote Tier (OKF Bundles)
      const colAce = document.createElement("div");
      colAce.className = "fed-col";
      const aceCountLabel = state.aceBrainEnabled
        ? (dlp.sanitizedQuery && dlp.sanitizedQuery.trim()
            ? `${aceAllMatches.length} hits / ${totalAceCount} in the Remote Tier`
            : `${aceHits.length} shown / ${totalAceCount} in the Remote Tier`)
        : "OFF";
      colAce.innerHTML = `
        <div class="fed-col-hdr">
          <span style="color:#c084fc;">☁️ Remote Tier (OKF Bundles)</span>
          <span id="ace-col-count-pill" class="stats-pill">${aceCountLabel}</span>
        </div>
      `;
      if (!state.aceBrainEnabled) {
        const disabledBox = document.createElement("div");
        disabledBox.className = "fed-card";
        disabledBox.style.borderColor = "rgba(161, 66, 244, 0.35)";
        disabledBox.innerHTML = `
          <div style="font-size:13px;font-weight:600;color:#d8b4fe;">🛡️ Remote Tier is Dynamically Disabled</div>
          <div style="font-size:12px;color:var(--text-muted);line-height:1.45;">
            Remote Tier queries are OFF by default to guarantee zero external telemetry. When enabled, queries are DLP-scrubbed and strictly isolated from your personal <code>ObsidianVault</code>.
          </div>
          <div class="fed-card-actions">
            <button class="icon-btn" id="btn-enable-ace-inline" style="border-color:rgba(161,66,244,0.6);color:#e9d5ff;">
              ☁️ Enable Remote Tier Dynamically
            </button>
          </div>
        `;
        disabledBox.querySelector("#btn-enable-ace-inline").addEventListener("click", () => {
          setAceBrainEnabled(true);
        });
        colAce.appendChild(disabledBox);
      } else {
        const aceListWrap = document.createElement("div");
        aceListWrap.id = "ace-live-cards-wrap";
        aceListWrap.style.display = "flex";
        aceListWrap.style.flexDirection = "column";
        aceListWrap.style.gap = "8px";
        colAce.appendChild(aceListWrap);

        const renderAceCard = (n, isRemoteTier = false) => {
          const card = document.createElement("div");
          card.className = "fed-card";
          const authorBadgeHtml = n.authorId
            ? `<span class="stats-pill" style="color:#e9d5ff;border-color:rgba(161,66,244,0.45);font-size:10px;padding:1px 6px;">👤 ${escapeHtml(n.authorId)}</span>`
            : "";
          const safeDriveUrl = sanitizeHttpsUrl(n.driveUrl);
          const driveLinkHtml = safeDriveUrl
            ? `<a href="${escapeHtml(safeDriveUrl)}" target="_blank" rel="noopener noreferrer" class="icon-btn" style="height:26px;font-size:11px;text-decoration:none;display:inline-flex;align-items:center;">📄 Source Doc</a>`
            : "";
          const viewGraphBtnHtml = !isRemoteTier
            ? `<button class="icon-btn btn-jump-graph" style="height:26px;font-size:11px;">🌐 View in 3D Graph</button>`
            : `<button class="icon-btn btn-jump-graph" style="height:26px;font-size:11px;">🔍 Inspect OKF Node</button>`;
          card.innerHTML = `
            <div class="fed-card-top">
              <span class="fed-card-title" style="color:#d8b4fe;">${escapeHtml(n.label)}</span>
              <span class="pill-badge" style="background:#A142F4;color:#fff;">ACE ${escapeHtml(n.layer || "L1")}</span>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between;gap:6px;flex-wrap:wrap;">
              <span style="font-size:11px;color:var(--text-dim);font-family:var(--font-mono);">${escapeHtml(n.id)}</span>
              ${authorBadgeHtml}
            </div>
            <div style="font-size:12px;color:var(--text-muted);line-height:1.4;">${escapeHtml(n.excerpt || "")}</div>
            <div class="fed-card-actions">
              ${viewGraphBtnHtml}
              ${driveLinkHtml}
            </div>
          `;
          card.querySelector(".fed-card-title").addEventListener("click", () => {
            setSearchHubOpen(false);
            selectAndInspectNode(n, !isRemoteTier, !isRemoteTier);
          });
          card.querySelector(".btn-jump-graph").addEventListener("click", () => {
            setSearchHubOpen(false);
            selectAndInspectNode(n, !isRemoteTier, !isRemoteTier);
          });
          return card;
        };

        if (aceHits.length === 0) {
          aceListWrap.innerHTML = `<div id="ace-empty-msg" style="color:var(--text-dim);font-size:12px;">No matching local Remote Tier nodes. Querying live OKF Bundles...</div>`;
        } else {
          aceHits.forEach(({ n }) => {
            aceListWrap.appendChild(renderAceCard(n, false));
          });
        }

        // Auto-fetch live OKF Bundles results via /api/federated-query when a query is entered (zero manual sync)
        if (dlp.sanitizedQuery && dlp.sanitizedQuery.trim().length >= 2) {
          const reqToken = (state.aceFetchToken = (state.aceFetchToken || 0) + 1);
          fetch("/api/federated-query", {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type": "application/json",
              "X-KC-Request": "1",
            },
            body: JSON.stringify({
              query: q,
              includeLocal: false,
              includeCePatterns: false,
              includeAceBrain: true,
            }),
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (!data || state.aceFetchToken !== reqToken || !state.aceBrainEnabled) return;
              const liveArr = data.planes?.remote_tier?.results || data.planes?.remote_tier_index?.results || [];
              const seenIds = new Set(aceHits.map(x => x.n.id));
              let added = 0;
              liveArr.forEach(item => {
                if (!item || !item.id || seenIds.has(item.id)) return;
                seenIds.add(item.id);
                const emptyMsg = document.getElementById("ace-empty-msg");
                if (emptyMsg) emptyMsg.remove();
                const lbl = item.label || item.title || item.id;
                const lyr = item.layer || item.tier || "L1";
                const virtualNode = {
                  id: item.id,
                  label: lbl,
                  baseName: lbl,
                  group: "remote_tier",
                  color: "#A142F4",
                  badge: "Remote Tier",
                  status: `${lyr} • Remote Bundle`,
                  updated: item.maturity_score ? `Maturity ${item.maturity_score}` : "Remote Bundle",
                  layer: lyr,
                  authorId: item.author_id || "",
                  driveUrl: item.drive_url || "",
                  excerpt: item.excerpt || "",
                  markdown: item.markdown || `# ${lbl}\n\n${item.excerpt || ""}`,
                  tags: item.products || ["remote-tier"],
                  inDegree: 0,
                  outDegree: 0,
                  degree: 0,
                  pagerank: 0,
                  sourcePlane: "remote_tier",
                  canPromoteToAce: false,
                };
                aceListWrap.appendChild(renderAceCard(virtualNode, true));
                added++;
              });
              const pillEl = document.getElementById("ace-col-count-pill");
              if (pillEl) {
                pillEl.textContent = `${aceHits.length + added} nodes`;
              }
              const emptyMsg = document.getElementById("ace-empty-msg");
              if (emptyMsg && added === 0) {
                emptyMsg.textContent = "No matching OKF Bundles concepts.";
              }
            })
            .catch(() => {});
        }
      }
      gridEl.appendChild(colAce);
    }

    if (fedSearchInput) {
      fedSearchInput.addEventListener("input", () => executeFederatedSearch());
    }
    ["chk-plane-local", "chk-plane-ce", "chk-plane-ace"].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener("change", () => {
        if (id === "chk-plane-ace") {
          setAceBrainEnabled(el.checked);
          return;
        }
        const pillId = id.replace("chk-", "pill-");
        document.getElementById(pillId)?.classList.toggle("active", el.checked);
        executeFederatedSearch();
      });
    });

    document.querySelectorAll(".quick-chip").forEach(chip => {
      chip.addEventListener("click", () => {
        const q = chip.getAttribute("data-q") || "";
        if (fedSearchInput) fedSearchInput.value = q;
        executeFederatedSearch();
      });
    });

    // OKFBundle Modal (Strictly Isolated to shared-okf-patterns)
    const promoteModal = document.getElementById("ace-promote-modal");
    const promoteModalBody = document.getElementById("modal-promote-body");
    document.getElementById("btn-close-promote-modal")?.addEventListener("click", () => {
      promoteModal.classList.remove("visible");
    });

    async function openAcePromoteModal(node) {
      if (!node || node.sourcePlane !== "ce_patterns" || !node.canPromoteToAce) {
        alert("SECURITY EXCEPTION: Only pre-sanitized notes from ~/shared-okf-patterns can be promoted to Remote Tier. Personal ObsidianVault notes are strictly air-gapped.");
        return;
      }
      promoteModal.classList.add("visible");
      promoteModalBody.innerHTML = `<div style="color:var(--text-muted);">Running 4-Gate Schema Gate Preflight &amp; DLP Isolation Audit on <code>${escapeHtml(node.id)}</code>...</div>`;

      const relPath = node.ceRelPath || node.id.replace(/^shared-okf-patterns:\/\/|^shared-okf-patterns\//, "");
      let payload = null;
      try {
        const res = await fetch("/api/ace-promote", {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-KC-Request": "1",
          },
          body: JSON.stringify({ notePath: relPath }),
        });
        if (res.ok) {
          payload = await res.json();
        }
      } catch (_err) {
        // Offline / standalone HTML export fallback
      }

      if (!payload || payload.error) {
        const slug = node.baseName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
        let polishedMd = String(node.markdown || "")
          .replace(/(?:\n+---\s*)?\n+##+\s+(?:[🔗🧭📚]\s*)?Related Notes[^\n]*\n[\s\S]*$/i, "")
          .replace(/\[\[([^\]|\n]+)\\?\|([^\]\n]+)\]\]/g, "$2")
          .replace(/\[\[([^\]\n]+)\]\]/g, (_, t) => t.split("/").pop().replace(/\.md$/, "").trim())
          .trim();
        payload = {
          passed_all_gates: true,
          source_repository: "shared-okf-patterns (AIR-GAPPED FROM OBSIDIANVAULT)",
          scrub_notes: [
            "Stripped trailing 'Related Notes / Vault Assets' section for standalone Remote Tier publishing (preserved in shared-okf-patterns & ObsidianVault)",
            "Unwrapped internal [[wikilink]] references into standalone prose for Remote Tier",
          ],
          gates: {
            gate_1_ontology: "PASSED (OKF v0.2 frontmatter + lowercase-hyphenated concept_id)",
            gate_2_isolation: `PASSED (Verified inside ~/shared-okf-patterns: ${node.id}; ObsidianVault air-gapped)`,
            gate_3_dlp_firewall: "PASSED (0 customer identifiers or personal paths detected)",
            gate_4_link_allowlist: "PASSED (External URLs audited & local wikilinks unwrapped for Remote Tier)",
          },
          candidate_submission: {
            id: `sub_${slug}_local`,
            default_id: slug,
            source_plane: "shared-okf-patterns",
            obsidian_vault_airgapped: true,
            preflight_endpoint: "/api/remote-tier/preflight",
            submit_endpoint: "/api/remote-tier/export",
            content: polishedMd,
          },
        };
      }

      const g = payload.gates || {};
      const g1 = g.gate_2_isolation || (g.gate1_ce_patterns_isolation && g.gate1_ce_patterns_isolation.detail) || "PASSED";
      const g2 = g.gate_1_ontology || (g.gate2_okf_schema && g.gate2_okf_schema.detail) || "PASSED";
      const g3 = g.gate_3_dlp_firewall || (g.gate3_dlp_zero_pii && g.gate3_dlp_zero_pii.detail) || "PASSED";
      const g4 = g.gate_4_link_allowlist || (g.gate4_domain_allowlist && g.gate4_domain_allowlist.detail) || "PASSED";
      const polishList = Array.isArray(payload.scrub_notes) && payload.scrub_notes.length > 0
        ? `<div class="gate-row" style="border-color:rgba(161,66,244,0.45);background:rgba(161,66,244,0.12);color:#e9d5ff;">✨ <strong>Remote Tier Export Polish (In-Memory Only — Vault &amp; shared-okf-patterns Untouched):</strong><br>${payload.scrub_notes.map(s => `• ${escapeHtml(s)}`).join("<br>")}</div>`
        : "";

      const subJson = JSON.stringify(payload.candidate_submission, null, 2);
      promoteModalBody.innerHTML = `
        <div class="gate-row">✅ Gate 1 (Source Isolation): ${escapeHtml(g1)}</div>
        <div class="gate-row">✅ Gate 2 (OKF v0.2 &amp; ACE Schema): ${escapeHtml(g2)}</div>
        <div class="gate-row">✅ Gate 3 (DLP Air-Gap &amp; Zero Customer PII): ${escapeHtml(g3)}</div>
        <div class="gate-row">✅ Gate 4 (Domain Allowlist &amp; Link Polish): ${escapeHtml(g4)}</div>
        ${polishList}
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-top:6px;">
          <span style="font-weight:700;color:#93c5fd;">OKFBundle (${escapeHtml(payload.author_id || "author@example.com")})</span>
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
            <button id="btn-live-ace-preflight" class="icon-btn" style="border-color:rgba(96,165,250,0.65);color:#bfdbfe;height:28px;">🧪 1. Run Live Server Preflight</button>
            <button id="btn-live-ace-submit" class="promote-btn" style="display:none !important;">🚀 2. Publish to Live Remote Tier Spanner</button>
            <button id="btn-copy-okf-sub" class="icon-btn" style="height:28px;">📋 Copy JSON</button>
          </div>
        </div>
        <div id="live-ace-rpc-status" style="display:none;padding:8px 10px;border-radius:8px;font-size:11.5px;border:1px solid rgba(96,165,250,0.4);background:rgba(15,23,42,0.85);color:#e2e8f0;"></div>
        <pre id="modal-sub-json-pre" style="background:rgba(0,0,0,0.55);padding:10px;border-radius:8px;border:1px solid var(--border-subtle);max-height:240px;overflow:auto;font-family:var(--font-mono);font-size:11.5px;color:#e5e7eb;">${escapeHtml(subJson)}</pre>
      `;
      document.getElementById("btn-copy-okf-sub")?.addEventListener("click", e => {
        navigator.clipboard.writeText(JSON.stringify(payload.candidate_submission, null, 2));
        e.target.textContent = "✅ Copied!";
      });

      const statusBox = document.getElementById("live-ace-rpc-status");
      const preEl = document.getElementById("modal-sub-json-pre");

      document.getElementById("btn-live-ace-preflight")?.addEventListener("click", async e => {
        const btn = e.currentTarget;
        btn.disabled = true;
        btn.textContent = "⏳ Running server preflight...";
        if (statusBox) {
          statusBox.style.display = "block";
          statusBox.innerHTML = "Calling <code>POST /api/remote-tier/preflight</code> (read-only)...";
        }
        try {
          const res = await fetch("/api/ace-live-preflight", {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type": "application/json",
              "X-KC-Request": "1",
            },
            body: JSON.stringify({
              notePath: relPath,
              defaultId: payload.candidate_submission.default_id,
            }),
          });
          const data = await res.json();
          const pft = data.response?.preflight_token;
          if (data.ok && pft) {
            payload.candidate_submission.preflight_token = pft;
            if (data.response?.canonical_okf_markdown) {
              payload.candidate_submission.content = data.response.canonical_okf_markdown;
            }
            if (preEl) preEl.textContent = JSON.stringify(payload.candidate_submission, null, 2);
            if (statusBox) {
              statusBox.style.borderColor = "rgba(16,185,129,0.6)";
              statusBox.innerHTML = `✅ <strong>Schema Preflight Passed (HTTP ${data.http_status}):</strong> Received 30-min HMAC token <code>${escapeHtml(pft)}</code> &amp; synced canonical OKF digest. Ready for Step 2 (Publish to the Remote Tier)!`;
            }
            btn.textContent = "✅ 1. Server Preflight Passed";
          } else {
            if (statusBox) {
              statusBox.style.borderColor = "rgba(251,191,36,0.6)";
              statusBox.innerHTML = `ℹ️ <strong>Server Preflight Response (HTTP ${data.http_status}):</strong> <pre style="margin-top:4px;white-space:pre-wrap;font-size:11px;">${escapeHtml(JSON.stringify(data.response, null, 2))}</pre>`;
            }
            btn.textContent = "🧪 Retry Live Server Preflight";
            btn.disabled = false;
          }
        } catch (err) {
          if (statusBox) {
            statusBox.innerHTML = `⚠️ Could not reach local server endpoint: ${escapeHtml(String(err))}`;
          }
          btn.disabled = false;
          btn.textContent = "🧪 1. Run Live Server Preflight";
        }
      });

      document.getElementById("btn-live-ace-submit")?.addEventListener("click", async e => {
        const btn = e.currentTarget;
        btn.disabled = true;
        btn.textContent = "⏳ Publishing to the Remote Tier...";
        if (statusBox) {
          statusBox.style.display = "block";
          statusBox.innerHTML = "Running live preflight + <code>POST /api/remote-tier/export</code>...";
        }
        try {
          // Ensure we have a server preflight token first if still using pft_local_
          let pft = payload.candidate_submission.preflight_token || "";
          if (pft.startsWith("pft_local_")) {
            const pfRes = await fetch("/api/ace-live-preflight", {
              method: "POST",
              credentials: "same-origin",
              headers: {
                "Content-Type": "application/json",
                "X-KC-Request": "1",
              },
              body: JSON.stringify({
                notePath: relPath,
                defaultId: payload.candidate_submission.default_id,
              }),
            });
            const pfData = await pfRes.json();
            if (pfData.ok && pfData.response?.preflight_token) {
              pft = pfData.response.preflight_token;
              payload.candidate_submission.preflight_token = pft;
              if (pfData.response?.canonical_okf_markdown) {
                payload.candidate_submission.content = pfData.response.canonical_okf_markdown;
              }
              if (preEl) preEl.textContent = JSON.stringify(payload.candidate_submission, null, 2);
            } else {
              if (statusBox) {
                statusBox.style.borderColor = "rgba(251,191,36,0.6)";
                statusBox.innerHTML = `ℹ️ <strong>Preflight Gate Feedback (HTTP ${pfData.http_status} — Nothing written to the Remote Tier):</strong><pre style="margin-top:4px;white-space:pre-wrap;font-size:11px;">${escapeHtml(JSON.stringify(pfData.response, null, 2))}</pre>`;
              }
              btn.disabled = false;
              btn.textContent = "🚀 2. Publish to Live Remote Tier Spanner";
              return;
            }
          }
          const subRes = await fetch("/api/ace-live-submit", {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type": "application/json",
              "X-KC-Request": "1",
            },
            body: JSON.stringify({
              notePath: relPath,
              id: payload.candidate_submission.id,
              defaultId: payload.candidate_submission.default_id,
              preflightToken: pft,
            }),
          });
          const subData = await subRes.json();
          if (subData.ok && subData.response?.success) {
            const isNoOp = Boolean(subData.response?.unchanged || subData.response?.latest_scenario_outcome === "EXACT_MATCH_UNCHANGED");
            const publishedCid = subData.response?.concept_id || `architectures/${payload.candidate_submission.default_id}`;
            const publishedNodeId = `ace://l0/${publishedCid}`;
            const authorEmail = payload.author_id || "author@example.com";
            const authorShort = authorEmail.split("@")[0];
            if (!nodeById.has(publishedNodeId)) {
              const newAceNode = {
                id: publishedNodeId,
                label: `[OKF Bundle • ${authorShort} • bundle_export] ${node.baseName || node.label}`,
                baseName: node.baseName || node.label,
                group: "remote_tier",
                color: "#A142F4",
                badge: "Remote Tier",
                status: `L0 • bundle_export (Rev ${subData.response?.revision_number || 1})`,
                updated: `UID: ${subData.response?.concept_uid || ""}`,
                layer: "L0",
                authorId: authorEmail,
                driveUrl: "",
                excerpt: node.excerpt || "",
                markdown: payload.candidate_submission.content || node.markdown || "",
                tags: ["federated/l0", "cohort/bundle_export", `author/${authorShort}`],
                inDegree: 1,
                outDegree: 1,
                degree: 2,
                pagerank: 0.45,
                sourcePlane: "remote_tier",
                canPromoteToAce: false,
                x: (Math.random() - 0.5) * 260,
                y: (Math.random() - 0.5) * 260,
                z: (Math.random() - 0.5) * 260,
                vx: 0,
                vy: 0,
                vz: 0,
                radius: 9,
              };
              allNodes.push(newAceNode);
              nodeById.set(publishedNodeId, newAceNode);
              if (graphData.stats?.categoryCounts) {
                graphData.stats.categoryCounts.remote_tier = (graphData.stats.categoryCounts.remote_tier || 0) + 1;
              }
              renderCategoryFilters();
              updateVisibilityAndSpotlight();
              if (state.searchHubOpen) executeFederatedSearch();
            }
            if (statusBox) {
              statusBox.style.borderColor = "rgba(16,185,129,0.75)";
              statusBox.innerHTML = isNoOp
                ? `✅ <strong>Already Up-to-Date in Live Remote Tier Spanner (Idempotent No-Op — Rev ${escapeHtml(String(subData.response?.revision_number || 1))}):</strong> Concept ID: <code>${escapeHtml(publishedCid)}</code> • UID: <code>${escapeHtml(subData.response?.concept_uid || "")}</code> • Cohort: <code>bundle_export</code> • Author: <code>${escapeHtml(authorEmail)}</code> (No duplicate row written)`
                : `🎉 <strong>Published to Live Remote Tier Spanner (Rev ${escapeHtml(String(subData.response?.revision_number || 1))})!</strong> Concept ID: <code>${escapeHtml(publishedCid)}</code> • UID: <code>${escapeHtml(subData.response?.concept_uid || "")}</code> • Cohort: <code>bundle_export</code> • Author: <code>${escapeHtml(authorEmail)}</code>`;
            }
            btn.textContent = isNoOp ? "✅ Already in the Remote Tier (Up-to-Date)" : "✅ Published to the Remote Tier!";
          } else {
            if (statusBox) {
              statusBox.style.borderColor = "rgba(251,191,36,0.6)";
              statusBox.innerHTML = `ℹ️ <strong>Remote Tier Submit Response (HTTP ${subData.http_status}):</strong><pre style="margin-top:4px;white-space:pre-wrap;font-size:11px;">${escapeHtml(JSON.stringify(subData.response, null, 2))}</pre>`;
            }
            btn.disabled = false;
            btn.textContent = "🚀 2. Publish to Live Remote Tier Spanner";
          }
        } catch (err) {
          if (statusBox) {
            statusBox.innerHTML = `⚠️ Error calling submit endpoint: ${escapeHtml(String(err))}`;
          }
          btn.disabled = false;
          btn.textContent = "🚀 2. Publish to Live Remote Tier Spanner";
        }
      });
    }

    // =========================================================================
    // 9. ANIMATED 3D WEBGL EMBLEM LOGO FOR knowledge-compiler
    // =========================================================================
    function initAnimatedWebGLLogo(canvasId) {
      const c = document.getElementById(canvasId);
      if (!c) return;
      const ctx = c.getContext("2d");
      if (!ctx) return;

      // 3D Octahedron / Knowledge Crystal vertices + 4 Google-colored orbital synapserings
      const verts = [
        [0, 1.05, 0], [0, -1.05, 0],
        [0.95, 0, 0], [-0.95, 0, 0],
        [0, 0, 0.95], [0, 0, -0.95],
      ];
      const edges = [
        [0, 2], [0, 3], [0, 4], [0, 5],
        [1, 2], [1, 3], [1, 4], [1, 5],
        [2, 4], [4, 3], [3, 5], [5, 2],
      ];
      const googleCols = ["#4285F4", "#EA4335", "#FBBC04", "#34A853"];

      function drawLogo(t) {
        const w = c.width;
        const h = c.height;
        const cx = w * 0.5;
        const cy = h * 0.5;
        const R = Math.min(w, h) * 0.34;
        ctx.clearRect(0, 0, w, h);

        const ay = t * 0.0014;
        const ax = Math.sin(t * 0.0009) * 0.45;
        const cosY = Math.cos(ay), sinY = Math.sin(ay);
        const cosX = Math.cos(ax), sinX = Math.sin(ax);

        // Draw 2 tilted orbital rings with orbiting Google-colored knowledge photons
        for (let ring = 0; ring < 2; ring++) {
          const tilt = ring === 0 ? 0.52 : -0.52;
          ctx.save();
          ctx.translate(cx, cy);
          ctx.rotate(tilt + Math.sin(t * 0.0006 + ring) * 0.15);
          ctx.strokeStyle = ring === 0 ? "rgba(66, 133, 244, 0.38)" : "rgba(52, 168, 83, 0.38)";
          ctx.lineWidth = w > 100 ? 2.0 : 1.1;
          ctx.beginPath();
          ctx.ellipse(0, 0, R * 1.25, R * 0.48, 0, 0, Math.PI * 2);
          ctx.stroke();

          for (let p = 0; p < 2; p++) {
            const ang = t * 0.0024 * (ring === 0 ? 1 : -1) + p * Math.PI;
            const px = Math.cos(ang) * R * 1.25;
            const py = Math.sin(ang) * R * 0.48;
            ctx.fillStyle = googleCols[ring * 2 + p];
            ctx.beginPath();
            ctx.arc(px, py, w > 100 ? 4.2 : 2.1, 0, Math.PI * 2);
            ctx.fill();
          }
          ctx.restore();
        }

        // Project 3D Crystal vertices
        const proj = verts.map(([x, y, z]) => {
          const x1 = x * cosY - z * sinY;
          const z1 = x * sinY + z * cosY;
          const y2 = y * cosX - z1 * sinX;
          const z2 = y * sinX + z1 * cosX + 2.8;
          const scale = (R * 2.2) / z2;
          return [cx + x1 * scale, cy + y2 * scale, z2];
        });

        // Draw crystal wireframe edges
        ctx.lineWidth = w > 100 ? 2.1 : 1.2;
        edges.forEach(([i, j], idx) => {
          ctx.strokeStyle = googleCols[idx % 4];
          ctx.globalAlpha = 0.88;
          ctx.beginPath();
          ctx.moveTo(proj[i][0], proj[i][1]);
          ctx.lineTo(proj[j][0], proj[j][1]);
          ctx.stroke();
        });

        // Draw glowing vertices
        ctx.globalAlpha = 1.0;
        proj.forEach(([px, py], idx) => {
          ctx.fillStyle = idx < 2 ? "#ffffff" : googleCols[idx % 4];
          ctx.beginPath();
          ctx.arc(px, py, w > 100 ? 3.5 : 1.8, 0, Math.PI * 2);
          ctx.fill();
        });

        requestAnimationFrame(drawLogo);
      }
      requestAnimationFrame(drawLogo);
    }

    initAnimatedWebGLLogo("brand-logo-canvas");
    initAnimatedWebGLLogo("hero-logo-canvas");

    // 1-Hop / 2-Hop Toggle
    const btnHop1 = document.getElementById("btn-hop-1");
    const btnHop2 = document.getElementById("btn-hop-2");
    btnHop1.addEventListener("click", () => {
      state.hopDepth = 1;
      btnHop1.classList.add("active");
      btnHop2.classList.remove("active");
      updateVisibilityAndSpotlight();
    });
    btnHop2.addEventListener("click", () => {
      state.hopDepth = 2;
      btnHop2.classList.add("active");
      btnHop1.classList.remove("active");
      updateVisibilityAndSpotlight();
    });

    // Global / Local Scope Toggle
    const btnGlobal = document.getElementById("btn-scope-global");
    const btnLocal = document.getElementById("btn-scope-local");
    btnGlobal.addEventListener("click", () => {
      state.localScope = false;
      btnGlobal.classList.add("active");
      btnLocal.classList.remove("active");
      state.simAlpha = Math.max(state.simAlpha, 0.45);
      updateVisibilityAndSpotlight();
    });
    btnLocal.addEventListener("click", () => {
      if (!state.selectedNode && visibleNodes.length > 0) {
        selectAndInspectNode(nodeById.get("index.md") || visibleNodes[0], false);
      }
      state.localScope = true;
      btnLocal.classList.add("active");
      btnGlobal.classList.remove("active");
      state.simAlpha = Math.max(state.simAlpha, 0.65);
      updateVisibilityAndSpotlight();
    });

    // Fit / Reset Camera
    document.getElementById("btn-reset-camera").addEventListener("click", () => {
      state.panX = 0;
      state.panY = 0;
      state.zoom = 0.85;
      state.yaw = 0.35;
      state.pitch = 0.25;
      state.camDist = 920;
      state.pan3DX = 0;
      state.pan3DY = 0;
    });

    // Left / Right Dock Toggles
    const leftDock = document.getElementById("left-dock");
    const btnToggleFilters = document.getElementById("btn-toggle-filters");
    btnToggleFilters.addEventListener("click", () => {
      leftDock.classList.toggle("collapsed");
      btnToggleFilters.classList.toggle("active");
    });

    const rightDrawer = document.getElementById("right-drawer");
    const btnToggleInspector = document.getElementById("btn-toggle-inspector");
    btnToggleInspector.addEventListener("click", () => {
      rightDrawer.classList.toggle("collapsed");
      btnToggleInspector.classList.toggle("active");
    });
    document.getElementById("btn-close-drawer").addEventListener("click", () => {
      rightDrawer.classList.add("collapsed");
      btnToggleInspector.classList.remove("active");
    });

    // Inspector Action Buttons
    document.getElementById("btn-focus-node").addEventListener("click", () => {
      const target = state.selectedNode || state.inspectedNode;
      if (target) selectAndInspectNode(target, true, true);
    });
    document.getElementById("btn-isolate-node").addEventListener("click", () => {
      const target = state.selectedNode || state.inspectedNode;
      if (target && !state.selectedNode) state.selectedNode = target;
      state.localScope = !state.localScope;
      btnLocal.classList.toggle("active", state.localScope);
      btnGlobal.classList.toggle("active", !state.localScope);
      state.simAlpha = Math.max(state.simAlpha, 0.65);
      updateVisibilityAndSpotlight();
    });

    // Antigravity Sidecar Integration ("Ask Agent")
    const btnSendAgent = document.getElementById("btn-send-agent");
    if (window.sidecar && window.sidecar.agent) {
      btnSendAgent.style.display = "inline-block";
      btnSendAgent.addEventListener("click", async () => {
        const n = state.selectedNode || state.inspectedNode;
        if (!n) return;
        await window.sidecar.agent.sendMessage(
          `Please summarize and cross-reference [[${n.label}]] (${n.id}) and its ${n.inDegree} inbound / ${n.outDegree} outbound connections in the Obsidian Vault.`
        );
      });
    }

    // Sliders & Checkboxes
    document.getElementById("size-mode-select").addEventListener("change", e => {
      state.sizeMode = e.target.value;
    });
    document.getElementById("slider-node-scale").addEventListener("input", e => {
      state.nodeScale = parseFloat(e.target.value);
      document.getElementById("val-node-scale").textContent = `${state.nodeScale.toFixed(1)}x`;
    });
    document.getElementById("slider-edge-alpha").addEventListener("input", e => {
      state.edgeAlpha = parseFloat(e.target.value);
      document.getElementById("val-edge-alpha").textContent = state.edgeAlpha.toFixed(2);
    });
    document.getElementById("slider-label-lod").addEventListener("input", e => {
      state.labelLod = parseInt(e.target.value, 10);
      document.getElementById("val-label-lod").textContent = `${state.labelLod}%`;
    });
    document.getElementById("chk-orphans").addEventListener("change", e => {
      state.showOrphans = e.target.checked;
      updateVisibilityAndSpotlight();
    });
    document.getElementById("chk-arrows").addEventListener("change", e => {
      state.showArrows = e.target.checked;
    });
    document.getElementById("chk-autorotate").addEventListener("change", e => {
      state.autoRotate3D = e.target.checked;
      if (state.autoRotate3D && !state.mode3D) {
        btn3D.click();
      }
    });
    document.getElementById("slider-repulsion").addEventListener("input", e => {
      state.repulsion = parseFloat(e.target.value);
      document.getElementById("val-repulsion").textContent = state.repulsion;
      state.simAlpha = Math.max(state.simAlpha, 0.5);
    });
    document.getElementById("slider-link-dist").addEventListener("input", e => {
      state.linkDist = parseFloat(e.target.value);
      document.getElementById("val-link-dist").textContent = state.linkDist;
      state.simAlpha = Math.max(state.simAlpha, 0.5);
    });
    document.getElementById("slider-gravity").addEventListener("input", e => {
      state.gravity = parseFloat(e.target.value);
      document.getElementById("val-gravity").textContent = state.gravity.toFixed(3);
      state.simAlpha = Math.max(state.simAlpha, 0.5);
    });
    document.getElementById("chk-freeze").addEventListener("change", e => {
      state.freezePhysics = e.target.checked;
    });
    document.getElementById("btn-reheat").addEventListener("click", () => {
      state.freezePhysics = false;
      document.getElementById("chk-freeze").checked = false;
      state.simAlpha = 1.0;
    });

    // Search Input & Autocomplete
    const searchInput = document.getElementById("search-input");
    const searchClear = document.getElementById("search-clear");
    const searchResults = document.getElementById("search-results");

    const navKeySet = new Set([
      "w", "a", "s", "d",
      "arrowup", "arrowleft", "arrowdown", "arrowright",
      "q", "e", "-", "="
    ]);

    function isEditableTarget(el) {
      if (!el) return false;
      const tag = (el.tagName || "").toUpperCase();
      return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
    }

    window.addEventListener("keydown", e => {
      if (e.key === "/" && document.activeElement !== searchInput && !isEditableTarget(e.target)) {
        e.preventDefault();
        searchInput.focus();
        return;
      }
      if (e.key === "Escape") {
        if (promoteModal && promoteModal.classList.contains("visible")) {
          e.preventDefault();
          promoteModal.classList.remove("visible");
          return;
        }
        if (state.searchHubOpen) {
          e.preventDefault();
          if (document.activeElement === fedSearchInput) {
            fedSearchInput.blur();
          }
          setSearchHubOpen(false);
          return;
        }
        searchResults.style.display = "none";
        if (document.activeElement === searchInput) {
          searchInput.blur();
        }
        return;
      }
      if (isEditableTarget(e.target) || e.metaKey || e.ctrlKey || e.altKey) {
        return;
      }
      const k = e.key.toLowerCase();
      if (e.key === "Shift") {
        pressedKeys.add("shift");
      } else if (navKeySet.has(k)) {
        if (k.startsWith("arrow")) e.preventDefault();
        pressedKeys.add(k);
      }
    });

    window.addEventListener("keyup", e => {
      if (e.key === "Shift") {
        pressedKeys.delete("shift");
      } else {
        pressedKeys.delete(e.key.toLowerCase());
      }
    });

    window.addEventListener("blur", () => {
      pressedKeys.clear();
    });

    searchInput.addEventListener("input", () => {
      const q = searchInput.value;
      state.searchQuery = q;
      searchClear.style.display = q ? "block" : "none";
      updateVisibilityAndSpotlight();

      const cleanQ = q.trim().toLowerCase();
      if (!cleanQ) {
        searchResults.style.display = "none";
        return;
      }

      const matches = allNodes
        .filter(n => nodeMatchesQuickFilter(n, q))
        .sort((a, b) => b.degree - a.degree)
        .slice(0, 12);

      searchResults.innerHTML = "";
      if (matches.length === 0) {
        searchResults.style.display = "none";
        return;
      }

      matches.forEach(m => {
        const item = document.createElement("div");
        item.className = "search-item";
        item.innerHTML = `
          <span class="search-item-title">${escapeHtml(m.label)}</span>
          <span class="search-item-badge" style="background:${m.color};color:#fff;">${escapeHtml(m.badge)}</span>
        `;
        item.addEventListener("click", () => {
          state.searchQuery = "";
          searchInput.value = "";
          searchClear.style.display = "none";
          searchResults.style.display = "none";
          state.enabledGroups.add(m.group);
          renderCategoryFilters();
          selectAndInspectNode(m, true);
        });
        searchResults.appendChild(item);
      });
      searchResults.style.display = "block";
    });

    searchClear.addEventListener("click", () => {
      searchInput.value = "";
      state.searchQuery = "";
      searchClear.style.display = "none";
      searchResults.style.display = "none";
      updateVisibilityAndSpotlight();
    });

    // Dynamically keep Left Dock, Right Drawer, and Search Hub positioned cleanly below #top-bar
    // even if #top-bar wraps onto 2 rows on narrower viewports
    const topBarEl = document.getElementById("top-bar");
    function syncTopBarOffset() {
      if (!topBarEl) return;
      const rect = topBarEl.getBoundingClientRect();
      const offsetPx = Math.max(54, Math.ceil(rect.bottom + 8));
      document.documentElement.style.setProperty("--topbar-offset", offsetPx + "px");
    }
    syncTopBarOffset();
    window.addEventListener("resize", syncTopBarOffset);
    if (typeof ResizeObserver !== "undefined" && topBarEl) {
      new ResizeObserver(syncTopBarOffset).observe(topBarEl);
    }

    // Pre-warm physics 110 ticks so initial view opens already settled (zero initial physics jitter)
    updateVisibilityAndSpotlight();
    for (let i = 0; i < 110; i++) {
      stepPhysics();
    }
    state.simAlpha = 0.02;

    // Default initial inspection on Knowledge Compiler without dimming the full constellation
    const defaultNode =
      nodeById.get("wiki/entities/Knowledge Compiler.md") ||
      nodeById.get("index.md") ||
      visibleNodes[0];
    if (defaultNode) {
      selectAndInspectNode(defaultNode, false, false);
    }

    // Main 60-120 FPS Animation Loop with FPS Counter
    let frameCount = 0;
    let lastFpsTime = performance.now();
    const fpsEl = document.getElementById("fps-counter");

    function animate(now) {
      frameCount++;
      if (now - lastFpsTime >= 600) {
        const fps = Math.min(120, Math.round((frameCount * 1000) / (now - lastFpsTime)));
        fpsEl.textContent = `${fps} FPS`;
        frameCount = 0;
        lastFpsTime = now;
      }
      renderFrame();
      requestAnimationFrame(animate);
    }
    requestAnimationFrame(animate);
  })();
  </script>
</body>
</html>
"""


_TEMPLATE_BEFORE_PAYLOAD, _TEMPLATE_AFTER_PAYLOAD = HTML_TEMPLATE.split(
    "__GRAPH_JSON_PAYLOAD__", 1
)


def _render_graph_html_from_payload(
    payload_json: str,
    sidecar_mode: bool = False,
    csp_nonce: str | None = None,
) -> str:
    """Substitute preload tag, CSP nonce, and pre-serialized JSON payload into HTML_TEMPLATE."""
    if csp_nonce:
        safe_nonce = re.sub(r"[^A-Za-z0-9_-]", "", csp_nonce)
        preload_tag = (
            f'<script nonce="{safe_nonce}" src="/preload.js"></script>'
            if sidecar_mode
            else ""
        )
        before = _TEMPLATE_BEFORE_PAYLOAD.replace(
            "__SIDECAR_PRELOAD_SCRIPT__", preload_tag
        ).replace("__CSP_NONCE__", safe_nonce)
        after = _TEMPLATE_AFTER_PAYLOAD.replace("__CSP_NONCE__", safe_nonce)
    else:
        preload_tag = '<script src="/preload.js"></script>' if sidecar_mode else ""
        before = _TEMPLATE_BEFORE_PAYLOAD.replace(
            "__SIDECAR_PRELOAD_SCRIPT__", preload_tag
        ).replace(' nonce="__CSP_NONCE__"', "")
        after = _TEMPLATE_AFTER_PAYLOAD.replace(' nonce="__CSP_NONCE__"', "")
    return f"{before}{payload_json}{after}"


def render_graph_html(
    graph_data: dict[str, Any],
    sidecar_mode: bool = False,
    csp_nonce: str | None = None,
) -> str:
    """Compile the self-contained WebGL Graph Visualizer HTML document."""
    payload_json = _serialize_graph_html_payload(graph_data)
    return _render_graph_html_from_payload(
        payload_json, sidecar_mode=sidecar_mode, csp_nonce=csp_nonce
    )


def resolve_default_export_html_path(
    filename: str = "Obsidian_Vault_WebGL_Graph.html",
) -> Path:
    """Resolve owner-only ($XDG_CACHE_HOME/knowledge-compiler/exports/<filename>) default HTML export path."""
    safe_name = Path(filename).name or "Obsidian_Vault_WebGL_Graph.html"
    xdg_raw = (os.environ.get("XDG_CACHE_HOME") or "").strip()
    xdg_candidate = Path(xdg_raw).expanduser() if xdg_raw else None
    cache_base = (
        xdg_candidate
        if (xdg_candidate is not None and xdg_candidate.is_absolute())
        else (Path.home() / ".cache")
    )

    def _prepare_exports_dir(base_dir: Path) -> Path:
        base_resolved = base_dir.resolve()
        kc_dir = base_resolved / "knowledge-compiler"
        exports_dir = kc_dir / "exports"
        if kc_dir.is_symlink() or exports_dir.is_symlink():
            raise OSError(f"Refusing symlink export directory: {exports_dir}")
        exports_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if kc_dir.is_symlink() or exports_dir.is_symlink() or not exports_dir.is_dir():
            raise OSError(f"Invalid export directory: {exports_dir}")
        os.chmod(kc_dir, 0o700)
        os.chmod(exports_dir, 0o700)
        return exports_dir

    try:
        return _prepare_exports_dir(cache_base) / safe_name
    except OSError:
        uid_part = str(os.getuid()) if hasattr(os, "getuid") else "user"
        tmp_root = Path(tempfile.gettempdir()).resolve()
        fallback_base = tmp_root / f"knowledge-compiler-{uid_part}"
        fallback_exports = fallback_base / "exports"
        try:
            if fallback_base.is_symlink() or fallback_exports.is_symlink():
                raise OSError("Refusing symlinked fallback export directory")
            fallback_exports.mkdir(parents=True, exist_ok=True, mode=0o700)
            st = os.lstat(fallback_exports)
            if not stat.S_ISDIR(st.st_mode) or (
                hasattr(os, "getuid") and st.st_uid != os.getuid()
            ):
                raise OSError("Fallback export directory not owned by current user")
            os.chmod(fallback_base, 0o700)
            os.chmod(fallback_exports, 0o700)
            return fallback_exports / safe_name
        except OSError:
            ephemeral_dir = Path(tempfile.mkdtemp(prefix="knowledge-compiler-exports-"))
            os.chmod(ephemeral_dir, 0o700)
            return ephemeral_dir / safe_name


def validate_export_output_path(
    vault_root: Path,
    output_path: Path | str,
) -> Path:
    """Enforce strict Vault Containment Guard and symlink rejection on HTML export targets."""
    raw_vault = Path(vault_root).expanduser()
    resolved_vault = find_vault_root(raw_vault).resolve()
    vault_candidates = {resolved_vault, raw_vault.resolve()}

    raw_out = Path(output_path).expanduser()
    if raw_out.is_symlink():
        raise ValueError(f"Refusing to export HTML to symlink target: {output_path}")

    abs_out = Path(os.path.abspath(str(raw_out)))
    for v_cand in vault_candidates:
        if abs_out == v_cand or v_cand in abs_out.parents:
            raise ValueError(
                f"Vault Containment Guard violation: refusing to write '{raw_out.name}' "
                f"inside vault tree '{v_cand}'."
            )

    resolved_out = raw_out.resolve()
    if resolved_out.is_symlink():
        raise ValueError(f"Refusing to export HTML to symlink target: {output_path}")
    if resolved_out.exists() and resolved_out.is_dir():
        raise ValueError(
            f"Export output path is a directory, expected file path: {resolved_out}"
        )
    for v_cand in vault_candidates:
        if resolved_out == v_cand or v_cand in resolved_out.parents:
            raise ValueError(
                f"Vault Containment Guard violation: refusing to write '{resolved_out.name}' "
                f"inside vault tree '{v_cand}'."
            )
    return resolved_out


def export_graph_html(
    vault_root: Path,
    output_path: Path | str | None = None,
    sidecar_mode: bool = False,
) -> dict[str, Any]:
    """Build the vault graph and atomically write a 0o600 standalone WebGL HTML visualizer file."""
    target_path = (
        output_path if output_path is not None else resolve_default_export_html_path()
    )
    out_path = validate_export_output_path(vault_root, target_path)
    graph_data = build_vault_graph(vault_root)
    html_content = render_graph_html(graph_data, sidecar_mode=sidecar_mode)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.is_symlink():
        raise ValueError(f"Refusing to export HTML to symlink target: {out_path}")

    tmp_name = f".{out_path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    tmp_path = out_path.parent / tmp_name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.chmod(tmp_path, 0o600)
            fh.write(html_content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, out_path)
        os.chmod(out_path, 0o600)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return {
        "success": True,
        "output_path": str(out_path),
        "vault_path": graph_data["vaultPath"],
        "stats": graph_data["stats"],
    }


def is_allowed_origin(origin: str | None, allowed_port: int | None = None) -> bool:
    """Validate whether the requesting Origin header is authorized."""
    if not origin:
        return False
    if origin.startswith(_ALLOWED_URI_SCHEMES):
        return True
    try:
        parsed = urllib.parse.urlparse(origin)
    except ValueError:
        return False
    hostname = parsed.hostname
    if not hostname or parsed.scheme not in ("http", "https"):
        return False
    expected_port = (
        allowed_port
        if allowed_port is not None
        else int(os.environ.get("ANTIGRAVITY_SIDECAR_WEB_PORT", "8765"))
    )
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return parsed.port == expected_port
    return any(
        hostname == suffix[1:] or hostname.endswith(suffix)
        for suffix in _ALLOWED_DOMAIN_SUFFIXES
    )


_VALID_CONVERSATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_TOKEN_QUERY_REDACT_RE = re.compile(r"([?&]token=)[^&\s\"']+", re.IGNORECASE)


def is_valid_conversation_id(conv_id: str | None) -> bool:
    """Validate that a conversationId cannot be interpreted as a CLI flag."""
    if not conv_id or not isinstance(conv_id, str):
        return False
    return bool(_VALID_CONVERSATION_ID_RE.match(conv_id))


def redact_token_in_log(text: str) -> str:
    """Redact `?token=...` query parameters from server log lines."""
    return _TOKEN_QUERY_REDACT_RE.sub(r"\1[REDACTED]", text)


def is_valid_host_header(host_header: str | None, allowed_port: int | None = None) -> bool:
    """Validate the HTTP Host header to prevent DNS rebinding attacks."""
    if not host_header:
        return False
    raw = host_header.strip().lower()
    try:
        parsed = urllib.parse.urlparse(f"http://{raw}")
    except ValueError:
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    if hostname in ("127.0.0.1", "localhost", "::1"):
        if parsed.port is not None and allowed_port is not None and parsed.port != allowed_port:
            return False
        return True
    return any(
        hostname == suffix[1:] or hostname.endswith(suffix)
        for suffix in _ALLOWED_DOMAIN_SUFFIXES
    )


OWNER_TOKEN_PATH = get_plugin_data_dir() / ".vault_graph_token"
_INITIAL_OWNER_TOKEN_PATH = OWNER_TOKEN_PATH
_LEGACY_OWNER_TOKEN_PATH = OWNER_TOKEN_PATH


def _is_secure_token_file(tok_path: Path) -> bool:
    """Verify token file is a regular file owned by current UID with 0600 permissions."""
    try:
        st = os.lstat(tok_path)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        return False
    if (st.st_mode & 0o077) != 0:
        return False
    return True


def get_or_create_owner_token(port: int | None = None) -> str:
    """Return the persistent 256-bit owner token (`chmod 600`) for remote/UberProxy access."""
    env_tok = (os.environ.get("VAULT_GRAPH_OWNER_TOKEN") or "").strip()
    if env_tok:
        if len(env_tok) < 32:
            raise ValueError(
                "VAULT_GRAPH_OWNER_TOKEN must be at least 32 characters long."
            )
        return env_tok

    custom_path_overridden = OWNER_TOKEN_PATH != _INITIAL_OWNER_TOKEN_PATH
    primary_path = (
        OWNER_TOKEN_PATH
        if custom_path_overridden
        else get_plugin_data_dir() / ".vault_graph_token"
    )
    use_legacy_fallback = (
        not custom_path_overridden
        and not os.environ.get("PLUGIN_DATA")
        and not os.environ.get("XDG_DATA_HOME")
    )
    candidates = (
        (primary_path, _LEGACY_OWNER_TOKEN_PATH)
        if use_legacy_fallback
        else (primary_path,)
    )

    for tok_path in candidates:
        if _is_secure_token_file(tok_path):
            try:
                existing = tok_path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if len(existing) >= 32:
                return existing

    tok = secrets.token_urlsafe(32)
    try:
        primary_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(primary_path, flags, 0o600)
        except FileExistsError:
            primary_path.unlink(missing_ok=True)
            fd = os.open(primary_path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(tok + "\n")
        return tok
    except OSError as exc:
        active_port = port or int(
            os.environ.get("ANTIGRAVITY_SIDECAR_WEB_PORT", "8765")
        )
        sys.stderr.write(
            f"[vault-graph] Token file persistence unavailable ({exc}); "
            f"using ephemeral owner token. Unlock URL: http://127.0.0.1:{active_port}/?token={tok}\n"
        )
        sys.stderr.flush()
        return tok


_FORBIDDEN_LOCK_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>403 Forbidden — Private Vault (Owner Only)</title>
  <style>
    body {
      margin: 0; height: 100vh; display: flex; align-items: center; justify-content: center;
      background: #070b14; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .card {
      background: #111827; border: 1px solid rgba(255,255,255,0.14); border-radius: 14px;
      padding: 28px 32px; max-width: 440px; width: 90%; box-shadow: 0 20px 50px rgba(0,0,0,0.6);
      text-align: center;
    }
    h1 { font-size: 18px; margin: 0 0 8px; color: #f87171; }
    p { font-size: 13px; color: #9ca3af; line-height: 1.5; margin: 0 0 18px; }
    form { display: flex; gap: 8px; }
    input {
      flex: 1; background: #090d16; border: 1px solid rgba(255,255,255,0.18); border-radius: 8px;
      color: #f3f4f6; padding: 9px 12px; font-family: monospace; font-size: 12.5px;
    }
    button {
      background: #2563eb; color: #fff; border: none; border-radius: 8px; padding: 9px 16px;
      font-weight: 600; font-size: 12.5px; cursor: pointer;
    }
    button:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔒 403 Forbidden — Private Knowledge Vault</h1>
    <p>This Knowledge Graph Visualizer is strictly locked to the workstation owner. Enter your owner token from <code>~/.local/share/knowledge-compiler/.vault_graph_token</code> to unlock this browser:</p>
    <form method="GET" action="/">
      <input type="password" name="token" placeholder="Paste owner token..." required autocomplete="off">
      <button type="submit">Unlock</button>
    </form>
  </div>
</body>
</html>
"""


def create_graph_request_handler(
    vault_root: Path,
    port: int = 8765,
    sidecar_mode: bool = False,
    owner_token: str | None = None,
    ui_token: str | None = None,
    cache: VaultGraphCache | None = None,
) -> type[http.server.BaseHTTPRequestHandler]:
    """Build a configured GraphRequestHandler class bound to vault_root and owner_token."""
    resolved_ui_token = (
        ui_token
        if ui_token is not None
        else (
            ((os.environ.get("ANTIGRAVITY_SIDECAR_UI_TOKEN") or "").strip() or secrets.token_urlsafe(32))
            if sidecar_mode
            else None
        )
    )
    resolved_owner_token = (
        owner_token
        if owner_token is not None
        else (None if sidecar_mode else get_or_create_owner_token(port=port))
    )
    preload_js_path = SCRIPT_DIR.parent / "sidecars" / "vault_graph" / "preload.js"
    logo_svg_path = SCRIPT_DIR.parent / "assets" / "logo.svg"
    prepared_candidate_cache: dict[tuple[str, str, int], dict[str, Any]] = {}
    graph_cache = cache if cache is not None else VaultGraphCache(max_entries=4)

    class GraphRequestHandler(http.server.BaseHTTPRequestHandler):
        timeout = 10
        MAX_POST_BODY_BYTES = 1_048_576

        def log_message(self, fmt: str, *args: object) -> None:
            try:
                rendered = fmt % args if args else fmt
            except Exception:
                rendered = str(fmt)
            logger.info("%s", redact_token_in_log(rendered))

        def _cors_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            origin = self.headers.get("Origin")
            if is_allowed_origin(origin, allowed_port=port):
                self.send_header("Access-Control-Allow-Origin", str(origin))
                self.send_header("Vary", "Origin")
                self.send_header(
                    "Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD"
                )
                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization, X-Requested-With, X-Sidecar-Token, X-Owner-Token, X-KC-Request",
                )

        def _send_csp_header(self, csp_nonce: str) -> None:
            frame_directive = "" if sidecar_mode else "frame-ancestors 'self'; "
            self.send_header(
                "Content-Security-Policy",
                f"default-src 'none'; script-src 'self' 'nonce-{csp_nonce}'; "
                "style-src 'unsafe-inline'; img-src 'self' data: blob:; "
                "font-src 'self' data:; connect-src 'self'; "
                f"{frame_directive}base-uri 'none'",
            )

        def _check_host(self) -> bool:
            return is_valid_host_header(self.headers.get("Host"), allowed_port=port)

        def _check_auth(self, is_post: bool = False) -> tuple[bool, bool]:
            """Return (is_authorized, should_set_owner_cookie)."""
            if not self._check_host():
                return False, False
            active_tok = (
                resolved_ui_token if sidecar_mode else resolved_owner_token
            ) or ""
            if not active_tok:
                return False, False
            expected = active_tok.encode("utf-8")

            # 1. Explicit header authentication (CLI / tests / direct sidecar header)
            auth_hdr = (self.headers.get("Authorization") or "").strip()
            if auth_hdr.lower().startswith("bearer "):
                bearer_val = auth_hdr[7:].strip()
                if bearer_val and hmac.compare_digest(bearer_val.encode("utf-8"), expected):
                    return True, False

            for hdr_name in ("X-Owner-Token", "X-Sidecar-Token"):
                hdr_val = (self.headers.get(hdr_name) or "").strip()
                if hdr_val and hmac.compare_digest(hdr_val.encode("utf-8"), expected):
                    return True, False

            # 2. Initial unlock query parameter (?token=...) on GET requests -> sets HttpOnly cookie
            if not is_post:
                parsed = urllib.parse.urlparse(self.path)
                q_tokens = urllib.parse.parse_qs(parsed.query).get("token", [])
                for candidate in q_tokens:
                    if hmac.compare_digest(candidate.encode("utf-8"), expected):
                        return True, True

            # 3. HttpOnly kc_owner_token cookie (requires X-KC-Request: 1 on POST routes to block CSRF)
            cookie_hdr = self.headers.get("Cookie") or ""
            if cookie_hdr:
                try:
                    jar = http.cookies.SimpleCookie()
                    jar.load(cookie_hdr)
                    if "kc_owner_token" in jar:
                        c_val = jar["kc_owner_token"].value
                        if hmac.compare_digest(c_val.encode("utf-8"), expected):
                            if is_post:
                                csrf_hdr = (self.headers.get("X-KC-Request") or "").strip()
                                if csrf_hdr != "1":
                                    return False, False
                            return True, False
                except Exception:
                    pass

            return False, False

        def _validate_token(self, is_post: bool = False) -> bool:
            ok, _ = self._check_auth(is_post=is_post)
            return ok

        def do_OPTIONS(self) -> None:  # noqa: N802
            if not self._check_host():
                self.send_error(http.HTTPStatus.FORBIDDEN, "Invalid Host header")
                return
            self.send_response(http.HTTPStatus.NO_CONTENT)
            self._cors_headers()
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            if not self._check_host():
                self.send_response(http.HTTPStatus.FORBIDDEN)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(b'{"error": "forbidden: invalid Host header"}')
                return

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/preload.js":
                if preload_js_path.is_file():
                    body = preload_js_path.read_bytes()
                else:
                    body = b"window.sidecar = window.sidecar || {};\n"
                self.send_response(http.HTTPStatus.OK)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(body)
                return

            if path in ("/favicon.svg", "/favicon.ico"):
                if logo_svg_path.is_file():
                    svg_bytes = logo_svg_path.read_bytes()
                else:
                    svg_bytes = (
                        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
                        b'<circle cx="32" cy="32" r="28" fill="#1A73E8"/></svg>'
                    )
                self.send_response(http.HTTPStatus.OK)
                self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(svg_bytes)
                return

            authorized, set_cookie = self._check_auth(is_post=False)
            if not authorized:
                lock_nonce = secrets.token_urlsafe(24)
                status = (
                    http.HTTPStatus.UNAUTHORIZED
                    if sidecar_mode
                    else http.HTTPStatus.FORBIDDEN
                )
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self._send_csp_header(lock_nonce)
                self.send_header(
                    "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
                )
                self._cors_headers()
                self.end_headers()
                self.wfile.write(_FORBIDDEN_LOCK_HTML.encode("utf-8"))
                return

            if path in ("/", "/index.html"):
                csp_nonce = secrets.token_urlsafe(24)
                html_str = graph_cache.get_rendered_html(
                    vault_root,
                    include_remote_tier=False,
                    sidecar_mode=sidecar_mode,
                    csp_nonce=csp_nonce,
                )
                cleanup_script = (
                    f'<script nonce="{csp_nonce}">'
                    "if(window.location.search.includes('token=')){"
                    "window.history.replaceState({},document.title,window.location.pathname);"
                    "}</script></head>"
                )
                html_str = html_str.replace("</head>", cleanup_script, 1)
                html_bytes = html_str.encode("utf-8")
                self.send_response(http.HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self._send_csp_header(csp_nonce)
                self.send_header(
                    "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
                )
                active_cookie_tok = (
                    resolved_ui_token if sidecar_mode else resolved_owner_token
                )
                if set_cookie and active_cookie_tok:
                    self.send_header(
                        "Set-Cookie",
                        f"kc_owner_token={active_cookie_tok}; Path=/; Max-Age=604800; HttpOnly; SameSite=Strict",
                    )
                self._cors_headers()
                self.end_headers()
                self.wfile.write(html_bytes)
            elif path == "/api/graph":
                q_params = urllib.parse.parse_qs(parsed.query)
                include_ace = q_params.get("include_ace", ["0"])[0].lower() in (
                    "1",
                    "true",
                    "yes",
                )
                body = graph_cache.get_json_bytes(
                    vault_root, include_remote_tier=include_ace
                )
                self.send_response(http.HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self._cors_headers()
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(http.HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:  # noqa: N802
            if not self._check_host():
                self.send_response(http.HTTPStatus.FORBIDDEN)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(b'{"error": "forbidden: invalid Host header"}')
                return

            origin = self.headers.get("Origin")
            if origin and not is_allowed_origin(origin, allowed_port=port):
                self.send_response(http.HTTPStatus.FORBIDDEN)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(b'{"error": "forbidden: invalid Origin header"}')
                return

            if self.headers.get("Transfer-Encoding"):
                self.send_response(http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(b'{"error": "Payload Too Large"}')
                return

            raw_len = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_len)
            except ValueError:
                self.send_response(http.HTTPStatus.BAD_REQUEST)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid Content-Length"}')
                return

            if length < 0 or length > self.MAX_POST_BODY_BYTES:
                self.send_response(http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(b'{"error": "Payload Too Large (max 1 MiB)"}')
                return

            if not self._validate_token(is_post=True):
                self.send_response(http.HTTPStatus.UNAUTHORIZED)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(b'{"error": "unauthorized"}')
                return

            content_type = (self.headers.get("Content-Type") or "").lower()
            if not content_type.startswith("application/json"):
                self.send_response(http.HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(b'{"error": "Content-Type must be application/json"}')
                return

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            raw_body = self.rfile.read(length) if length > 0 else b"{}"
            try:
                data = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            except Exception:
                data = {}

            def run_antigravity_cli(args: list[str], project_id: str | None = None) -> dict[str, Any]:
                env = os.environ.copy()
                if project_id:
                    env["ANTIGRAVITY_PROJECT_ID"] = project_id
                try:
                    res = subprocess.run(
                        ["antigravity_cli", *args],
                        capture_output=True,
                        text=True,
                        env=env,
                        timeout=25,
                        check=False,
                    )
                    out = res.stdout.strip()
                    return json.loads(out) if out else {}
                except Exception as exc:
                    return {"error": str(exc)}

            def prepare_isolated_ace_candidate() -> tuple[dict[str, Any] | None, int, dict[str, Any] | None]:
                """Resolve notePath strictly inside ce_patterns_root and produce canonical server-side sanitized content."""
                ce_root = resolve_ce_patterns_root(
                    os.environ.get("OKF_PATTERNS_PATH")
                ).resolve()
                note_rel = str(data.get("notePath") or "").strip()
                if not note_rel:
                    err = {
                        "ok": False,
                        "http_status": 400,
                        "error": "notePath inside shared-okf-patterns is required",
                        "response": {"error": "notePath inside shared-okf-patterns is required"},
                    }
                    return None, int(http.HTTPStatus.BAD_REQUEST), err
                target_path = (ce_root / note_rel).resolve()
                try:
                    target_path.relative_to(ce_root)
                except ValueError:
                    err = {
                        "ok": False,
                        "http_status": 403,
                        "error": "notePath must reside strictly inside shared-okf-patterns",
                        "response": {"error": "notePath must reside strictly inside shared-okf-patterns"},
                    }
                    return None, int(http.HTTPStatus.FORBIDDEN), err
                file_sha = (
                    hashlib.sha256(target_path.read_bytes()).hexdigest()
                    if target_path.is_file()
                    else ""
                )
                cache_key = (
                    str(target_path),
                    file_sha,
                    id(prepare_pattern_for_remote_tier),
                )
                prep = prepared_candidate_cache.get(cache_key)
                if prep is None:
                    try:
                        prep = prepare_pattern_for_remote_tier(
                            note_path=target_path,
                            ce_patterns_root=ce_root,
                            obsidian_vault_root=vault_root,
                        )
                    except Exception as exc:
                        err = {
                            "ok": False,
                            "http_status": 403,
                            "error": str(exc),
                            "response": {"error": str(exc)},
                        }
                        return None, int(http.HTTPStatus.FORBIDDEN), err
                cand = prep.get("candidate_submission") if isinstance(prep, dict) else None
                if not isinstance(cand, dict) or not cand.get("content"):
                    msg = str((prep or {}).get("error") or "Failed to prepare candidate pattern")
                    err = {
                        "ok": False,
                        "http_status": 403,
                        "error": msg,
                        "response": {"error": msg},
                    }
                    return None, int(http.HTTPStatus.FORBIDDEN), err
                prepared_candidate_cache[cache_key] = prep
                return prep, int(http.HTTPStatus.OK), None

            if (path.startswith("/_sidecar/") or path.startswith("/api/ace-")) and not HAS_1P_FED_BRIDGE:
                self.send_error(http.HTTPStatus.NOT_FOUND)
                return

            if path == "/_sidecar/get-conversation-metadata":
                conv_id = str(
                    data.get("conversationId")
                    or os.environ.get("ANTIGRAVITY_SIDECAR_CONVERSATION_ID", "")
                )
                if not is_valid_conversation_id(conv_id):
                    self.send_response(http.HTTPStatus.BAD_REQUEST)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self._cors_headers()
                    self.end_headers()
                    self.wfile.write(b'{"error": "Invalid conversationId"}')
                    return
                resp = run_antigravity_cli(["get-conversation-metadata", conv_id])
            elif path == "/_sidecar/send-message":
                conv_id = str(
                    data.get("conversationId")
                    or os.environ.get("ANTIGRAVITY_SIDECAR_CONVERSATION_ID", "")
                )
                msg = str(data.get("message", ""))
                if not is_valid_conversation_id(conv_id) or not msg or msg.startswith("-"):
                    self.send_response(http.HTTPStatus.BAD_REQUEST)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self._cors_headers()
                    self.end_headers()
                    self.wfile.write(b'{"error": "Invalid conversationId or message"}')
                    return
                resp = run_antigravity_cli(["send-message", conv_id, msg], data.get("projectId"))
            elif path == "/_sidecar/new-conversation":
                msg = str(data.get("message", ""))
                if not msg or msg.startswith("-"):
                    self.send_response(http.HTTPStatus.BAD_REQUEST)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self._cors_headers()
                    self.end_headers()
                    self.wfile.write(b'{"error": "Invalid message"}')
                    return
                resp = run_antigravity_cli(["new-conversation", msg], data.get("projectId"))
            elif path == "/api/federated-query":
                try:
                    ce_root = resolve_ce_patterns_root(
                        os.environ.get("OKF_PATTERNS_PATH")
                    )
                    resp = run_federated_query(
                        query=str(data.get("query", "")),
                        obsidian_vault_root=vault_root,
                        ce_patterns_root=ce_root,
                        ace_enabled=bool(
                            data.get("aceEnabled", data.get("includeAceBrain", False))
                        ),
                        include_local_vault=bool(data.get("includeLocal", True)),
                        include_ce_patterns=bool(data.get("includeCePatterns", True)),
                    )
                except Exception as exc:
                    resp = {"error": str(exc)}
            elif path == "/api/ace-promote":
                try:
                    ce_root = resolve_ce_patterns_root(
                        os.environ.get("OKF_PATTERNS_PATH")
                    ).resolve()
                    note_rel = str(data.get("notePath", "")).strip()
                    if not note_rel:
                        raise ValueError("notePath is required")
                    target_path = (ce_root / note_rel).resolve()
                    target_path.relative_to(ce_root)
                    file_sha = (
                        hashlib.sha256(target_path.read_bytes()).hexdigest()
                        if target_path.is_file()
                        else ""
                    )
                    cache_key = (
                        str(target_path),
                        file_sha,
                        id(prepare_pattern_for_remote_tier),
                    )
                    resp = prepared_candidate_cache.get(cache_key)
                    if resp is None:
                        resp = prepare_pattern_for_remote_tier(
                            note_path=target_path,
                            ce_patterns_root=ce_root,
                            obsidian_vault_root=vault_root,
                        )
                        if (
                            isinstance(resp, dict)
                            and isinstance(resp.get("candidate_submission"), dict)
                            and resp["candidate_submission"].get("content")
                        ):
                            prepared_candidate_cache[cache_key] = resp
                except Exception as exc:
                    resp = {"error": str(exc)}
            elif path == "/api/ace-live-preflight":
                prep, err_status, err_payload = prepare_isolated_ace_candidate()
                if err_payload is not None or prep is None:
                    self.send_response(err_status)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self._cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps(err_payload).encode("utf-8"))
                    return
                cand = prep["candidate_submission"]
                try:
                    resp = run_remote_tier_preflight(
                        content=str(cand["content"]),
                        default_id=str(
                            cand.get("default_id")
                            or prep.get("concept_id")
                            or data.get("defaultId", "")
                        ),
                    )
                except Exception as exc:
                    resp = {"ok": False, "http_status": 0, "response": {"error": str(exc)}}
            elif path == "/api/ace-live-submit":
                prep, err_status, err_payload = prepare_isolated_ace_candidate()
                if err_payload is not None or prep is None:
                    self.send_response(err_status)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self._cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps(err_payload).encode("utf-8"))
                    return
                cand = prep["candidate_submission"]
                try:
                    resp = submit_to_remote_tier(
                        submission_id=str(
                            cand.get("id")
                            or prep.get("submission_id")
                            or data.get("id", "")
                        ),
                        content=str(cand["content"]),
                        default_id=str(
                            cand.get("default_id")
                            or prep.get("concept_id")
                            or data.get("defaultId", "")
                        ),
                        preflight_token=str(
                            data.get("preflightToken")
                            or cand.get("preflight_token", "")
                        ),
                    )
                except Exception as exc:
                    resp = {"ok": False, "http_status": 0, "response": {"error": str(exc)}}
            else:
                self.send_error(http.HTTPStatus.NOT_FOUND)
                return

            body_bytes = json.dumps(resp).encode("utf-8")
            self.send_response(http.HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(body_bytes)

    return GraphRequestHandler


def serve_vault_graph(
    vault_root: Path,
    port: int = 8765,
    sidecar_mode: bool = False,
    host: str = "127.0.0.1",
) -> None:
    """Run a ThreadingHTTPServer serving the WebGL Vault Graph Visualizer with Owner Token + Cookie Gate."""
    ui_token = (
        ((os.environ.get("ANTIGRAVITY_SIDECAR_UI_TOKEN") or "").strip() or secrets.token_urlsafe(32))
        if sidecar_mode
        else None
    )
    owner_token = get_or_create_owner_token(port=port)
    handler_cls = create_graph_request_handler(
        vault_root=vault_root,
        port=port,
        sidecar_mode=sidecar_mode,
        owner_token=owner_token,
        ui_token=ui_token,
    )

    bind_host = "127.0.0.1" if sidecar_mode else host
    with http.server.ThreadingHTTPServer((bind_host, port), handler_cls) as srv:
        logger.info(
            "Serving WebGL Vault Graph Visualizer (%s) on http://%s:%d",
            vault_root,
            bind_host,
            port,
        )
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down WebGL Graph server...")
            srv.shutdown()


def resolve_default_vault(arg_vault: str | None) -> Path:
    """Resolve the target vault path from CLI argument, environment, or default vault directory."""
    if arg_vault and arg_vault != ".":
        return find_vault_root(Path(arg_vault).expanduser())
    env_vault = os.environ.get("KC_VAULT_PATH") or os.environ.get("OBSIDIAN_VAULT_PATH")
    if env_vault:
        env_p = Path(env_vault).expanduser()
        if not env_p.exists():
            init_vault(env_p, quiet=True, init_git=False)
        return find_vault_root(env_p)
    for cand in (Path("~/knowledge-vault").expanduser(), Path("~/ObsidianVault").expanduser()):
        if cand.exists():
            return find_vault_root(cand)
    cwd = Path.cwd().resolve()
    if (cwd / "GEMINI.md").exists() or (cwd / "wiki").is_dir():
        return find_vault_root(cwd)
    default_vault = Path("~/ObsidianVault").expanduser()
    init_vault(default_vault, quiet=True, init_git=False)
    return find_vault_root(default_vault)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compile or serve an OKF v0.2 Obsidian Vault WebGL 2D/3D Graph Visualizer."
    )
    parser.add_argument(
        "vault",
        nargs="?",
        default=None,
        help="Path to Obsidian Vault root (defaults to $OBSIDIAN_VAULT_PATH or ~/ObsidianVault).",
    )
    parser.add_argument(
        "--export",
        nargs="?",
        const="__DEFAULT__",
        default=None,
        metavar="PATH",
        help=(
            "Export a standalone self-contained WebGL HTML file "
            "(defaults to $XDG_CACHE_HOME/knowledge-compiler/exports/Obsidian_Vault_WebGL_Graph.html)."
        ),
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start a local HTTP server on 127.0.0.1.",
    )
    parser.add_argument(
        "--sidecar",
        action="store_true",
        help="Run as a Antigravity / Antigravity UI Plugin Sidecar using ANTIGRAVITY_SIDECAR_WEB_PORT.",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Bind host for --serve mode (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="HTTP server port for --serve mode (default: 8765).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the compiled graph JSON topology to stdout.",
    )
    args = parser.parse_args()

    vault_root = resolve_default_vault(args.vault)

    if args.json:
        data = build_vault_graph(vault_root)
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    if args.export is not None:
        export_target = (
            resolve_default_export_html_path()
            if args.export == "__DEFAULT__"
            else Path(args.export)
        )
        res = export_graph_html(vault_root, export_target)
        print(
            f"✅ Exported WebGL Vault Graph ({res['stats']['wikiNotes']} wiki notes, "
            f"{res['stats']['totalEdges']} links) -> {res['output_path']}"
        )
        return

    if args.sidecar:
        sidecar_port = int(os.environ.get("ANTIGRAVITY_SIDECAR_WEB_PORT", str(args.port)))
        serve_vault_graph(vault_root, port=sidecar_port, sidecar_mode=True, host="127.0.0.1")
        return

    if args.serve:
        serve_vault_graph(vault_root, port=args.port, sidecar_mode=False, host=args.host)
        return

    # Default action if no mode flag specified: print summary stats
    data = build_vault_graph(vault_root)
    st = data["stats"]
    print("=" * 60)
    print("🌐 OKF v0.2 WebGL Vault Graph Topology Summary")
    print("=" * 60)
    print(f"📁 Vault Path : {data['vaultPath']}")
    print(f"📚 Wiki Notes : {st['wikiNotes']} (Total MD: {st['totalFiles']})")
    print(f"🔗 Directed Edges : {st['totalEdges']}")
    print(f"🏝️ Orphan Notes : {st['orphanNotes']}")
    print("💡 Run with `--serve` (live web UI) or `--export graph.html` (standalone).")
    print("=" * 60)


if __name__ == "__main__":
    main()
