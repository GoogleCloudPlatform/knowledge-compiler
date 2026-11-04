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
"""sanitize_check.py - Strict Semantic DLP, Air-Gap & Link Integrity Scanner for shared OKF pattern repositories.

Audits staged or committed Markdown files in a shared pattern repository to guarantee:
1. Zero customer, Private Equity sponsor, or partner deal identifiers.
2. Zero real 12-digit AWS account IDs, customer GCP project IDs, or private Google Sheets/Docs IDs.
3. Zero local workstation paths (`/home/<user>`, `/Users/<user>`, `/usr/local/google/home/<user>`) or personal handles.
4. Zero HR/performance/compensation keywords (`salary`, `promo packet`, `peer bonus`).
5. Full OKF v0.2 YAML frontmatter compliance and unescaped Markdown table pipes (`[[Target|Alias]]`).
6. In `--strict` mode: zero private vault path references (`raw/`, `wiki/entities/`, `wiki/sources/`,
   `wiki/synthesis/`) and zero broken `[[wikilinks]]` outside code blocks/spans.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from sync_patterns import (  # noqa: E402
    BLOCKED_KEYWORD_PATTERNS,
    DEFAULT_CUSTOMER_ANONYMIZATIONS,
    EPISTEMIC_FRONTMATTER_KEYS,
    build_entity_archetype_map,
    discover_customer_entities,
    lookup_sha256_archetype,
    scan_sha256_entities_in_text,
)

# Extended strict enterprise customer, PE sponsor, and engagement code-name patterns
# (Generic synthetic names only; additional SHA-256 prefixes loaded dynamically if present)
STRICT_ENTITY_PATTERNS: list[tuple[str, str]] = [
    (r"\bAcmeCorp\b", "Synthetic customer name 'AcmeCorp'"),
    (r"\bNorthwind\b", "Synthetic customer name 'Northwind'"),
    (r"\bContoso\b", "Synthetic customer name 'Contoso'"),
    (r"\bFabrikam\b", "Synthetic customer name 'Fabrikam'"),
]

# Cloud project IDs, dataset names, cluster names, and private Workspace IDs
STRICT_INFRA_PATTERNS: list[tuple[str, str]] = [
    (
        r"docs\.google\.com/(?:spreadsheets|document)/d/[a-zA-Z0-9_-]{20,}",
        "Private Google Docs/Sheets URL",
    ),
]

ENTITY_SHA256_PATTERNS: dict[str, str] = {}
INFRA_SHA256_PREFIXES: dict[str, str] = {}
IDENTITY_SHA256_PREFIXES: dict[str, str] = {}

# Workstation paths and personal handles prohibited inside shared pattern notes
WORKSTATION_AND_IDENTITY_PATTERNS: list[tuple[str, str]] = [
    (r"/usr/local/[a-zA-Z0-9._-]+/home/[a-zA-Z0-9._-]+", "Workstation home path"),
    (r"/home/[a-zA-Z0-9._-]+", "Local Linux /home/<user> path"),
    (r"/Users/[a-zA-Z0-9._-]+", "Local macOS /Users/<user> path"),
    (r"\bhuman:(?!(?:cloud-ce|ce-name|author)\b)[a-zA-Z0-9._-]+\b", "Personal frontmatter verifier handle"),
]

SYNTHETIC_AWS_ACCOUNT_ALLOWLIST = {
    "000000000000",
    "111111111111",
    "111122223333",
    "222233334444",
    "333344445555",
    "444455556666",
    "999988887777",
    "123456789012",
}

ALLOWED_OKF_STATUSES = {"stable", "draft", "deprecated", "proposed"}
REQUIRED_OKF_KEYS = ("title", "type", "status", "tags", "created", "updated")
PRIVATE_VAULT_LINK_PREFIXES = (
    "raw/",
    "wiki/entities/",
    "wiki/sources/",
    "wiki/synthesis/",
    "wiki/skill-impact",
)


def _parse_frontmatter_stdlib(content: str) -> tuple[dict[str, Any] | None, list[str]]:
    """Zero-dependency OKF v0.2 YAML frontmatter validator."""
    if not content.startswith("---"):
        return None, ["Missing frontmatter opening '---'"]
    parts = content.split("---", 2)
    if len(parts) < 3:
        return None, ["Malformed frontmatter (closing '---' missing)"]

    raw_yaml = parts[1]
    data: dict[str, Any] = {}
    current_list_key: str | None = None

    for raw_line in raw_yaml.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and current_list_key:
            val = stripped[2:].strip().strip("\"'")
            existing = data.get(current_list_key)
            if isinstance(existing, list):
                existing.append(val)
            continue
        if ":" in raw_line and not raw_line.startswith((" ", "\t")):
            key, val_part = raw_line.split(":", 1)
            key = key.strip()
            # Strip inline YAML comment if outside quotes
            val_clean = val_part.strip()
            if val_clean and val_clean[0] not in ('"', "'") and " #" in val_clean:
                val_clean = val_clean.split(" #", 1)[0].strip()
            if not val_clean:
                data[key] = []
                current_list_key = key
            elif val_clean.startswith("[") and val_clean.endswith("]"):
                inner = val_clean[1:-1].strip()
                items = (
                    [x.strip().strip("\"'") for x in inner.split(",") if x.strip()]
                    if inner
                    else []
                )
                data[key] = items
                current_list_key = None
            else:
                data[key] = val_clean.strip("\"'")
                current_list_key = None

    errors: list[str] = []
    for req in REQUIRED_OKF_KEYS:
        if req not in data or data[req] == "":
            errors.append(f"Missing required OKF v0.2 frontmatter key '{req}'")

    status_val = str(data.get("status", ""))
    if status_val and status_val not in ALLOWED_OKF_STATUSES:
        errors.append(
            f"Invalid OKF status '{status_val}' (expected one of {sorted(ALLOWED_OKF_STATUSES)})"
        )

    if "tags" in data and not isinstance(data["tags"], list):
        errors.append("Frontmatter 'tags' must be a YAML list")

    return data, errors


def _strip_code_blocks_and_inline_spans(content: str) -> str:
    """Remove fenced code blocks and inline backtick code spans before scanning prose wikilinks."""
    no_fenced = re.sub(r"```[\s\S]*?```", "", content)
    no_inline = re.sub(r"`[^`\n]+`", "", no_fenced)
    return no_inline


def collect_repo_link_targets(repo_root: Path) -> set[str]:
    """Collect all valid wikilink resolution targets inside a shared pattern repository."""
    valid: set[str] = set()
    if not repo_root.is_dir():
        return valid

    for md in repo_root.glob("wiki/**/*.md"):
        rel = str(md.relative_to(repo_root)).replace("\\", "/")
        valid.add(rel)
        valid.add(rel.removesuffix(".md"))
        valid.add(md.name)
        valid.add(md.stem)
        txt = md.read_text(encoding="utf-8", errors="ignore")
        fm, _ = _parse_frontmatter_stdlib(txt)
        if fm and fm.get("title"):
            valid.add(str(fm["title"]).strip())

    for root_doc in ("index.md", "GEMINI.md", "README.md", "log.md"):
        if (repo_root / root_doc).is_file():
            valid.add(root_doc)
            valid.add(root_doc.removesuffix(".md"))

    return valid


def _resolve_entity_archetype(
    stem: str,
    alias: str | None,
    archetypes: dict[str, str],
    lower_archetypes: dict[str, str],
) -> str | None:
    """Resolve a candidate entity name or alias to its enterprise archetype prose."""
    for cand in (stem, alias or ""):
        clean = cand.strip()
        if not clean:
            continue
        if clean in archetypes:
            return archetypes[clean]
        if len(clean) > 3 and clean.lower() in lower_archetypes:
            return lower_archetypes[clean.lower()]
        sha_arch = lookup_sha256_archetype(clean)
        if sha_arch:
            return sha_arch
    return None


def detect_private_entity_wikilinks(
    content: str,
    vault_root: Path | None = None,
    valid_targets: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Detect private `wiki/entities/` and customer entity wikilinks and suggest archetype prose."""
    archetypes, public_entities = build_entity_archetype_map(vault_root=vault_root)
    lower_archetypes = {k.lower(): v for k, v in archetypes.items() if len(k) > 3}
    lower_public = {p.lower(): p for p in public_entities}

    findings: list[dict[str, Any]] = []
    in_fence = False

    for line_no, raw_line in enumerate(content.splitlines(), 1):
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue

        # Mask inline backtick code spans on this line before matching wikilinks
        line_no_code = re.sub(r"`[^`\n]+`", "", raw_line)
        line_norm = re.sub(
            r"\[\[([^\]\n]+?)\\+\|([^\]\n]+?)\]\]", r"[[\1|\2]]", line_no_code
        )
        for m in re.finditer(r"\[\[([^\]|#\n]+)(?:#[^\]|\n]*)?(?:\|([^\]\n]+))?\]\]", line_norm):
            raw_target = m.group(1).strip().strip("\"'")
            raw_alias = m.group(2).strip().strip("\"'") if m.group(2) else None
            if not raw_target or raw_target.startswith(("http://", "https://", "file:")):
                continue

            norm_target = raw_target.lstrip("/")
            norm_lower = norm_target.lower()
            stem = norm_target.removesuffix(".md").split("/")[-1].strip()

            if norm_lower.startswith(("wiki/entities/", "entities/")):
                arch = _resolve_entity_archetype(stem, raw_alias, archetypes, lower_archetypes)
                if arch:
                    suggested = arch
                    kind = "private_customer_entity"
                elif stem.lower() in lower_public:
                    suggested = (
                        f"[[{stem}]]"
                        if (valid_targets and stem in valid_targets)
                        else (raw_alias or lower_public[stem.lower()])
                    )
                    kind = "public_tech_entity_path"
                else:
                    suggested = "Enterprise Commercial Account"
                    kind = "unmapped_private_entity"
                findings.append(
                    {
                        "line": line_no,
                        "wikilink": m.group(0),
                        "target": raw_target,
                        "suggested_archetype": suggested,
                        "kind": kind,
                    }
                )
                continue

            arch = _resolve_entity_archetype(stem, raw_alias, archetypes, lower_archetypes)
            if arch:
                findings.append(
                    {
                        "line": line_no,
                        "wikilink": m.group(0),
                        "target": raw_target,
                        "suggested_archetype": arch,
                        "kind": "bare_customer_entity",
                    }
                )

    return findings


def rewrite_private_entity_wikilinks(
    content: str,
    vault_root: Path | None = None,
    valid_targets: set[str] | None = None,
) -> tuple[str, list[dict[str, str]]]:
    """Automatically convert private `wiki/entities/` & customer wikilinks into clean archetype prose.

    Preserves fenced code blocks and inline code spans, heals escaped table pipes, unwraps
    private vault `wiki/sources/` and `wiki/synthesis/` links, and prunes private vault
    entries from YAML frontmatter `sources:` and 5-way epistemic lists.
    """
    archetypes, public_entities = build_entity_archetype_map(vault_root=vault_root)
    lower_archetypes = {k.lower(): v for k, v in archetypes.items() if len(k) > 3}
    lower_public = {p.lower(): p for p in public_entities}
    conversions: list[dict[str, str]] = []

    def _scrub_free_text(txt: str) -> str:
        out = txt
        for name in sorted(archetypes.keys(), key=len, reverse=True):
            if len(name) <= 3:
                out = re.sub(r"\b" + re.escape(name) + r"\b", archetypes[name], out)
            else:
                out = re.sub(
                    r"\b" + re.escape(name) + r"\b",
                    archetypes[name],
                    out,
                    flags=re.IGNORECASE,
                )
        sha_hits = scan_sha256_entities_in_text(out)
        for start_off, end_off, _span, arch in reversed(sha_hits):
            out = out[:start_off] + arch + out[end_off:]
        return out

    fm_prefix = ""
    body_text = content
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            fm_lines = parts[1].splitlines()
            cleaned_fm: list[str] = []
            active_key: str | None = None
            buf_header: str | None = None
            buf_items: list[str] = []

            def _flush_fm() -> None:
                nonlocal active_key, buf_header, buf_items
                if active_key is None or buf_header is None:
                    return
                if active_key == "sources":
                    cleaned_fm.append(buf_header)
                    cleaned_fm.extend(buf_items)
                elif buf_items:
                    cleaned_fm.append(buf_header)
                    cleaned_fm.extend(buf_items)
                active_key = None
                buf_header = None
                buf_items = []

            for fl in fm_lines:
                s_fl = fl.strip()
                matched_k = None
                for k in ("sources", *EPISTEMIC_FRONTMATTER_KEYS):
                    if s_fl == f"{k}:":
                        matched_k = k
                        break
                if matched_k:
                    _flush_fm()
                    active_key = matched_k
                    buf_header = fl
                    buf_items = []
                    continue
                if active_key is not None:
                    if s_fl.startswith("- ") or s_fl == "-":
                        low = fl.lower()
                        drop = any(
                            p in low
                            for p in (
                                "raw/",
                                "wiki/entities/",
                                "entities/",
                                "wiki/sources/",
                                "wiki/synthesis/",
                                "wiki/skill-impact",
                                "/home/",
                                "/users/",
                                "/usr/local/google/home/",
                            )
                        )
                        if not drop:
                            for wm in re.finditer(r"\[\[([^\]|#]+)(?:[|#][^\]]*)?\]\]", fl):
                                w_stem = wm.group(1).strip().removesuffix(".md").split("/")[-1].strip()
                                if _resolve_entity_archetype(w_stem, None, archetypes, lower_archetypes):
                                    drop = True
                                elif vault_root and (
                                    (vault_root / "wiki" / "entities" / f"{w_stem}.md").is_file()
                                    or (vault_root / "wiki" / "synthesis" / f"{w_stem}.md").is_file()
                                    or (vault_root / "wiki" / "sources" / f"{w_stem}.md").is_file()
                                ):
                                    drop = True
                                elif valid_targets is not None and w_stem not in valid_targets:
                                    drop = True
                        if drop:
                            conversions.append(
                                {
                                    "original": s_fl,
                                    "replacement": "<pruned private frontmatter link>",
                                    "kind": f"frontmatter_{active_key}",
                                }
                            )
                            continue
                        buf_items.append(fl)
                        continue
                    elif not fl.startswith((" ", "\t")) and ":" in s_fl:
                        _flush_fm()
                if "by: human:" in fl and "by: human:cloud-ce" not in fl:
                    new_fl = re.sub(r"by:\s*human:[a-zA-Z0-9._-]+", "by: human:cloud-ce", fl)
                    if new_fl != fl:
                        conversions.append(
                            {
                                "original": s_fl,
                                "replacement": new_fl.strip(),
                                "kind": "frontmatter_verifier",
                            }
                        )
                        cleaned_fm.append(new_fl)
                        continue
                cleaned_fm.append(fl)
            _flush_fm()
            fm_prefix = "---" + "\n".join(cleaned_fm) + "\n---"
            body_text = parts[2]

    protected_spans: list[str] = []

    def _mask_span(m: re.Match) -> str:
        idx = len(protected_spans)
        protected_spans.append(m.group(0))
        return f"\x00SPAN_{idx}\x00"

    masked_body = re.sub(r"```[\s\S]*?```|`[^`\n]+`", _mask_span, body_text)
    masked_body = re.sub(
        r"\[\[([^\]\n]+?)\\+\|([^\]\n]+?)\]\]", r"[[\1|\2]]", masked_body
    )

    def _replace_wl(m: re.Match) -> str:
        orig = m.group(0)
        raw_target = m.group(1).strip().strip("\"'")
        raw_alias = m.group(2).strip().strip("\"'") if m.group(2) else None
        if not raw_target or raw_target.startswith(("http://", "https://", "file:")):
            return orig

        norm_target = raw_target.lstrip("/")
        norm_lower = norm_target.lower()
        no_anchor = norm_target.split("#", 1)[0].removesuffix(".md").strip()
        stem = no_anchor.split("/")[-1].strip()

        # 1. Explicit private `wiki/entities/` or `entities/` wikilink
        if norm_lower.startswith(("wiki/entities/", "entities/")):
            arch = _resolve_entity_archetype(stem, raw_alias, archetypes, lower_archetypes)
            if arch:
                conversions.append(
                    {"original": orig, "replacement": arch, "kind": "private_entity_archetype"}
                )
                return arch
            if stem.lower() in lower_public:
                if valid_targets and stem in valid_targets:
                    rep = f"[[{stem}|{raw_alias}]]" if raw_alias else f"[[{stem}]]"
                else:
                    rep = raw_alias or lower_public[stem.lower()]
                conversions.append(
                    {"original": orig, "replacement": rep, "kind": "public_tech_entity"}
                )
                return rep
            fallback = "Enterprise Commercial Account"
            conversions.append(
                {"original": orig, "replacement": fallback, "kind": "unmapped_private_entity"}
            )
            return fallback

        # 2. Explicit private vault `raw/`, `wiki/sources/`, `wiki/synthesis/`, `wiki/skill-impact`
        if norm_lower.startswith(
            (
                "raw/",
                "wiki/sources/",
                "sources/",
                "wiki/synthesis/",
                "synthesis/",
                "wiki/skill-impact",
            )
        ):
            rep = _scrub_free_text(raw_alias or stem)
            conversions.append(
                {"original": orig, "replacement": rep, "kind": "private_plane1_unwrap"}
            )
            return rep

        # 3. Bare customer / PE / private entity wikilink
        arch = _resolve_entity_archetype(stem, raw_alias, archetypes, lower_archetypes)
        if not arch:
            arch = _resolve_entity_archetype(no_anchor, raw_alias, archetypes, lower_archetypes)
        if arch:
            conversions.append(
                {"original": orig, "replacement": arch, "kind": "bare_customer_archetype"}
            )
            return arch

        # 4. Bare private synthesis or source note in vault_root
        if vault_root and (
            (vault_root / "wiki" / "synthesis" / f"{stem}.md").is_file()
            or (vault_root / "wiki" / "sources" / f"{stem}.md").is_file()
        ):
            rep = _scrub_free_text(raw_alias or stem)
            conversions.append(
                {"original": orig, "replacement": rep, "kind": "private_synthesis_unwrap"}
            )
            return rep

        # 5. Bare public tech entity link absent from shared pattern repository
        if (
            valid_targets is not None
            and stem.lower() in lower_public
            and stem not in valid_targets
            and norm_target not in valid_targets
        ):
            rep = raw_alias or stem
            conversions.append(
                {"original": orig, "replacement": rep, "kind": "unresolved_tech_unwrap"}
            )
            return rep

        return orig

    rewritten_body = re.sub(
        r"\[\[([^\]|\n]+)(?:\|([^\]\n]+))?\]\]", _replace_wl, masked_body
    )
    for idx, sp in enumerate(protected_spans):
        rewritten_body = rewritten_body.replace(f"\x00SPAN_{idx}\x00", sp)

    return fm_prefix + rewritten_body, conversions


def scan_markdown_file(
    file_path: Path,
    repo_root: Path | None = None,
    valid_targets: set[str] | None = None,
    dynamic_customers: set[str] | None = None,
    vault_root: Path | None = None,
    strict: bool = True,
) -> list[dict[str, Any]]:
    """Scan a single Markdown file for DLP, air-gap, schema, and link violations."""
    violations: list[dict[str, Any]] = []
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    rel_display = (
        str(file_path.relative_to(repo_root)).replace("\\", "/")
        if repo_root and file_path.is_relative_to(repo_root)
        else str(file_path)
    )
    is_wiki_pattern = (
        rel_display.startswith("wiki/concepts/")
        or rel_display.startswith("wiki/patterns/")
        or "/wiki/concepts/" in str(file_path)
        or "/wiki/patterns/" in str(file_path)
    )

    def _add(category: str, message: str, line: int = 1) -> None:
        violations.append(
            {
                "file": rel_display,
                "line": line,
                "category": category,
                "message": message,
            }
        )

    def _line_of(offset: int) -> int:
        return content.count("\n", 0, offset) + 1

    # 1. OKF v0.2 Frontmatter & Table Pipe Invariant on wiki notes
    if is_wiki_pattern:
        _, fm_errors = _parse_frontmatter_stdlib(content)
        for err in fm_errors:
            _add("okf_frontmatter", err, 1)

    in_fence = False
    for line_no, raw_line in enumerate(content.splitlines(), 1):
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if stripped.startswith("|") and stripped.endswith("|"):
            if re.search(r"\[\[[^\]]+\\+\|[^\]]+\]\]", raw_line):
                _add(
                    "table_pipe_invariant",
                    "Escaped pipe inside Markdown table wikilink (use [[Target|Alias]])",
                    line_no,
                )

    # 2. Customer, PE Sponsor, and Partner Entity Checks
    for pat, label in STRICT_ENTITY_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            _add(
                "customer_dlp",
                f"Forbidden identifier detected ({label}): '{m.group(0)}'",
                _line_of(m.start()),
            )

    for start_off, _end_off, span_txt, s_label in scan_sha256_entities_in_text(
        content, sha_map=ENTITY_SHA256_PATTERNS
    ):
        _add(
            "customer_dlp",
            f"Forbidden identifier detected ({s_label}): '{span_txt}'",
            _line_of(start_off),
        )

    for start_off, _end_off, span_txt, _arch in scan_sha256_entities_in_text(content):
        _add(
            "customer_dlp",
            f"Customer entity detected: '{span_txt}'",
            _line_of(start_off),
        )

    all_customers = set(DEFAULT_CUSTOMER_ANONYMIZATIONS.keys())
    if dynamic_customers:
        all_customers.update(dynamic_customers)
    for cust in sorted(all_customers):
        # Skip 2-3 letter ambiguous acronyms unless exact case-sensitive match
        if len(cust) <= 3:
            for m in re.finditer(r"\b" + re.escape(cust) + r"\b", content):
                _add(
                    "customer_dlp",
                    f"Customer acronym detected: '{m.group(0)}'",
                    _line_of(m.start()),
                )
        else:
            for m in re.finditer(r"\b" + re.escape(cust) + r"\b", content, re.IGNORECASE):
                _add(
                    "customer_dlp",
                    f"Customer entity detected: '{m.group(0)}'",
                    _line_of(m.start()),
                )

    # 3. Cloud Account IDs, Project IDs & Private Workspace Doc IDs
    for pat, label in STRICT_INFRA_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            _add("infra_dlp", f"{label}: '{m.group(0)}'", _line_of(m.start()))

    for m in re.finditer(r"\b([a-zA-Z0-9_-]{7,64})\b", content):
        tok = m.group(1)
        exact_prefix = hashlib.sha256(tok.encode("utf-8")).hexdigest()[:24]
        lower_prefix = hashlib.sha256(tok.lower().encode("utf-8")).hexdigest()[:24]
        matched_label = INFRA_SHA256_PREFIXES.get(
            exact_prefix
        ) or INFRA_SHA256_PREFIXES.get(lower_prefix)
        if matched_label:
            _add("infra_dlp", f"{matched_label}: '{tok}'", _line_of(m.start()))
        elif is_wiki_pattern:
            id_label = IDENTITY_SHA256_PREFIXES.get(lower_prefix)
            if id_label:
                _add("identity_or_path", f"{id_label}: '{tok}'", _line_of(m.start()))

    for m in re.finditer(r"\b(\d{12})\b", content):
        acct_id = m.group(1)
        if acct_id not in SYNTHETIC_AWS_ACCOUNT_ALLOWLIST:
            _add(
                "aws_account_id",
                f"Non-allowlisted 12-digit number (potential AWS Account ID): '{acct_id}'",
                _line_of(m.start()),
            )

    # 4. Workstation Paths & Personal Handles (strictly enforced on wiki/ pattern notes;
    #    root README.md may legitimately link to internal documentation portal paths)
    for pat, label in WORKSTATION_AND_IDENTITY_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            _add("identity_or_path", f"{label}: '{m.group(0)}'", _line_of(m.start()))

    # 5. HR / Performance / Compensation Keywords
    for pat in BLOCKED_KEYWORD_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            _add(
                "hr_sensitive_keyword",
                f"Blocked HR/compensation keyword: '{m.group(0)}'",
                _line_of(m.start()),
            )

    # 6. Automated Detection of Private `wiki/entities/` Wikilinks (always active on shared wiki notes)
    if is_wiki_pattern or rel_display == "index.md":
        entity_findings = detect_private_entity_wikilinks(
            content, vault_root=vault_root, valid_targets=valid_targets
        )
        for ef in entity_findings:
            if ef["kind"] in (
                "private_customer_entity",
                "public_tech_entity_path",
                "unmapped_private_entity",
            ):
                _add(
                    "private_vault_link",
                    f"Wikilink points to private vault entity: '{ef['wikilink']}' "
                    f"(auto-rewrite -> '{ef['suggested_archetype']}')",
                    ef["line"],
                )

    # 7. Strict Private-Vault Leak & Wikilink Resolution Check
    if strict and (is_wiki_pattern or rel_display == "index.md"):
        prose_only = _strip_code_blocks_and_inline_spans(content)
        for m in re.finditer(r"\[\[([^\]|#\n]+)(?:[|#][^\]\n]*)?\]\]", prose_only):
            raw_target = m.group(1).strip().strip("\"'")
            if not raw_target or raw_target.startswith(("http://", "https://", "file:")):
                continue
            norm_target = raw_target.lstrip("/")
            norm_lower = norm_target.lower()
            for priv_prefix in PRIVATE_VAULT_LINK_PREFIXES:
                if norm_lower.startswith(priv_prefix) and not norm_lower.startswith(
                    ("wiki/entities/", "entities/")
                ):
                    _add(
                        "private_vault_link",
                        f"Wikilink points to private vault path: '[[{raw_target}]]'",
                        1,
                    )
            if valid_targets is not None:
                stem_candidate = norm_target.removesuffix(".md").split("/")[-1].strip()
                if (
                    norm_target not in valid_targets
                    and stem_candidate not in valid_targets
                    and f"Pattern: {stem_candidate}" not in valid_targets
                ):
                    _add(
                        "broken_wikilink",
                        f"Unresolved wikilink in shared patterns repository: '[[{raw_target}]]'",
                        1,
                    )

    # Deduplicate identical (file, line, category, message) entries
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for v in violations:
        key = (v["file"], v["line"], v["category"], v["message"])
        if key not in seen:
            seen.add(key)
            deduped.append(v)
    return deduped


def run_sanitize_check(
    targets: list[Path],
    repo_root: Path | None = None,
    vault_root: Path | None = None,
    strict: bool = True,
    fix: bool = False,
) -> dict[str, Any]:
    """Run semantic DLP, air-gap, and link checks (with optional `--fix` entity link rewriting)."""
    resolved_repo = repo_root.resolve() if repo_root else None
    if resolved_repo is None and len(targets) == 1 and targets[0].is_dir():
        resolved_repo = targets[0].resolve()

    md_files: list[Path] = []
    for t in targets:
        tp = t.expanduser().resolve()
        if tp.is_file() and tp.suffix.lower() == ".md":
            md_files.append(tp)
        elif tp.is_dir():
            if (tp / "wiki").is_dir():
                md_files.extend(sorted((tp / "wiki").rglob("*.md")))
                for root_md in ("index.md", "README.md", "GEMINI.md"):
                    if (tp / root_md).is_file():
                        md_files.append(tp / root_md)
            else:
                md_files.extend(sorted(tp.rglob("*.md")))

    # Deduplicate preserving order
    unique_files: list[Path] = []
    seen_paths: set[Path] = set()
    for f in md_files:
        if f not in seen_paths:
            seen_paths.add(f)
            unique_files.append(f)

    valid_targets = collect_repo_link_targets(resolved_repo) if resolved_repo else None
    fixed_files: list[str] = []
    rewritten_links: list[dict[str, Any]] = []

    if fix:
        for f in unique_files:
            rel_f = (
                str(f.relative_to(resolved_repo)).replace("\\", "/")
                if resolved_repo and f.is_relative_to(resolved_repo)
                else str(f)
            )
            is_wiki = (
                rel_f.startswith("wiki/concepts/")
                or rel_f.startswith("wiki/patterns/")
                or "/wiki/concepts/" in str(f)
                or "/wiki/patterns/" in str(f)
            )
            if not is_wiki:
                continue
            orig_txt = f.read_text(encoding="utf-8", errors="ignore")
            new_txt, convs = rewrite_private_entity_wikilinks(
                orig_txt, vault_root=vault_root, valid_targets=valid_targets
            )
            if new_txt != orig_txt:
                f.write_text(new_txt, encoding="utf-8")
                fixed_files.append(rel_f)
                for c in convs:
                    rewritten_links.append({"file": rel_f, **c})

    dynamic_customers: set[str] = set()
    if vault_root and vault_root.is_dir():
        dynamic_customers = discover_customer_entities(vault_root)

    all_violations: list[dict[str, Any]] = []
    for f in unique_files:
        all_violations.extend(
            scan_markdown_file(
                file_path=f,
                repo_root=resolved_repo,
                valid_targets=valid_targets,
                dynamic_customers=dynamic_customers,
                vault_root=vault_root,
                strict=strict,
            )
        )

    return {
        "ok": len(all_violations) == 0,
        "strict": strict,
        "fix": fix,
        "scanned_files": len(unique_files),
        "fixed_files": fixed_files,
        "rewritten_links": rewritten_links,
        "violation_count": len(all_violations),
        "violations": all_violations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Strict Semantic DLP, Air-Gap & Private Entity Link Scanner/Rewriter for shared OKF pattern repositories."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Files or directories to scan (defaults to ~/shared-okf-patterns).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Enforce zero broken [[wikilinks]] and zero private vault link prefixes.",
    )
    parser.add_argument(
        "--fix",
        "--rewrite-entities",
        dest="fix",
        action="store_true",
        default=False,
        help="Automatically convert private wiki/entities/ & customer wikilinks into clean archetype prose.",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Root of shared patterns repository for wikilink resolution.",
    )
    parser.add_argument(
        "--vault",
        default="~/ObsidianVault",
        help="Optional local ObsidianVault root to load dynamic customer names & archetypes.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON report.")
    args = parser.parse_args()

    default_ce = Path("~/shared-okf-patterns").expanduser()
    if args.targets:
        target_paths = [Path(t) for t in args.targets]
    elif (Path.cwd() / "scripts" / "validate_patterns.py").is_file():
        target_paths = [Path.cwd()]
    else:
        target_paths = [default_ce]

    repo_root = (
        Path(args.repo_root).expanduser().resolve()
        if args.repo_root
        else (
            target_paths[0].expanduser().resolve()
            if len(target_paths) == 1 and target_paths[0].expanduser().is_dir()
            else (default_ce.resolve() if default_ce.is_dir() else None)
        )
    )
    vault_path = Path(args.vault).expanduser()
    vault_root = vault_path.resolve() if vault_path.is_dir() else None

    report = run_sanitize_check(
        targets=target_paths,
        repo_root=repo_root,
        vault_root=vault_root,
        strict=args.strict,
        fix=args.fix,
    )

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        mode_str = "STRICT (DLP + Air-Gap + Link Graph)" if args.strict else "STANDARD (DLP + Air-Gap)"
        print("=" * 72)
        print(f"🛡️  Knowledge Compiler — Sanitize Check [{mode_str}]")
        print("=" * 72)
        print(f"📂 Scanned Markdown Files : {report['scanned_files']}")
        if report["fixed_files"]:
            print(
                f"🔧 Rewrote Entity Links   : {len(report['rewritten_links'])} link(s) across {len(report['fixed_files'])} file(s)"
            )
        print(f"🚨 Total Violations       : {report['violation_count']}")
        if report["violations"]:
            print("-" * 72)
            for v in report["violations"]:
                print(f"  ❌ [{v['category']}] {v['file']}:{v['line']} — {v['message']}")
            print("=" * 72)
        else:
            print("✅ PASSED: Zero DLP leaks, zero customer identifiers, and 100% link integrity!")
            print("=" * 72)

    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
