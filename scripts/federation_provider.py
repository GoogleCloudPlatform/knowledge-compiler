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
"""federation_provider.py - Portable OKF v0.2 Federation Provider Protocol & Export Helpers.

Provides 100% 3P-safe Open Knowledge Format (`OKF v0.2`) normalization, link defanging,
markdown export polish, and the pluggable `FederationProvider` protocol with a built-in
open-source implementation:
  1. `LocalGitPatternProvider`: Queries and shares sanitized architecture patterns across
     a Git-backed team pattern repository (`$OKF_PATTERNS_PATH` or `~/shared-okf-patterns`).
"""

from __future__ import annotations

import getpass
import os
import re
import sys
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from sync_patterns import (  # noqa: E402
    BLOCKED_KEYWORD_PATTERNS,
    DEFAULT_CUSTOMER_ANONYMIZATIONS,
    SecurityException,
    _build_customer_regex,
    build_entity_archetype_map,
    check_content_security,
    collect_egress_customer_names,
    discover_customer_entities,
    load_custom_denylist,
    scan_sha256_entities_in_text,
    share_pattern,
)
from vault_lint import find_vault_root, parse_simple_yaml  # noqa: E402
from vault_query import (  # noqa: E402
    _build_plain_excerpt,
    expand_customer_anonymization_variants,
    extract_note_fields,
    iter_vault_markdown_files,
    normalize_query_for_dlp,
    score_notes_bm25,
    tokenize_for_bm25,
)

DEFAULT_ALLOWLISTED_DOMAINS: tuple[str, ...] = (
    "cloud.google.com",
    "docs.google.com",
    "drive.google.com",
    "developers.google.com",
    "goto.google.com",
    "github.com",
    "arxiv.org",
    "okf.md",
)

# Unified sensitive local filesystem pattern to sanitize
LOCAL_PATH_REGEX = re.compile(
    r"/(?:usr/local/[a-zA-Z0-9._-]+/home|home|Users|users)/[a-zA-Z0-9._-]+(?:/[^\s\"'`)\]>]*)?"
)

CANONICAL_GCP_PRODUCTS: dict[str, str] = {
    "spanner": "Cloud Spanner",
    "alloydb": "AlloyDB for PostgreSQL",
    "cloud sql": "Cloud SQL",
    "bigquery": "BigQuery",
    "cloud run": "Cloud Run",
    "gke": "Google Kubernetes Engine",
    "kubernetes": "Google Kubernetes Engine",
    "vertex ai": "Vertex AI",
    "gemini": "Gemini",
    "adk": "Vertex AI",
    "model armor": "Model Armor",
    "cloud kms": "Cloud KMS",
    "cloud storage": "Cloud Storage",
    "gcs": "Cloud Storage",
    "apigee": "Apigee API Management",
    "cloud workstations": "Cloud Workstations",
    "dms": "Database Migration Service",
    "migration center": "Migration Center",
    "security command center": "Security Command Center",
    "pub/sub": "Cloud Pub/Sub",
    "memorystore": "Memorystore",
}


def detect_canonical_products(text: str) -> list[str]:
    """Extract canonical Google Cloud products mentioned in a pattern note."""
    lower = text.lower()
    found: list[str] = []
    for key, canonical in CANONICAL_GCP_PRODUCTS.items():
        if re.search(r"\b" + re.escape(key) + r"\b", lower) and canonical not in found:
            found.append(canonical)
    return found or ["Google Cloud Platform"]


def resolve_ce_patterns_root(explicit_path: str | Path | None = None) -> Path:
    """Locate the shared OKF patterns repository root."""
    if explicit_path is not None and str(explicit_path).strip():
        return Path(explicit_path).expanduser().resolve()
    for env_key in ("OKF_PATTERNS_PATH",):
        env_p = os.environ.get(env_key, "").strip()
        if env_p:
            return Path(env_p).expanduser().resolve()
    default_p = Path("~/shared-okf-patterns").expanduser().resolve()
    if default_p.exists():
        return default_p
    sibling = SCRIPT_DIR.parent.parent / "shared-okf-patterns"
    if Path.home().resolve() == SCRIPT_DIR.resolve().parent.parent and sibling.exists():
        return sibling.resolve()
    return default_p


resolve_shared_patterns_root = resolve_ce_patterns_root


def list_ce_patterns_catalog(
    ce_patterns_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Return all sanitized concept & pattern notes available in the shared patterns repository."""
    ce_root = resolve_ce_patterns_root(ce_patterns_root)
    if not ce_root.exists():
        return []

    catalog: list[dict[str, Any]] = []
    for folder in ("wiki/concepts", "wiki/patterns"):
        dir_path = ce_root / folder
        if not dir_path.is_dir():
            continue
        for md_file in sorted(dir_path.glob("*.md")):
            content = md_file.read_text(encoding="utf-8", errors="ignore")
            fm: dict[str, Any] = {}
            yaml_text: str | None = None
            body = content
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    yaml_text = parts[1]
                    parsed = parse_simple_yaml(yaml_text)
                    if isinstance(parsed, dict):
                        fm = parsed
                    body = parts[2].strip()
            title = str(fm.get("title") or md_file.stem).strip()
            plain = _build_plain_excerpt(body, max_chars=260)
            rel_path = str(md_file.relative_to(ce_root)).replace("\\", "/")
            raw_tags = fm.get("tags", [])
            tags = (
                [str(t).strip() for t in raw_tags if str(t).strip()]
                if isinstance(raw_tags, list)
                else []
            )
            catalog.append(
                {
                    "id": f"shared-patterns://{rel_path}",
                    "rel_path": rel_path,
                    "full_path": str(md_file),
                    "concept_id": normalize_okf_concept_id(md_file.stem),
                    "label": title,
                    "group": "ce_pattern",
                    "type": "pattern" if folder.endswith("patterns") else "concept",
                    "status": str(fm.get("status") or "stable"),
                    "updated": str(fm.get("updated") or fm.get("created") or ""),
                    "frontmatter": fm,
                    "yaml_text": yaml_text,
                    "tags": tags,
                    "products": detect_canonical_products(content),
                    "excerpt": plain[:260] + ("..." if len(plain) > 260 else ""),
                    "markdown": body[:18000],
                }
            )
    return catalog


def normalize_okf_concept_id(title_or_stem: str) -> str:
    """Normalize a note title or filename stem into a machine-facing OKF v0.2 concept ID (lowercase hyphenated)."""
    cleaned = re.sub(r"\s*\[[^\]]+\]\s*$", "", title_or_stem, flags=re.IGNORECASE)
    cleaned = cleaned.removesuffix(".md").strip().lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", cleaned).strip("-")
    return cleaned or "unnamed-concept"


def defang_non_allowlisted_links(
    markdown_text: str,
    allowlisted_domains: tuple[str, ...] = DEFAULT_ALLOWLISTED_DOMAINS,
) -> tuple[str, list[str]]:
    """Allow only trusted https:// domains; defang insecure http:// and unknown external links into inline code."""
    defanged_notes: list[str] = []

    def _check_url(match: re.Match[str]) -> str:
        label = match.group(1)
        url = match.group(2).strip()
        if url.startswith("http://"):
            defanged_notes.append(f"Defanged insecure http:// link: {url}")
            return f"{label} (`{url}`)"
        if url.startswith("https://"):
            domain_match = re.match(r"https://([^/:\s]+)", url)
            domain = domain_match.group(1).lower() if domain_match else ""
            if any(
                domain == d or domain.endswith("." + d) for d in allowlisted_domains
            ):
                return match.group(0)
            defanged_notes.append(f"Defanged non-allowlisted external domain: {domain}")
            return f"{label} (`{url}`)"
        return match.group(0)

    updated = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", _check_url, markdown_text)

    def _check_bare_url(match: re.Match[str]) -> str:
        prefix = match.group(1)
        url = match.group(2).rstrip(".,;:")
        trailing = match.group(2)[len(url) :]
        if url.startswith("http://"):
            defanged_notes.append(f"Defanged insecure bare http:// URL: {url}")
            return f"{prefix}`{url}`{trailing}"
        domain_match = re.match(r"https://([^/:\s]+)", url)
        domain = domain_match.group(1).lower() if domain_match else ""
        if any(domain == d or domain.endswith("." + d) for d in allowlisted_domains):
            return match.group(0)
        defanged_notes.append(f"Defanged non-allowlisted bare URL domain: {domain}")
        return f"{prefix}`{url}`{trailing}"

    updated = re.sub(r"(^|[\s(])(https?://[^\s)`]+)", _check_bare_url, updated)
    return updated, defanged_notes


def polish_markdown_for_okf_export(markdown_body: str) -> tuple[str, list[str]]:
    """Polish markdown for standalone OKF bundle export without modifying files on disk.

    1. Strips trailing vault cross-reference sections (`## Related Notes...`) and their preceding `---` divider.
    2. Unwraps inline Obsidian `[[Target|Alias]]` and `[[Target]]` wikilinks outside fenced code blocks into standalone prose.
    """
    polish_notes: list[str] = []
    polished = markdown_body

    footer_pattern = re.compile(
        r"(?:\n+---\s*)?\n+##+\s+(?:[🔗🧭📚]\s*)?Related Notes[^\n]*\n[\s\S]*$",
        flags=re.IGNORECASE,
    )
    if footer_pattern.search(polished):
        polished = footer_pattern.sub("", polished).rstrip()
        polish_notes.append(
            "Stripped trailing 'Related Notes / Vault Assets' section for standalone OKF export"
        )

    wikilink_count = 0

    def _unwrap_wikilinks_in_segment(segment: str) -> str:
        nonlocal wikilink_count

        def _repl_aliased(m: re.Match[str]) -> str:
            nonlocal wikilink_count
            wikilink_count += 1
            return m.group(2).strip()

        def _repl_plain(m: re.Match[str]) -> str:
            nonlocal wikilink_count
            wikilink_count += 1
            raw_target = m.group(1).strip()
            clean_target = raw_target.split("/")[-1].removesuffix(".md").strip()
            return clean_target

        seg = re.sub(
            r"\[\[([^\[\]|\n]{1,512})\\?\|([^\[\]\n]{1,512})\]\]",
            _repl_aliased,
            segment,
        )
        seg = re.sub(r"\[\[([^\[\]\n]{1,512})\]\]", _repl_plain, seg)
        return seg

    parts = re.split(r"(```[\s\S]*?```)", polished)
    for idx in range(0, len(parts), 2):
        parts[idx] = _unwrap_wikilinks_in_segment(parts[idx])
    polished = "".join(parts).strip()

    if wikilink_count > 0:
        polish_notes.append(
            f"Unwrapped {wikilink_count} internal [[wikilink]] reference(s) into standalone prose"
        )

    return polished, polish_notes


polish_markdown_for_remote_tier = polish_markdown_for_okf_export


def resolve_caller_ldap() -> str:
    """Resolve the active username/handle for OKF provenance attribution."""
    for env_key in ("USER", "LOGNAME", "USERNAME"):
        val = (os.environ.get(env_key) or "").strip()
        if val and val not in ("root", "nobody", "cloud-ce"):
            return val.split("@")[0].strip().lower()
    try:
        user = getpass.getuser().strip()
        if user and user not in ("root", "nobody", "cloud-ce"):
            return user.split("@")[0].strip().lower()
    except Exception:
        pass
    return "cloud-ce"


def sanitize_query_for_federation(
    query: str,
    obsidian_vault_root: Path | None = None,
) -> dict[str, Any]:
    """Scrub customer names, local paths, and private keywords from an outbound federated search query."""
    cleaned = normalize_query_for_dlp(query).strip()
    redactions: list[str] = []

    anonymizations = dict(DEFAULT_CUSTOMER_ANONYMIZATIONS)
    if obsidian_vault_root and obsidian_vault_root.exists():
        anonymizations.update(load_custom_denylist(obsidian_vault_root))
        entity_map, _ = build_entity_archetype_map(obsidian_vault_root)
        for cust_name, archetype in entity_map.items():
            if cust_name not in anonymizations:
                anonymizations[cust_name] = archetype
        for cust in discover_customer_entities(obsidian_vault_root):
            if cust not in anonymizations:
                anonymizations[cust] = "Enterprise Customer"
        for cust in collect_egress_customer_names(obsidian_vault_root):
            if cust not in anonymizations:
                anonymizations[cust] = "Enterprise Customer"
    anonymizations = expand_customer_anonymization_variants(anonymizations)

    fallback_industry = ""
    for cust_name in sorted(anonymizations.keys(), key=len, reverse=True):
        if len(cust_name) < 2:
            continue
        pattern = _build_customer_regex(cust_name)
        if pattern.search(cleaned):
            replacement = anonymizations[cust_name]
            if not fallback_industry:
                fallback_industry = replacement
            cleaned = pattern.sub("", cleaned)
            redactions.append(
                f"Redacted customer '{cust_name}' (stripped from outbound federated query)"
            )

    sha_hits = scan_sha256_entities_in_text(cleaned)
    for start_off, end_off, span_txt, arch in reversed(sha_hits):
        if not fallback_industry:
            fallback_industry = arch
        cleaned = (cleaned[:start_off] + " " + cleaned[end_off:]).strip()
        redactions.append(
            f"Redacted customer '{span_txt}' (stripped from outbound federated query)"
        )

    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned and fallback_industry:
        cleaned = fallback_industry

    if LOCAL_PATH_REGEX.search(cleaned):
        cleaned = LOCAL_PATH_REGEX.sub("", cleaned).strip()
        redactions.append("Scrubbed local workstation path")

    violations = check_content_security(cleaned)
    if violations:
        for pat in BLOCKED_KEYWORD_PATTERNS:
            cleaned = re.sub(pat, "", cleaned, flags=re.IGNORECASE).strip()
        redactions.extend(violations)

    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return {
        "original_query": query,
        "sanitized_query": cleaned,
        "dlp_triggered": len(redactions) > 0,
        "dlp_modified": len(redactions) > 0,
        "redactions": redactions,
    }


def _search_markdown_dir(
    root_dir: Path,
    subdirs: tuple[str, ...],
    query: str,
    plane_label: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Rank markdown notes in `root_dir` matching `query` tokens using Okapi BM25."""
    if not root_dir.exists():
        return []
    tokens = tokenize_for_bm25(query)
    results: list[dict[str, Any]] = []

    if tokens:
        bm25_hits = score_notes_bm25(
            root_dir,
            query,
            subdirs=subdirs,
            include_raw=False,
            limit=limit,
        )
        for hit in bm25_hits:
            results.append(
                {
                    "id": hit["id"],
                    "title": hit["title"],
                    "plane": plane_label,
                    "score": float(hit["score"]),
                    "excerpt": str(hit.get("excerpt") or "")[:240],
                    "tags": (
                        hit.get("tags", [])
                        if isinstance(hit.get("tags"), list)
                        else []
                    ),
                }
            )
        return results

    for full_path, rel_id, _is_raw in iter_vault_markdown_files(
        root_dir, subdirs=subdirs, include_raw=False
    ):
        fields = extract_note_fields(full_path, rel_id)
        if fields is None:
            continue
        plain = _build_plain_excerpt(str(fields["body"]), max_chars=240)
        results.append(
            {
                "id": rel_id,
                "title": str(fields["title"]),
                "plane": plane_label,
                "score": 1.0,
                "excerpt": plain[:240],
                "tags": (
                    fields.get("tags", [])
                    if isinstance(fields.get("tags"), list)
                    else []
                ),
            }
        )
        if len(results) >= limit:
            break

    return results[:limit]


@runtime_checkable
class FederationProvider(Protocol):
    """Pluggable protocol for querying and exporting sanitized OKF v0.2 knowledge planes."""

    provider_id: str
    display_name: str

    def query(self, query_text: str, *, limit: int = 10) -> list[dict[str, Any]]:
        """Query the federated plane for matching OKF v0.2 concepts or patterns."""
        ...

    def export_pattern(
        self, note_path: Path, output_dir: Path | None = None
    ) -> dict[str, Any]:
        """Validate, sanitize, and export a single OKF v0.2 pattern note."""
        ...


def verify_ce_patterns_isolation(
    note_path: Path,
    ce_patterns_root: Path | None = None,
    obsidian_vault_root: Path | None = None,
) -> tuple[Path, Path]:
    """Verify `note_path` resides inside the shared patterns repository (`wiki/concepts` or `wiki/patterns`) and NOT inside a personal `ObsidianVault`."""
    resolved = note_path.expanduser().resolve()
    ce_root = resolve_ce_patterns_root(ce_patterns_root)
    obs_root = (
        obsidian_vault_root.expanduser().resolve()
        if obsidian_vault_root
        else find_vault_root(Path.cwd())
    )

    if obs_root.exists() and (resolved == obs_root or obs_root in resolved.parents):
        raise SecurityException(
            f"Hard Air-Gap Violation: '{resolved}' is inside personal ObsidianVault ('{obs_root}'). "
            "Promote patterns via `/vault-share` to the shared patterns repository first."
        )

    if resolved != ce_root and ce_root not in resolved.parents:
        raise SecurityException(
            f"Source Isolation Violation: '{resolved}' is outside shared patterns repository ('{ce_root}')."
        )

    rel = resolved.relative_to(ce_root)
    if len(rel.parts) < 2 or rel.parts[0] != "wiki" or rel.parts[1] not in ("concepts", "patterns"):
        raise SecurityException(
            f"Directory Boundary Violation: '{rel}' must reside under 'wiki/concepts/' or 'wiki/patterns/'."
        )
    return resolved, ce_root


class LocalGitPatternProvider:
    """3P FederationProvider backed by a shared Git repository of sanitized OKF v0.2 patterns."""

    provider_id = "local_git_patterns"
    display_name = "Shared Git Pattern Repository"

    def __init__(
        self,
        patterns_root: str | Path | None = None,
        vault_root: str | Path | None = None,
    ) -> None:
        self.patterns_root = resolve_ce_patterns_root(patterns_root)
        self.vault_root = (
            Path(vault_root).expanduser().resolve()
            if vault_root
            else find_vault_root(Path.cwd())
        )

    def query(self, query_text: str, *, limit: int = 10) -> list[dict[str, Any]]:
        dlp = sanitize_query_for_federation(query_text, self.vault_root)
        if dlp["dlp_triggered"] and not dlp["sanitized_query"]:
            return []
        q = dlp["sanitized_query"] if dlp["dlp_triggered"] else query_text
        return _search_markdown_dir(
            self.patterns_root,
            ("wiki/concepts", "wiki/patterns"),
            q,
            plane_label="shared-patterns",
            limit=limit,
        )

    def export_pattern(
        self, note_path: Path, output_dir: Path | None = None
    ) -> dict[str, Any]:
        target_repo = output_dir.expanduser().resolve() if output_dir else self.patterns_root
        return share_pattern(
            pattern_file=note_path,
            target_repo_path=target_repo,
            vault_root=self.vault_root,
            dry_run=False,
        )


def run_portable_federated_query(
    query: str,
    obsidian_vault_root: Path | None = None,
    ce_patterns_root: Path | None = None,
    limit: int = 8,
    include_local_vault: bool = True,
    include_ce_patterns: bool = True,
    ace_enabled: bool = False,
    limit_per_source: int | None = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Execute a 2-plane portable federated search across the local vault and shared patterns repo."""
    del ace_enabled
    effective_limit = (
        int(limit_per_source) if limit_per_source is not None else int(limit)
    )
    v_root = (
        obsidian_vault_root.expanduser().resolve()
        if obsidian_vault_root
        else find_vault_root(Path.cwd())
    )
    p_root = resolve_ce_patterns_root(ce_patterns_root)
    dlp_info = sanitize_query_for_federation(query, obsidian_vault_root=v_root)

    local_hits: list[dict[str, Any]] = []
    if include_local_vault:
        local_hits = _search_markdown_dir(
            v_root,
            (
                "wiki/concepts",
                "wiki/patterns",
                "wiki/entities",
                "wiki/synthesis",
                "wiki/sources",
            ),
            query,
            plane_label="local-vault",
            limit=effective_limit,
        )

    shared_hits: list[dict[str, Any]] = []
    if include_ce_patterns:
        sanitized_q = dlp_info["sanitized_query"]
        if not (dlp_info["dlp_triggered"] and not sanitized_q):
            shared_hits = _search_markdown_dir(
                p_root,
                ("wiki/concepts", "wiki/patterns"),
                sanitized_q if dlp_info["dlp_triggered"] else query,
                plane_label="shared-patterns",
                limit=effective_limit,
            )

    local_ui_results: list[dict[str, Any]] = [
        {
            "id": h["id"],
            "label": h["title"],
            "title": h["title"],
            "plane": h["plane"],
            "source_plane": "local_vault",
            "source_badge": "🔒 Local Vault (Air-Gapped)",
            "can_promote_to_ace": False,
            "score": float(h["score"]),
            "excerpt": h["excerpt"],
            "tags": h.get("tags", []),
        }
        for h in local_hits
    ]
    shared_ui_results: list[dict[str, Any]] = [
        {
            "id": (
                h["id"]
                if str(h["id"]).startswith("shared-patterns://")
                else f"shared-patterns://{h['id']}"
            ),
            "rel_path": h["id"],
            "concept_id": normalize_okf_concept_id(Path(str(h["id"])).stem),
            "label": h["title"],
            "title": h["title"],
            "plane": h["plane"],
            "source_plane": "ce_patterns",
            "source_badge": "🛡️ Shared Patterns (Sanitized)",
            "can_promote_to_ace": False,
            "score": float(h["score"]),
            "excerpt": h["excerpt"],
            "tags": h.get("tags", []),
        }
        for h in shared_hits
    ]
    combined: list[dict[str, Any]] = local_ui_results + shared_ui_results
    combined.sort(key=lambda r: float(r.get("score", 0.0)), reverse=True)

    return {
        "query": query,
        "sanitized_query": dlp_info["sanitized_query"],
        "dlp": dlp_info,
        "dlp_guard": dlp_info,
        "remote_tier_enabled": False,
        "total_results": len(combined),
        "results": combined,
        "planes": {
            "obsidian_vault": {
                "path": str(v_root),
                "count": len(local_hits),
                "results": local_hits,
            },
            "local_vault": {
                "path": str(v_root),
                "count": len(local_hits),
                "results": local_ui_results,
            },
            "ce_patterns": {
                "path": str(p_root),
                "count": len(shared_hits),
                "results": shared_hits,
            },
        },
    }
