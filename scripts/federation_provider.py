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
    check_content_security,
    discover_customer_entities,
    load_custom_denylist,
    scan_sha256_entities_in_text,
    share_pattern,
)
from vault_lint import find_vault_root, parse_simple_yaml  # noqa: E402

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
    if explicit_path:
        p = Path(explicit_path).expanduser().resolve()
        if p.exists():
            return p
    for env_key in ("OKF_PATTERNS_PATH",):
        env_p = os.environ.get(env_key)
        if env_p:
            p = Path(env_p).expanduser().resolve()
            if p.exists():
                return p
    default_p = Path("~/shared-okf-patterns").expanduser().resolve()
    if default_p.exists():
        return default_p
    sibling = SCRIPT_DIR.parent.parent / "shared-okf-patterns"
    if sibling.exists():
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
            body = content
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    parsed = parse_simple_yaml(parts[1])
                    if isinstance(parsed, dict):
                        fm = parsed
                    body = parts[2].strip()
            title = str(fm.get("title") or md_file.stem).strip()
            plain = re.sub(r"```.*?```", "", body, flags=re.DOTALL)
            plain = re.sub(r"^#+\s+.*$", "", plain, flags=re.MULTILINE)
            plain = re.sub(r"\[\[([^\]|]+)\|([^\]]+)\]\]", r"\2", plain)
            plain = re.sub(r"\[\[([^\]]+)\]\]", r"\1", plain)
            plain = re.sub(r"[*_`>|#-]", " ", plain)
            plain = re.sub(r"\s+", " ", plain).strip()
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

        seg = re.sub(r"\[\[([^\]|\n]+)\\?\|([^\]\n]+)\]\]", _repl_aliased, segment)
        seg = re.sub(r"\[\[([^\]\n]+)\]\]", _repl_plain, seg)
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


polish_markdown_for_ace_brain = polish_markdown_for_okf_export


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
    cleaned = query.strip()
    redactions: list[str] = []

    anonymizations = dict(DEFAULT_CUSTOMER_ANONYMIZATIONS)
    if obsidian_vault_root and obsidian_vault_root.exists():
        anonymizations.update(load_custom_denylist(obsidian_vault_root))
        for cust in discover_customer_entities(obsidian_vault_root):
            if cust not in anonymizations:
                anonymizations[cust] = "Enterprise Customer"

    fallback_industry = ""
    for cust_name in sorted(anonymizations.keys(), key=len, reverse=True):
        if len(cust_name) < 3:
            continue
        pattern = re.compile(r"\b" + re.escape(cust_name) + r"\b", re.IGNORECASE)
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

    path_pat = re.compile(r"/(?:usr/local/google/home|home|Users)/[a-zA-Z0-9._/-]+")
    if path_pat.search(cleaned):
        cleaned = path_pat.sub("", cleaned).strip()
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
    """Rank markdown notes in `root_dir` matching `query` tokens."""
    if not root_dir.exists():
        return []
    tokens = [t.lower() for t in re.split(r"[^a-zA-Z0-9]+", query) if len(t) >= 2]
    results: list[dict[str, Any]] = []

    for sub in subdirs:
        target = root_dir / sub
        if not target.is_dir():
            continue
        for md_file in sorted(target.rglob("*.md")):
            raw = md_file.read_text(encoding="utf-8", errors="ignore")
            fm: dict[str, Any] = {}
            body = raw
            if raw.startswith("---"):
                parts = raw.split("---", 2)
                if len(parts) >= 3:
                    parsed = parse_simple_yaml(parts[1])
                    if isinstance(parsed, dict):
                        fm = parsed
                    body = parts[2].strip()
            title = str(fm.get("title") or md_file.stem).strip()
            haystack = f"{title} {md_file.stem} {raw}".lower()
            if not tokens:
                score = 1.0
            else:
                matched = sum(1 for tok in tokens if tok in haystack)
                title_hits = sum(2 for tok in tokens if tok in title.lower())
                if matched == 0:
                    continue
                score = round((matched + title_hits) / (len(tokens) * 3), 3)

            plain = re.sub(r"```[\s\S]*?```", "", body)
            plain = re.sub(r"^#+\s+.*$", "", plain, flags=re.MULTILINE)
            plain = re.sub(r"\s+", " ", plain).strip()
            rel_id = str(md_file.relative_to(root_dir)).replace("\\", "/")
            results.append(
                {
                    "id": rel_id,
                    "title": title,
                    "plane": plane_label,
                    "score": score,
                    "excerpt": plain[:240],
                    "tags": fm.get("tags", []) if isinstance(fm.get("tags"), list) else [],
                }
            )

    results.sort(key=lambda r: float(r.get("score", 0.0)), reverse=True)
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
        q = dlp["sanitized_query"] or query_text
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
            note_path=note_path,
            shared_repo_root=target_repo,
            vault_root=self.vault_root,
            dry_run=False,
        )


def run_portable_federated_query(
    query: str,
    obsidian_vault_root: Path | None = None,
    ce_patterns_root: Path | None = None,
    limit: int = 8,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Execute a 2-plane portable federated search across the local vault and shared patterns repo."""
    v_root = (
        obsidian_vault_root.expanduser().resolve()
        if obsidian_vault_root
        else find_vault_root(Path.cwd())
    )
    p_root = resolve_ce_patterns_root(ce_patterns_root)
    dlp_info = sanitize_query_for_federation(query, obsidian_vault_root=v_root)

    local_hits = _search_markdown_dir(
        v_root,
        ("wiki/concepts", "wiki/patterns", "wiki/entities", "wiki/synthesis", "wiki/sources"),
        query,
        plane_label="local-vault",
        limit=limit,
    )
    shared_hits = _search_markdown_dir(
        p_root,
        ("wiki/concepts", "wiki/patterns"),
        dlp_info["sanitized_query"] or query,
        plane_label="shared-patterns",
        limit=limit,
    )
    return {
        "query": query,
        "sanitized_query": dlp_info["sanitized_query"],
        "dlp": dlp_info,
        "planes": {
            "obsidian_vault": {
                "path": str(v_root),
                "count": len(local_hits),
                "results": local_hits,
            },
            "ce_patterns": {
                "path": str(p_root),
                "count": len(shared_hits),
                "results": shared_hits,
            },
        },
    }
