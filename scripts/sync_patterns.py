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
Federated Pattern Exchange & Sanitization Engine for OKF v0.2 Knowledge Compilers.

Safely shares reusable cloud architecture concepts and engineering invariants across
engineering teams via a shared repository (e.g. shared-okf-patterns), while strictly air-gapping
and scrubbing private personal notes, performance evaluations, customer dossiers,
and raw materials.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None


def get_plugin_data_dir() -> Path:
    """Return the per-user writable runtime data directory (outside immutable plugin source)."""
    for env_key in ("PLUGIN_DATA", "ANTIGRAVITY_EXECUTABLE_DATA_DIR", "KC_DATA_DIR"):
        val = (os.environ.get(env_key) or "").strip()
        if val:
            p = Path(val).expanduser().resolve()
            try:
                p.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            return p
    default_dir = Path("~/.local/share/knowledge-compiler").expanduser().resolve()
    try:
        default_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(default_dir, 0o700)
    except Exception:
        pass
    return default_dir

# Private and personal indicators that MUST NEVER be shared
BLOCKED_PATH_PATTERNS = [
    r"/raw(/|$)",
    r"/raw/assets(/|$)",
    r"/wiki/entities/.*",  # Customer and personal entity dossiers
    r"/wiki/synthesis/.*resume.*",
    r"/wiki/synthesis/.*1-?1.*",
    r"/wiki/synthesis/.*comp.*",
    r"/wiki/synthesis/.*perf.*",
]

BLOCKED_KEYWORD_PATTERNS = [
    r"\bPerformance & Business Impact\b",
    r"\bperformance rating\b",
    r"\bpromo packet\b",
    r"\bbase salary\b",
    r"\b(?:total|base|executive|employee|annual|target)\s+compensation\b",
    r"\bpeer bonus\b",
    r"\bdiscretionary bonus\b",
]

# Sensitive local filesystem patterns to sanitize
LOCAL_PATH_REGEX = re.compile(
    r"/(?:usr/local/[a-zA-Z0-9._-]+/home|home|Users|users)/[a-zA-Z0-9._-]+(?:/[^\s\"'`)\]>]*)?"
)

_INVISIBLE_CHARS_RE = re.compile(
    r"[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\U000e0000-\U000e007f]"
)
_HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")


def normalize_shadow_view(text: str) -> str:
    """Normalize text (NFKC) and strip zero-width, bidi, tag characters, and HTML comments for DLP/secret detection."""
    norm = unicodedata.normalize("NFKC", text)
    no_comments = _HTML_COMMENT_RE.sub("", norm)
    return _INVISIBLE_CHARS_RE.sub("", no_comments)


# Known public technology, framework, and cloud service entities (never customer accounts)
PUBLIC_TECH_ENTITIES: Set[str] = {
    "index",
    "log",
    "purpose",
    "GEMINI",
    "Open Knowledge Format (OKF)",
    "Knowledge Compiler",
    "Knowledge Compiler Plugin",
    "LLM Wiki (Nashsu)",
    "Model Armor & Semantic Governance",
    "Andrej Karpathy",
    "Antigravity 2.0",
    "Cloud Run",
    "Google Kubernetes Engine (GKE)",
    "AlloyDB for PostgreSQL",
    "Discovery Engine",
    "Security Command Center",
    "Wiz",
    "Mandiant",
    "Deloitte",
    "Accenture",
    "Onix",
    "Pythian",
    "SADA",
    "LanceDB",
    "Tauri",
    "React",
    "Obsidian",
    "Memex",
    "WikiSkill",
    "CodeMender",
    "Gemini CLI Environment & Customizations",
    "AWS to GCP Migration TCO Extractor",
    "Migration Center Utils",
}

# Default generic synthetic customer archetypes (zero real customer names stored in plaintext)
DEFAULT_CUSTOMER_ANONYMIZATIONS: Dict[str, str] = {
    "AcmeCorp": "Enterprise Commercial Account",
    "Northwind": "Global Retail & Supply Chain Enterprise",
    "Contoso": "Multinational Financial Services Institution",
    "Fabrikam": "Industrial Manufacturing Conglomerate",
}

# Optional SHA-256 hex digest prefixes (first 24 chars) loaded dynamically when
# the optional 1P DLP hash module is present; falls back to empty dict in 3P OSS.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

try:
    import okf  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    from . import okf  # type: ignore[import-not-found]

_DEFAULT_PATTERNS_ENV_KEYS: Tuple[str, ...] = ("OKF_PATTERNS_PATH",)
_DEFAULT_PATTERNS_DIR_NAMES: Tuple[str, ...] = ("shared-okf-patterns",)
_DEFAULT_PATTERNS_CACHE_SUBDIRS: Tuple[str, ...] = ()
_DEFAULT_PATTERNS_REPO_URL: str = ""
_DEFAULT_PATTERNS_FALLBACK_HINT: str = (
    "Pass --repo-dir <local-clone> or --repo-url <git-url> "
    "(or set OKF_PATTERNS_PATH / OKF_PATTERNS_REPO_URL)."
)

HAS_1P_DLP_HASHES = False
CUSTOMER_SHA256_ARCHETYPES: Dict[str, str] = {}
_INTERNAL_1P_FORBIDDEN_REFS: list[str] = []

_SHA256_TOKEN_RE = re.compile(r"[A-Za-zÀ-ÿ0-9.&/]+")


def lookup_sha256_archetype(
    candidate: str, sha_map: Optional[Dict[str, str]] = None
) -> Optional[str]:
    """Lookup candidate entity phrase against SHA-256 digest prefix map."""
    smap = sha_map if sha_map is not None else CUSTOMER_SHA256_ARCHETYPES
    clean = " ".join(candidate.strip().split())
    if not clean:
        return None
    exact_key = "exact:" + hashlib.sha256(clean.encode("utf-8")).hexdigest()[:24]
    if exact_key in smap:
        return smap[exact_key]
    if len(clean) > 3:
        lower_key = hashlib.sha256(clean.lower().encode("utf-8")).hexdigest()[:24]
        if lower_key in smap:
            return smap[lower_key]
    return None


def scan_sha256_entities_in_text(
    text: str,
    sha_map: Optional[Dict[str, str]] = None,
    max_words: int = 6,
) -> List[Tuple[int, int, str, str]]:
    """Slide a 1-to-max_words token window over `text` and match phrases against `sha_map`."""
    smap = sha_map if sha_map is not None else CUSTOMER_SHA256_ARCHETYPES
    tokens = [(m.start(), m.end(), m.group(0)) for m in _SHA256_TOKEN_RE.finditer(text)]
    n_tok = len(tokens)
    consumed = [False] * n_tok
    hits: List[Tuple[int, int, str, str]] = []
    for i in range(n_tok):
        if consumed[i]:
            continue
        for w in range(min(max_words, n_tok - i), 0, -1):
            if any(consumed[i + k] for k in range(w)):
                continue
            start_off = tokens[i][0]
            end_off = tokens[i + w - 1][1]
            span_txt = text[start_off:end_off]
            if "\n" in span_txt:
                continue
            inter = [text[tokens[i + k][1] : tokens[i + k + 1][0]] for k in range(w - 1)]
            if any(not re.fullmatch(r"[ \t/-]+", sep) for sep in inter):
                continue
            arch = lookup_sha256_archetype(span_txt, smap)
            if arch:
                for k in range(w):
                    consumed[i + k] = True
                hits.append((start_off, end_off, span_txt, arch))
                break
    return hits


def load_custom_denylist(vault_root: Optional[Path] = None) -> Dict[str, str]:
    """Load optional per-vault or per-user customer archetype rules from `denylist.json`."""
    merged: Dict[str, str] = {}
    candidates: List[Path] = [get_plugin_data_dir() / "denylist.json"]
    if vault_root and vault_root.is_dir():
        candidates.append(vault_root / ".knowledge-compiler" / "denylist.json")
        candidates.append(vault_root / "denylist.json")
    for path in candidates:
        if path.is_file():
            try:
                raw_text = path.read_text(encoding="utf-8")
                # Handle possible trailing commas before JSON parsing
                cleaned_text = re.sub(r",\s*([\]}])", r"\1", raw_text)
                data = json.loads(cleaned_text)
                if isinstance(data, dict):
                    ca = data.get("customer_archetypes")
                    if isinstance(ca, dict):
                        for k, v in ca.items():
                            if k:
                                merged[str(k)] = str(v) if v else "Enterprise Account"
                    for list_key in ("denylist", "blocked_customers", "customers", "blocked"):
                        sub_list = data.get(list_key)
                        if isinstance(sub_list, list):
                            for item in sub_list:
                                if item and isinstance(item, (str, int)):
                                    merged[str(item)] = "Enterprise Account"
                elif isinstance(data, list):
                    for item in data:
                        if item and isinstance(item, (str, int)):
                            merged[str(item)] = "Enterprise Account"
            except Exception as exc:
                raise ValueError(f"Failed to parse denylist file '{path}': {exc}") from exc
    return merged

EPISTEMIC_FRONTMATTER_KEYS = (
    "x-kc-corroborates",
    "x-kc-complements",
    "x-kc-extends",
    "x-kc-contradicts",
    "x-kc-supersedes",
    "corroborates",
    "complements",
    "extends",
    "contradicts",
    "supersedes",
)


class SecurityException(Exception):
    """Raised when an operation attempts to share private, personal, or raw data."""

    pass


def find_vault_root(start_path: Optional[Path] = None) -> Path:
    """Locate vault root by finding GEMINI.md or wiki/ folder."""
    curr = (start_path or Path.cwd()).resolve()
    while curr != curr.parent:
        if (curr / "GEMINI.md").exists() or (curr / "wiki").exists():
            return curr
        curr = curr.parent
    return (start_path or Path.cwd()).resolve()


def _format_industry_archetype(raw_industry: str) -> str:
    """Convert a table industry cell or frontmatter `industry/<slug>` tag into clean archetype prose."""
    cleaned = raw_industry.strip().strip("\"'")
    if not cleaned:
        return "Enterprise Commercial Account"
    if "/" in cleaned and " " not in cleaned:
        slug = cleaned.split("/", 1)[1].replace("-", " ").replace("_", " ").strip()
        cleaned = slug.title()
    return f"Enterprise {cleaned} Organization"


def _split_markdown_table_row(line: str) -> List[str]:
    """Split a Markdown table row on `|` delimiters while preserving unescaped pipes inside `[[Target|Alias]]`."""
    return [c.strip() for c in re.split(r"\|(?![^\[]*\]\])", line)]


def build_entity_archetype_map(
    vault_root: Optional[Path] = None,
    custom_anonymizations: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, str], Set[str]]:
    """Build a comprehensive `(private_entity_archetypes, public_tech_entities)` map.

    Inspects `DEFAULT_CUSTOMER_ANONYMIZATIONS`, optional per-vault `denylist.json`,
    `tables/customers.md` (Customer + Industry columns), and `wiki/entities/*.md`
    YAML frontmatter (`tags`, `title`, `aliases`) so private customer/PE entity wikilinks
    (`[[wiki/entities/<Customer>]]` or `[[<Customer>]]`) deterministically convert into
    clean industry archetype prose.
    """
    archetypes: Dict[str, str] = dict(DEFAULT_CUSTOMER_ANONYMIZATIONS)
    if vault_root and vault_root.is_dir():
        archetypes.update(load_custom_denylist(vault_root))
    if custom_anonymizations:
        archetypes.update(custom_anonymizations)
    public_entities: Set[str] = set(PUBLIC_TECH_ENTITIES)

    if not vault_root or not vault_root.is_dir():
        return archetypes, public_entities

    # 1. Parse tables/customers.md (Column 1: Customer Account, Column 2: Industry)
    cust_table = vault_root / "tables" / "customers.md"
    if cust_table.exists():
        content = cust_table.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            stripped = line.strip()
            if (
                stripped.startswith("|")
                and not stripped.startswith("| :---")
                and not stripped.startswith("| Customer Account")
            ):
                cols = _split_markdown_table_row(stripped)
                if len(cols) > 2:
                    first_col = cols[1]
                    industry_col = cols[2] if len(cols) > 2 else ""
                    derived = _format_industry_archetype(industry_col)
                    for match in re.finditer(
                        r"\[\[([^\]|]+)(?:\|([^\]]+))?\]\]", first_col
                    ):
                        target = (
                            match.group(1)
                            .strip()
                            .removeprefix("wiki/entities/")
                            .removeprefix("entities/")
                            .removesuffix(".md")
                        )
                        alias = match.group(2).strip() if match.group(2) else None
                        if target and target not in public_entities:
                            sha_arch = lookup_sha256_archetype(target)
                            archetypes.setdefault(target, sha_arch or derived)
                        if alias and alias not in public_entities:
                            sha_alias = lookup_sha256_archetype(alias)
                            archetypes.setdefault(
                                alias, sha_alias or archetypes.get(target, derived)
                            )

    # 2. Inspect wiki/entities/*.md dossiers
    entities_dir = vault_root / "wiki" / "entities"
    if entities_dir.exists():
        for file in sorted(entities_dir.glob("*.md")):
            stem = file.stem
            try:
                text = file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            _fm_raw, fm_opt, _body = okf.split_frontmatter(text)
            fm_block = fm_opt or ""

            if stem in public_entities:
                m_title = re.search(r"(?m)^title:\s*['\"]?([^'\"\n]+)['\"]?", fm_block)
                if m_title:
                    public_entities.add(m_title.group(1).strip())
                continue

            is_customer = bool(
                re.search(r"(?m)^\s*-\s*(?:entity/)?customer\b", fm_block)
            )
            is_pe = bool(re.search(r"(?m)^\s*-\s*private-equity\b", fm_block))
            m_ind = re.search(
                r"(?m)^\s*-\s*industry/([a-zA-Z0-9_-]+)", fm_block
            )

            sha_stem = lookup_sha256_archetype(stem)
            if stem in archetypes:
                resolved_arch = archetypes[stem]
            elif sha_stem:
                resolved_arch = sha_stem
            elif is_pe:
                resolved_arch = "Private Equity Sponsor"
            elif m_ind:
                resolved_arch = _format_industry_archetype(f"industry/{m_ind.group(1)}")
            elif is_customer:
                resolved_arch = "Enterprise Commercial Account"
            else:
                # Non-public private dossier inside wiki/entities/ (e.g. internal team/partner note)
                resolved_arch = "Enterprise Organization"

            archetypes.setdefault(stem, resolved_arch)
            m_title = re.search(r"(?m)^title:\s*['\"]?([^'\"\n]+)['\"]?", fm_block)
            if m_title:
                t_val = m_title.group(1).strip()
                if t_val and t_val not in public_entities:
                    archetypes.setdefault(t_val, resolved_arch)

            # Extract aliases list if present (supporting scalar, list, and inline flow list)
            for al in _extract_aliases_from_frontmatter(fm_block):
                if al and al not in public_entities:
                    archetypes.setdefault(al, resolved_arch)

    return archetypes, public_entities


_HEX_KEY_ESCAPE_RE = re.compile(
    r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})"
)


def _extract_aliases_from_frontmatter(fm_text: str) -> list[str]:
    """Extract all alias strings from YAML frontmatter supporting scalar, list, and inline flow list."""
    use_yaml = yaml is not None and sys.modules.get("yaml") is not None
    out: list[str] = list(
        okf.extract_string_list(fm_text, "aliases", use_pyyaml=use_yaml)
    )
    seen: set[str] = set(out)
    has_hex_esc = "\\" in fm_text and bool(_HEX_KEY_ESCAPE_RE.search(fm_text))
    checked_variants: set[str] = set()
    for key_variant, pat in (
        ("Aliases", "Aliases"),
        ("ALIASES", "ALIASES"),
        ("alias", "alias:"),
        ("alias", "alias "),
        ("alias", 'alias"'),
        ("alias", "alias'"),
        ("Alias", "Alias:"),
        ("Alias", "Alias "),
        ("Alias", 'Alias"'),
        ("Alias", "Alias'"),
        ("ALIAS", "ALIAS"),
    ):
        if key_variant in checked_variants:
            continue
        if not has_hex_esc and pat not in fm_text:
            continue
        checked_variants.add(key_variant)
        for val in okf.extract_string_list(
            fm_text, key_variant, use_pyyaml=use_yaml
        ):
            if val not in seen:
                seen.add(val)
                out.append(val)
    return out


def discover_customer_entities(vault_root: Path) -> Set[str]:
    """Dynamically extract customer names and aliases from vault tables and entities."""
    customers: Set[str] = set()

    # 1. Inspect tables/customers.md (Target specifically Column 1: Customer Account)
    cust_table = vault_root / "tables" / "customers.md"
    if cust_table.exists():
        content = cust_table.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if (
                line.startswith("|")
                and not line.startswith("| :---")
                and not line.startswith("| Customer Account")
            ):
                cols = _split_markdown_table_row(line)
                if len(cols) > 1:
                    first_col = cols[1]
                    for match in re.finditer(
                        r"\[\[([^\]|]+)(?:\|([^\]]+))?\]\]", first_col
                    ):
                        target = (
                            match.group(1)
                            .strip()
                            .removeprefix("wiki/entities/")
                            .removeprefix("entities/")
                            .removesuffix(".md")
                        )
                        alias = match.group(2).strip() if match.group(2) else None
                        if target not in PUBLIC_TECH_ENTITIES:
                            customers.add(target)
                        if alias and alias not in PUBLIC_TECH_ENTITIES:
                            customers.add(alias)

    # 2. Inspect wiki/entities/ for customer or private-equity tags
    entities_dir = vault_root / "wiki" / "entities"
    if entities_dir.exists():
        for file in entities_dir.glob("*.md"):
            if file.stem in PUBLIC_TECH_ENTITIES:
                continue
            try:
                text = file.read_text(encoding="utf-8", errors="ignore")
                if re.search(
                    r"tags:\s*\n(?:\s*-\s*.*\n)*\s*-\s*(?:entity/)?(?:customer|private-equity)\b",
                    text,
                ):
                    customers.add(file.stem)
            except Exception:
                continue

    # 3. denylist.json
    denylist_map = load_custom_denylist(vault_root)
    customers.update(denylist_map.keys())

    return customers


def is_path_blocked(rel_path: str) -> Tuple[bool, str]:
    """Check if a relative path violates isolation boundaries."""
    norm = "/" + rel_path.lstrip("/")
    for pat in BLOCKED_PATH_PATTERNS:
        if re.search(pat, norm, re.IGNORECASE):
            return True, f"Path matched blocked pattern: {pat}"
    return False, ""


def check_content_security(content: str) -> List[str]:
    """Check content for sensitive personal, performance, or financial tokens."""
    violations = []
    for pat in BLOCKED_KEYWORD_PATTERNS:
        matches = re.findall(pat, content, re.IGNORECASE)
        if matches:
            violations.append(
                f"Contains blocked sensitive keyword: '{matches[0]}' (pattern: {pat})"
            )
    return violations


def _lookup_archetype(
    candidate: str, archetypes: Dict[str, str], lower_map: Dict[str, str]
) -> Optional[str]:
    """Lookup candidate name in archetype dictionary or SHA-256 prefix map."""
    clean = candidate.strip()
    if not clean:
        return None
    if clean in archetypes:
        return archetypes[clean]
    if len(clean) > 3 and clean.lower() in lower_map:
        return lower_map[clean.lower()]
    return lookup_sha256_archetype(clean)


def _collect_shared_targets(repo_root: Optional[Path]) -> Optional[Set[str]]:
    """Collect valid wikilink stems/paths in a target shared patterns repository."""
    if not repo_root or not repo_root.is_dir():
        return None
    valid: Set[str] = set()
    for md in repo_root.glob("wiki/**/*.md"):
        rel = str(md.relative_to(repo_root)).replace("\\", "/")
        valid.add(rel)
        valid.add(rel.removesuffix(".md"))
        valid.add(md.name)
        valid.add(md.stem)
    for root_doc in ("index.md", "GEMINI.md", "README.md", "log.md"):
        if (repo_root / root_doc).is_file():
            valid.add(root_doc)
            valid.add(root_doc.removesuffix(".md"))
    return valid


def _anonymize_free_text(text: str, archetypes: Dict[str, str]) -> str:
    """Replace any known customer/PE entity names inside free text (e.g. unwrapped synthesis titles)."""
    out = text
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
    # Also replace any SHA-256 matched customer/engagement phrases in reverse offset order
    sha_hits = scan_sha256_entities_in_text(out)
    for start_off, end_off, _span, arch in reversed(sha_hits):
        out = out[:start_off] + arch + out[end_off:]
    return out


_PRIVATE_FM_ITEM_FRAGMENTS = (
    "raw/",
    "wiki/entities/",
    "entities/",
    "wiki/sources/",
    "wiki/synthesis/",
    "wiki/skill-impact",
    "/home/",
    "/users/",
    "/usr/local/google/home/",
    "/workspace/obsidianvault/raw/",
)


def is_private_frontmatter_item_block(
    item_lines: List[str],
    *,
    archetypes: Dict[str, str],
    lower_archetypes: Dict[str, str],
    vault_root: Optional[Path] = None,
    valid_targets: Optional[Set[str]] = None,
) -> bool:
    """Return True if a single-line or multi-line YAML sequence item references private vault paths or entities."""
    block_text = "\n".join(item_lines)
    decoded_block = urllib.parse.unquote(block_text)
    low = decoded_block.lower()
    if any(frag in low for frag in _PRIVATE_FM_ITEM_FRAGMENTS):
        return True
    if LOCAL_PATH_REGEX.search(decoded_block):
        return True

    def _is_private_target_ref(raw_ref: str) -> bool:
        ref_raw = urllib.parse.unquote(raw_ref).strip().lstrip("/")
        ref_low = ref_raw.lower()
        if ref_low.startswith(
            (
                "raw/",
                "wiki/entities/",
                "entities/",
                "wiki/sources/",
                "sources/",
                "wiki/synthesis/",
                "synthesis/",
                "wiki/skill-impact",
            )
        ):
            return True
        ref_stem = ref_raw.removesuffix(".md").split("/")[-1].strip()
        if _lookup_archetype(ref_stem, archetypes, lower_archetypes):
            return True
        if vault_root and (
            (vault_root / "wiki" / "entities" / f"{ref_stem}.md").is_file()
            or (vault_root / "wiki" / "synthesis" / f"{ref_stem}.md").is_file()
            or (vault_root / "wiki" / "sources" / f"{ref_stem}.md").is_file()
        ):
            return True
        if (
            valid_targets is not None
            and ref_stem not in valid_targets
            and ref_raw.removesuffix(".md") not in valid_targets
        ):
            return True
        return False

    for wl_m in re.finditer(r"\[\[([^\]|#]+)(?:[|#][^\]]*)?\]\]", block_text):
        if _is_private_target_ref(wl_m.group(1)):
            return True

    for md_m in re.finditer(r"(?<!!)\[[^\]\n]+\]\(([^)\s]+)\)", block_text):
        href = md_m.group(1).strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", href) and href.split("#", 1)[0].lower().endswith(".md"):
            if _is_private_target_ref(href.split("#", 1)[0]):
                return True

    for path_m in re.finditer(r"['\"]?(/wiki/[^'\"\n]+\.md)['\"]?", decoded_block, re.IGNORECASE):
        if _is_private_target_ref(path_m.group(1)):
            return True

    dehyphen_block = re.sub(r"[-_/]+", " ", decoded_block)
    for variant in (decoded_block, dehyphen_block):
        if scan_sha256_entities_in_text(variant):
            return True
        for cust_name in archetypes:
            if len(cust_name) <= 3:
                if cust_name in _MERMAID_DIRECTIONS:
                    continue
                if re.search(r"(?<!\w)" + re.escape(cust_name) + r"(?!\w)", variant):
                    return True
            else:
                if re.search(
                    r"(?<!\w)" + re.escape(cust_name) + r"(?!\w)",
                    variant,
                    re.IGNORECASE,
                ):
                    return True
    return False


def _scrub_fm_identity_in_item_line(line: str) -> Tuple[str, List[str]]:
    """Scrub personal human/agent identities inside a kept frontmatter list item line."""
    notes: List[str] = []
    out = line

    def _rep_human_q(m: re.Match) -> str:
        handle = m.group(3).strip()
        if handle in ("cloud-ce", "ce-name", "author"):
            return m.group(0)
        notes.append("Sanitized human identity in frontmatter item to 'human:cloud-ce'")
        return f"{m.group(1)}{m.group(2)}human:cloud-ce{m.group(2)}"

    out = re.sub(
        r'(\b(?:by|author|authors|owner|owners|created_by|maintainer|reviewed_by|contributor|contributors):\s*)(["\'])human:([^"\'\n]+)\2',
        _rep_human_q,
        out,
    )

    def _rep_human_unq(m: re.Match) -> str:
        handle = m.group(2).strip()
        if handle in ("cloud-ce", "ce-name", "author"):
            return m.group(0)
        notes.append("Sanitized human identity in frontmatter item to 'human:cloud-ce'")
        return f"{m.group(1)}human:cloud-ce"

    out = re.sub(
        r'(\b(?:by|author|authors|owner|owners|created_by|maintainer|reviewed_by|contributor|contributors):\s*)human:([^\s"\'}\],#]+)',
        _rep_human_unq,
        out,
    )

    def _rep_agent_q(m: re.Match) -> str:
        handle = m.group(3).strip()
        if handle == "knowledge-compiler":
            return m.group(0)
        notes.append("Sanitized agent identity in frontmatter item to 'agent:knowledge-compiler'")
        return f"{m.group(1)}{m.group(2)}agent:knowledge-compiler{m.group(2)}"

    out = re.sub(r'(\bby:\s*)(["\'])agent:([^"\'\n]+)\2', _rep_agent_q, out)

    def _rep_agent_unq(m: re.Match) -> str:
        handle = m.group(2).strip()
        if handle == "knowledge-compiler":
            return m.group(0)
        notes.append("Sanitized agent identity in frontmatter item to 'agent:knowledge-compiler'")
        return f"{m.group(1)}agent:knowledge-compiler"

    out = re.sub(r'(\bby:\s*)agent:([^\s"\'}\],#]+)', _rep_agent_unq, out)

    m_flow_id = re.match(
        r'^(\s*(?:-\s*)?(?:author|authors|owner|owners|created_by|maintainer|reviewed_by|contributor|contributors):\s*)\[(.*)\](\s*(?:#.*)?)$',
        out,
    )
    if m_flow_id:
        inner = m_flow_id.group(2).strip()
        if inner:
            raw_items = [it.strip() for it in okf._split_flow_items(inner) if it.strip()]
            new_items = ['"human:cloud-ce"' for _ in raw_items]
            rebuilt = f"{m_flow_id.group(1)}[{', '.join(new_items)}]{m_flow_id.group(3)}"
            if rebuilt != out:
                notes.append("Sanitized inline identity list in frontmatter item to 'human:cloud-ce'")
                out = rebuilt
        return out, notes

    m_scalar_id = re.match(
        r'^(\s*(?:-\s*)?(?:author|authors|owner|owners|created_by|maintainer|reviewed_by|contributor|contributors):\s*)(["\']?)([^"\'{\[\n#][^"\'\n]*?)(["\']?)(\s*(?:#.*)?)$',
        out,
    )
    if m_scalar_id:
        val = m_scalar_id.group(3).strip()
        if (
            val
            and not val.startswith("-")
            and val not in ("human:cloud-ce", "human:ce-name", "human:author")
        ):
            q = m_scalar_id.group(2) or m_scalar_id.group(4) or ""
            q_end = m_scalar_id.group(4) or m_scalar_id.group(2) or q
            rebuilt = f"{m_scalar_id.group(1)}{q}human:cloud-ce{q_end}{m_scalar_id.group(5)}"
            if rebuilt != out:
                notes.append("Sanitized identity in frontmatter item to 'human:cloud-ce'")
                out = rebuilt
            return out, notes

    def _rep_inline_id(m: re.Match) -> str:
        val = (m.group(3) or m.group(4) or "").strip()
        if (
            not val
            or val in ("human:cloud-ce", "human:ce-name", "human:author")
            or val.startswith(("[", "{"))
        ):
            return m.group(0)
        q = m.group(2) or ""
        notes.append("Sanitized inline mapping identity in frontmatter item to 'human:cloud-ce'")
        return f"{m.group(1)}{q}human:cloud-ce{q}"

    out = re.sub(
        r'(\b(?:author|owner|created_by|maintainer|reviewed_by):\s*)(?:(["\'])([^"\'\n]+)\2|([^,\}\]\s]+))',
        _rep_inline_id,
        out,
    )
    return out, notes


def sanitize_markdown(
    content: str,
    vault_root: Optional[Path] = None,
    custom_anonymizations: Optional[Dict[str, str]] = None,
    valid_shared_targets: Optional[Set[str]] = None,
) -> Tuple[str, List[str]]:
    """Sanitize markdown content for shared pattern repository publishing.

    1. Automatically detects private `wiki/entities/<Target>` (and bare `[[<Customer>]]`) wikilinks
       and converts them into clean enterprise archetype prose while preserving code blocks/spans.
    2. Unwraps private `wiki/sources/` and `wiki/synthesis/` wikilinks and unresolved public tech
       entity links so zero broken or private vault links enter the shared repository.
    3. Prunes private vault entries (including multi-line `{id, resource}` blocks and flow lists)
       from YAML frontmatter `sources:` and 5-way epistemic lists before local path rewriting.
    4. Scrubs local filesystem paths (`/usr/local/google/home/...`, `/home/...`, `/Users/...`).
    """
    scrub_notes: List[str] = []
    if _HTML_COMMENT_RE.search(content):
        scrub_notes.append("Stripped HTML comments")
    content = _HTML_COMMENT_RE.sub("", content)

    if _INVISIBLE_CHARS_RE.search(content):
        scrub_notes.append("Stripped invisible bidi/tag control characters")
    content = _INVISIBLE_CHARS_RE.sub("", content)

    archetypes, public_entities = build_entity_archetype_map(
        vault_root=vault_root, custom_anonymizations=custom_anonymizations
    )
    lower_archetypes = {k.lower(): v for k, v in archetypes.items() if len(k) > 3}
    lower_public = {p.lower(): p for p in public_entities}

    # 1. Scrub frontmatter `sources:`, 5-way epistemic lists, and personal identities FIRST
    #    (before LOCAL_PATH_REGEX rewrites `/home/...` so local source entries are pruned cleanly)
    def _sanitize_frontmatter_lines(fm_lines: List[str]) -> List[str]:
        out_lines: List[str] = []
        active_list_key: Optional[str] = None
        list_key_indent: int = 0
        item_dash_indent: Optional[int] = None
        buffered_list_header: Optional[str] = None
        buffered_list_items: List[str] = []
        current_item_lines: Optional[List[str]] = None
        had_dropped: bool = False
        active_id_list_key: Optional[str] = None
        active_flow_id_list: bool = False

        list_key_set = ("sources", *EPISTEMIC_FRONTMATTER_KEYS)
        list_key_re = re.compile(
            r"^(" + "|".join(re.escape(k) for k in list_key_set) + r"):(.*)$"
        )

        def _flush_current_item() -> None:
            nonlocal current_item_lines, had_dropped
            if not current_item_lines:
                current_item_lines = None
                return
            if is_private_frontmatter_item_block(
                current_item_lines,
                archetypes=archetypes,
                lower_archetypes=lower_archetypes,
                vault_root=vault_root,
                valid_targets=valid_shared_targets,
            ):
                had_dropped = True
                scrub_notes.append(
                    f"Scrubbed private vault reference from frontmatter '{active_list_key}': {current_item_lines[0].strip()}"
                )
            else:
                for iline in current_item_lines:
                    cleaned_iline, line_notes = _scrub_fm_identity_in_item_line(iline)
                    scrub_notes.extend(line_notes)
                    buffered_list_items.append(cleaned_iline)
            current_item_lines = None

        def _flush_list() -> None:
            nonlocal active_list_key, list_key_indent, item_dash_indent
            nonlocal buffered_list_header, buffered_list_items, had_dropped
            _flush_current_item()
            if active_list_key is None or buffered_list_header is None:
                return
            if active_list_key == "sources":
                if buffered_list_items:
                    out_lines.append(buffered_list_header)
                    out_lines.extend(buffered_list_items)
                elif had_dropped:
                    out_lines.append("sources: []")
                else:
                    out_lines.append(buffered_list_header)
            else:
                if buffered_list_items:
                    out_lines.append(buffered_list_header)
                    out_lines.extend(buffered_list_items)
            active_list_key = None
            list_key_indent = 0
            item_dash_indent = None
            buffered_list_header = None
            buffered_list_items = []
            had_dropped = False

        idx = 0
        n_fm = len(fm_lines)
        while idx < n_fm:
            line = fm_lines[idx]
            stripped_l = line.strip()
            line_indent = len(line) - len(line.lstrip(" "))

            if active_list_key is not None:
                if not stripped_l:
                    peek_idx = idx + 1
                    while peek_idx < n_fm and not fm_lines[peek_idx].strip():
                        peek_idx += 1
                    if (
                        peek_idx < n_fm
                        and current_item_lines is not None
                        and item_dash_indent is not None
                    ):
                        p_line = fm_lines[peek_idx]
                        p_indent = len(p_line) - len(p_line.lstrip(" "))
                        p_dash = bool(re.match(r"^[ \t]*-(?:\s+.*|\s*)$", p_line))
                        if p_indent > item_dash_indent or (
                            p_dash and p_indent == item_dash_indent
                        ):
                            if p_indent > item_dash_indent and not p_dash:
                                current_item_lines.append(line)
                            idx += 1
                            continue
                    _flush_list()
                    out_lines.append(line)
                    idx += 1
                    continue

                if stripped_l.startswith("#"):
                    if (
                        current_item_lines is not None
                        and item_dash_indent is not None
                        and line_indent > item_dash_indent
                    ):
                        current_item_lines.append(line)
                    elif item_dash_indent is None or line_indent >= item_dash_indent:
                        _flush_current_item()
                        buffered_list_items.append(line)
                    else:
                        _flush_list()
                        out_lines.append(line)
                    idx += 1
                    continue

                m_dash = re.match(r"^[ \t]*-(?:\s+(.*)|\s*)$", line)
                if m_dash and line_indent >= list_key_indent:
                    if item_dash_indent is None:
                        item_dash_indent = line_indent
                        current_item_lines = [line]
                        idx += 1
                        continue
                    if line_indent == item_dash_indent:
                        _flush_current_item()
                        current_item_lines = [line]
                        idx += 1
                        continue
                    if line_indent > item_dash_indent and current_item_lines is not None:
                        current_item_lines.append(line)
                        idx += 1
                        continue

                if (
                    current_item_lines is not None
                    and item_dash_indent is not None
                    and line_indent > item_dash_indent
                ):
                    current_item_lines.append(line)
                    idx += 1
                    continue

                _flush_list()

            m_lk = list_key_re.match(line)
            if m_lk:
                _flush_list()
                active_id_list_key = None
                active_flow_id_list = False
                k_name = m_lk.group(1)
                raw_rest = m_lk.group(2)
                val_clean = okf._strip_inline_comment(raw_rest).strip()
                if not val_clean:
                    active_list_key = k_name
                    list_key_indent = 0
                    item_dash_indent = None
                    buffered_list_header = line
                    buffered_list_items = []
                    current_item_lines = None
                    had_dropped = False
                    idx += 1
                    continue
                if val_clean.startswith("["):
                    flow_str, next_idx = okf._accumulate_multiline_flow(
                        fm_lines, raw_rest.lstrip(), idx + 1, strict=False
                    )
                    flow_clean = okf._strip_inline_comment(flow_str).strip()
                    if flow_clean.startswith("[") and flow_clean.endswith("]"):
                        inner = flow_clean[1:-1].strip()
                        if not inner:
                            out_lines.extend(fm_lines[idx:next_idx])
                            idx = next_idx
                            continue
                        raw_items = okf._split_flow_items(inner)
                        kept_items: List[str] = []
                        flow_dropped = False
                        flow_identity_changed = False
                        for item in raw_items:
                            if is_private_frontmatter_item_block(
                                [item],
                                archetypes=archetypes,
                                lower_archetypes=lower_archetypes,
                                vault_root=vault_root,
                                valid_targets=valid_shared_targets,
                            ):
                                flow_dropped = True
                                scrub_notes.append(
                                    f"Scrubbed private vault reference from frontmatter '{k_name}': {item.strip()}"
                                )
                            else:
                                cleaned_item, inotes = _scrub_fm_identity_in_item_line(item)
                                if cleaned_item != item:
                                    flow_identity_changed = True
                                    scrub_notes.extend(inotes)
                                kept_items.append(cleaned_item)
                        if flow_dropped or flow_identity_changed:
                            if kept_items:
                                out_lines.append(f"{k_name}: [{', '.join(kept_items)}]")
                            elif k_name == "sources":
                                out_lines.append("sources: []")
                        else:
                            out_lines.extend(fm_lines[idx:next_idx])
                        idx = next_idx
                        continue
                if is_private_frontmatter_item_block(
                    [val_clean],
                    archetypes=archetypes,
                    lower_archetypes=lower_archetypes,
                    vault_root=vault_root,
                    valid_targets=valid_shared_targets,
                ):
                    scrub_notes.append(
                        f"Scrubbed private vault reference from frontmatter '{k_name}': {val_clean}"
                    )
                    if k_name == "sources":
                        out_lines.append("sources: []")
                    idx += 1
                    continue

            # Multi-line or inline identity flow list e.g. authors: [jdoe, Jane Doe] or authors: [
            if re.search(
                r"^\s*(?:author|authors|owner|owners|created_by|maintainer|reviewed_by|contributor|contributors):\s*\[",
                line,
            ):
                if "]" in line:
                    m_lead = re.match(
                        r"(^\s*(?:author|authors|owner|owners|created_by|maintainer|reviewed_by|contributor|contributors):\s*)\[(.*)\]",
                        line,
                    )
                    if m_lead:
                        prefix = m_lead.group(1)
                        inner = m_lead.group(2).strip()
                        if inner:
                            items = [item.strip() for item in inner.split(",") if item.strip()]
                            new_items = ['"human:cloud-ce"' for _ in items]
                            subbed_line = f"{prefix}[{', '.join(new_items)}]"
                        else:
                            subbed_line = f"{prefix}[]"
                        out_lines.append(subbed_line)
                        scrub_notes.append(
                            "Sanitized inline identity list in frontmatter to 'human:cloud-ce'"
                        )
                        active_id_list_key = None
                        active_flow_id_list = False
                        idx += 1
                        continue
                else:
                    active_flow_id_list = True
                    out_lines.append(line)
                    idx += 1
                    continue

            if active_flow_id_list:
                if "]" in line:
                    active_flow_id_list = False
                subbed_line = re.sub(
                    r'([^,\[\]\s"\']+(?:\s+[^,\[\]\s"\']+)*)',
                    r"human:cloud-ce",
                    line,
                )
                out_lines.append(subbed_line)
                scrub_notes.append(
                    "Sanitized multi-line flow identity item in frontmatter to 'human:cloud-ce'"
                )
                idx += 1
                continue

            matched_id_key = None
            for ik in (
                "author",
                "authors",
                "owner",
                "owners",
                "created_by",
                "maintainer",
                "reviewed_by",
                "contributor",
                "contributors",
            ):
                if stripped_l == f"{ik}:":
                    matched_id_key = ik
                    break
            if matched_id_key:
                _flush_list()
                active_id_list_key = matched_id_key
                out_lines.append(line)
                idx += 1
                continue

            if active_id_list_key is not None:
                if stripped_l.startswith("- ") or stripped_l == "-":
                    subbed_item = re.sub(
                        r'(-\s*)(["\']?)[^"\'\n]+(["\']?)',
                        r"\1\2human:cloud-ce\3",
                        line,
                    )
                    out_lines.append(subbed_item)
                    scrub_notes.append(
                        f"Sanitized identity in frontmatter list '{active_id_list_key}' to 'human:cloud-ce'"
                    )
                    idx += 1
                    continue
                if re.search(r'^\s+name:\s*["\']?[^"\'{\[\s][^"\'\n]*', line):
                    subbed_line = re.sub(
                        r'(^\s*name:\s*)(["\']?)[^"\'\n]+(["\']?)',
                        r"\1\2Google Cloud CE\3",
                        line,
                    )
                    out_lines.append(subbed_line)
                    scrub_notes.append(
                        "Sanitized name under author/contributor in frontmatter to 'Google Cloud CE'"
                    )
                    idx += 1
                    continue
                if not line.startswith((" ", "\t")) and ":" in stripped_l:
                    active_id_list_key = None

            # Sanitize author/owner/by names in frontmatter verified/generated/author
            if re.search(
                r'\b(?:by|author|authors|owner|owners|created_by|maintainer|reviewed_by):\s*["\']?human:[^"\']+',
                line,
            ):
                subbed_line = re.sub(
                    r'(\b(?:by|author|authors|owner|owners|created_by|maintainer|reviewed_by):\s*)(["\']?)human:[^"\'}\],]+(["\']?)',
                    r"\1\2human:cloud-ce\3",
                    line,
                )
                out_lines.append(subbed_line)
                if subbed_line != line:
                    scrub_notes.append(
                        "Sanitized human identity in frontmatter to 'human:cloud-ce'"
                    )
                idx += 1
                continue
            if re.search(
                r'^\s*(?:author|authors|owner|owners|created_by|maintainer|reviewed_by|contributor|contributors):\s*["\']?[^"\'{\[\s\-][^"\'\n]*',
                line,
            ):
                subbed_line = re.sub(
                    r'(^\s*(?:author|authors|owner|owners|created_by|maintainer|reviewed_by|contributor|contributors):\s*)(["\']?)[^"\'\n]+(["\']?)',
                    r"\1\2human:cloud-ce\3",
                    line,
                )
                out_lines.append(subbed_line)
                if subbed_line != line:
                    scrub_notes.append(
                        "Sanitized identity in frontmatter to 'human:cloud-ce'"
                    )
                idx += 1
                continue
            if re.search(r'\bby:\s*["\']?agent:[^"\'}\],]+', line):
                subbed_line = re.sub(
                    r'(\bby:\s*)(["\']?)agent:[^"\'}\],]+(["\']?)',
                    r"\1\2agent:knowledge-compiler\3",
                    line,
                )
                out_lines.append(subbed_line)
                if subbed_line != line:
                    scrub_notes.append(
                        "Sanitized agent identity in frontmatter to 'agent:knowledge-compiler'"
                    )
                idx += 1
                continue

            out_lines.append(line)
            idx += 1

        _flush_list()
        return out_lines

    _fm_raw, fm_opt, body_after = okf.split_frontmatter(content)
    if fm_opt is not None:
        cleaned_fm_lines = _sanitize_frontmatter_lines(fm_opt.splitlines())
        if cleaned_fm_lines:
            fm_prefix = "---\n" + "\n".join(cleaned_fm_lines) + "\n---\n"
        else:
            fm_prefix = "---\n---\n"
        body_text = body_after
    else:
        fm_prefix = ""
        body_text = content.lstrip("\ufeff")

    # 2. Protect fenced code blocks and inline code spans in body_text during wikilink rewriting
    protected_tokens: List[str] = []

    def _stash_code(m: re.Match) -> str:
        idx = len(protected_tokens)
        protected_tokens.append(m.group(0))
        return f"\x00CODE_TOKEN_{idx}\x00"

    masked_body = re.sub(r"```[\s\S]*?```|`[^`\n]+`", _stash_code, body_text)
    # Normalize escaped pipes inside wikilinks (`[[Target\|Alias]]` -> `[[Target|Alias]]`)
    masked_body = re.sub(
        r"\[\[([^\]\n]+?)\\+\|([^\]\n]+?)\]\]", r"[[\1|\2]]", masked_body
    )

    def replace_wikilink(match: re.Match) -> str:
        raw_target = match.group(1).strip().strip("\"'")
        raw_alias = match.group(2).strip().strip("\"'") if match.group(2) else None
        norm_target = raw_target.lstrip("/")
        norm_lower = norm_target.lower()
        target_no_anchor = norm_target.split("#", 1)[0].removesuffix(".md").strip()
        stem = target_no_anchor.split("/")[-1].strip()

        # Case A: Explicit private `wiki/entities/<X>` or `entities/<X>` link
        if norm_lower.startswith(("wiki/entities/", "entities/")):
            arch = _lookup_archetype(stem, archetypes, lower_archetypes)
            if not arch and raw_alias:
                arch = _lookup_archetype(raw_alias, archetypes, lower_archetypes)
            if arch:
                scrub_notes.append(
                    f"Converted private entity wikilink [[{raw_target}]] -> '{arch}'"
                )
                return arch
            if stem.lower() in lower_public:
                if valid_shared_targets and stem in valid_shared_targets:
                    rewritten = f"[[{stem}|{raw_alias}]]" if raw_alias else f"[[{stem}]]"
                    scrub_notes.append(
                        f"Normalized public entity wikilink [[{raw_target}]] -> '{rewritten}'"
                    )
                    return rewritten
                prose = raw_alias or lower_public[stem.lower()]
                scrub_notes.append(
                    f"Unwrapped public entity wikilink [[{raw_target}]] -> '{prose}'"
                )
                return prose
            # Fail-closed default for unmapped private wiki/entities/<X> links: never leak <X>
            fallback_arch = "Enterprise Commercial Account"
            scrub_notes.append(
                f"Converted unmapped private entity wikilink [[{raw_target}]] -> '{fallback_arch}'"
            )
            return fallback_arch

        # Case B: Explicit private vault `raw/`, `wiki/sources/`, `wiki/synthesis/`, `wiki/skill-impact`
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
            display = _anonymize_free_text(raw_alias or stem, archetypes)
            scrub_notes.append(
                f"Unwrapped private vault wikilink [[{raw_target}]] -> '{display}'"
            )
            return display

        # Case C: Bare customer / PE / private entity wikilink `[[AcmeCorp]]` or `[[Northwind|NW]]`
        arch = _lookup_archetype(stem, archetypes, lower_archetypes)
        if not arch:
            arch = _lookup_archetype(target_no_anchor, archetypes, lower_archetypes)
        if not arch and raw_alias:
            arch = _lookup_archetype(raw_alias, archetypes, lower_archetypes)
        if arch:
            label = f"[[{raw_target}|{raw_alias}]]" if raw_alias else f"[[{raw_target}]]"
            scrub_notes.append(
                f"De-identified customer wikilink: {label} -> '{arch}'"
            )
            return arch

        # Case D: Bare synthesis link in vault (`vault_root/wiki/synthesis/<stem>.md`)
        if vault_root and (vault_root / "wiki" / "synthesis" / f"{stem}.md").is_file():
            display = _anonymize_free_text(raw_alias or stem, archetypes)
            scrub_notes.append(
                f"Unwrapped private synthesis wikilink [[{raw_target}]] -> '{display}'"
            )
            return display

        # Case E: Bare public tech entity link (`[[Cloud Run]]`) that is absent from shared repo
        if (
            valid_shared_targets is not None
            and stem.lower() in lower_public
            and stem not in valid_shared_targets
            and norm_target not in valid_shared_targets
        ):
            prose = raw_alias or stem
            scrub_notes.append(
                f"Unwrapped unresolved tech entity wikilink [[{raw_target}]] -> '{prose}'"
            )
            return prose

        return match.group(0)

    rewritten_body = re.sub(
        r"\[\[([^\]|\n]+)(?:\|([^\]\n]+))?\]\]", replace_wikilink, masked_body
    )

    for idx, tok in enumerate(protected_tokens):
        rewritten_body = rewritten_body.replace(f"\x00CODE_TOKEN_{idx}\x00", tok)

    sanitized = fm_prefix + rewritten_body

    # 3. Scrub remaining local absolute filesystem paths (`/usr/local/*/home/...`, `/home/...`, `/Users/...`)
    def replace_local_path(match: re.Match) -> str:
        path_str = match.group(0)
        if path_str.startswith("/usr/local/"):
            parts = path_str.split("/")
            # ['', 'usr', 'local', '<org>', 'home', '<user>', ...]
            sanitized_path = (
                "/workspace/" + "/".join(parts[6:]) if len(parts) > 6 else "/workspace"
            )
            scrub_notes.append(
                f"Sanitized workstation path: {path_str} -> {sanitized_path}"
            )
            return sanitized_path
        if path_str.startswith("/home/") or path_str.startswith("/Users/"):
            parts = path_str.split("/")
            if len(parts) >= 3:
                sanitized_path = (
                    "/workspace/" + "/".join(parts[3:])
                    if len(parts) > 3
                    else "/workspace"
                )
                scrub_notes.append(
                    f"Sanitized local path: {path_str} -> {sanitized_path}"
                )
                return sanitized_path
        return path_str

    sanitized = LOCAL_PATH_REGEX.sub(replace_local_path, sanitized)
    if sanitized and not sanitized.endswith("\n"):
        sanitized += "\n"
    return sanitized, scrub_notes


def audit_vault(vault_root: Path) -> Dict[str, List[Dict]]:
    """
    Audits concepts and patterns in the vault to report which are clean/ready-to-share,
    which require sanitization, and which are blocked.
    """
    results: Dict[str, List[Dict]] = {
        "clean": [],
        "scrub_needed": [],
        "blocked": [],
    }

    scannable_dirs = [
        vault_root / "wiki" / "concepts",
        vault_root / "wiki" / "patterns",
    ]
    discovered_customers = discover_customer_entities(vault_root)

    for s_dir in scannable_dirs:
        if not s_dir.exists():
            continue
        for file in sorted(s_dir.glob("*.md")):
            rel_path = str(file.relative_to(vault_root))
            blocked, reason = is_path_blocked(rel_path)
            if blocked:
                results["blocked"].append({"file": rel_path, "reason": reason})
                continue

            content = file.read_text(encoding="utf-8", errors="ignore")
            violations = check_content_security(content)
            if violations:
                results["blocked"].append(
                    {"file": rel_path, "reason": "; ".join(violations)}
                )
                continue

            # Check if customer mentions, private wiki/entities/ wikilinks, or local paths exist
            customer_matches = []
            for cust in discovered_customers | set(
                DEFAULT_CUSTOMER_ANONYMIZATIONS.keys()
            ):
                if re.search(r"\b" + re.escape(cust) + r"\b", content):
                    customer_matches.append(cust)
            for _s, _e, span_txt, _arch in scan_sha256_entities_in_text(content):
                customer_matches.append(span_txt)

            entity_links = re.findall(
                r"\[\[(?:wiki/)?entities/([^\]|#\n]+)", content, re.IGNORECASE
            )
            local_paths = LOCAL_PATH_REGEX.findall(content)

            if customer_matches or entity_links or local_paths:
                reasons = []
                if customer_matches:
                    reasons.append(
                        f"Customer references: {', '.join(sorted(set(customer_matches)))}"
                    )
                if entity_links:
                    reasons.append(
                        f"Private wiki/entities/ wikilinks: {', '.join(sorted(set(entity_links)))}"
                    )
                if local_paths:
                    reasons.append(
                        f"Local file paths detected ({len(local_paths)} occurrences)"
                    )
                results["scrub_needed"].append(
                    {
                        "file": rel_path,
                        "reasons": reasons,
                        "title": file.stem,
                    }
                )
            else:
                results["clean"].append(
                    {
                        "file": rel_path,
                        "title": file.stem,
                    }
                )

    return results


# Secret / credential patterns for mandatory fail-closed egress check
_EGRESS_SECRET_PATTERNS = [
    (re.compile(r"AIza[0-9A-Za-z_-]{20,}"), "Google API Key"),
    (re.compile(r"ya29\.[0-9A-Za-z_-]+"), "Google OAuth Token"),
    (re.compile(r"(?:gh[pousr]_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,})"), "GitHub Token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "Private Key Header"),
]

# Internal reference and infrastructure patterns for mandatory fail-closed egress check
_EGRESS_INTERNAL_REF_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"gs://[a-z0-9._-]+"), "GCS Bucket URI"),
    (re.compile(r"\bb/\d{6,}\b"), "Internal Bug Reference"),
    (re.compile(r"\bcl/\d{6,}\b"), "Internal Changelist Reference"),
    (re.compile(r"(?<![/.\w])go/(?!no-go\b)[a-z0-9_-]+\b"), "Internal Go Link"),
]
_UNBUCKETED_CURRENCY_RE = re.compile(r"\$(?:\d{1,3}(?:,\d{3})+|\d{4,})\.\d{2}\b")

# Email regex (synthetic @example.com and @example.org stay allowed)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")

# Direction keywords used in Mermaid diagrams that must not be flagged when matching 2-letter customer acronyms
_MERMAID_DIRECTIONS = frozenset({"TB", "TD", "BT", "LR", "RL"})


def _build_customer_regex(cust: str) -> re.Pattern:
    """Build a robust regex for a customer or entity name handling wraps, multi-spaces, and non-word endings."""
    parts = cust.split()
    if not parts:
        return re.compile(r"$^")
    escaped_parts = [re.escape(p) for p in parts]
    pattern_body = r"\s+".join(escaped_parts)
    pattern = r"(?<!\w)" + pattern_body + r"(?!\w)"
    flags = 0 if len(cust) <= 3 else re.IGNORECASE
    return re.compile(pattern, flags)


def collect_egress_customer_names(vault_root: Optional[Path] = None) -> Set[str]:
    """Collect customer and private entity names from tables/customers.md, wiki/entities/, and denylist.json."""
    customers: Set[str] = set()
    customers.update(DEFAULT_CUSTOMER_ANONYMIZATIONS.keys())

    if vault_root and vault_root.is_dir():
        # 1. tables/customers.md (supports both wikilinks and plain-text table rows)
        cust_table = vault_root / "tables" / "customers.md"
        if cust_table.is_file():
            try:
                content = cust_table.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if (
                        line.startswith("|")
                        and not line.startswith("| :---")
                        and not line.startswith("| Customer Account")
                    ):
                        cols = _split_markdown_table_row(line)
                        if len(cols) > 1:
                            first_col = cols[1].strip()
                            wikilinks = list(
                                re.finditer(r"\[\[([^\]|]+)(?:\|([^\]]+))?\]\]", first_col)
                            )
                            if wikilinks:
                                for match in wikilinks:
                                    target = (
                                        match.group(1)
                                        .strip()
                                        .removeprefix("wiki/entities/")
                                        .removeprefix("entities/")
                                        .removesuffix(".md")
                                    )
                                    alias = match.group(2).strip() if match.group(2) else None
                                    if target and target not in PUBLIC_TECH_ENTITIES:
                                        customers.add(target)
                                    if alias and alias not in PUBLIC_TECH_ENTITIES:
                                        customers.add(alias)
                            else:
                                plain_val = first_col.strip("`*\"' ")
                                if plain_val and plain_val not in PUBLIC_TECH_ENTITIES:
                                    customers.add(plain_val)
            except Exception:
                pass

        # 2. wiki/entities/ stems (excluding PUBLIC_TECH_ENTITIES)
        entities_dir = vault_root / "wiki" / "entities"
        if entities_dir.is_dir():
            for file in entities_dir.rglob("*.md"):
                stem = file.stem
                if stem not in PUBLIC_TECH_ENTITIES:
                    customers.add(stem)
                    try:
                        text = file.read_text(encoding="utf-8", errors="ignore")
                        _fm_raw, fm_opt, _body = okf.split_frontmatter(text)
                        if fm_opt is not None:
                            for val in _extract_aliases_from_frontmatter(fm_opt):
                                if val and val not in PUBLIC_TECH_ENTITIES:
                                    customers.add(val)
                    except Exception:
                        pass

        # 3. denylist.json
        denylist_map = load_custom_denylist(vault_root)
        customers.update(denylist_map.keys())

    return customers


def verify_pattern_egress_security(
    content: str,
    vault_root: Optional[Path] = None,
    rel_path: str = "",
) -> List[str]:
    """Perform fail-closed egress check across frontmatter, body, code blocks, and note paths.

    Scans both raw and normalize_shadow_view text for customer names, secrets,
    credentials, forbidden emails, internal refs, workstation paths, and unbucketed currency.
    """
    findings: List[str] = []
    shadow_content = normalize_shadow_view(content)
    variants = [("raw", content)]
    if shadow_content != content:
        variants.append(("shadow_view", shadow_content))

    customer_names = collect_egress_customer_names(vault_root)
    explicit_denylist = set(load_custom_denylist(vault_root).keys())
    active_sha_map = CUSTOMER_SHA256_ARCHETYPES

    # 0. Scan note path, filename, stem, and directories against customer names, secrets, and internal refs
    if rel_path:
        p_obj = Path(rel_path)
        path_targets = [str(rel_path), p_obj.stem, p_obj.name]
        for part in p_obj.parts:
            if part and part not in ("/", "\\", ".", "..") and part not in path_targets:
                path_targets.append(part)

        for p_target in path_targets:
            p_unquote = urllib.parse.unquote(p_target)
            p_norm = normalize_shadow_view(p_unquote)
            p_space = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", p_norm)
            p_space = re.sub(r"([a-zA-Z])([0-9])", r"\1 \2", p_space)
            p_space = re.sub(r"[-_./\\]+", " ", p_space)
            p_variants = [p_target]
            for candidate in (p_unquote, p_norm, p_space):
                if candidate not in p_variants:
                    p_variants.append(candidate)

            for pv in p_variants:
                for _start, _end, span_txt, arch in scan_sha256_entities_in_text(pv, active_sha_map):
                    findings.append(f"Forbidden customer entity detected via SHA-256 in note path/stem ({arch}): '{span_txt}'")
                for cust in customer_names:
                    if not cust:
                        continue
                    if cust in PUBLIC_TECH_ENTITIES and cust not in explicit_denylist:
                        continue
                    rgx = _build_customer_regex(cust)
                    m = rgx.search(pv)
                    if m:
                        findings.append(f"Customer name detected in note path/stem: '{m.group(0)}'")
                for pat, sec_label in _EGRESS_SECRET_PATTERNS:
                    m = pat.search(pv)
                    if m:
                        findings.append(f"Secret/credential detected in note path/stem ({sec_label}): '{m.group(0)}'")
                for pat, ref_label in _EGRESS_INTERNAL_REF_PATTERNS:
                    m = pat.search(pv)
                    if m:
                        findings.append(f"Internal reference detected in note path/stem ({ref_label}): '{m.group(0)}'")
                m_path = LOCAL_PATH_REGEX.search(pv)
                if m_path:
                    findings.append(f"Unredacted workstation path detected in note path/stem: '{m_path.group(0)}'")
                for m in _UNBUCKETED_CURRENCY_RE.finditer(pv):
                    findings.append(f"Unbucketed exact decimal currency figure detected in note path/stem: '{m.group(0)}'")

    # Explicitly check parsed frontmatter fields if frontmatter is present
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            fm_text = parts[1]
            in_target_list = False
            for line in fm_text.splitlines():
                s_line = line.strip()
                matched_header = False
                for fm_field in ("title:", "aliases:", "tags:"):
                    if s_line.startswith(fm_field):
                        val_part = s_line[len(fm_field):].strip().strip("\"'")
                        matched_header = True
                        in_target_list = (fm_field in ("aliases:", "tags:"))
                        if val_part:
                            for cust in customer_names:
                                if not cust:
                                    continue
                                if cust in PUBLIC_TECH_ENTITIES and cust not in explicit_denylist:
                                    continue
                                rgx = _build_customer_regex(cust)
                                if rgx.search(val_part):
                                    findings.append(f"Customer name detected in frontmatter '{fm_field[:-1]}': '{cust}'")
                        break
                if not matched_header:
                    if in_target_list and s_line.startswith("- "):
                        item_val = s_line[2:].strip().strip("\"'")
                        for cust in customer_names:
                            if not cust:
                                continue
                            if cust in PUBLIC_TECH_ENTITIES and cust not in explicit_denylist:
                                continue
                            rgx = _build_customer_regex(cust)
                            if rgx.search(item_val):
                                findings.append(f"Customer name detected in frontmatter list item: '{cust}'")
                    elif not line.startswith((" ", "\t")):
                        in_target_list = False

    for v_label, text_variant in variants:
        # 1. SHA-256 Entities
        for _start, _end, span_txt, arch in scan_sha256_entities_in_text(text_variant, active_sha_map):
            findings.append(f"Forbidden customer entity detected via SHA-256 [{v_label}] ({arch}): '{span_txt}'")

        # 2. Plaintext customer names
        for cust in customer_names:
            if not cust:
                continue
            if cust in PUBLIC_TECH_ENTITIES and cust not in explicit_denylist:
                continue
            rgx = _build_customer_regex(cust)
            for m in rgx.finditer(text_variant):
                if cust.upper() in _MERMAID_DIRECTIONS:
                    start = m.start()
                    prefix = text_variant[max(0, start - 15) : start]
                    if re.search(r"\b(?:flowchart|graph|direction)\s+$", prefix, re.IGNORECASE):
                        continue
                findings.append(f"Customer name detected [{v_label}]: '{m.group(0)}'")

        # 3. Secrets / credentials
        for pat, sec_label in _EGRESS_SECRET_PATTERNS:
            m = pat.search(text_variant)
            if m:
                findings.append(f"Secret/credential detected [{v_label}] ({sec_label}): '{m.group(0)}'")

        # 4. Emails (except synthetic @example.com / @example.org)
        for m in _EMAIL_RE.finditer(text_variant):
            domain = m.group(1).lower()
            if domain in ("example.com", "example.org") or domain.endswith((".example.com", ".example.org")):
                continue
            findings.append(f"Forbidden email address detected [{v_label}]: '{m.group(0)}'")

        # 5. Internal refs
        for pat, ref_label in _EGRESS_INTERNAL_REF_PATTERNS:
            m = pat.search(text_variant)
            if m:
                findings.append(f"Internal reference detected [{v_label}] ({ref_label}): '{m.group(0)}'")

        # 6. Unredacted workstation paths
        m_path = LOCAL_PATH_REGEX.search(text_variant)
        if m_path:
            findings.append(f"Unredacted workstation path detected [{v_label}]: '{m_path.group(0)}'")

        # 7. Unbucketed exact decimal currency figures
        for m in _UNBUCKETED_CURRENCY_RE.finditer(text_variant):
            findings.append(f"Unbucketed exact decimal currency figure detected [{v_label}]: '{m.group(0)}'")

        # 8. Unscrubbed human author handles
        for m in re.finditer(r"\bhuman:(?!cloud-ce\b)[a-zA-Z0-9._-]+", text_variant):
            findings.append(f"Unscrubbed human author handle detected [{v_label}]: '{m.group(0)}'")

    deduped: List[str] = []
    seen: Set[str] = set()
    for f in findings:
        if f not in seen:
            seen.add(f)
            deduped.append(f)
    return deduped


def share_pattern(
    pattern_file: Path,
    target_repo_path: Path,
    vault_root: Optional[Path] = None,
    dry_run: bool = False,
) -> Dict:
    """
    Shares a concept or pattern note to the shared patterns repository.
    Strictly verifies privacy boundaries, sanitizes content, updates target index and log.
    """
    if vault_root is None:
        if pattern_file.is_absolute():
            vault_root = find_vault_root(pattern_file.parent)
        else:
            vault_root = find_vault_root()

    vault_root = vault_root.resolve()
    if not pattern_file.is_absolute():
        if (vault_root / pattern_file).exists():
            pattern_file = (vault_root / pattern_file).resolve()
        else:
            pattern_file = pattern_file.resolve()
    else:
        pattern_file = pattern_file.resolve()

    try:
        rel_path = str(pattern_file.relative_to(vault_root))
    except ValueError:
        raise SecurityException(
            f"File '{pattern_file}' is outside the vault root '{vault_root}'."
        )

    # 1. Enforce Path Isolation Boundary
    blocked, reason = is_path_blocked(rel_path)
    if blocked:
        raise SecurityException(f"Cannot share file '{rel_path}': {reason}")

    # Ensure file originates strictly from concepts or patterns
    if not (
        rel_path.startswith("wiki/concepts/") or rel_path.startswith("wiki/patterns/")
    ):
        raise SecurityException(
            f"Only notes from 'wiki/concepts/' or 'wiki/patterns/' may be shared. Attempted: '{rel_path}'"
        )

    content = pattern_file.read_text(encoding="utf-8")

    # 2. Check for personal / evaluation / compensation content
    violations = check_content_security(content)
    if violations:
        raise SecurityException(f"Cannot share '{rel_path}': {'; '.join(violations)}")

    # 3. Sanitize markdown (including private wiki/entities/ archetype prose conversion)
    shared_targets = _collect_shared_targets(target_repo_path)
    if shared_targets is not None:
        shared_targets = set(shared_targets) | {
            pattern_file.stem,
            rel_path,
            rel_path.removesuffix(".md"),
        }
    sanitized_content, scrub_notes = sanitize_markdown(
        content,
        vault_root=vault_root,
        valid_shared_targets=shared_targets,
    )

    dest_file = target_repo_path / rel_path
    dest_rel_str = str(dest_file.relative_to(target_repo_path)).replace("\\", "/")

    # 4. Mandatory fail-closed egress security check BEFORE any filesystem write
    egress_violations = verify_pattern_egress_security(
        content=sanitized_content,
        vault_root=vault_root,
        rel_path=rel_path,
    )
    dest_violations = verify_pattern_egress_security(
        content="",
        vault_root=vault_root,
        rel_path=dest_rel_str,
    )
    for dv in dest_violations:
        if dv not in egress_violations:
            egress_violations.append(dv)

    if egress_violations:
        diag = "\n  - " + "\n  - ".join(egress_violations)
        raise SecurityException(
            f"Mandatory egress security check failed for '{rel_path}':{diag}"
        )

    # 5. Destination path in target repo (fail-closed: zero write if any gate failed)
    if not dry_run:
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        dest_file.write_text(sanitized_content, encoding="utf-8")

        # Update index.md and log.md in target repo
        update_target_index(target_repo_path, rel_path, pattern_file.stem)
        append_target_log(target_repo_path, pattern_file.stem, rel_path)

    return {
        "success": True,
        "source": rel_path,
        "destination": str(dest_file.relative_to(target_repo_path)),
        "scrub_notes": scrub_notes,
        "dry_run": dry_run,
    }


def open_pattern_pr(
    pattern_file: Path,
    target_repo_path: Path,
    vault_root: Optional[Path] = None,
    branch_name: Optional[str] = None,
    base_branch: str = "main",
    pr_title: Optional[str] = None,
    dry_run: bool = False,
) -> Dict:
    """
    Share a single sanitized pattern into an isolated temporary git worktree of
    `target_repo_path`, commit, push, and open a Pull Request via `gh pr create`.
    """
    target_repo_path = Path(target_repo_path).resolve()
    if not target_repo_path.is_dir():
        raise ValueError(f"Target repository directory not found: {target_repo_path}")

    git_check = subprocess.run(
        ["git", "-C", str(target_repo_path), "rev-parse", "--git-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if git_check.returncode != 0:
        raise ValueError(
            f"Target directory is not a Git repository: {target_repo_path}"
        )

    slug = re.sub(r"[^a-z0-9]+", "-", Path(pattern_file).stem.lower()).strip("-") or "pattern"
    branch = (branch_name or f"docs/share-{slug}").strip()
    if not branch or branch.startswith("-") or ".." in branch or any(c.isspace() for c in branch):
        raise ValueError(f"Invalid Git branch name: {branch!r}")
    base = (base_branch or "main").strip()
    if not base or base.startswith("-") or ".." in base or any(c.isspace() for c in base):
        raise ValueError(f"Invalid base branch name: {base!r}")

    if dry_run:
        dry_res = share_pattern(
            pattern_file, target_repo_path, vault_root=vault_root, dry_run=True
        )
        return {
            "success": True,
            "dry_run": True,
            "branch": branch,
            "base": base,
            "source": dry_res["source"],
            "destination": dry_res["destination"],
            "scrub_notes": dry_res["scrub_notes"],
            "pr_url": None,
        }

    # Resolve start ref cleanly without modifying the caller's checked-out branch
    start_ref = "HEAD"
    for candidate_ref in (f"origin/{base}", base):
        chk = subprocess.run(
            ["git", "-C", str(target_repo_path), "rev-parse", "--verify", candidate_ref],
            capture_output=True,
            text=True,
            check=False,
        )
        if chk.returncode == 0:
            start_ref = candidate_ref
            break

    wt_parent = Path(tempfile.mkdtemp(prefix="kc_share_pr_"))
    wt_dir = wt_parent / "wt"
    try:
        wt_add = subprocess.run(
            [
                "git",
                "-C",
                str(target_repo_path),
                "worktree",
                "add",
                "-B",
                branch,
                str(wt_dir),
                start_ref,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if wt_add.returncode != 0:
            raise ValueError(
                f"Failed to create isolated git worktree: {(wt_add.stderr or wt_add.stdout).strip()}"
            )

        res = share_pattern(
            pattern_file, wt_dir, vault_root=vault_root, dry_run=False
        )

        validator_script = wt_dir / "scripts" / "validate_patterns.py"
        if validator_script.is_file():
            val_proc = subprocess.run(
                [sys.executable, str(validator_script)],
                cwd=str(wt_dir),
                capture_output=True,
                text=True,
                check=False,
            )
            if val_proc.returncode != 0:
                raise SecurityException(
                    f"Target repository validation failed:\n{(val_proc.stderr or val_proc.stdout).strip()}"
                )

        stage_candidates = [res["destination"], "index.md", "log.md"]
        to_stage = [p for p in stage_candidates if (wt_dir / p).exists()]
        subprocess.run(
            ["git", "-C", str(wt_dir), "add", "--", *to_stage],
            capture_output=True,
            text=True,
            check=True,
        )

        diff_chk = subprocess.run(
            ["git", "-C", str(wt_dir), "diff", "--cached", "--quiet"],
            capture_output=True,
            check=False,
        )
        title = (pr_title or f"docs(patterns): share {Path(pattern_file).stem} pattern").strip()
        if diff_chk.returncode != 0:
            commit_proc = subprocess.run(
                ["git", "-C", str(wt_dir), "commit", "-m", title],
                capture_output=True,
                text=True,
                check=False,
            )
            if commit_proc.returncode != 0:
                raise ValueError(
                    f"git commit failed: {(commit_proc.stderr or commit_proc.stdout).strip()}"
                )

        push_proc = subprocess.run(
            ["git", "-C", str(wt_dir), "push", "-u", "origin", branch],
            capture_output=True,
            text=True,
            check=False,
        )
        if push_proc.returncode != 0:
            raise ValueError(
                f"git push failed for branch '{branch}': {(push_proc.stderr or push_proc.stdout).strip()}"
            )

        pr_body = (
            f"Shares sanitized pattern `{res['destination']}` with full OKF v0.2 "
            "compliance and zero private identifiers."
        )
        gh_proc = subprocess.run(
            [
                "gh",
                "pr",
                "create",
                "--base",
                base,
                "--head",
                branch,
                "--title",
                title,
                "--body",
                pr_body,
            ],
            cwd=str(wt_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        if gh_proc.returncode != 0:
            raise ValueError(
                f"gh pr create failed: {(gh_proc.stderr or gh_proc.stdout).strip()}"
            )

        pr_url = ""
        for line in reversed(gh_proc.stdout.splitlines()):
            cand = line.strip()
            if cand.startswith(("https://", "http://")):
                pr_url = cand
                break
        if not pr_url:
            pr_url = gh_proc.stdout.strip()

        return {
            "success": True,
            "dry_run": False,
            "branch": branch,
            "base": base,
            "source": res["source"],
            "destination": res["destination"],
            "scrub_notes": res["scrub_notes"],
            "pr_url": pr_url,
        }
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"Git operation failed: {(exc.stderr or exc.stdout or str(exc)).strip()}") from exc
    finally:
        subprocess.run(
            ["git", "-C", str(target_repo_path), "worktree", "remove", "--force", str(wt_dir)],
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["git", "-C", str(target_repo_path), "worktree", "prune"],
            capture_output=True,
            check=False,
        )
        shutil.rmtree(wt_parent, ignore_errors=True)


def _extract_updated_date(text: str) -> str:
    """Extract ISO `updated: YYYY-MM-DD` frontmatter timestamp if present."""
    if not text.startswith("---"):
        return ""
    parts = text.split("---", 2)
    if len(parts) < 3:
        return ""
    m = re.search(r"(?m)^updated:\s*['\"]?(\d{4}-\d{2}-\d{2})", parts[1])
    return m.group(1) if m else ""


_ALLOWED_CLONE_URL_PREFIXES: Tuple[str, ...] = (
    "https://",
    "ssh://",
    "git@",
    "file://",
)


def _validate_clone_repo_url(repo_url: str) -> str:
    """Validate a git remote URL or local bare/git directory path against option injection."""
    cleaned = str(repo_url or "").strip()
    if not cleaned:
        raise ValueError("Shared patterns repository URL cannot be empty.")
    if cleaned.startswith("-"):
        raise ValueError(f"Invalid repository URL (leading dash rejected): {cleaned!r}")
    if any(cleaned.startswith(pfx) for pfx in _ALLOWED_CLONE_URL_PREFIXES):
        return cleaned
    candidate = Path(cleaned).expanduser()
    if candidate.exists() and candidate.is_dir():
        return str(candidate.resolve())
    raise ValueError(
        f"Unsupported shared patterns repository URL scheme: {cleaned!r}. "
        "Use https://, ssh://, git@, file://, or an existing local git directory."
    )


def resolve_patterns_repo_dir(
    explicit_dir: Optional[str | Path] = None,
    vault_root: Optional[Path] = None,
) -> Optional[Path]:
    """Return the first existing local shared patterns repository clone, or None."""
    if explicit_dir is not None and str(explicit_dir).strip():
        cand = Path(explicit_dir).expanduser().resolve()
        return cand if cand.exists() else None

    candidates: List[Path] = []
    for env_key in _DEFAULT_PATTERNS_ENV_KEYS:
        env_val = (os.environ.get(env_key) or "").strip()
        if env_val:
            candidates.append(Path(env_val).expanduser())

    home = Path.home()
    for dir_name in _DEFAULT_PATTERNS_DIR_NAMES:
        candidates.append(home / dir_name)
        if vault_root is not None:
            candidates.append(vault_root.parent / dir_name)
        candidates.append(home / ".cache" / "knowledge-compiler" / dir_name)
    for cache_sub in _DEFAULT_PATTERNS_CACHE_SUBDIRS:
        candidates.append(home / cache_sub)

    seen: Set[str] = set()
    for cand in candidates:
        key = str(cand)
        if key in seen:
            continue
        seen.add(key)
        if cand.exists() and cand.is_dir():
            return cand.resolve()
    return None


def default_patterns_clone_target(explicit_dir: Optional[str | Path] = None) -> Path:
    """Return the canonical local directory where the shared patterns repo should be cloned."""
    if explicit_dir is not None and str(explicit_dir).strip():
        return Path(explicit_dir).expanduser().resolve()
    for env_key in _DEFAULT_PATTERNS_ENV_KEYS:
        env_val = (os.environ.get(env_key) or "").strip()
        if env_val:
            return Path(env_val).expanduser().resolve()
    return (Path.home() / _DEFAULT_PATTERNS_DIR_NAMES[0]).resolve()


def ensure_patterns_repo(
    repo_dir: Optional[str | Path] = None,
    repo_url: Optional[str] = None,
    vault_root: Optional[Path] = None,
    auto_clone: bool = True,
    pull_latest: bool = True,
    dry_run: bool = False,
    timeout_sec: int = 30,
) -> Dict:
    """Locate, optionally auto-clone, and fast-forward the shared patterns repository.

    Never prompts interactively for git credentials (`GIT_TERMINAL_PROMPT=0`), and never
    mutates disk when `dry_run=True`.
    """
    existing = resolve_patterns_repo_dir(repo_dir, vault_root=vault_root)
    git_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}

    if existing is not None:
        result: Dict = {
            "ok": True,
            "path": existing,
            "cloned": False,
            "updated_remote": False,
            "warning": "",
            "fallback_hint": _DEFAULT_PATTERNS_FALLBACK_HINT,
        }
        if pull_latest and not dry_run and (existing / ".git").exists():
            try:
                proc = subprocess.run(
                    ["git", "-C", str(existing), "pull", "--ff-only"],
                    capture_output=True,
                    text=True,
                    env=git_env,
                    timeout=timeout_sec,
                    check=False,
                )
                if proc.returncode == 0:
                    result["updated_remote"] = True
                else:
                    err_txt = (proc.stderr or proc.stdout or "").strip().splitlines()
                    result["warning"] = (
                        f"Skipped upstream git pull ({err_txt[-1] if err_txt else 'non-zero exit'}); "
                        "using existing local clone."
                    )
            except (OSError, subprocess.TimeoutExpired) as exc:
                result["warning"] = (
                    f"Skipped upstream git pull ({exc}); using existing local clone."
                )
        return result

    clone_target = default_patterns_clone_target(repo_dir)
    resolved_url = (
        (repo_url or "").strip()
        or (os.environ.get("OKF_PATTERNS_REPO_URL") or "").strip()
        or _DEFAULT_PATTERNS_REPO_URL
    )

    if dry_run:
        return {
            "ok": False,
            "dry_run_missing": True,
            "path": clone_target,
            "repo_url": resolved_url,
            "cloned": False,
            "error": f"Shared patterns repository is not cloned at {clone_target} yet.",
            "fallback_hint": _DEFAULT_PATTERNS_FALLBACK_HINT,
        }

    if not auto_clone:
        return {
            "ok": False,
            "path": clone_target,
            "repo_url": resolved_url,
            "cloned": False,
            "error": f"Shared patterns repository not found at {clone_target} (auto-clone disabled).",
            "fallback_hint": _DEFAULT_PATTERNS_FALLBACK_HINT,
        }

    if not resolved_url:
        return {
            "ok": False,
            "path": clone_target,
            "repo_url": "",
            "cloned": False,
            "error": "Shared patterns repository not found locally and no --repo-url was configured.",
            "fallback_hint": _DEFAULT_PATTERNS_FALLBACK_HINT,
        }

    safe_url = _validate_clone_repo_url(resolved_url)
    clone_target.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--", safe_url, str(clone_target)],
            capture_output=True,
            text=True,
            env=git_env,
            timeout=timeout_sec,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "path": clone_target,
            "repo_url": safe_url,
            "cloned": False,
            "error": f"Auto-clone of {safe_url} failed: {exc}",
            "fallback_hint": _DEFAULT_PATTERNS_FALLBACK_HINT,
        }

    if proc.returncode != 0:
        err_lines = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = err_lines[-1] if err_lines else f"git clone exited with code {proc.returncode}"
        return {
            "ok": False,
            "path": clone_target,
            "repo_url": safe_url,
            "cloned": False,
            "error": f"Could not auto-clone {safe_url} into {clone_target}: {detail}",
            "fallback_hint": _DEFAULT_PATTERNS_FALLBACK_HINT,
        }

    return {
        "ok": True,
        "path": clone_target.resolve(),
        "repo_url": safe_url,
        "cloned": True,
        "updated_remote": True,
        "warning": "",
        "fallback_hint": _DEFAULT_PATTERNS_FALLBACK_HINT,
    }


def pull_patterns(
    source_repo_path: Path,
    vault_root: Optional[Path] = None,
    dry_run: bool = False,
    overwrite: bool = False,
) -> Dict:
    """
    Pulls shared concepts and patterns from the shared patterns repository into the local vault.
    Guarantees it only writes to wiki/concepts/ and wiki/patterns/, and preserves
    existing local notes unless the shared pattern has a strictly newer `updated:`
    frontmatter date (or `overwrite=True` is explicitly passed).
    """
    if not source_repo_path.exists() or not source_repo_path.is_dir():
        raise FileNotFoundError(
            f"Shared patterns repository directory does not exist: {source_repo_path}"
        )

    if vault_root is None:
        vault_root = find_vault_root()

    if not dry_run and not vault_root.exists():
        try:
            import init_vault as _init_vault_mod  # type: ignore[import-not-found]
            _init_vault_mod.init_vault(vault_root)
        except Exception:
            vault_root.mkdir(parents=True, exist_ok=True)

    pulled_files = []
    skipped_up_to_date = []

    for category in ["wiki/concepts", "wiki/patterns"]:
        src_cat = source_repo_path / category
        if not src_cat.exists():
            continue

        dest_cat = vault_root / category
        if not dry_run:
            dest_cat.mkdir(parents=True, exist_ok=True)

        for src_file in sorted(src_cat.glob("*.md")):
            dest_file = dest_cat / src_file.name
            rel_path = f"{category}/{src_file.name}"

            should_copy = True
            if dest_file.exists():
                src_text = src_file.read_text(encoding="utf-8", errors="ignore")
                dst_text = dest_file.read_text(encoding="utf-8", errors="ignore")
                if src_text == dst_text:
                    should_copy = False
                elif not overwrite:
                    src_upd = _extract_updated_date(src_text)
                    dst_upd = _extract_updated_date(dst_text)
                    # Do not clobber local vault notes (which hold richer entity links)
                    # unless the shared repo has a strictly newer `updated:` date.
                    if not (src_upd and dst_upd and src_upd > dst_upd):
                        should_copy = False
                        skipped_up_to_date.append(rel_path)

            if should_copy:
                if not dry_run:
                    shutil.copy2(src_file, dest_file)
                pulled_files.append(rel_path)

    # Update local index and log if files were pulled
    if pulled_files and not dry_run:
        for rel in pulled_files:
            stem = Path(rel).stem
            update_target_index(vault_root, rel, stem)
        append_pull_log(vault_root, pulled_files)

    return {
        "success": True,
        "pulled_count": len(pulled_files),
        "pulled_files": pulled_files,
        "skipped_count": len(skipped_up_to_date),
        "dry_run": dry_run,
    }


def update_target_index(repo_root: Path, rel_path: str, title: str):
    """Ensures index.md references the pattern file without duplicating existing entries."""
    index_file = repo_root / "index.md"
    if not index_file.exists():
        return

    content = index_file.read_text(encoding="utf-8")
    rel_no_ext = rel_path[:-3] if rel_path.endswith(".md") else rel_path

    if (
        f"[[{title}]]" in content
        or f"[[{title}|" in content
        or f"[[{rel_no_ext}]]" in content
        or f"[[{rel_no_ext}|" in content
        or f"[[{rel_path}]]" in content
        or f"[[{rel_path}|" in content
    ):
        return

    # Determine which section to insert into
    target_section = "## 🔬 Core Concepts & Frameworks"
    if "patterns" in rel_path:
        target_section = "## 🛠 Invariants & Engineering Patterns"
        if target_section not in content:
            target_section = "## 🔬 Core Concepts & Frameworks"

    lines = content.splitlines()
    new_lines = []
    inserted = False

    for line in lines:
        new_lines.append(line)
        if not inserted and target_section in line:
            new_lines.append(
                f"- [[{rel_no_ext}|{title}]]: Shared architectural pattern."
            )
            inserted = True

    if not inserted:
        new_lines.append(
            f"\n- [[{rel_no_ext}|{title}]]: Shared architectural pattern."
        )

    index_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def append_target_log(repo_root: Path, title: str, source: str):
    """Appends an OKF v0.2 audit log entry."""
    log_file = repo_root / "log.md"
    if not log_file.exists():
        return

    today = datetime.date.today().isoformat()
    entry = f"\n## [{today}] share | [[{title}]] (via {source})\n- Sync operation completed.\n"

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(entry)


def append_pull_log(repo_root: Path, pulled_files: List[str]):
    """Appends an OKF v0.2 pull audit log entry with valid per-note wikilinks."""
    log_file = repo_root / "log.md"
    if not log_file.exists() or not pulled_files:
        return

    today = datetime.date.today().isoformat()
    bullets = "\n".join(
        f"- Pulled [[{Path(rel).stem}]] (`{rel}`) from shared patterns repository."
        for rel in pulled_files
    )
    entry = f"\n## [{today}] pull | Synchronized {len(pulled_files)} shared pattern(s) from shared repository\n{bullets}\n"

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(entry)


def init_patterns_repo(target_dir: Path, init_git: bool = True):
    """Scaffolds a new, standalone shared OKF patterns repository with OKF v0.2 structure."""
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    (target_dir / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
    (target_dir / "wiki" / "patterns").mkdir(parents=True, exist_ok=True)
    (target_dir / ".github" / "workflows").mkdir(parents=True, exist_ok=True)

    # 1. GEMINI.md
    gemini_content = """# Shared Architecture & Patterns Protocol (GEMINI.md)

Welcome to the **Shared Architecture & Patterns** repository (`shared-okf-patterns`).
This repository serves as the shared, federated architectural pattern exchange for engineering teams.

---

## 🏛 Privacy & Anonymization Invariants

1. **Air-Gapped Privacy**:
   - Customer-specific dossiers, pricing, deal terms, and internal performance ratings are strictly forbidden in this repository.
   - All contributions MUST be processed and validated via `scripts/sync_patterns.py` from `knowledge-compiler`.

2. **OKF v0.2 Compliance**:
   - All patterns in `wiki/concepts/` and `wiki/patterns/` adhere to the Open Knowledge Format (OKF v0.2) frontmatter standards.
   - Run `vault-lint` before submitting Pull Requests.

3. **Reciprocal Wikilinking**:
   - Ensure all concept references use standard `[[wikilinks]]`.
"""
    (target_dir / "GEMINI.md").write_text(gemini_content, encoding="utf-8")

    # 2. README.md
    readme_content = """# Shared Architecture & OKF Patterns (`shared-okf-patterns`)

[![OKF v0.2 Compliant](https://img.shields.io/badge/Schema-OKF%20v0.2-blue)](https://github.com/GoogleCloudPlatform/knowledge-compiler)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

A curated catalog of enterprise cloud architecture patterns, autonomous agent frameworks, and engineering invariants.

---

## 📚 Pattern Catalog

### 🔬 Core Concepts (`wiki/concepts/`)
- Architecture patterns for multi-agent systems, A2A communication, FinOps, security shift-left, and context engineering.

### 🛠 Invariants & Diagnostic Patterns (`wiki/patterns/`)
- Engineering invariants, process guards, and robust operational techniques discovered during real-world deployments.

---

## 🔄 How to Share and Pull Patterns

Using the `knowledge-compiler` CLI or skills:

```bash
# Audit local concepts and check readiness for sharing
sync-patterns audit

# Share a pattern to shared-okf-patterns
sync-patterns share "wiki/concepts/A2A Protocol & Agent Interoperability.md"

# Pull latest shared patterns into your personal vault
sync-patterns pull
```
"""
    (target_dir / "README.md").write_text(readme_content, encoding="utf-8")

    # 3. index.md (OKF v0.3 §8.1 root bundle metadata)
    today = datetime.date.today().isoformat()
    index_content = """---
okf_version: "0.3"
title: "Shared Patterns Index"
description: "Curated, de-identified architectural patterns and engineering invariants."
---

# 📚 Master Pattern Index

Curated architectural patterns and engineering invariants.

---

## 🔬 Core Concepts & Frameworks
- Catalog will be populated as patterns are contributed.

---

## 🛠 Invariants & Engineering Patterns
- Catalog will be populated as patterns are contributed.
"""
    (target_dir / "index.md").write_text(index_content, encoding="utf-8")

    # 4. log.md (OKF v0.3 §9: no frontmatter, ## YYYY-MM-DD date headings)
    log_content = f"""# Operations Log

Chronological audit ledger of pattern contributions and updates.

## {today}
- **init** | Repository Initialized: Initialized OKF v0.3 shared-okf-patterns repository.
"""
    (target_dir / "log.md").write_text(log_content, encoding="utf-8")

    # 5. .github/workflows/lint.yml
    workflow_content = """name: OKF Vault Lint

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install pyyaml
      - name: Run Vault Linter
        run: |
          python3 -c "
import sys
from pathlib import Path
# Basic link and frontmatter validation
errors = 0
for f in Path('wiki').rglob('*.md'):
    content = f.read_text()
    if not content.startswith('---'):
        print(f'Missing frontmatter: {f}')
        errors += 1
if errors > 0:
    sys.exit(1)
print('All patterns validated successfully!')
"
"""
    (target_dir / ".github" / "workflows" / "lint.yml").write_text(
        workflow_content, encoding="utf-8"
    )

    # 6. .gitignore
    (target_dir / ".gitignore").write_text(
        ".DS_Store\n*.swp\n__pycache__/\n.obsidian/\n", encoding="utf-8"
    )

    if init_git:
        try:
            subprocess.run(
                ["git", "init"], cwd=str(target_dir), check=True, capture_output=True
            )
            subprocess.run(
                ["git", "add", "-A"],
                cwd=str(target_dir),
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "git",
                    "commit",
                    "-m",
                    "chore: initialize shared-okf-patterns repository with OKF v0.2",
                ],
                cwd=str(target_dir),
                check=True,
                capture_output=True,
            )
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Federated Pattern Exchange & Sanitization Engine for OKF v0.2 Vaults."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: audit
    p_audit = subparsers.add_parser(
        "audit",
        help="Audit local vault concepts and patterns for privacy and customer mentions.",
    )
    p_audit.add_argument(
        "--vault", default=None, help="Path to Knowledge Compiler vault root."
    )
    p_audit.add_argument(
        "--json", action="store_true", help="Output audit report in JSON format."
    )

    # Subcommand: sanitize
    p_sanitize = subparsers.add_parser(
        "sanitize",
        help="Sanitize a markdown file by de-identifying customer references.",
    )
    p_sanitize.add_argument("file", help="Path to the file to sanitize.")
    p_sanitize.add_argument(
        "--output", "-o", default=None, help="Output destination (defaults to stdout)."
    )

    # Subcommand: share
    p_share = subparsers.add_parser(
        "share", help="Share a concept or pattern to the shared patterns repository."
    )
    p_share.add_argument(
        "file",
        nargs="?",
        default=None,
        help="Path to note in wiki/concepts/ or wiki/patterns/ to share.",
    )
    p_share.add_argument(
        "--all-clean",
        action="store_true",
        help="Share all clean/vetted patterns discovered in the vault.",
    )
    p_share.add_argument(
        "--repo-dir",
        "--target-repo",
        "--patterns-repo",
        dest="repo_dir",
        default=None,
        help="Local directory of the shared patterns clone.",
    )
    p_share.add_argument("--vault", default=None, help="Path to local vault root.")
    p_share.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform privacy checks and preview diff without writing.",
    )
    p_share.add_argument(
        "--open-pr",
        action="store_true",
        help="Stage the shared pattern on an isolated git worktree branch, push, and open a PR via gh.",
    )
    p_share.add_argument(
        "--branch",
        default=None,
        help="Feature branch name for --open-pr (defaults to docs/share-<slug>).",
    )
    p_share.add_argument(
        "--base",
        default="main",
        help="Base branch for --open-pr (default: main).",
    )
    p_share.add_argument(
        "--pr-title",
        default=None,
        help="Custom commit & Pull Request title for --open-pr.",
    )

    # Subcommand: pull
    p_pull = subparsers.add_parser(
        "pull",
        help="Pull shared concepts and patterns from the shared patterns repository into the local vault.",
    )
    p_pull.add_argument(
        "--repo-dir",
        "--patterns-repo",
        dest="repo_dir",
        default=None,
        help="Local directory of the shared patterns clone (auto-resolved or auto-cloned if omitted).",
    )
    p_pull.add_argument(
        "--repo-url",
        default=None,
        help="Optional Git URL to auto-clone if the shared patterns repository is not present locally.",
    )
    p_pull.add_argument(
        "--no-auto-clone",
        action="store_true",
        help="Disable automatic git clone when the shared patterns repository is not found locally.",
    )
    p_pull.add_argument(
        "--no-git-pull",
        action="store_true",
        help="Skip running `git pull --ff-only` on an existing local shared patterns clone.",
    )
    p_pull.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing local vault files even if local `updated:` is newer.",
    )
    p_pull.add_argument("--vault", default=None, help="Path to local vault root.")
    p_pull.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview incoming patterns without modifying local vault.",
    )

    # Subcommand: init-repo
    p_init = subparsers.add_parser(
        "init-repo", help="Scaffold a new OKF v0.2 shared patterns repository."
    )
    p_init.add_argument(
        "dir", help="Directory where the repository should be initialized."
    )
    p_init.add_argument(
        "--no-git", action="store_true", help="Do not initialize a git repository."
    )

    args = parser.parse_args()
    v_root = (
        Path(args.vault).resolve()
        if getattr(args, "vault", None)
        else find_vault_root()
    )

    try:
        if args.command == "audit":
            audit_res = audit_vault(v_root)
            if args.json:
                print(json.dumps(audit_res, indent=2))
            else:
                print("=" * 60)
                print("🔍 OKF Pattern Exchange Privacy & Sanitization Audit")
                print("=" * 60)
                print(f"📁 Vault Root: {v_root}")
                print(f"✅ Ready to Share ({len(audit_res['clean'])} clean patterns):")
                for item in audit_res["clean"][:15]:
                    print(f"   • {item['title']} ({item['file']})")
                if len(audit_res["clean"]) > 15:
                    print(f"   ... and {len(audit_res['clean']) - 15} more.")

                print(
                    f"\n⚠️ Requires Scrubbing ({len(audit_res['scrub_needed'])} patterns with customer references/paths):"
                )
                for item in audit_res["scrub_needed"]:
                    print(f"   • {item['title']}: {'; '.join(item['reasons'])}")

                if audit_res["blocked"]:
                    print(f"\n❌ Air-Gapped / Blocked ({len(audit_res['blocked'])} notes):")
                    for item in audit_res["blocked"]:
                        print(f"   • {item['file']}: {item['reason']}")
                print("=" * 60)

        elif args.command == "sanitize":
            f_path = Path(args.file).resolve()
            content = f_path.read_text(encoding="utf-8")
            sanitized, notes = sanitize_markdown(content, vault_root=v_root)
            if args.output:
                # Vault-relative input path if within vault_root, otherwise filename (avoids /home/user workstation false-positive)
                try:
                    input_rel = (
                        str(f_path.relative_to(v_root)).replace("\\", "/")
                        if v_root
                        else f_path.name
                    )
                except ValueError:
                    input_rel = f_path.name

                egress_violations = verify_pattern_egress_security(
                    content=sanitized,
                    vault_root=v_root,
                    rel_path=input_rel,
                )

                # Scan output path components (filename, stem, and directories) for customer names/secrets
                out_p = Path(args.output)
                out_targets = [out_p.name, out_p.stem] + [
                    p for p in out_p.parts if p and p not in ("/", "\\", ".", "..")
                ]
                for ot in out_targets:
                    ot_violations = verify_pattern_egress_security(
                        content="",
                        vault_root=v_root,
                        rel_path=ot,
                    )
                    for v in ot_violations:
                        if "workstation path" not in v.lower() and v not in egress_violations:
                            egress_violations.append(v)

                if egress_violations:
                    print(
                        f"❌ Egress security check failed for '{f_path.name}':\n  - "
                        + "\n  - ".join(egress_violations),
                        file=sys.stderr,
                    )
                    sys.exit(1)
                out_p = out_p.resolve()
                out_p.parent.mkdir(parents=True, exist_ok=True)
                out_p.write_text(sanitized, encoding="utf-8")
                print(f"✅ Sanitized file written to {out_p} ({len(notes)} redactions)")
            else:
                print(sanitized)

        elif args.command == "share":
            target_dir = resolve_patterns_repo_dir(args.repo_dir, vault_root=v_root)

            if not target_dir:
                print(
                    "❌ Target patterns repository directory not found. "
                    f"{_DEFAULT_PATTERNS_FALLBACK_HINT}",
                    file=sys.stderr,
                )
                sys.exit(1)

            if args.open_pr and args.all_clean:
                raise ValueError(
                    "--open-pr requires a single pattern file (cannot be combined with --all-clean)."
                )

            if args.all_clean:
                audit_res = audit_vault(v_root)
                clean_list = audit_res["clean"]
                if not clean_list:
                    print("ℹ️ No clean patterns ready to share.")
                    return
                print(f"📦 Sharing {len(clean_list)} clean patterns to {target_dir}...")
                shared_count = 0
                for item in clean_list:
                    item_f = v_root / item["file"]
                    try:
                        res = share_pattern(
                            item_f, target_dir, vault_root=v_root, dry_run=args.dry_run
                        )
                        print(f"   + Shared '{item['title']}'")
                        shared_count += 1
                    except SecurityException as e:
                        print(f"   ⚠️ Skipped '{item['title']}': {e}")
                print(f"🎉 Successfully shared {shared_count}/{len(clean_list)} patterns.")
            else:
                if not args.file:
                    print(
                        "❌ File path required when not using --all-clean.", file=sys.stderr
                    )
                    sys.exit(1)
                f_path = Path(args.file)
                if not f_path.is_absolute() and v_root and (v_root / f_path).exists():
                    f_path = (v_root / f_path).resolve()
                else:
                    f_path = f_path.resolve()

                if args.open_pr:
                    res = open_pattern_pr(
                        f_path,
                        target_dir,
                        vault_root=v_root,
                        branch_name=args.branch,
                        base_branch=args.base,
                        pr_title=args.pr_title,
                        dry_run=args.dry_run,
                    )
                    if res.get("dry_run"):
                        print(
                            f"🧪 Dry-run PR preview for '{res['source']}' -> '{res['destination']}' "
                            f"(branch: {res['branch']} -> {res['base']})"
                        )
                    else:
                        print(
                            f"🚀 Opened PR {res['pr_url']} for '{res['source']}' -> '{res['destination']}' "
                            f"(branch: {res['branch']})"
                        )
                else:
                    res = share_pattern(
                        f_path, target_dir, vault_root=v_root, dry_run=args.dry_run
                    )
                    print(
                        f"✅ Successfully shared '{res['source']}' -> '{res['destination']}'"
                    )
                if res["scrub_notes"]:
                    print("   Applied Sanitization:")
                    for n in res["scrub_notes"]:
                        print(f"   - {n}")

        elif args.command == "pull":
            ensured = ensure_patterns_repo(
                repo_dir=args.repo_dir,
                repo_url=args.repo_url,
                vault_root=v_root,
                auto_clone=not args.no_auto_clone,
                pull_latest=not args.no_git_pull,
                dry_run=args.dry_run,
            )
            if not ensured["ok"]:
                if ensured.get("dry_run_missing"):
                    print(f"ℹ️ {ensured['error']}")
                    if ensured.get("repo_url"):
                        print(
                            f"   Run without --dry-run to auto-clone from {ensured['repo_url']} "
                            f"into {ensured['path']}."
                        )
                    if ensured.get("fallback_hint"):
                        print(f"   {ensured['fallback_hint']}")
                    return
                print(f"❌ {ensured['error']}", file=sys.stderr)
                if ensured.get("fallback_hint"):
                    print(f"ℹ️ {ensured['fallback_hint']}", file=sys.stderr)
                sys.exit(1)

            source_dir = Path(ensured["path"])
            if ensured.get("cloned"):
                print(f"📥 Auto-cloned shared patterns repository into {source_dir}")
            elif ensured.get("warning"):
                print(f"⚠️ {ensured['warning']}", file=sys.stderr)

            res = pull_patterns(
                source_dir,
                vault_root=v_root,
                dry_run=args.dry_run,
                overwrite=args.overwrite,
            )
            print(
                f"✅ Pulled {res['pulled_count']} new/updated patterns into {v_root} "
                f"({res.get('skipped_count', 0)} existing local notes already up to date)"
            )
            for p in res["pulled_files"]:
                print(f"   + {p}")

        elif args.command == "init-repo":
            t_dir = Path(args.dir)
            init_patterns_repo(t_dir, init_git=not args.no_git)
            print(f"🚀 Initialized OKF v0.2 shared-okf-patterns repository at: {t_dir}")

    except SecurityException as e:
        print(f"🚨 Security Violation: {e}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, FileNotFoundError) as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
