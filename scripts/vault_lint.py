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
OKF v0.2 Knowledge Compiler Vault Linter & Graph Auditor.
Validates wikilink integrity, table formatting invariants, orphan notes,
frontmatter compliance, and index alignment across an Obsidian Knowledge Vault.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

SUPPORTED_OKF_VERSION = "0.2"
UPSTREAM_OKF_REPO_URL = "https://github.com/GoogleCloudPlatform/open-knowledge-format"
UPSTREAM_OKF_SPEC_RAW_URL = (
    "https://raw.githubusercontent.com/GoogleCloudPlatform/open-knowledge-format/main/SPEC.md"
)
UPSTREAM_OKF_COMMITS_API_URL = (
    "https://api.github.com/repos/GoogleCloudPlatform/open-knowledge-format/commits/main"
)


def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """Convert a version string like '0.2' or '0.3.1' into an integer tuple for comparison."""
    parts = re.findall(r"\d+", version_str or "")
    return tuple(int(p) for p in parts) if parts else (0,)


def check_upstream_okf_version(timeout: float = 5.0) -> dict:
    """
    Check the official GoogleCloudPlatform/open-knowledge-format GitHub repository
    to see if a newer version of the Open Knowledge Format (OKF) specification has
    been published beyond SUPPORTED_OKF_VERSION (v0.2).
    """
    result = {
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
        "User-Agent": "knowledge-compiler-okf-checker/0.9.0",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        req = urllib.request.Request(UPSTREAM_OKF_SPEC_RAW_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            spec_text = resp.read().decode("utf-8", errors="replace")

        # Match e.g. '**Version 0.2**' or 'Version: 0.2' in the first 40 lines of SPEC.md
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

    # Best-effort fetch of latest commit metadata on main
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


def parse_simple_yaml(text: str) -> dict:
    """Lenient YAML parser for frontmatter that works without pyyaml if needed."""
    try:
        import yaml

        parsed = yaml.safe_load(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Fallback stdlib parser supporting key-value pairs, inline lists, and multi-line lists
    data: dict = {}
    current_list_key: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and current_list_key:
            item = stripped[2:].strip().strip("'\"")
            if isinstance(data.get(current_list_key), list):
                data[current_list_key].append(item)
            continue
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            k = k.strip()
            v = v.strip()
            if not v:
                data[k] = []
                current_list_key = k
            elif v.startswith("[") and v.endswith("]"):
                inner = v[1:-1].strip()
                data[k] = (
                    [x.strip().strip("'\"") for x in inner.split(",") if x.strip()]
                    if inner
                    else []
                )
                current_list_key = None
            else:
                data[k] = v.strip("'\"")
                current_list_key = None
    return data


def run_vault_lint(
    vault_root: Path,
    auto_fix: bool = False,
    as_json: bool = False,
    check_okf_upstream: bool = False,
) -> dict:
    vault_root = vault_root.resolve()
    wiki_dir = vault_root / "wiki"

    if not wiki_dir.exists():
        return {
            "success": False,
            "error": f"Vault wiki directory not found at {wiki_dir}",
            "vault_path": str(vault_root),
        }

    all_md_files = {}
    raw_assets = {}

    for root, _, files in os.walk(vault_root):
        if any(
            ignored in root for ignored in [".obsidian", ".git", "__pycache__", ".venv"]
        ):
            continue
        for f in files:
            full_path = Path(root) / f
            rel_path = str(full_path.relative_to(vault_root))
            base_name = full_path.stem
            if f.endswith(".md"):
                all_md_files[rel_path] = {
                    "full_path": full_path,
                    "base_name": base_name,
                    "rel_path": rel_path,
                }
            else:
                raw_assets[rel_path] = {
                    "full_path": full_path,
                    "base_name": base_name,
                    "rel_path": rel_path,
                }

    # Build name lookup dictionaries
    name_to_rel = {}
    for rel_path, data in all_md_files.items():
        name_to_rel[data["base_name"].lower()] = rel_path
        name_to_rel[rel_path.lower()] = rel_path
        if rel_path.endswith(".md"):
            name_to_rel[rel_path[:-3].lower()] = rel_path
        if rel_path.startswith("wiki/"):
            name_to_rel[rel_path[5:].lower()] = rel_path
            if rel_path.endswith(".md"):
                name_to_rel[rel_path[5:-3].lower()] = rel_path
        if rel_path.startswith("raw/"):
            name_to_rel[rel_path[4:].lower()] = rel_path
            if rel_path.endswith(".md"):
                name_to_rel[rel_path[4:-3].lower()] = rel_path

    for rel_path, data in raw_assets.items():
        name_to_rel[data["base_name"].lower()] = rel_path
        name_to_rel[rel_path.lower()] = rel_path
        if rel_path.startswith("raw/"):
            name_to_rel[rel_path[4:].lower()] = rel_path

    graph = {
        k: {
            "outbound": set(),
            "inbound": set(),
            "frontmatter": None,
            "has_fm": False,
            "errors": [],
        }
        for k in all_md_files
    }

    # Matches [[target]] and [[target|alias]] and [[target\|alias]]
    wikilink_pattern = re.compile(r"\[\[([^\]\n]+)\]\]")
    table_escaped_pipe_pattern = re.compile(r"\[\[([^\]\n]+?\\\|[^\]\n]+)\]\]")

    table_invariant_violations = []
    fixed_files = []

    # Read and parse all Markdown files
    for rel_path, data in all_md_files.items():
        content = data["full_path"].read_text(encoding="utf-8", errors="ignore")

        # Strip code blocks and inline code
        cleaned = re.sub(r"```.*?```", "", content, flags=re.DOTALL)
        cleaned = re.sub(r"`[^`]+`", "", cleaned)

        # Check for escaped pipe violations inside tables / wikilinks
        escaped_matches = table_escaped_pipe_pattern.findall(cleaned)
        if escaped_matches:
            for m in escaped_matches:
                fix_snippet = m.replace(r"\|", "|")
                table_invariant_violations.append(
                    {
                        "file": rel_path,
                        "snippet": f"[[{m}]]",
                        "fix": f"[[{fix_snippet}]]",
                    }
                )
            if auto_fix:
                new_content = re.sub(
                    r"\[\[([^\]\n`]+?)\\\|([^\]\n`]+?)\]\]", r"[[\1|\2]]", content
                )
                data["full_path"].write_text(new_content, encoding="utf-8")
                fixed_files.append(rel_path)
                content = new_content

        # Parse frontmatter
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                fm = parse_simple_yaml(parts[1])
                graph[rel_path]["frontmatter"] = fm
                graph[rel_path]["has_fm"] = isinstance(fm, dict)

        # Extract links
        for match in wikilink_pattern.finditer(cleaned):
            raw_link = match.group(1).strip()
            # Handle alias if present (split on | or \|)
            target = re.split(r"(?<!\\)\|", raw_link)[0].strip()
            if target.startswith("#"):
                continue  # Heading-only link in same note
            if "#" in target:
                target = target.split("#")[0].strip()
            if target:
                graph[rel_path]["outbound"].add(target)

    # Resolve links and build inbound edges
    broken_links = []
    for src, data in graph.items():
        for target in data["outbound"]:
            target_clean = target.lower()
            target_clean = target_clean.removesuffix(".md")
            target_basename = target_clean.split("/")[-1]

            resolved_dst = None
            if target_clean in name_to_rel:
                resolved_dst = name_to_rel[target_clean]
            elif target.lower() in name_to_rel:
                resolved_dst = name_to_rel[target.lower()]
            elif target_basename in name_to_rel:
                resolved_dst = name_to_rel[target_basename]
            else:
                # Check title and aliases in frontmatter
                for candidate, c_data in graph.items():
                    fm = c_data.get("frontmatter")
                    if fm and isinstance(fm, dict):
                        fm_title = str(fm.get("title", "")).lower()
                        if fm_title and fm_title in (target_clean, target_basename):
                            resolved_dst = candidate
                            break
                        if "aliases" in fm:
                            aliases = fm["aliases"]
                            if isinstance(aliases, list):
                                for alias in aliases:
                                    if str(alias).lower() in (
                                        target_clean,
                                        target_basename,
                                    ):
                                        resolved_dst = candidate
                                        break
                    if resolved_dst:
                        break

            if resolved_dst:
                if resolved_dst in graph:
                    graph[resolved_dst]["inbound"].add(src)
            else:
                broken_links.append({"source": src, "target": target})

    # Find orphan notes in wiki/
    orphan_notes = []
    for rel_path, data in graph.items():
        if rel_path.startswith("wiki/") and rel_path.endswith(".md"):
            # If no inbound links and not an index
            if len(data["inbound"]) == 0:
                orphan_notes.append(rel_path)

    # Check index.md coverage
    missing_from_index = []
    index_file = vault_root / "index.md"
    if index_file.exists():
        index_content = index_file.read_text(encoding="utf-8")
        for rel_path in all_md_files:
            if rel_path.startswith("wiki/") and rel_path.endswith(".md"):
                note_base = all_md_files[rel_path]["base_name"]
                if (
                    note_base.lower() not in index_content.lower()
                    and f"[[{note_base}" not in index_content
                ):
                    missing_from_index.append(rel_path)

    # Check frontmatter compliance & count 5-way typed epistemic edges for wiki notes
    missing_frontmatter = []
    epistemic_edge_counts = {
        "CORROBORATES": 0,
        "COMPLEMENTS": 0,
        "EXTENDS": 0,
        "CONTRADICTS": 0,
        "SUPERSEDES": 0,
    }
    for rel_path, data in graph.items():
        if rel_path.startswith("wiki/") and rel_path.endswith(".md"):
            if not data["has_fm"]:
                missing_frontmatter.append(rel_path)
            else:
                fm = data.get("frontmatter") or {}
                for ep_k in ("corroborates", "complements", "extends", "contradicts", "supersedes"):
                    val = fm.get(ep_k)
                    if isinstance(val, list):
                        epistemic_edge_counts[ep_k.upper()] += len(val)
                    elif isinstance(val, str) and val.strip():
                        epistemic_edge_counts[ep_k.upper()] += 1

    is_healthy = (
        len(broken_links) == 0
        and len(table_invariant_violations) == 0
        and len(missing_frontmatter) == 0
    )

    okf_upstream_report = check_upstream_okf_version() if check_okf_upstream else None

    results = {
        "vault_path": str(vault_root),
        "supported_okf_version": SUPPORTED_OKF_VERSION,
        "total_markdown_files": len(all_md_files),
        "total_wiki_notes": len([k for k in all_md_files if k.startswith("wiki/")]),
        "broken_links": broken_links,
        "table_invariant_violations": table_invariant_violations,
        "fixed_files": fixed_files,
        "orphan_notes": orphan_notes,
        "missing_from_index": missing_from_index,
        "missing_frontmatter": missing_frontmatter,
        "epistemic_edge_counts": epistemic_edge_counts,
        "is_healthy": is_healthy,
    }
    if okf_upstream_report is not None:
        results["okf_upstream"] = okf_upstream_report

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        total_ep = sum(epistemic_edge_counts.values())
        print("=" * 60)
        print("🔍 OKF v0.2 Knowledge Compiler Vault Audit Report")
        print("=" * 60)
        print(f"📁 Vault Path: {vault_root}")
        print(f"📄 Total Markdown Files: {results['total_markdown_files']}")
        print(f"📚 Total Wiki Notes: {results['total_wiki_notes']}")
        print(
            f"🧭 Explicit 5-Way Epistemic Frontmatter Edges: {total_ep} "
            f"(CORROBORATES={epistemic_edge_counts['CORROBORATES']}, "
            f"COMPLEMENTS={epistemic_edge_counts['COMPLEMENTS']}, "
            f"EXTENDS={epistemic_edge_counts['EXTENDS']}, "
            f"CONTRADICTS={epistemic_edge_counts['CONTRADICTS']}, "
            f"SUPERSEDES={epistemic_edge_counts['SUPERSEDES']})"
        )
        print("-" * 60)

        if is_healthy and len(orphan_notes) == 0 and len(missing_from_index) == 0:
            print(
                "✨ 100% HEALTHY! All links resolve, table invariants hold, and index is synchronized."
            )
        else:
            if broken_links:
                print(f"❌ Broken Wikilinks ({len(broken_links)}):")
                for b in broken_links:
                    print(f"   • [{b['source']}] -> [[{b['target']}]]")

            if table_invariant_violations:
                print(
                    f"⚠️ Table Wikilink Pipe Invariant Violations ({len(table_invariant_violations)}):"
                )
                for v in table_invariant_violations:
                    print(f"   • [{v['file']}] {v['snippet']}  (Should be: {v['fix']})")
                if auto_fix:
                    print(f"   ⚡ Automatically fixed in {len(fixed_files)} files!")

            if missing_frontmatter:
                print(
                    f"⚠️ Missing/Invalid OKF Frontmatter ({len(missing_frontmatter)}):"
                )
                for m in missing_frontmatter:
                    print(f"   • {m}")

            if orphan_notes:
                print(f"ℹ️ Orphan Notes (0 inbound links, {len(orphan_notes)}):")
                for o in orphan_notes:
                    print(f"   • {o}")

            if missing_from_index:
                print(f"ℹ️ Notes not mentioned in index.md ({len(missing_from_index)}):")
                for mi in missing_from_index:
                    print(f"   • {mi}")

        if okf_upstream_report is not None:
            print("-" * 60)
            _print_okf_upstream_report(okf_upstream_report)

        print("=" * 60)

    return results


def _print_okf_upstream_report(report: dict) -> None:
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


def main():
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
        "--json", action="store_true", help="Output audit results in JSON format."
    )
    parser.add_argument(
        "--check-okf-upstream",
        action="store_true",
        help="Check https://github.com/GoogleCloudPlatform/open-knowledge-format for a newer OKF spec version.",
    )
    args = parser.parse_args()

    # If invoked purely to check upstream OKF version outside a vault, support standalone mode
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
    )

    if not res.get("is_healthy", False):
        if res.get("broken_links") or res.get("table_invariant_violations"):
            sys.exit(1)


if __name__ == "__main__":
    main()
