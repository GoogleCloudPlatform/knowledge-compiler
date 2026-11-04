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
3. Preserves graph integrity and enforces Table Pipe Invariants.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


def find_vault_root(start_path: Optional[Path] = None) -> Path:
    """Locates the active Knowledge Compiler vault root."""
    if start_path:
        p = Path(start_path).expanduser().resolve()
        if (p / "GEMINI.md").exists() or (p / "wiki").exists() or (p / "raw").exists():
            return p
        if p.is_dir():
            return p

    cwd = Path.cwd().resolve()
    for parent in [cwd] + list(cwd.parents):
        if (
            (parent / "GEMINI.md").exists()
            or (parent / "wiki").exists()
            or (parent / "raw").exists()
        ):
            return parent

    vault_env = os.environ.get("OBSIDIAN_VAULT_PATH")
    default_vault = (
        Path(vault_env).expanduser().resolve()
        if vault_env
        else (Path.home() / "ObsidianVault")
    )
    if default_vault.exists():
        return default_vault

    return cwd


def parse_frontmatter(content: str) -> Tuple[Dict[str, Any], str]:
    """Extracts YAML frontmatter and body from markdown content."""
    if not content.startswith("---"):
        return {}, content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content

    fm_text = parts[1]
    body = parts[2]

    # Simple lenient key-value YAML parser
    data: Dict[str, Any] = {}
    for line in fm_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip().strip("'\"")
            data[k] = v

    return data, body


def update_frontmatter_date(content: str, new_date: Optional[str] = None) -> str:
    """Updates the 'updated: YYYY-MM-DD' field in frontmatter."""
    if new_date is None:
        new_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if not content.startswith("---"):
        return content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return content

    fm_text = parts[1]
    body = parts[2]

    if re.search(r"^updated:\s*.*$", fm_text, re.MULTILINE):
        new_fm = re.sub(
            r"^updated:\s*.*$", f"updated: {new_date}", fm_text, flags=re.MULTILINE
        )
    else:
        new_fm = fm_text.rstrip() + f"\nupdated: {new_date}\n"

    return f"---{new_fm}---{body}"


def is_historical_note(
    file_path: Path, vault_root: Path, frontmatter: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Determines if a note is historical and MUST be preserved without rewriting.

    A note is historical if ANY one holds:
    1. It sits under an immutable or record directory (raw/, archive/, meetings/, 1-1/, journal/, incidents/).
    2. Its relative path or filename carries a date pattern (e.g. YYYY-MM-DD or (YYYY-MM-DD)).
    3. It is in wiki/sources/ (immutable source extraction summaries).
    4. Its frontmatter status is 'superseded', 'archived', 'completed', 'deprecated', or 'done'.
    5. It is the operations ledger 'log.md'.
    """
    rel = str(file_path.relative_to(vault_root)).replace("\\", "/")

    if rel == "log.md":
        return True, "Operations audit log is immutable ledger"

    record_dirs = ["raw/", "archive/", "meetings/", "1-1/", "journal/", "incidents/"]
    for rd in record_dirs:
        if rd in rel or rel.startswith(rd):
            return True, f"Located in record directory '{rd}'"

    if rel.startswith("wiki/sources/"):
        return (
            True,
            "Source summaries in wiki/sources/ represent historical ingest snapshots",
        )

    # Check for date patterns in filename or path
    # e.g., 2026-10-08, (2026-10-07), 2026-Q3
    stem = file_path.stem
    if re.search(r"\b\d{4}-\d{2}-\d{2}\b", stem) or re.search(r"\(\d{4}-\d{2}\)", stem):
        return True, f"Filename contains explicit date provenance '{stem}'"

    # Frontmatter status
    status = str(frontmatter.get("status", "")).lower()
    historical_statuses = {"superseded", "archived", "completed", "deprecated", "done"}
    if status in historical_statuses:
        return True, f"Frontmatter status is '{status}'"

    return False, ""


def find_candidate_notes(
    vault_root: Path,
    terms: List[str],
    exclude_patterns: Optional[List[str]] = None,
) -> List[Path]:
    """Finds markdown files in the vault matching any of the given search terms."""
    matched = []
    exclude_patterns = exclude_patterns or [
        ".git",
        ".obsidian",
        ".gemini",
        "__pycache__",
        ".venv",
    ]

    for root, dirs, files in os.walk(vault_root):
        dirs[:] = [d for d in dirs if d not in exclude_patterns]
        for f in files:
            if not f.endswith(".md"):
                continue
            full_path = Path(root) / f
            try:
                text = full_path.read_text(encoding="utf-8", errors="ignore")
                for term in terms:
                    if re.search(re.escape(term), text, re.IGNORECASE):
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
    }

    # Extract target authoritative stem if given
    target_stem = None
    if target_authoritative:
        t_path = Path(target_authoritative)
        target_stem = t_path.stem.lower()

    for f in matched_files:
        rel = str(f.relative_to(vault_root)).replace("\\", "/")
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        fm, body = parse_frontmatter(content)
        title = fm.get("title", f.stem)

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
        if target_stem:
            if (
                f.stem.lower() == target_stem
                or rel.lower() == target_stem
                or title.lower() == target_stem
            ):
                is_auth = True
        elif rel.startswith("wiki/entities/") or rel.startswith("wiki/concepts/"):
            # If no target specified, check if note title is heavily featured in the fact
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


def replace_restatements_with_link(
    content: str,
    stale_patterns: List[str],
    authoritative_title: str,
) -> Tuple[str, int]:
    """
    Replaces stale pattern occurrences outside of code blocks with a clean [[Authoritative Title]] link.
    Guarantees no escaped pipes in table context.
    """
    lines = content.splitlines()
    in_code_block = False
    replacements_made = 0
    new_lines = []

    link_target = f"[[{authoritative_title}]]"

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            new_lines.append(line)
            continue

        if in_code_block:
            new_lines.append(line)
            continue

        modified_line = line
        for pat in stale_patterns:
            if not pat.strip():
                continue
            # Regex match case-insensitive
            regex = re.compile(re.escape(pat), re.IGNORECASE)
            if regex.search(modified_line):
                # Replace with wikilink
                modified_line = regex.sub(link_target, modified_line)
                replacements_made += 1

        new_lines.append(modified_line)

    return "\n".join(new_lines) + (
        "\n" if content.endswith("\n") else ""
    ), replacements_made


def execute_vault_correction(
    vault_root: Path,
    fact: str,
    stale_claim: Optional[str] = None,
    target_authoritative: Optional[str] = None,
    dry_run: bool = False,
    auto: bool = False,
) -> Dict[str, Any]:
    """
    Runs the complete tri-state vault correction sweep.
    """
    vault_root = vault_root.resolve()
    search_terms = []
    if stale_claim:
        search_terms.append(stale_claim.strip())

    # Extract salient keywords from fact (numbers, version tokens, capitalized phrases)
    keywords = re.findall(
        r"\b[A-Z][a-zA-Z0-9_\-\.]+\b|\$\d+[\d,]*|\bv\d+[\d\.]*\b|\b\d+[\d,]*\b", fact
    )
    for kw in keywords:
        if len(kw) > 2 and kw not in ["The", "And", "For", "With", "Not"]:
            if kw not in search_terms:
                search_terms.append(kw)

    if not search_terms:
        search_terms = [fact[:40]]

    # 1. Sweep files
    candidates = find_candidate_notes(vault_root, search_terms)

    # 2. Tri-state classification
    classified = classify_notes(
        matched_files=candidates,
        vault_root=vault_root,
        target_authoritative=target_authoritative,
        fact=fact,
    )

    results: Dict[str, Any] = {
        "vault_path": str(vault_root),
        "fact": fact,
        "stale_claim": stale_claim,
        "dry_run": dry_run,
        "authoritative_updated": [],
        "restatements_refactored": [],
        "historical_preserved": [],
        "errors": [],
    }

    # Record historical preservations
    for hist in classified["historical"]:
        results["historical_preserved"].append(
            {
                "rel_path": hist["rel_path"],
                "title": hist["title"],
                "reason": hist["reason"],
            }
        )

    # Validate authoritative note identification
    auth_list = classified["authoritative"]
    if not auth_list:
        if not auto:
            # If no authoritative note identified, do not guess
            results["errors"].append(
                "No authoritative note identified. Provide --target <note> or name an entity/concept."
            )
            return results
        # In auto mode without explicit auth note, we report without destructive replacement
        results["errors"].append(
            "Skipping edits: authoritative single-source note could not be resolved."
        )
        return results

    auth_entry = auth_list[0]
    auth_path = auth_entry["path"]
    auth_title = auth_entry["title"]

    # 3. Apply to Authoritative Note
    try:
        auth_content = auth_path.read_text(encoding="utf-8")
        updated_auth = update_frontmatter_date(auth_content)

        # If stale claim is directly present in authoritative note, replace it with the new fact
        if stale_claim and re.search(
            re.escape(stale_claim), updated_auth, re.IGNORECASE
        ):
            updated_auth = re.sub(
                re.escape(stale_claim), fact, updated_auth, flags=re.IGNORECASE
            )
        elif fact not in updated_auth:
            # Append fact note or bullet if not present
            updated_auth = (
                updated_auth.rstrip()
                + f"\n\n> [!NOTE] Architectural Specification Update\n> {fact}\n"
            )

        if not dry_run:
            auth_path.write_text(updated_auth, encoding="utf-8")

        results["authoritative_updated"].append(
            {
                "rel_path": auth_entry["rel_path"],
                "title": auth_title,
                "status": "updated",
            }
        )
    except Exception as e:
        results["errors"].append(
            f"Failed to update authoritative note {auth_path}: {e}"
        )

    # 4. Refactor Restatements
    stale_patterns = [stale_claim] if stale_claim else []
    if not stale_patterns:
        # Use distinctive keywords that identify the stale claim
        stale_patterns = [kw for kw in keywords if kw.startswith("$") or "v" in kw]

    for rest in classified["restatement"]:
        r_path = rest["path"]
        try:
            r_content = r_path.read_text(encoding="utf-8")
            if stale_patterns:
                new_content, count = replace_restatements_with_link(
                    r_content,
                    stale_patterns=stale_patterns,
                    authoritative_title=auth_title,
                )
                if count > 0:
                    new_content = update_frontmatter_date(new_content)
                    if not dry_run:
                        r_path.write_text(new_content, encoding="utf-8")
                    results["restatements_refactored"].append(
                        {
                            "rel_path": rest["rel_path"],
                            "title": rest["title"],
                            "replacements": count,
                            "status": "refactored_to_wikilink",
                        }
                    )
        except Exception as e:
            results["errors"].append(f"Failed to refactor restatement {r_path}: {e}")

    # 5. Record Operation in log.md
    if not dry_run and (
        results["authoritative_updated"] or results["restatements_refactored"]
    ):
        log_file = vault_root / "log.md"
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

        if log_file.exists():
            try:
                cur_log = log_file.read_text(encoding="utf-8")
                # Insert below header or prepend
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
                log_file.write_text(new_log, encoding="utf-8")
            except Exception as e:
                results["errors"].append(f"Failed to update log.md: {e}")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sweep a corrected fact through the OKF v0.2 Knowledge Compiler vault."
    )
    parser.add_argument(
        "fact", nargs="?", help="The corrected fact, stated as it is now true."
    )
    parser.add_argument(
        "--stale", "-s", help="The stale claim or phrase to find and replace."
    )
    parser.add_argument(
        "--target", "-t", help="Authoritative note title or path to update."
    )
    parser.add_argument("--vault-path", "-p", help="Root path of the knowledge vault.")
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Report what would change without modifying files.",
    )
    parser.add_argument(
        "--auto", action="store_true", help="Autonomous mode for agent pipelines."
    )
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON."
    )

    args = parser.parse_args()

    if not args.fact:
        parser.print_help()
        sys.exit(1)

    vault_root = find_vault_root(Path(args.vault_path) if args.vault_path else None)
    results = execute_vault_correction(
        vault_root=vault_root,
        fact=args.fact,
        stale_claim=args.stale,
        target_authoritative=args.target,
        dry_run=args.dry_run,
        auto=args.auto,
    )

    if args.json:
        print(json.dumps(results, indent=2))
        return

    # User-facing report
    print(
        f"\n🔍 OKF v0.2 Vault Correction Sweep ({'DRY RUN' if args.dry_run else 'EXECUTED'})"
    )
    print(f"📁 Vault: {vault_root}")
    print(f'📌 Corrected Fact: "{args.fact}"\n')

    if results["authoritative_updated"]:
        print("  AUTHORITATIVE (Source of Truth):")
        for au in results["authoritative_updated"]:
            print(f"    ✓ {au['rel_path']}  ← applied & updated")

    if results["restatements_refactored"]:
        print("\n  RESTATEMENTS (Refactored to Wikilinks):")
        for rf in results["restatements_refactored"]:
            print(
                f"    🔗 {rf['rel_path']}  → {rf['replacements']} assertion(s) replaced with link"
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

    if results["errors"]:
        print("\n  ⚠️ WARNINGS / ERRORS:")
        for err in results["errors"]:
            print(f"    • {err}")

    summary_counts = (
        f"{len(results['authoritative_updated'])} authoritative updated, "
        f"{len(results['restatements_refactored'])} restatements refactored, "
        f"{len(results['historical_preserved'])} historical notes preserved."
    )
    print(f"\n📊 Summary: {summary_counts}")
    if args.dry_run:
        print("Dry run completed. Re-run without --dry-run to apply changes.")


if __name__ == "__main__":
    main()
