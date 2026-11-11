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
"""Deterministic offline Asymmetric Rollback Evaluator for WikiSkill (`SKILL.md`) updates."""

from __future__ import annotations

import argparse
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import init_vault  # noqa: E402
import okf  # noqa: E402

_WIKI_CHEAT_WIKILINK_RE = re.compile(
    r"\[\[\s*(?:wiki|patterns|concepts|entities|synthesis|sources|raw)/[^\]\n]+\]\]",
    re.IGNORECASE,
)
_WIKI_CHEAT_MDLINK_RE = re.compile(
    r"\]\(\s*(?:\.\./)*(?:wiki|patterns|concepts|entities|synthesis|sources|raw)/[^\)\n]+\)",
    re.IGNORECASE,
)


def _pattern_matches(text: str, pattern: str) -> bool:
    """Return True if literal case-insensitive substring or compiled regex matches text."""
    if not pattern:
        return True
    if pattern.lower() in text.lower():
        return True
    try:
        return bool(re.search(pattern, text, re.IGNORECASE | re.MULTILINE))
    except re.error:
        return False


def _validate_skill_frontmatter(skill_text: str, max_bytes: int) -> dict[str, Any]:
    """Validate SKILL.md YAML frontmatter (`name`, `description`) and UTF-8 byte ceiling."""
    utf8_bytes = len(skill_text.encode("utf-8"))
    size_ok = utf8_bytes <= max_bytes
    has_fm, yaml_block, _body = okf.split_frontmatter(skill_text)
    errors: list[str] = []
    name_val = ""
    desc_val = ""
    if not has_fm or yaml_block is None:
        errors.append("Missing YAML frontmatter block (`--- ... ---`).")
    else:
        parsed = okf.parse_frontmatter(yaml_block)
        if not parsed:
            errors.append("Invalid or unparseable YAML frontmatter.")
        else:
            name_raw = parsed.get("name")
            desc_raw = parsed.get("description")
            if not isinstance(name_raw, str) or not name_raw.strip():
                errors.append("Frontmatter must include a non-empty `name` string.")
            else:
                name_val = name_raw.strip()
            if not isinstance(desc_raw, str) or not desc_raw.strip():
                errors.append("Frontmatter must include a non-empty `description` string.")
            else:
                desc_val = desc_raw.strip()
    if not size_ok:
        errors.append(
            f"Candidate SKILL.md exceeds max byte budget ({utf8_bytes} > {max_bytes} bytes)."
        )
    return {
        "valid_frontmatter": len([e for e in errors if "budget" not in e]) == 0,
        "size_ok": size_ok,
        "utf8_bytes": utf8_bytes,
        "max_bytes": max_bytes,
        "skill_name": name_val,
        "description": desc_val,
        "errors": errors,
    }


def detect_isolation_violations(skill_text: str) -> list[str]:
    """Detect forbidden background-wiki references inside SKILL.md (Failure Mode Isolation)."""
    violations: list[str] = []
    for rx in (_WIKI_CHEAT_WIKILINK_RE, _WIKI_CHEAT_MDLINK_RE):
        for match in rx.finditer(skill_text):
            snippet = match.group(0).strip()
            if snippet not in violations:
                violations.append(snippet)
    return violations


def _evaluate_cases(skill_text: str, cases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Run deterministic required/forbidden pattern checks for all suite cases."""
    results: dict[str, dict[str, Any]] = {}
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"Eval suite case at index {idx} must be a JSON object.")
        case_id = str(case.get("id") or f"case-{idx + 1}")
        req = case.get("required_patterns") or []
        forb = case.get("forbidden_patterns") or []
        if not isinstance(req, list) or not isinstance(forb, list):
            raise ValueError(
                f"Eval case '{case_id}' required_patterns and forbidden_patterns must be lists."
            )
        missing = [str(p) for p in req if not _pattern_matches(skill_text, str(p))]
        forbidden_hits = [str(p) for p in forb if _pattern_matches(skill_text, str(p))]
        passed = len(missing) == 0 and len(forbidden_hits) == 0
        results[case_id] = {
            "id": case_id,
            "passed": passed,
            "missing_required": missing,
            "forbidden_hits": forbidden_hits,
            "target_error_signature": str(case.get("target_error_signature") or ""),
        }
    return results


def _build_diff_summary(baseline_text: str, candidate_text: str) -> str:
    diff_lines = list(
        difflib.unified_diff(
            baseline_text.splitlines(),
            candidate_text.splitlines(),
            fromfile="baseline/SKILL.md",
            tofile="candidate/SKILL.md",
            n=2,
            lineterm="",
        )
    )
    if len(diff_lines) > 60:
        diff_lines = diff_lines[:60] + ["... (diff truncated)"]
    return "\n".join(diff_lines)


def _append_skill_impact_ledger(
    vault_root: Path,
    eval_report: dict[str, Any],
    diff_summary: str,
) -> Path:
    """Append Accepted/Rejected outcome to `<vault>/wiki/skill-impact.md` with SHA-256 CAS."""
    if vault_root.is_symlink():
        raise ValueError(f"Refusing symlinked vault root: {vault_root}")
    vault_resolved = vault_root.resolve()
    wiki_dir = vault_resolved / "wiki"
    if not wiki_dir.is_dir() or wiki_dir.is_symlink():
        raise ValueError(f"Invalid or missing wiki/ directory inside vault: {wiki_dir}")

    impact_path = wiki_dir / "skill-impact.md"
    if impact_path.is_symlink():
        raise ValueError(f"Refusing symlinked ledger path: {impact_path}")
    resolved_impact = impact_path.resolve()
    if resolved_impact.parent != wiki_dir.resolve() or resolved_impact.name != "skill-impact.md":
        raise ValueError(f"Ledger containment violation: {resolved_impact}")

    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    if impact_path.exists():
        raw_before = impact_path.read_bytes()
        expected_sha: str | None = hashlib.sha256(raw_before).hexdigest()
        existing_text = raw_before.decode("utf-8")
    else:
        expected_sha = None
        existing_text = init_vault.DEFAULT_SKILL_IMPACT_MD.format(today=today)

    decision_label = "Accepted" if eval_report["decision"] == "ACCEPTED" else "Rejected"
    skill_name = eval_report.get("skill_name") or Path(eval_report["candidate_skill"]).parent.name
    entry_lines = [
        "",
        f"## [{today}] {decision_label} | `{skill_name}`",
        f"- **Baseline Pass Rate**: {eval_report['baseline_passed']}/{eval_report['total_cases']}",
        f"- **Candidate Pass Rate**: {eval_report['candidate_passed']}/{eval_report['total_cases']}",
        f"- **Regressions**: {len(eval_report['regressions'])}",
        f"- **Isolation Violations**: {len(eval_report['isolation_violations'])}",
    ]
    if eval_report["regressions"]:
        entry_lines.append(
            f"- **Regressed Cases**: {', '.join(eval_report['regressions'])}"
        )
    if eval_report["isolation_violations"]:
        entry_lines.append(
            "- **Isolation Matches**: "
            + ", ".join(f"`{v}`" for v in eval_report["isolation_violations"])
        )
    if eval_report.get("frontmatter_errors"):
        entry_lines.append(
            "- **Schema/Budget Errors**: "
            + "; ".join(eval_report["frontmatter_errors"])
        )
    if diff_summary:
        entry_lines.extend(["", "```diff", diff_summary, "```"])

    new_text = existing_text.rstrip("\n") + "\n" + "\n".join(entry_lines) + "\n"

    # Verify CAS immediately prior to atomic write
    if expected_sha is not None:
        if not impact_path.exists() or impact_path.is_symlink():
            raise RuntimeError("CAS conflict: skill-impact.md disappeared or became a symlink.")
        cur_sha = hashlib.sha256(impact_path.read_bytes()).hexdigest()
        if cur_sha != expected_sha:
            raise RuntimeError(
                f"CAS conflict on {impact_path}: expected {expected_sha}, found {cur_sha}"
            )
    elif impact_path.exists():
        raise RuntimeError(f"CAS conflict: {impact_path} was created concurrently.")

    tmp_path = wiki_dir / f".skill-impact.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp_path, flags, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(new_text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, impact_path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return impact_path


def evaluate_skill_update(
    baseline_skill: str | Path,
    candidate_skill: str | Path,
    eval_suite_path: str | Path,
    *,
    max_bytes: int = 32768,
    vault_path: str | Path | None = None,
    apply_impact: bool = False,
) -> tuple[dict[str, Any], int]:
    """Evaluate candidate SKILL.md vs baseline SKILL.md under the Asymmetric Rollback Gate."""
    base_p = Path(baseline_skill).expanduser()
    cand_p = Path(candidate_skill).expanduser()
    suite_p = Path(eval_suite_path).expanduser()

    for lbl, p in (
        ("baseline skill", base_p),
        ("candidate skill", cand_p),
        ("eval suite", suite_p),
    ):
        if not p.is_file() or p.is_symlink():
            raise FileNotFoundError(f"Missing or invalid {lbl} file: {p}")

    if apply_impact and vault_path is None:
        raise ValueError("--vault is required when --apply-impact is specified.")

    baseline_text = base_p.read_text(encoding="utf-8")
    candidate_text = cand_p.read_text(encoding="utf-8")
    suite_raw = json.loads(suite_p.read_text(encoding="utf-8"))
    if isinstance(suite_raw, dict):
        cases = suite_raw.get("cases")
    elif isinstance(suite_raw, list):
        cases = suite_raw
    else:
        raise ValueError("Eval suite JSON must be an object with 'cases' list or a list.")
    if not isinstance(cases, list):
        raise ValueError("Eval suite 'cases' field must be a list.")

    fm_info = _validate_skill_frontmatter(candidate_text, max_bytes=max_bytes)
    isolation_violations = detect_isolation_violations(candidate_text)
    base_results = _evaluate_cases(baseline_text, cases)
    cand_results = _evaluate_cases(candidate_text, cases)

    total_cases = len(cases)
    baseline_passed = sum(1 for r in base_results.values() if r["passed"])
    candidate_passed = sum(1 for r in cand_results.values() if r["passed"])
    regressions = [
        cid
        for cid, b_res in base_results.items()
        if b_res["passed"] and not cand_results[cid]["passed"]
    ]

    accepted = (
        fm_info["valid_frontmatter"]
        and fm_info["size_ok"]
        and len(isolation_violations) == 0
        and len(regressions) == 0
        and total_cases > 0
        and (candidate_passed > baseline_passed or candidate_passed == total_cases)
    )
    decision = "ACCEPTED" if accepted else "REJECTED"
    diff_summary = _build_diff_summary(baseline_text, candidate_text)

    report: dict[str, Any] = {
        "success": True,
        "decision": decision,
        "accepted": accepted,
        "skill_name": fm_info["skill_name"] or cand_p.parent.name,
        "baseline_skill": str(base_p.resolve()),
        "candidate_skill": str(cand_p.resolve()),
        "eval_suite": str(suite_p.resolve()),
        "valid_frontmatter": fm_info["valid_frontmatter"],
        "size_ok": fm_info["size_ok"],
        "utf8_bytes": fm_info["utf8_bytes"],
        "max_bytes": max_bytes,
        "frontmatter_errors": fm_info["errors"],
        "isolation_violations": isolation_violations,
        "total_cases": total_cases,
        "baseline_passed": baseline_passed,
        "candidate_passed": candidate_passed,
        "regressions": regressions,
        "case_results": [
            {
                "id": cid,
                "baseline_passed": base_results[cid]["passed"],
                "candidate_passed": cand_results[cid]["passed"],
                "missing_required": cand_results[cid]["missing_required"],
                "forbidden_hits": cand_results[cid]["forbidden_hits"],
            }
            for cid in base_results
        ],
        "diff_summary": diff_summary,
        "impact_ledger_updated": None,
    }

    if apply_impact and vault_path is not None:
        v_dir = Path(vault_path).expanduser()
        ledger_path = _append_skill_impact_ledger(v_dir, report, diff_summary)
        report["impact_ledger_updated"] = str(ledger_path)

    return report, (0 if accepted else 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic offline Asymmetric Rollback Evaluator for WikiSkill SKILL.md patches."
    )
    parser.add_argument(
        "--baseline-skill",
        required=True,
        help="Path to baseline SKILL.md.",
    )
    parser.add_argument(
        "--candidate-skill",
        required=True,
        help="Path to candidate SKILL.md.",
    )
    parser.add_argument(
        "--eval-suite",
        required=True,
        help="Path to JSON evaluation suite.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=32768,
        help="Maximum UTF-8 byte budget for candidate SKILL.md (default: 32768).",
    )
    parser.add_argument(
        "--vault",
        default=None,
        help="Path to vault root containing wiki/skill-impact.md.",
    )
    parser.add_argument(
        "--apply-impact",
        action="store_true",
        help="Append evaluation outcome to <vault>/wiki/skill-impact.md using SHA-256 CAS.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON.",
    )
    args = parser.parse_args(argv)

    try:
        report, exit_code = evaluate_skill_update(
            args.baseline_skill,
            args.candidate_skill,
            args.eval_suite,
            max_bytes=args.max_bytes,
            vault_path=args.vault,
            apply_impact=args.apply_impact,
        )
    except (FileNotFoundError, ValueError, json.JSONDecodeError, RuntimeError, OSError) as exc:
        err_payload = {"success": False, "error": str(exc)}
        if args.json:
            print(json.dumps(err_payload, indent=2))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"WikiSkill Eval [{report['decision']}]: "
            f"baseline {report['baseline_passed']}/{report['total_cases']} -> "
            f"candidate {report['candidate_passed']}/{report['total_cases']} "
            f"(regressions={len(report['regressions'])}, "
            f"isolation_violations={len(report['isolation_violations'])})"
        )
        if report["impact_ledger_updated"]:
            print(f"Updated ledger: {report['impact_ledger_updated']}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
