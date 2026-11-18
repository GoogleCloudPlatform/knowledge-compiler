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
"""Open Source License, Leakr, & Clean-Room Compliance Gate."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

IS_3P_BUNDLE = (REPO_ROOT / ".kc_oss_release").exists() or not (
    REPO_ROOT / "scripts" / "build_oss_release.py"
).exists()

_SKIP_DIR_NAMES = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
}
_HEADER_REQUIRED_SUFFIXES = {".py", ".js", ".sh", ".yml", ".yaml"}
_HEADER_REQUIRED_NAMES = {"Makefile"}
_LEAKR_WORDS_RE = re.compile(
    r"\b(" + "wh" + "itelist" + r"|" + "bl" + "acklist" + r")\b",
    re.IGNORECASE,
)
_SENSITIVE_TERM_RE = re.compile(r"\b" + "confid" + "ential" + r"\b", re.IGNORECASE)
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
)
_STRICT_1P_PRIVACY_PREFIXES = (
    "scripts/",
    "sidecars/",
    ".github/",
    "STABILITY.md",
    "SECURITY.md",
)


def _iter_repo_files(root_dir: Path) -> list[Path]:
    """Return tracked files when git is present, otherwise walk clean source files."""
    if (root_dir / ".git").exists():
        try:
            proc = subprocess.run(
                ["git", "-C", str(root_dir), "ls-files"],
                capture_output=True,
                text=True,
                check=True,
                timeout=15,
            )
            paths = []
            for rel in proc.stdout.splitlines():
                rel = rel.strip()
                if rel:
                    p = root_dir / rel
                    if p.exists() or p.is_symlink():
                        paths.append(p)
            return sorted(paths)
        except Exception:
            pass

    collected: list[Path] = []
    for cur_root, dirs, files in os.walk(root_dir, topdown=True):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIR_NAMES)
        cur_p = Path(cur_root)
        for fname in sorted(files):
            if fname == ".kc_oss_release" or fname.endswith(".pyc"):
                continue
            collected.append(cur_p / fname)
    return collected


def audit_tree_compliance(root_dir: Path, *, strict_mode: bool) -> list[str]:
    """Run Apache-2.0 header, encoding, symlink, disclaimer, and secret checks."""
    violations: list[str] = []

    license_path = root_dir / "LICENSE"
    if not license_path.is_file() or "Apache License" not in license_path.read_text(
        encoding="utf-8"
    ):
        violations.append("Missing or invalid Apache-2.0 LICENSE file.")

    sec_path = root_dir / "SECURITY.md"
    sec_txt = sec_path.read_text(encoding="utf-8") if sec_path.is_file() else ""
    if "g.co/vulnz" not in sec_txt and "bughunters.google.com" not in sec_txt:
        violations.append("Missing SECURITY.md or Google VRP reporting link.")

    contrib_path = root_dir / "CONTRIBUTING.md"
    if not contrib_path.is_file():
        violations.append("Missing CONTRIBUTING.md.")
    elif strict_mode:
        contrib_txt = contrib_path.read_text(encoding="utf-8")
        if "cla.developers.google.com" not in contrib_txt:
            violations.append("CONTRIBUTING.md must reference cla.developers.google.com.")
        if "This is not an officially supported Google product" not in contrib_txt:
            violations.append("CONTRIBUTING.md must include Google OSS disclaimer.")

    ci_path = root_dir / ".github" / "workflows" / "ci.yml"
    if not ci_path.is_file():
        violations.append("Missing .github/workflows/ci.yml.")
    else:
        ci_txt = ci_path.read_text(encoding="utf-8")
        if "tests/test_oss_cross_compliance.py" not in ci_txt:
            violations.append(
                ".github/workflows/ci.yml must run tests/test_oss_cross_compliance.py."
            )
        if "Run Open Source License & Clean-Room Compliance Gate" not in ci_txt:
            violations.append(
                ".github/workflows/ci.yml must name the Compliance Gate step."
            )
        if "permissions:" not in ci_txt:
            violations.append(
                ".github/workflows/ci.yml must declare explicit permissions."
            )
        for ci_line_no, raw_ci_line in enumerate(ci_txt.splitlines(), start=1):
            stripped_ci = raw_ci_line.split("#", 1)[0].strip()
            m_uses = re.search(
                r"(?:^|-\s+)uses:\s*(['\"]?)([^'\"\s]+)\1", stripped_ci
            )
            if m_uses:
                action_ref = m_uses.group(2)
                if not re.search(r"@[0-9a-f]{40}$", action_ref):
                    violations.append(
                        f".github/workflows/ci.yml:{ci_line_no}: action {action_ref!r} must be pinned to a 40-char commit SHA."
                    )

    if strict_mode:
        readme_path = root_dir / "README.md"
        if not readme_path.is_file() or (
            "This is not an officially supported Google product"
            not in readme_path.read_text(encoding="utf-8")
        ):
            violations.append(
                "3P README.md must include 'This is not an officially supported Google product'."
            )

    for fpath in _iter_repo_files(root_dir):
        rel = fpath.relative_to(root_dir).as_posix()
        if fpath.is_symlink():
            violations.append(f"{rel}: symlinks are forbidden in open-source tree.")
            continue
        if not fpath.is_file():
            continue

        raw = fpath.read_bytes()
        if b"\r\n" in raw:
            violations.append(f"{rel}: CRLF line endings found (LF required).")

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            violations.append(f"{rel}: invalid UTF-8 encoding: {exc}")
            continue

        if fpath.suffix in _HEADER_REQUIRED_SUFFIXES or fpath.name in _HEADER_REQUIRED_NAMES:
            head = text[:800]
            if "Copyright 2026 Google LLC" not in head or "Apache License, Version 2.0" not in head:
                violations.append(
                    f"{rel}: missing 13-line Google LLC Apache-2.0 license header."
                )

        m_leakr = _LEAKR_WORDS_RE.search(text)
        if m_leakr:
            line_no = text[: m_leakr.start()].count("\n") + 1
            violations.append(
                f"{rel}:{line_no}: non-inclusive term {m_leakr.group(0)!r} found."
            )

        if strict_mode or rel.startswith(_STRICT_1P_PRIVACY_PREFIXES):
            m_conf = _SENSITIVE_TERM_RE.search(text)
            if m_conf:
                line_no = text[: m_conf.start()].count("\n") + 1
                violations.append(
                    f"{rel}:{line_no}: forbidden term {m_conf.group(0)!r} found."
                )

        for sec_re in _SECRET_PATTERNS:
            if (
                rel == "tests/test_p0_correct_and_hooks.py"
                and "PRIVATE KEY" in sec_re.pattern
                and "MIIEowIBAAKCAQEA" in text
            ):
                continue
            m_sec = sec_re.search(text)
            if m_sec:
                line_no = text[: m_sec.start()].count("\n") + 1
                violations.append(
                    f"{rel}:{line_no}: potential credential/secret pattern found."
                )

    return violations


class TestOssCrossCompliance(unittest.TestCase):
    """Verify Open Source licensing, Clean-Room compliance, and CI gate invariants."""

    def test_repository_open_source_compliance(self) -> None:
        violations = audit_tree_compliance(
            REPO_ROOT,
            strict_mode=IS_3P_BUNDLE,
        )
        self.assertEqual(violations, [], msg="\n".join(violations))

        if not IS_3P_BUNDLE:
            import build_oss_release

            readme_3p = build_oss_release._render_3p_readme(
                "knowledge-compiler", "Knowledge Compiler", "1.2.0"
            )
            self.assertIn("This is not an officially supported Google product", readme_3p)
            contrib_3p = build_oss_release._render_3p_contributing(
                "knowledge-compiler", "Knowledge Compiler"
            )
            self.assertIn("cla.developers.google.com", contrib_3p)
            self.assertIn("This is not an officially supported Google product", contrib_3p)


if __name__ == "__main__":
    unittest.main()
