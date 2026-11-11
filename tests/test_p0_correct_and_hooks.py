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
"""Regression tests for P0-2 (vault_correct) and P0-5b (hooks & trace analysis)."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
HOOKS_DIR = SCRIPTS_DIR / "hooks"
for _p in (str(REPO_ROOT), str(SCRIPTS_DIR), str(HOOKS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import analyze_trace  # noqa: E402
import auto_sync_vault  # noqa: E402
import install_plugin  # noqa: E402
import log_tool_failure  # noqa: E402
import session_sync  # noqa: E402
import vault_correct  # noqa: E402


class TestP0VaultCorrect(unittest.TestCase):
    """Verify P0-2 correctness, safety masking, exclusions, Plan-by-default, and CAS."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="kc_p0_correct_"))
        self.vault_root = self.tmp_dir / "TestVault"
        for rel_dir in ("raw", "wiki/entities", "wiki/concepts", "wiki/synthesis", "wiki/sources", "rules", "skills/demo", ".agents/rules", ".gemini"):
            (self.vault_root / rel_dir).mkdir(parents=True, exist_ok=True)
        (self.vault_root / "GEMINI.md").write_text("# GEMINI\n16GiB RAM policy\n", encoding="utf-8")
        (self.vault_root / "AGENTS.md").write_text("# AGENTS\n16GiB RAM policy\n", encoding="utf-8")
        (self.vault_root / "CLAUDE.md").write_text("# CLAUDE\n16GiB RAM policy\n", encoding="utf-8")
        (self.vault_root / "index.md").write_text("# Index\n- 16GiB RAM\n", encoding="utf-8")
        (self.vault_root / "log.md").write_text("# Log\n\n## [2026-10-01] init\n- 16GiB RAM\n", encoding="utf-8")
        (self.vault_root / "wiki" / "skill-impact.md").write_text("# Skill Impact\n- 16GiB RAM\n", encoding="utf-8")
        (self.vault_root / ".agents" / "rules" / "AGENTS.md").write_text("# Rules\n16GiB RAM\n", encoding="utf-8")
        (self.vault_root / "rules" / "custom.md").write_text("# Custom Rule\n16GiB RAM\n", encoding="utf-8")
        (self.vault_root / "skills" / "demo" / "SKILL.md").write_text("# Skill\n16GiB RAM\n", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_parse_frontmatter_yaml_and_fallback(self) -> None:
        doc = (
            "---\n"
            "title: Cloud Run Limits\n"
            "type: concept\n"
            "tags:\n"
            "  - gcp/cloud-run\n"
            "  - serverless\n"
            "aliases:\n"
            "  - CR Limits\n"
            "sources:\n"
            "  - resource: https://cloud.google.com/run\n"
            "    id: cr-docs\n"
            "generated:\n"
            "  by: knowledge-compiler/0.9.0\n"
            "  at: 2026-10-01\n"
            "verified:\n"
            "  - by: human:reviewer\n"
            "    at: 2026-10-02\n"
            "---\n"
            "# Cloud Run Limits\n"
        )
        fm, body = vault_correct.parse_frontmatter(doc)
        self.assertEqual(fm["tags"], ["gcp/cloud-run", "serverless"])
        self.assertEqual(fm["aliases"], ["CR Limits"])
        self.assertIsInstance(fm["sources"], list)
        self.assertEqual(fm["sources"][0]["id"], "cr-docs")
        self.assertIsInstance(fm["generated"], dict)
        self.assertEqual(fm["generated"]["by"], "knowledge-compiler/0.9.0")
        self.assertIsInstance(fm["verified"], list)
        self.assertEqual(fm["verified"][0]["by"], "human:reviewer")
        self.assertEqual(body, "# Cloud Run Limits\n")

        # Fallback path with yaml=None still parses lists cleanly
        orig_yaml = vault_correct.yaml
        try:
            vault_correct.yaml = None
            fm_fb, body_fb = vault_correct.parse_frontmatter(doc)
            self.assertEqual(fm_fb["title"], "Cloud Run Limits")
            self.assertEqual(fm_fb["tags"], ["gcp/cloud-run", "serverless"])
            self.assertEqual(body_fb, "# Cloud Run Limits\n")
        finally:
            vault_correct.yaml = orig_yaml

    def test_requires_explicit_stale_claim_no_v_fallback(self) -> None:
        auth = self.vault_root / "wiki" / "concepts" / "Cloud Run Limits.md"
        auth_text = "---\ntitle: Cloud Run Limits\ntype: concept\nstatus: stable\n---\n# Cloud Run Limits\nSupports 16GiB RAM.\n"
        auth.write_text(auth_text, encoding="utf-8")

        unrelated = self.vault_root / "wiki" / "concepts" / "Microservices.md"
        unrelated_text = "---\ntitle: Microservices\ntype: concept\nstatus: stable\n---\nEvery service runs over HTTP.\n"
        unrelated.write_text(unrelated_text, encoding="utf-8")

        res = vault_correct.execute_vault_correction(
            vault_root=self.vault_root,
            fact="Cloud Run Service supports 32GiB RAM on Vertex",
            stale_claim=None,
            target_authoritative="Cloud Run Limits",
            dry_run=False,
        )
        self.assertTrue(res["errors"])
        self.assertEqual(res["restatements_refactored"], [])
        self.assertEqual(unrelated.read_text(encoding="utf-8"), unrelated_text)
        self.assertEqual(auth.read_text(encoding="utf-8"), auth_text)

    def test_readme_authoritative_duplication_and_backslash_safety(self) -> None:
        auth = self.vault_root / "wiki" / "concepts" / "Cloud Run Limits.md"
        auth.write_text(
            "---\n"
            "title: Cloud Run Limits\n"
            "type: concept\n"
            "status: stable\n"
            "tags:\n"
            "  - 16GiB RAM\n"
            "aliases:\n"
            "  - 16GiB RAM Limits\n"
            "generated:\n"
            "  by: agent\n"
            "updated: 2026-10-01\n"
            "---\n"
            "# Cloud Run Limits\n\n"
            "Cloud Run supports 16GiB RAM per instance.\n\n"
            "```bash\n"
            "gcloud run deploy --memory 16GiB RAM\n"
            "```\n\n"
            "Flag `--memory 16GiB RAM` and link [[Cloud Run Limits|16GiB RAM]].\n",
            encoding="utf-8",
        )

        rest = self.vault_root / "wiki" / "synthesis" / "Sizing Guide.md"
        rest.write_text(
            "---\n"
            "title: Sizing Guide 16GiB RAM\n"
            "type: synthesis\n"
            "status: stable\n"
            "tags:\n"
            "  - 16GiB RAM\n"
            "updated: 2026-10-01\n"
            "---\n"
            "# Sizing Guide\n\n"
            "Default memory cap is 16GiB RAM.\n"
            "Inline `16GiB RAM` and [[Cloud Run Limits|16GiB RAM]] stay intact.\n",
            encoding="utf-8",
        )

        res = vault_correct.execute_vault_correction(
            vault_root=self.vault_root,
            fact="Cloud Run supports 32GiB RAM",
            stale_claim="16GiB RAM",
            target_authoritative="Cloud Run Limits",
            apply=True,
        )
        self.assertEqual(res["errors"], [])
        self.assertTrue(res["applied"])

        auth_out = auth.read_text(encoding="utf-8")
        self.assertIn("Cloud Run supports 32GiB RAM per instance.\n", auth_out)
        self.assertNotIn("Cloud Run supports Cloud Run supports", auth_out)
        # Frontmatter, fenced code, inline code, and existing wikilink preserved
        self.assertIn("  - 16GiB RAM\n", auth_out)
        self.assertIn("  - 16GiB RAM Limits\n", auth_out)
        self.assertIn("gcloud run deploy --memory 16GiB RAM", auth_out)
        self.assertIn("`--memory 16GiB RAM`", auth_out)
        self.assertIn("[[Cloud Run Limits|16GiB RAM]]", auth_out)

        rest_out = rest.read_text(encoding="utf-8")
        self.assertIn("title: Sizing Guide 16GiB RAM", rest_out)
        self.assertIn("Default memory cap is [[Cloud Run Limits]].", rest_out)
        self.assertIn("`16GiB RAM`", rest_out)
        self.assertIn("[[Cloud Run Limits|16GiB RAM]]", rest_out)
        self.assertNotIn("[[[[", rest_out)

        # Backslash in fact must never raise re.error
        auth.write_text(
            "---\ntitle: Path Note\ntype: concept\nstatus: stable\n---\nPath is /old/dir.\n",
            encoding="utf-8",
        )
        res_bs = vault_correct.execute_vault_correction(
            vault_root=self.vault_root,
            fact=r"Path is C:\new\1\dir\g<0>",
            stale_claim="/old/dir",
            target_authoritative="Path Note",
            apply=True,
        )
        self.assertEqual(res_bs["errors"], [])
        self.assertIn(r"C:\new\1\dir\g<0>", auth.read_text(encoding="utf-8"))

    def test_reserved_historical_and_symlink_exclusions_with_relative_parts(self) -> None:
        # Vault residing inside a parent directory named `.agents` or `raw` must still work!
        nested_vault = self.tmp_dir / ".agents" / "raw" / "NestedVault"
        (nested_vault / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
        (nested_vault / "wiki" / "sources").mkdir(parents=True, exist_ok=True)
        (nested_vault / "raw").mkdir(parents=True, exist_ok=True)
        (nested_vault / "GEMINI.md").write_text("# GEMINI\nold_val\n", encoding="utf-8")
        (nested_vault / "index.md").write_text("# Index\nold_val\n", encoding="utf-8")
        (nested_vault / "wiki" / "skill-impact.md").write_text("# Impact\nold_val\n", encoding="utf-8")
        (nested_vault / "raw" / "ingest.md").write_text("old_val\n", encoding="utf-8")
        (nested_vault / "wiki" / "sources" / "src.md").write_text("old_val\n", encoding="utf-8")
        outside = self.tmp_dir / "outside_secret.md"
        outside.write_text("old_val\n", encoding="utf-8")
        symlink_note = nested_vault / "wiki" / "concepts" / "LinkNote.md"
        symlink_note.symlink_to(outside)

        auth = nested_vault / "wiki" / "concepts" / "TargetNote.md"
        auth.write_text(
            "---\ntitle: TargetNote\ntype: concept\nstatus: stable\n---\nValue is old_val.\n",
            encoding="utf-8",
        )

        res = vault_correct.execute_vault_correction(
            vault_root=nested_vault,
            fact="new_val",
            stale_claim="old_val",
            target_authoritative="TargetNote",
            apply=True,
        )
        self.assertEqual(res["errors"], [])
        self.assertIn("Value is new_val.", auth.read_text(encoding="utf-8"))
        # Protected files & symlink untouched
        self.assertIn("old_val", (nested_vault / "GEMINI.md").read_text(encoding="utf-8"))
        self.assertIn("old_val", (nested_vault / "index.md").read_text(encoding="utf-8"))
        self.assertIn("old_val", (nested_vault / "wiki" / "skill-impact.md").read_text(encoding="utf-8"))
        self.assertIn("old_val", (nested_vault / "raw" / "ingest.md").read_text(encoding="utf-8"))
        self.assertIn("old_val", (nested_vault / "wiki" / "sources" / "src.md").read_text(encoding="utf-8"))
        self.assertEqual(outside.read_text(encoding="utf-8"), "old_val\n")

    def test_cli_plan_by_default_apply_exit_codes_and_cas_conflict(self) -> None:
        auth = self.vault_root / "wiki" / "concepts" / "Service Limits.md"
        orig_auth = (
            "---\ntitle: Service Limits\ntype: concept\nstatus: stable\nupdated: 2026-10-01\n---\n"
            "Limit is 16GiB RAM.\n"
        )
        auth.write_text(orig_auth, encoding="utf-8")

        # 1. Default CLI (no --apply) is Plan/Diff preview -> writes 0 files, exit 0
        stdout_buf = io.StringIO()
        with contextlib.redirect_stdout(stdout_buf):
            vault_correct.main(
                [
                    "Limit is 32GiB RAM",
                    "--stale",
                    "16GiB RAM",
                    "--target",
                    "Service Limits",
                    "--vault-path",
                    str(self.vault_root),
                ]
            )
        self.assertEqual(auth.read_text(encoding="utf-8"), orig_auth)
        self.assertIn("PLAN / DIFF PREVIEW", stdout_buf.getvalue())
        self.assertIn("+Limit is 32GiB RAM.", stdout_buf.getvalue())

        # 2. Missing vault path -> exit 2
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stderr(io.StringIO()):
                vault_correct.main(
                    [
                        "Limit is 32GiB RAM",
                        "--stale",
                        "16GiB RAM",
                        "--vault-path",
                        str(self.tmp_dir / "missing_vault"),
                    ]
                )
        self.assertEqual(cm.exception.code, 2)

        # 3. Missing --stale -> exit 1
        with self.assertRaises(SystemExit) as cm_stale:
            with contextlib.redirect_stdout(io.StringIO()):
                vault_correct.main(
                    [
                        "Limit is 32GiB RAM",
                        "--target",
                        "Service Limits",
                        "--vault-path",
                        str(self.vault_root),
                    ]
                )
        self.assertEqual(cm_stale.exception.code, 1)

        # 4. CAS conflict -> exit 2 and concurrent edit preserved
        concurrent_text = (
            "---\ntitle: Service Limits\ntype: concept\nstatus: stable\nupdated: 2026-10-01\n---\n"
            "Limit is 16GiB RAM (edited concurrently).\n"
        )

        def _simulate_race(path: Path, new_content: str, expected_sha256: str | None = None) -> None:
            path.write_text(concurrent_text, encoding="utf-8")
            raise vault_correct.CASConflictError(f"Simulated CAS conflict on {path}")

        with patch.object(vault_correct, "_atomic_write_text", side_effect=_simulate_race):
            with self.assertRaises(SystemExit) as cm_cas:
                with contextlib.redirect_stdout(io.StringIO()):
                    vault_correct.main(
                        [
                            "Limit is 32GiB RAM",
                            "--stale",
                            "16GiB RAM",
                            "--target",
                            "Service Limits",
                            "--vault-path",
                            str(self.vault_root),
                            "--apply",
                        ]
                    )
        self.assertEqual(cm_cas.exception.code, 2)
        self.assertEqual(auth.read_text(encoding="utf-8"), concurrent_text)

        # 5. --apply with --replacement applies cleanly -> exit 0
        out_apply = io.StringIO()
        with contextlib.redirect_stdout(out_apply):
            vault_correct.main(
                [
                    "Limit is 32GiB RAM",
                    "--stale",
                    "16GiB RAM",
                    "--replacement",
                    "64GiB RAM",
                    "--target",
                    "Service Limits",
                    "--vault-path",
                    str(self.vault_root),
                    "--apply",
                ]
            )
        self.assertIn("Limit is 64GiB RAM (edited concurrently).", auth.read_text(encoding="utf-8"))

    def test_frontmatter_preserved_verbatim_and_unchanged_body_keeps_updated_date(self) -> None:
        auth = self.vault_root / "wiki" / "concepts" / "Structured Note.md"
        orig = (
            "---\n"
            "title: Structured Note\n"
            "type: concept\n"
            "status: stable\n"
            "tags:\n"
            "  - gcp/run\n"
            "  - compute\n"
            "aliases:\n"
            "  - Struct Note\n"
            "sources:\n"
            "  - resource: https://cloud.google.com/run\n"
            "    id: cr-1\n"
            "generated:\n"
            "  by: knowledge-compiler/0.9.0\n"
            "  at: 2026-10-01\n"
            "verified:\n"
            "  - by: human:reviewer\n"
            "    at: 2026-10-02\n"
            "updated: 2026-10-01\n"
            "---\n"
            "Cloud Run supports 16GiB RAM per instance.\n"
        )
        auth.write_text(orig, encoding="utf-8")

        # Update body -> nested dicts & multi-line lists preserved verbatim, updated: bumped
        res = vault_correct.execute_vault_correction(
            vault_root=self.vault_root,
            fact="Cloud Run supports 32GiB RAM",
            stale_claim="16GiB RAM",
            target_authoritative="Structured Note",
            apply=True,
        )
        self.assertEqual(res["errors"], [])
        updated_txt = auth.read_text(encoding="utf-8")
        self.assertIn("  - resource: https://cloud.google.com/run\n    id: cr-1\n", updated_txt)
        self.assertIn("generated:\n  by: knowledge-compiler/0.9.0\n  at: 2026-10-01\n", updated_txt)
        self.assertIn("verified:\n  - by: human:reviewer\n    at: 2026-10-02\n", updated_txt)

        # Force old updated: date, run again when body already contains fact (no stale match) -> date unchanged
        auth.write_text(updated_txt.replace(updated_txt.split("updated: ")[1].splitlines()[0], "2026-10-01"), encoding="utf-8")
        before = auth.read_text(encoding="utf-8")
        res2 = vault_correct.execute_vault_correction(
            vault_root=self.vault_root,
            fact="Cloud Run supports 32GiB RAM",
            stale_claim="16GiB RAM",
            target_authoritative="Structured Note",
            apply=True,
        )
        self.assertEqual(res2["errors"], [])
        self.assertEqual(auth.read_text(encoding="utf-8"), before)

    def test_skill_md_documents_plan_by_default_and_apply(self) -> None:
        skill_txt = (REPO_ROOT / "skills" / "vault-correct" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("--stale", skill_txt)
        self.assertIn("--apply", skill_txt)
        self.assertIn("Plan", skill_txt)

    def test_masking_sentinel_tilde_fences_word_boundaries_bom_crlf_and_mode(self) -> None:
        # B2a + B2b + B2c + P2 BOM/CRLF/mode preservation
        auth = self.vault_root / "wiki" / "concepts" / "Cloud Run.md"
        auth.write_bytes(
            (
                "\ufeff---\r\n"
                "title: Cloud Run\r\n"
                "type: concept\r\n"
                "status: stable\r\n"
                "aliases:\r\n"
                "  - 16GiB RAM Alias\r\n"
                "updated: 2026-10-01\r\n"
                "---\r\n"
                "Cloud Run supports 16GiB RAM per instance.\r\n"
                "Some service had 116GiB RAM and 0.16GiB RAM.\r\n\r\n"
                "~~~yaml\r\n"
                "memory: 16GiB RAM\r\n"
                "~~~\r\n\r\n"
                "````markdown\r\n"
                "```\r\n"
                "16GiB RAM\r\n"
                "```\r\n"
                "````\r\n\r\n"
                "    indented: 16GiB RAM\r\n\r\n"
                "<!-- comment 16GiB RAM -->\r\n"
                "Docs: [guide](https://example.com/16GiB-RAM) and https://example.org/16GiB-RAM\r\n"
            ).encode("utf-8")
        )
        os.chmod(auth, 0o644)

        rest = self.vault_root / "wiki" / "synthesis" / "Edge Cases.md"
        links = " ".join(f"[[Note {i}]]" for i in range(18))
        rest.write_text(
            "---\ntitle: Edge Cases\ntype: synthesis\nstatus: stable\nupdated: 2026-10-01\n---\n"
            f"{links}\n"
            "Legacy 16 vCPU and 116 vCPU and 16GiB RAM and 116GiB RAM.\n"
            "~~~yaml\nmemory: 16GiB RAM\n~~~\n",
            encoding="utf-8",
        )
        os.chmod(rest, 0o644)

        # Run --stale "16" against restatement with [[Note 16]] (B2a)
        res_16 = vault_correct.execute_vault_correction(
            vault_root=self.vault_root,
            fact="32",
            stale_claim="16",
            target_authoritative="Cloud Run",
            apply=True,
        )
        self.assertEqual(res_16["errors"], [])
        rest_after_16 = rest.read_text(encoding="utf-8")
        self.assertIn("[[Note 16]]", rest_after_16)
        self.assertNotIn("\ue000", rest_after_16)
        self.assertIn("Legacy [[Cloud Run]] vCPU and 116 vCPU", rest_after_16)

        # Run --stale "16GiB RAM" (B2b + B2c + BOM/CRLF/mode)
        res_mem = vault_correct.execute_vault_correction(
            vault_root=self.vault_root,
            fact="Cloud Run supports 32GiB RAM",
            stale_claim="16GiB RAM",
            target_authoritative="Cloud Run",
            apply=True,
        )
        self.assertEqual(res_mem["errors"], [])
        auth_bytes = auth.read_bytes()
        self.assertTrue(auth_bytes.startswith(b"\xef\xbb\xbf"))
        auth_txt = auth_bytes.decode("utf-8")
        self.assertEqual(stat.S_IMODE(auth.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(rest.stat().st_mode), 0o644)
        # CRLF preserved on updated: line
        self.assertNotRegex(auth_txt, r"(?<!\r)\n")
        self.assertIn("Cloud Run supports 32GiB RAM per instance.\r\n", auth_txt)
        self.assertIn("Some service had 116GiB RAM and 0.16GiB RAM.", auth_txt)
        self.assertIn("~~~yaml\r\nmemory: 16GiB RAM\r\n~~~", auth_txt)
        self.assertIn("````markdown\r\n```\r\n16GiB RAM\r\n```\r\n````", auth_txt)
        self.assertIn("    indented: 16GiB RAM", auth_txt)
        self.assertIn("<!-- comment 16GiB RAM -->", auth_txt)
        self.assertIn("https://example.com/16GiB-RAM", auth_txt)
        self.assertIn("https://example.org/16GiB-RAM", auth_txt)
        self.assertIn("  - 16GiB RAM Alias\r\n", auth_txt)

        rest_after_mem = rest.read_text(encoding="utf-8")
        self.assertIn("[[Cloud Run]] and 116GiB RAM.", rest_after_mem)
        self.assertIn("~~~yaml\nmemory: 16GiB RAM\n~~~", rest_after_mem)

    def test_lifo_nested_masks_list_fences_loose_lists_and_crlf_nonfinal_updated(self) -> None:
        # #105 items 1, 2, 3, 4
        auth = self.vault_root / "wiki" / "concepts" / "List And CRLF.md"
        auth.write_bytes(
            (
                "\ufeff---\r\n"
                "title: List And CRLF\r\n"
                "type: concept\r\n"
                "status: stable\r\n"
                "updated: 2025-01-01\r\n"
                "tags:\r\n"
                "  - cr\r\n"
                "---\r\n"
                "# Heading\r\n"
                "    indented_after_heading: 16GiB RAM\r\n\r\n"
                "```\r\n"
                "fence\r\n"
                "```\r\n"
                "    indented_after_fence: 16GiB RAM\r\n\r\n"
                "- Parent\r\n\r\n"
                "    - Child: Cloud Run supports 16GiB RAM per instance.\r\n\r\n"
                "1. Step one\r\n\r\n"
                "    Run `kubectl apply` with 16GiB RAM and [[Guide `v2`]] and `<!-- 16GiB RAM -->`.\r\n\r\n"
                "- Step:\r\n"
                "    ```bash\r\n"
                "    echo 16GiB RAM\r\n"
                "    ```\r\n"
                "  - Nested:\r\n"
                "      ~~~yaml\r\n"
                "      memory: 16GiB RAM\r\n"
                "      ~~~\r\n"
            ).encode("utf-8")
        )

        res = vault_correct.execute_vault_correction(
            vault_root=self.vault_root,
            fact="Cloud Run supports 32GiB RAM",
            stale_claim="16GiB RAM",
            target_authoritative="List And CRLF",
            apply=True,
        )
        self.assertEqual(res["errors"], [])
        txt = auth.read_bytes().decode("utf-8")
        self.assertNotRegex(txt, r"(?<!\r)\n")
        # Exactly one updated: line (no duplicate)
        self.assertEqual(txt.count("updated:"), 1)
        self.assertNotIn("2025-01-01", txt)
        # Indented code after heading/fence and list-indented fences are preserved
        self.assertIn("    indented_after_heading: 16GiB RAM\r\n", txt)
        self.assertIn("    indented_after_fence: 16GiB RAM\r\n", txt)
        self.assertIn("    echo 16GiB RAM\r\n", txt)
        self.assertIn("      memory: 16GiB RAM\r\n", txt)
        self.assertIn("[[Guide `v2`]]", txt)
        self.assertIn("`<!-- 16GiB RAM -->`", txt)
        # Loose-list child and ordered continuation paragraph ARE updated
        self.assertIn("    - Child: Cloud Run supports 32GiB RAM per instance.\r\n", txt)
        self.assertIn("    Run `kubectl apply` with Cloud Run supports 32GiB RAM", txt)

    def test_blockquote_callout_fences_unclosed_fence_and_list_fence_continuation(self) -> None:
        # #118 items 2, 3, 4
        auth = self.vault_root / "wiki" / "concepts" / "Callout And Lists.md"
        auth.write_text(
            "---\n"
            "title: Callout And Lists\n"
            "type: concept\n"
            "status: stable\n"
            "updated: 2026-10-01\n"
            "---\n"
            "> [!example]\n"
            "> ```bash\n"
            "> echo 16GiB RAM\n"
            "> ```\n"
            "> ~~~yaml\n"
            "> memory: 16GiB RAM\n"
            "> ~~~\n\n"
            "<!--\n"
            "```\n"
            "lone backticks inside html comment 16GiB RAM\n"
            "-->\n"
            "After comment 16GiB RAM.\n\n"
            "- ```bash\n"
            "  code_in_bullet_fence 16GiB RAM\n"
            "  ```\n"
            "- bullet prose 16GiB RAM\n\n"
            "- Step:\n"
            "    ```bash\n"
            "    echo hi 16GiB RAM\n"
            "    ```\n"
            "    Then prose 16GiB RAM per instance.\n",
            encoding="utf-8",
        )

        unclosed_orig = (
            "---\n"
            "title: Unclosed Fence\n"
            "type: synthesis\n"
            "status: stable\n"
            "updated: 2026-10-01\n"
            "---\n"
            "prose1 16GiB RAM\n"
            "```\n"
            "code1 16GiB RAM\n\n"
            "code2 16GiB RAM\n"
        )
        unclosed_rest = self.vault_root / "wiki" / "synthesis" / "Unclosed Fence.md"
        unclosed_rest.write_text(unclosed_orig, encoding="utf-8")

        res = vault_correct.execute_vault_correction(
            vault_root=self.vault_root,
            fact="Cloud Run supports 32GiB RAM",
            stale_claim="16GiB RAM",
            target_authoritative="Callout And Lists",
            apply=True,
        )
        self.assertEqual(res["errors"], [])
        self.assertTrue(any("Unclosed" in w for w in res["warnings"]))

        auth_txt = auth.read_text(encoding="utf-8")
        self.assertIn("> echo 16GiB RAM\n", auth_txt)
        self.assertIn("> memory: 16GiB RAM\n", auth_txt)
        self.assertIn("lone backticks inside html comment 16GiB RAM\n", auth_txt)
        self.assertIn("After comment Cloud Run supports 32GiB RAM.\n", auth_txt)
        self.assertIn("  code_in_bullet_fence 16GiB RAM\n", auth_txt)
        self.assertIn("- bullet prose Cloud Run supports 32GiB RAM\n", auth_txt)
        self.assertIn("    echo hi 16GiB RAM\n", auth_txt)
        self.assertIn("    Then prose Cloud Run supports 32GiB RAM per instance.\n", auth_txt)

        # Unclosed fence in restatement fails closed: skips entire note with warning
        self.assertEqual(unclosed_rest.read_text(encoding="utf-8"), unclosed_orig)

        # #124: Unclosed fence in AUTHORITATIVE note must fail closed (rc1, 0 restatements refactored, 0 log writes)
        bad_auth_orig = (
            "---\n"
            "title: Bad Auth\n"
            "type: concept\n"
            "status: stable\n"
            "updated: 2026-10-01\n"
            "---\n"
            "Cloud Run supports 16GiB RAM per instance.\n\n"
            "```\n"
            "unclosed stray fence\n"
        )
        bad_auth = self.vault_root / "wiki" / "concepts" / "Bad Auth.md"
        bad_auth.write_text(bad_auth_orig, encoding="utf-8")

        dep_rest_orig = (
            "---\n"
            "title: Dependent Note\n"
            "type: synthesis\n"
            "status: stable\n"
            "updated: 2026-10-01\n"
            "---\n"
            "See 16GiB RAM limit.\n"
        )
        dep_rest = self.vault_root / "wiki" / "synthesis" / "Dependent Note.md"
        dep_rest.write_text(dep_rest_orig, encoding="utf-8")
        log_before = (self.vault_root / "log.md").read_text(encoding="utf-8")

        with self.assertRaises(SystemExit) as cm_bad_auth:
            with contextlib.redirect_stdout(io.StringIO()) as bad_out:
                vault_correct.main(
                    [
                        "Cloud Run supports 32GiB RAM",
                        "--stale",
                        "16GiB RAM",
                        "--target",
                        "Bad Auth",
                        "--vault-path",
                        str(self.vault_root),
                        "--apply",
                        "--json",
                    ]
                )
        self.assertEqual(cm_bad_auth.exception.code, 1)
        bad_rep = json.loads(bad_out.getvalue())
        self.assertTrue(bad_rep["errors"])
        self.assertEqual(bad_rep["restatements_refactored"], [])
        self.assertFalse(bad_rep["applied"])
        self.assertEqual(bad_auth.read_text(encoding="utf-8"), bad_auth_orig)
        self.assertEqual(dep_rest.read_text(encoding="utf-8"), dep_rest_orig)
        self.assertEqual((self.vault_root / "log.md").read_text(encoding="utf-8"), log_before)


class TestP0HooksAndAnalyzeTrace(unittest.TestCase):
    """Verify P0-5b hooks.json defaults, log_tool_failure hardening, trace analyzer, and git locks."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="kc_p0_hooks_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_hooks_json_error_recorder_disabled_by_default(self) -> None:
        hooks_cfg = json.loads((REPO_ROOT / "hooks.json").read_text(encoding="utf-8"))
        self.assertFalse(hooks_cfg["wikiskill-error-recorder"]["enabled"])
        self.assertFalse(hooks_cfg["vault-session-start"]["enabled"])
        self.assertFalse(hooks_cfg["vault-stop-hook"]["enabled"])
        agents_hooks_path = REPO_ROOT / ".agents" / "hooks.json"
        if agents_hooks_path.is_file():
            agents_hooks = json.loads(agents_hooks_path.read_text(encoding="utf-8"))
            self.assertFalse(agents_hooks["wikiskill-error-recorder"]["enabled"])
        self.assertFalse(install_plugin.REPO_HOOKS_CONFIG["wikiskill-error-recorder"]["enabled"])
        self.assertFalse(install_plugin.GLOBAL_HOOKS_CONFIG["wikiskill-error-recorder"]["enabled"])

    def test_log_tool_failure_path_redaction_caps_perms_and_rotation(self) -> None:
        # 1. Never writes to $CWD/.agents/ even if present
        fake_cwd = self.tmp_dir / "project"
        (fake_cwd / ".agents").mkdir(parents=True)
        xdg_state = self.tmp_dir / "xdg_state"
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(xdg_state)}, clear=False):
            resolved = log_tool_failure.resolve_default_trace_file(fake_cwd)
        self.assertEqual(
            resolved,
            xdg_state / "knowledge-compiler" / "logs" / "error_traces.jsonl",
        )
        self.assertNotIn(".agents", str(resolved))

        # 2. Secret redaction in BOTH error and args + size caps + permissions
        trace_file = self.tmp_dir / "state" / "logs" / "error_traces.jsonl"
        fake_gapi = "AIza" + "SyDummyTestKey1234567890abcdef"
        fake_oauth = "ya29." + "DummyOAuthToken1234567890"
        fake_gh = "ghp_" + "DummyGitHubToken1234567890abcdef"
        fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        fake_bearer = "Bearer " + "DummyJwtTokenValue999"
        long_pad = "x" * 5000

        payload = {
            "stepIdx": 7,
            "toolName": "run_command",
            "args": {
                "CommandLine": (
                    f"curl -H 'Authorization: {fake_bearer}' "
                    f"'https://127.0.0.1/?token=secret_val&email=alice@example.com' {long_pad}"
                ),
                "apiKey": fake_gapi,
                "gh": fake_gh,
            },
            "error": (
                f"Failed with {fake_gapi} {fake_oauth} {fake_gh} {fake_aws} "
                f"{fake_bearer} token=topsecret alice@example.com {long_pad}"
            ),
        }
        log_tool_failure.process_hook(payload, trace_file)
        self.assertTrue(trace_file.is_file())
        self.assertEqual(stat.S_IMODE(trace_file.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(trace_file.stat().st_mode), 0o600)

        rec = json.loads(trace_file.read_text(encoding="utf-8").strip())
        self.assertLessEqual(len(rec["error"]), 2048)
        self.assertLessEqual(len(json.dumps(rec["args"])), 4096)
        serialized = json.dumps(rec)
        for secret in (
            fake_gapi,
            fake_oauth,
            fake_gh,
            fake_aws,
            "DummyJwtTokenValue999",
            "secret_val",
            "topsecret",
            "alice@example.com",
        ):
            self.assertNotIn(secret, serialized)

        # 3. Fallback to get_plugin_data_dir() when XDG_STATE_HOME unset + reject relative env paths
        pdata = self.tmp_dir / "pdata"
        with patch.dict(
            os.environ,
            {"XDG_STATE_HOME": ".agents", "PLUGIN_DATA": str(pdata)},
            clear=False,
        ):
            fb = log_tool_failure.resolve_default_trace_file(fake_cwd)
            self.assertEqual(fb, pdata / "logs" / "error_traces.jsonl")
        with patch.dict(
            os.environ,
            {"XDG_STATE_HOME": "", "PLUGIN_DATA": str(pdata)},
            clear=False,
        ):
            fb = log_tool_failure.resolve_default_trace_file(fake_cwd)
            self.assertEqual(fb, pdata / "logs" / "error_traces.jsonl")
            stdin_payload = json.dumps({"toolName": "edit_file", "error": "boom token=abc123", "args": {}})
            out_buf = io.StringIO()
            with patch.object(sys, "stdin", io.StringIO(stdin_payload)):
                with contextlib.redirect_stdout(out_buf):
                    log_tool_failure.main()
            self.assertEqual(out_buf.getvalue(), "{}")
            self.assertTrue(fb.is_file())
            self.assertNotIn("abc123", fb.read_text(encoding="utf-8"))

        # 4. Prefixed secret env vars, Basic auth, --password flag, dict keys, symlink dir guard & perf
        adv_trace = self.tmp_dir / "adv" / "logs" / "error_traces.jsonl"
        fake_slack = "xoxb-" + "1234567890-abcdef123456"
        fake_jwt = "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        adv_payload = {
            "toolName": "run_command",
            "args": {
                "CommandLine": (
                    f"DB_PASSWORD=hunter2 GITHUB_TOKEN=gh_plain_secret SLACK_TOKEN={fake_slack} "
                    f"id_token={fake_jwt} AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
                    "curl -H 'Authorization: Basic dXNlcjpwYXNz' --password hunter3"
                ),
                "alice@example.com": "val",
                fake_gh: "val2",
            },
            "error": (
                f"DB_PASSWORD=hunter2 SLACK_TOKEN={fake_slack} id_token={fake_jwt} "
                "Authorization: Basic dXNlcjpwYXNz --password hunter3 "
                + ("A" * 80000)
            ),
        }
        log_tool_failure.process_hook(adv_payload, adv_trace)
        adv_txt = adv_trace.read_text(encoding="utf-8")
        for leaked in (
            "hunter2",
            "gh_plain_secret",
            fake_slack,
            fake_jwt,
            "wJalrXUtnFEMI",
            "dXNlcjpwYXNz",
            "hunter3",
            "alice@example.com",
            fake_gh,
        ):
            self.assertNotIn(leaked, adv_txt)

        # Symlinked logs/ directory must NOT be followed or chmodded
        victim_dir = self.tmp_dir / "victim_dir"
        victim_dir.mkdir(parents=True)
        os.chmod(victim_dir, 0o755)
        sym_logs = self.tmp_dir / "sym_app" / "logs"
        sym_logs.parent.mkdir(parents=True)
        sym_logs.symlink_to(victim_dir)
        log_tool_failure.process_hook(
            {"toolName": "run_command", "error": "boom", "args": {}},
            sym_logs / "error_traces.jsonl",
        )
        self.assertEqual(stat.S_IMODE(victim_dir.stat().st_mode), 0o755)
        self.assertFalse((victim_dir / "error_traces.jsonl").exists())

        # ReDoS guard: pathological dotted/dashed runs must complete quickly (<1s)
        import time
        t0 = time.monotonic()
        for pat in ("auth-" * 800, "a." * 50000, "1.2.3.4." * 5000):
            _ = log_tool_failure.redact_secrets(pat)
        self.assertLess(time.monotonic() - t0, 1.0)

        # Quoted env vars, Python repr dicts, => separator, >64-char prefix, YAML block, & flag boundary
        quoted_trace = self.tmp_dir / "quoted" / "logs" / "error_traces.jsonl"
        long_prefix_var = ("LONG_" * 16) + "API_TOKEN=super_long_prefix_secret"
        quoted_payload = {
            "toolName": "run_command",
            "args": {
                "CommandLine": (
                    "export GITHUB_TOKEN=\"gh_quoted_val\" API_TOKEN=\"abc_quoted\" "
                    "DB_PASSWORD='hunter2_quoted' client_secret = \"cs-123\" "
                    "secret => 'arrow_secret' multi-line-secret safe_arg "
                    f"{long_prefix_var}"
                ),
            },
            "error": (
                "password=\"err_pw\" {'password': 'py_pw', 'token': 'py_tok'} "
                "password:\n  yaml_secret_val\nmulti-line-secret ok_value"
            ),
        }
        log_tool_failure.process_hook(quoted_payload, quoted_trace)
        q_txt = quoted_trace.read_text(encoding="utf-8")
        for leaked in (
            "gh_quoted_val",
            "abc_quoted",
            "hunter2_quoted",
            "cs-123",
            "arrow_secret",
            "super_long_prefix_secret",
            "err_pw",
            "py_pw",
            "py_tok",
            "yaml_secret_val",
        ):
            self.assertNotIn(leaked, q_txt)
        self.assertIn("multi-line-secret safe_arg", q_txt)
        self.assertIn("multi-line-secret ok_value", q_txt)

        # Unterminated PEM key > 8KB before EOF and > 8KB key body must still redact cleanly
        pem_trace = self.tmp_dir / "pem" / "logs" / "error_traces.jsonl"
        pem_secret = "MIIEowIBAAKCAQEA" + ("B" * 9000)
        log_tool_failure.process_hook(
            {
                "toolName": "run_command",
                "args": {},
                "error": f"-----BEGIN RSA PRIVATE KEY-----\n{pem_secret}",
            },
            pem_trace,
        )
        pem_txt = pem_trace.read_text(encoding="utf-8")
        self.assertIn("[REDACTED_PRIVATE_KEY]", pem_txt)
        self.assertNotIn("MIIEowIBAAKCAQEA", pem_txt)

        # 5. Rotation at 5 MiB -> error_traces.jsonl.1
        rot_file = self.tmp_dir / "rot" / "error_traces.jsonl"
        rot_file.parent.mkdir(parents=True)
        rot_file.write_bytes(b"a" * (5 * 1024 * 1024))
        log_tool_failure.process_hook(
            {"toolName": "read_file", "error": "boom", "args": {}},
            rot_file,
        )
        rotated = rot_file.with_name("error_traces.jsonl.1")
        self.assertTrue(rotated.is_file())
        self.assertEqual(rotated.stat().st_size, 5 * 1024 * 1024)
        self.assertLess(rot_file.stat().st_size, 4096)

    def test_analyze_trace_provenance_triggers_and_error_log(self) -> None:
        transcript = self.tmp_dir / "transcript.jsonl"
        err_log = self.tmp_dir / "error_traces.jsonl"
        lines = [
            json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "no problem, carry on"}),
            json.dumps({"type": "USER_INPUT", "source": "SYSTEM", "content": "That failed badly"}),
            json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "<SYSTEM_MESSAGE> wrong tool"}),
            json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "That failed, use --apply instead"}),
            json.dumps({"type": "PLANNER_RESPONSE", "tool_calls": None, "content": "ok"}),
        ]
        transcript.write_text("\n".join(lines) + "\n", encoding="utf-8")
        err_log.write_text(
            json.dumps({"tool_name": "run_command", "error": "permission denied"}) + "\n",
            encoding="utf-8",
        )

        stdout_buf = io.StringIO()
        with contextlib.redirect_stdout(stdout_buf):
            analyze_trace.main(
                ["--transcript", str(transcript), "--error-log", str(err_log), "--json"]
            )
        rep = json.loads(stdout_buf.getvalue())
        self.assertEqual(rep["user_correction_count"], 1)
        self.assertEqual(rep["error_trace_count"], 1)
        self.assertEqual(rep["tool_error_count"], 1)
        self.assertIn("--apply instead", rep["corrections"][0]["content"])

        # Also check positional CLI arg and auto-discovered XDG_STATE_HOME error log
        xdg_state = self.tmp_dir / "auto_xdg"
        auto_err = xdg_state / "knowledge-compiler" / "logs" / "error_traces.jsonl"
        auto_err.parent.mkdir(parents=True)
        auto_err.write_text(
            json.dumps({"tool_name": "write_file", "error": "disk full"}) + "\n",
            encoding="utf-8",
        )
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(xdg_state)}, clear=False):
            pos_buf = io.StringIO()
            with contextlib.redirect_stdout(pos_buf):
                analyze_trace.main([str(transcript)])
            pos_rep = json.loads(pos_buf.getvalue())
            self.assertEqual(pos_rep["error_trace_count"], 1)
            self.assertEqual(pos_rep["tool_error_count"], 0)
            self.assertEqual(pos_rep["error_traces"][0]["tool_name"], "write_file")

    def _init_git_repo(self, repo_dir: Path) -> None:
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo_dir), check=True, capture_output=True)
        (repo_dir / "index.md").write_text("# Index\n", encoding="utf-8")
        (repo_dir / "log.md").write_text("# Log\n", encoding="utf-8")
        subprocess.run(["git", "add", "index.md", "log.md"], cwd=str(repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), check=True, capture_output=True)

    def test_git_hooks_flock_manual_rebase_guard_and_no_add_all(self) -> None:
        vault = self.tmp_dir / "Vault"
        self._init_git_repo(vault)
        plugin_data = self.tmp_dir / "plugin_data"

        with patch.dict(os.environ, {"PLUGIN_DATA": str(plugin_data)}, clear=False):
            # 1. Pre-held lock causes both hooks to skip cleanly
            sha16 = hashlib.sha256(str(vault.resolve()).encode("utf-8")).hexdigest()[:16]
            lock_path = plugin_data / "locks" / f"vault-{sha16}.lock"
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            with open(lock_path, "a+") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    stop_res = auto_sync_vault.sync_vault(vault)
                    start_res = session_sync.sync_session_start(
                        vault_path=vault,
                        ce_patterns_path=self.tmp_dir / "none1",
                        compiler_repo_path=self.tmp_dir / "none2",
                    )
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

            self.assertEqual(stop_res["status"], "locked_skipped")
            self.assertEqual(start_res["vault"]["status"], "locked_skipped")

            # 2. Manual rebase-merge / rebase-apply is NEVER aborted
            for marker in ("rebase-merge", "rebase-apply"):
                rb_dir = vault / ".git" / marker
                rb_dir.mkdir(parents=True, exist_ok=True)
                try:
                    stop_rb = auto_sync_vault.sync_vault(vault)
                    start_rb = session_sync.sync_session_start(
                        vault_path=vault,
                        ce_patterns_path=self.tmp_dir / "none1",
                        compiler_repo_path=self.tmp_dir / "none2",
                    )
                    self.assertEqual(stop_rb["status"], "skipped_rebase_in_progress")
                    self.assertEqual(start_rb["vault"]["status"], "skipped_rebase_in_progress")
                    self.assertTrue(rb_dir.exists())
                finally:
                    rb_dir.rmdir()

        # 3. session_sync source code contains zero `git add -A` and never stages untracked root secrets
        session_src = (HOOKS_DIR / "session_sync.py").read_text(encoding="utf-8")
        self.assertNotIn('"add", "-A"', session_src)

        origin = self.tmp_dir / "origin.git"
        subprocess.run(["git", "init", "--bare", "-b", "main", str(origin)], check=True, capture_output=True)
        local_v = self.tmp_dir / "LocalVault"
        self._init_git_repo(local_v)
        subprocess.run(["git", "remote", "add", "origin", str(origin)], cwd=str(local_v), check=True, capture_output=True)
        subprocess.run(["git", "push", "-u", "origin", "main"], cwd=str(local_v), check=True, capture_output=True)

        peer_v = self.tmp_dir / "PeerVault"
        subprocess.run(["git", "clone", str(origin), str(peer_v)], check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "peer@example.com"], cwd=str(peer_v), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Peer"], cwd=str(peer_v), check=True, capture_output=True)
        (peer_v / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
        (peer_v / "wiki" / "concepts" / "Remote Note.md").write_text("# Remote\n", encoding="utf-8")
        subprocess.run(["git", "add", "wiki"], cwd=str(peer_v), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "remote commit"], cwd=str(peer_v), check=True, capture_output=True)
        subprocess.run(["git", "push", "origin", "main"], cwd=str(peer_v), check=True, capture_output=True)

        # Create local committed wiki note with escaped pipe + untracked root .env secret
        (local_v / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
        (local_v / "wiki" / "concepts" / "Local Note.md").write_text(
            "| A | B |\n| --- | --- |\n| [[Remote Note\\|Alias]] | val |\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "wiki"], cwd=str(local_v), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "local commit"], cwd=str(local_v), check=True, capture_output=True)
        (local_v / ".env").write_text("SECRET_TOKEN=do_not_commit\n", encoding="utf-8")

        with patch.dict(os.environ, {"PLUGIN_DATA": str(plugin_data)}, clear=False):
            ss_res = session_sync.sync_session_start(
                vault_path=local_v,
                ce_patterns_path=self.tmp_dir / "none1",
                compiler_repo_path=self.tmp_dir / "none2",
            )
        self.assertEqual(ss_res["vault"]["status"], "rebased")
        tracked = subprocess.run(["git", "ls-files"], cwd=str(local_v), capture_output=True, text=True, check=True).stdout
        self.assertNotIn(".env", tracked)

        # Verify _stage_vault_files (used by both hooks) also never stages untracked .env
        auto_sync_vault._stage_vault_files(local_v)
        staged = subprocess.run(["git", "diff", "--cached", "--name-only"], cwd=str(local_v), capture_output=True, text=True, check=True).stdout
        self.assertNotIn(".env", staged)

        # 4. Conflicted `git merge` (MERGE_HEAD + unmerged markers) skips cleanly without committing or pushing
        merge_origin = self.tmp_dir / "merge_origin.git"
        subprocess.run(["git", "init", "--bare", "-b", "main", str(merge_origin)], check=True, capture_output=True)
        m1 = self.tmp_dir / "MergePeer1"
        self._init_git_repo(m1)
        (m1 / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
        (m1 / "wiki" / "concepts" / "Shared.md").write_text("line1: base\n", encoding="utf-8")
        subprocess.run(["git", "add", "wiki"], cwd=str(m1), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "base"], cwd=str(m1), check=True, capture_output=True)
        subprocess.run(["git", "remote", "add", "origin", str(merge_origin)], cwd=str(m1), check=True, capture_output=True)
        subprocess.run(["git", "push", "-u", "origin", "main"], cwd=str(m1), check=True, capture_output=True)

        m2 = self.tmp_dir / "MergeUser"
        subprocess.run(["git", "clone", str(merge_origin), str(m2)], check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "u@example.com"], cwd=str(m2), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "User"], cwd=str(m2), check=True, capture_output=True)

        # Push conflicting change from m1
        (m1 / "wiki" / "concepts" / "Shared.md").write_text("line1: remote\n", encoding="utf-8")
        subprocess.run(["git", "add", "wiki"], cwd=str(m1), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "remote edit"], cwd=str(m1), check=True, capture_output=True)
        subprocess.run(["git", "push", "origin", "main"], cwd=str(m1), check=True, capture_output=True)

        # Local edit in m2 + start `git merge` producing conflict + MERGE_HEAD
        (m2 / "wiki" / "concepts" / "Shared.md").write_text("line1: local\n", encoding="utf-8")
        subprocess.run(["git", "add", "wiki"], cwd=str(m2), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "local edit"], cwd=str(m2), check=True, capture_output=True)
        subprocess.run(["git", "fetch", "origin", "main"], cwd=str(m2), check=True, capture_output=True)
        merge_proc = subprocess.run(["git", "merge", "origin/main"], cwd=str(m2), capture_output=True, text=True)
        self.assertNotEqual(merge_proc.returncode, 0)
        self.assertTrue((m2 / ".git" / "MERGE_HEAD").exists())

        with patch.dict(os.environ, {"PLUGIN_DATA": str(plugin_data)}, clear=False):
            stop_m = auto_sync_vault.sync_vault(m2)
            start_m = session_sync.sync_session_start(
                vault_path=m2,
                ce_patterns_path=self.tmp_dir / "none1",
                compiler_repo_path=self.tmp_dir / "none2",
            )
        self.assertEqual(stop_m["status"], "skipped_merge_in_progress")
        self.assertFalse(stop_m["committed"])
        self.assertFalse(stop_m["pushed"])
        self.assertEqual(start_m["vault"]["status"], "skipped_merge_in_progress")
        self.assertTrue((m2 / ".git" / "MERGE_HEAD").exists())
        # Verify markers were NOT pushed to origin
        remote_shared = subprocess.run(
            ["git", "--git-dir", str(merge_origin), "show", "main:wiki/concepts/Shared.md"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertNotIn("<<<<<<<", remote_shared)

        # 5. Reftable cherry-pick / revert with staged resolution skips cleanly without committing
        rt_origin = self.tmp_dir / "rt_origin.git"
        rt_init = subprocess.run(
            ["git", "init", "--bare", "--ref-format=reftable", "-b", "main", str(rt_origin)],
            capture_output=True,
            text=True,
        )
        if rt_init.returncode == 0:
            rt_v = self.tmp_dir / "ReftableVault"
            subprocess.run(["git", "clone", str(rt_origin), str(rt_v)], check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "u@example.com"], cwd=str(rt_v), check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "User"], cwd=str(rt_v), check=True, capture_output=True)
            (rt_v / "index.md").write_text("# Index\n", encoding="utf-8")
            (rt_v / "log.md").write_text("# Log\n", encoding="utf-8")
            subprocess.run(["git", "add", "index.md", "log.md"], cwd=str(rt_v), check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=str(rt_v), check=True, capture_output=True)
            subprocess.run(["git", "push", "-u", "origin", "main"], cwd=str(rt_v), check=True, capture_output=True)

            subprocess.run(["git", "checkout", "-b", "feat"], cwd=str(rt_v), check=True, capture_output=True)
            (rt_v / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
            (rt_v / "wiki" / "concepts" / "Pick.md").write_text("from feat\n", encoding="utf-8")
            subprocess.run(["git", "add", "wiki"], cwd=str(rt_v), check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "feat pick"], cwd=str(rt_v), check=True, capture_output=True)
            feat_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(rt_v), capture_output=True, text=True, check=True).stdout.strip()

            subprocess.run(["git", "checkout", "main"], cwd=str(rt_v), check=True, capture_output=True)
            (rt_v / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
            (rt_v / "wiki" / "concepts" / "Pick.md").write_text("from main\n", encoding="utf-8")
            subprocess.run(["git", "add", "wiki"], cwd=str(rt_v), check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "main diverge"], cwd=str(rt_v), check=True, capture_output=True)
            subprocess.run(["git", "push", "origin", "main"], cwd=str(rt_v), check=True, capture_output=True)

            cp = subprocess.run(["git", "cherry-pick", feat_sha], cwd=str(rt_v), capture_output=True, text=True)
            self.assertNotEqual(cp.returncode, 0)
            # User resolves conflict and stages Pick.md, before running `git cherry-pick --continue`
            (rt_v / "wiki" / "concepts" / "Pick.md").write_text("resolved pick\n", encoding="utf-8")
            subprocess.run(["git", "add", "wiki/concepts/Pick.md"], cwd=str(rt_v), check=True, capture_output=True)

            with patch.dict(os.environ, {"PLUGIN_DATA": str(plugin_data)}, clear=False):
                rt_stop = auto_sync_vault.sync_vault(rt_v)
                rt_start = session_sync.sync_session_start(
                    vault_path=rt_v,
                    ce_patterns_path=self.tmp_dir / "none1",
                    compiler_repo_path=self.tmp_dir / "none2",
                )
            self.assertEqual(rt_stop["status"], "skipped_cherry_pick_in_progress")
            self.assertFalse(rt_stop["committed"])
            self.assertEqual(rt_start["vault"]["status"], "skipped_cherry_pick_in_progress")


if __name__ == "__main__":
    unittest.main()
