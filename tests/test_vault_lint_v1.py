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
"""Hermetic Wave 2 tests for OKF v0.2 conformance linting and trust-tier integrity."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import init_vault  # noqa: E402
import vault_lint  # noqa: E402


class TestVaultLintV1Conformance(unittest.TestCase):
    """Verify OKF v0.2 bundle conformance, exit codes, migration, wanted_pages, and trust tiers."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="kc_lint_v1_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _create_clean_vault(self, name: str = "CleanVault") -> Path:
        vault = self.tmp_dir / name
        init_vault.init_vault(vault, quiet=True)
        note_a = vault / "wiki" / "concepts" / "Alpha Pattern.md"
        note_a.write_text(
            "---\n"
            'title: "Alpha Pattern"\n'
            "type: concept\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-15\n"
            "status: stable\n"
            "sources:\n"
            "  - id: alpha-doc\n"
            '    resource: "https://example.org/alpha"\n'
            "---\n\n"
            "# Alpha Pattern\n\n"
            "Details supported by source.[^alpha-doc]\n\n"
            "Links to [[wiki/skill-impact|Skill Impact]] and [[Beta Pattern]].\n\n"
            "[^alpha-doc]: Alpha reference\n",
            encoding="utf-8",
        )
        note_b = vault / "wiki" / "concepts" / "Beta Pattern.md"
        note_b.write_text(
            "---\n"
            'title: "Beta Pattern"\n'
            "type: concept\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-15\n"
            "status: stable\n"
            "verified:\n"
            '  - by: "process:nightly-check"\n'
            '    at: "2026-10-16T00:00:00Z"\n'
            "---\n\n"
            "# Beta Pattern\n\n"
            "Extends [[Alpha Pattern]].\n",
            encoding="utf-8",
        )
        idx = vault / "index.md"
        idx.write_text(
            idx.read_text(encoding="utf-8")
            + "\n- [[Alpha Pattern]]\n- [[Beta Pattern]]\n- [[wiki/skill-impact|Skill Impact]]\n",
            encoding="utf-8",
        )
        return vault

    def _run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            try:
                vault_lint.main(argv)
            except SystemExit as exc:
                code = int(exc.code) if isinstance(exc.code, int) else 1
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_okf_bundle_root_conformance_and_reserved_files(self) -> None:
        vault = self._create_clean_vault()
        # Reserved files inside wiki/ must not require frontmatter `type:`
        (vault / "wiki" / "index.md").write_text("# Wiki Bundle Index\n", encoding="utf-8")
        (vault / "wiki" / "log.md").write_text(
            "# Wiki Log\n\n## 2026-10-15\n* Added [[Alpha Pattern]].\n",
            encoding="utf-8",
        )

        # Clean conformant vault passes both normal and --strict
        code, stdout_json, _ = self._run_cli([str(vault), "--strict", "--json"])
        self.assertEqual(code, 0)
        rep = json.loads(stdout_json)
        self.assertTrue(rep["is_healthy"])
        self.assertTrue(rep["strict_passed"])
        self.assertEqual(rep["conformance_errors"], [])
        self.assertEqual(rep["missing_frontmatter"], [])
        self.assertEqual(rep["trust_tier_counts"]["unverified"], 2)  # Alpha + skill-impact
        self.assertEqual(rep["trust_tier_counts"]["machine-confirmed"], 1)  # Beta
        self.assertEqual(rep["trust_tier_counts"]["human-reviewed"], 0)

        # Missing `type:` inside wiki/ fails with exit 1
        bad_type = vault / "wiki" / "concepts" / "NoType.md"
        bad_type.write_text(
            "---\ntitle: NoType\n---\nLinked from [[index]].\n", encoding="utf-8"
        )
        code, out, _ = self._run_cli([str(vault), "--json"])
        self.assertEqual(code, 1)
        rep_bad = json.loads(out)
        self.assertFalse(rep_bad["is_healthy"])
        self.assertTrue(any(e["file"] == "wiki/concepts/NoType.md" for e in rep_bad["conformance_errors"]))
        bad_type.unlink()

        # Missing frontmatter inside wiki/ populates both missing_frontmatter and conformance_errors
        no_fm = vault / "wiki" / "concepts" / "NoFM.md"
        no_fm.write_text("# Plain Markdown Without Frontmatter\n", encoding="utf-8")
        code, out, _ = self._run_cli([str(vault), "--json"])
        self.assertEqual(code, 1)
        rep_nofm = json.loads(out)
        self.assertIn("wiki/concepts/NoFM.md", rep_nofm["missing_frontmatter"])
        self.assertTrue(any(e["file"] == "wiki/concepts/NoFM.md" for e in rep_nofm["conformance_errors"]))
        no_fm.unlink()

        # Oversized >16 KiB frontmatter and YAML anchor/alias bombs fail conformance
        huge_fm = vault / "wiki" / "concepts" / "HugeFM.md"
        huge_pad = "a" * (17 * 1024)
        huge_fm.write_text(
            f"---\ntitle: Huge\ntype: concept\ndescription: \"{huge_pad}\"\n---\n# Huge\n",
            encoding="utf-8",
        )
        code, out, _ = self._run_cli([str(vault), "--json"])
        self.assertEqual(code, 1)
        self.assertIn("wiki/concepts/HugeFM.md", json.loads(out)["missing_frontmatter"])
        huge_fm.unlink()

        anchor_fm = vault / "wiki" / "concepts" / "AnchorFM.md"
        anchor_fm.write_text(
            "---\ntitle: &a Anchor\ntype: concept\nalias: *a\n---\n# Anchor\n",
            encoding="utf-8",
        )
        code, out, _ = self._run_cli([str(vault), "--json"])
        self.assertEqual(code, 1)
        self.assertIn("wiki/concepts/AnchorFM.md", json.loads(out)["missing_frontmatter"])
        anchor_fm.unlink()

    def test_attested_computation_sources_footnotes_and_staleness(self) -> None:
        vault = self._create_clean_vault()

        # 1. Attested Computation missing `runtime` -> conformance error (exit 1)
        bad_comp = vault / "wiki" / "concepts" / "Revenue Calc.md"
        bad_comp.write_text(
            "---\ntitle: Revenue Calc\ntype: Attested Computation\n---\n# Computation\nSELECT 1;\n",
            encoding="utf-8",
        )
        code, out, _ = self._run_cli([str(vault), "--json"])
        self.assertEqual(code, 1)
        self.assertTrue(
            any("runtime" in e["message"] for e in json.loads(out)["conformance_errors"])
        )

        # 2. Valid Attested Computation with `runtime` + `# Computation` passes
        bad_comp.write_text(
            "---\ntitle: Revenue Calc\ntype: Attested Computation\nruntime: bigquery\n---\n"
            "# Computation\n\n```sql\nSELECT 1;\n```\n",
            encoding="utf-8",
        )
        code, _, _ = self._run_cli([str(vault), "--json"])
        self.assertEqual(code, 0)

        # 3. Dict entry in `sources` missing `resource` -> conformance error
        bad_src = vault / "wiki" / "concepts" / "BadSource.md"
        bad_src.write_text(
            "---\ntitle: BadSource\ntype: concept\nsources:\n  - id: missing-res\n---\n# Body\n",
            encoding="utf-8",
        )
        code, out, _ = self._run_cli([str(vault), "--json"])
        self.assertEqual(code, 1)
        self.assertTrue(
            any("resource" in e["message"] for e in json.loads(out)["conformance_errors"])
        )
        bad_src.unlink()

        # 4. Empty placeholder `sources: [""]` is ignored (clean!)
        starter = vault / "wiki" / "concepts" / "Starter.md"
        starter.write_text(
            "---\ntitle: Starter\ntype: concept\nsources:\n  - \"\"\n---\n"
            "Links to [[Alpha Pattern]].\n",
            encoding="utf-8",
        )
        (vault / "index.md").write_text(
            (vault / "index.md").read_text(encoding="utf-8") + "\n- [[Starter]]\n- [[Revenue Calc]]\n",
            encoding="utf-8",
        )
        code, out, _ = self._run_cli([str(vault), "--json"])
        rep_starter = json.loads(out)
        self.assertEqual(code, 0)
        self.assertNotIn("wiki/concepts/Starter.md", rep_starter["legacy_sources_notes"])

        # 5. Dangling footnotes outside code spans vs code-masked footnotes
        fn_note = vault / "wiki" / "concepts" / "Footnote Check.md"
        fn_note.write_text(
            "---\ntitle: Footnote Check\ntype: concept\nsources:\n  - id: valid-id\n    resource: https://example.org\n---\n"
            "Claim one.[^valid-id]\n"
            "Code ignored: `[^inside-inline]`.\n"
            "```markdown\n"
            "[^inside-fence]\n"
            "```\n"
            "Dangling claim.[^missing-fn]\n",
            encoding="utf-8",
        )
        code, out, _ = self._run_cli([str(vault), "--json"])
        self.assertEqual(code, 1)
        rep_fn = json.loads(out)
        dangling_labels = {d["label"] for d in rep_fn["dangling_footnotes"]}
        self.assertEqual(dangling_labels, {"missing-fn"})
        fn_note.unlink()

        # 6. `stale_after` + legacy string `sources` + bad `log.md` date heading: warn by default (0), fail under --strict (1)
        stale_note = vault / "wiki" / "concepts" / "Stale Legacy.md"
        stale_note.write_text(
            "---\n"
            "title: Stale Legacy\n"
            "type: concept\n"
            "stale_after: 2020-01-01T00:00:00Z\n"
            "sources:\n"
            "  - raw/briefing.pptx\n"
            "---\n"
            "# Stale Legacy\n",
            encoding="utf-8",
        )
        (vault / "index.md").write_text(
            (vault / "index.md").read_text(encoding="utf-8") + "\n- [[Stale Legacy]]\n",
            encoding="utf-8",
        )
        (vault / "log.md").write_text(
            (vault / "log.md").read_text(encoding="utf-8") + "\n## Missing Date Heading\n- Oops\n",
            encoding="utf-8",
        )

        code_default, out_default, _ = self._run_cli([str(vault), "--json"])
        self.assertEqual(code_default, 0)
        rep_def = json.loads(out_default)
        self.assertTrue(rep_def["is_healthy"])
        self.assertIn("wiki/concepts/Stale Legacy.md", rep_def["legacy_sources_notes"])
        self.assertEqual(rep_def["stale_notes"][0]["file"], "wiki/concepts/Stale Legacy.md")
        self.assertTrue(rep_def["workspace_profile_warnings"])

        code_strict, _, _ = self._run_cli([str(vault), "--strict", "--json"])
        self.assertEqual(code_strict, 1)

    def test_exit_code_2_missing_vault_or_wiki_dir(self) -> None:
        missing_path = self.tmp_dir / "does_not_exist"
        code_json, out_json, err_json = self._run_cli([str(missing_path), "--json"])
        self.assertEqual(code_json, 2)
        parsed = json.loads(out_json)
        self.assertFalse(parsed["success"])
        self.assertEqual(err_json, "")

        code_txt, _, err_txt = self._run_cli([str(missing_path)])
        self.assertEqual(code_txt, 2)
        self.assertIn("not found", err_txt.lower())

        no_wiki = self.tmp_dir / "NoWikiDir"
        no_wiki.mkdir(parents=True)
        code_nowiki, out_nowiki, _ = self._run_cli([str(no_wiki), "--json"])
        self.assertEqual(code_nowiki, 2)
        self.assertFalse(json.loads(out_nowiki)["success"])

    def test_parent_dot_git_path_symlinks_and_code_masking_no_churn(self) -> None:
        # Vault residing inside a `.git` / `.agents` named parent directory must STILL be scanned!
        nested_parent = self.tmp_dir / ".git-parent" / ".agents-parent" / "NestedVault"
        init_vault.init_vault(nested_parent, quiet=True)
        (nested_parent / ".git").mkdir(parents=True, exist_ok=True)
        (nested_parent / ".git" / "ignored.md").write_text(
            "Broken [[ShouldBeIgnored]].\n", encoding="utf-8"
        )

        # Outside secret symlink inside wiki/ must be skipped
        outside_file = self.tmp_dir / "outside_secret.md"
        outside_file.write_text("Broken [[SecretLink]].\n", encoding="utf-8")
        (nested_parent / "wiki" / "concepts" / "symlink.md").symlink_to(outside_file)

        # Note with code-masked escaped pipes (``` and ~~~ and inline ``) + real table pipe violation
        code_note = nested_parent / "wiki" / "concepts" / "Code Masking.md"
        code_note.write_text(
            "---\n"
            "title: Code Masking\n"
            "type: concept\n"
            "updated: 2026-10-01\n"
            "---\n\n"
            "Inline code `[[Ignore\\|Inline]]` and `[[MissingInInline]]`.\n\n"
            "```markdown\n"
            "| [[Ignore\\|BacktickFence]] | [[MissingInBacktickFence]] |\n"
            "```\n\n"
            "~~~markdown\n"
            "| [[Ignore\\|TildeFence]] | [[MissingInTildeFence]] |\n"
            "~~~\n\n"
            "| Col A | Col B |\n"
            "| --- | --- |\n"
            "| [[wiki/skill-impact\\|Skill Impact]] | Fixed row |\n",
            encoding="utf-8",
        )
        (nested_parent / "index.md").write_text(
            (nested_parent / "index.md").read_text(encoding="utf-8")
            + "\n- [[Code Masking]]\n- [[wiki/skill-impact|Skill Impact]]\n",
            encoding="utf-8",
        )

        res1 = vault_lint.run_vault_lint(nested_parent, auto_fix=True, as_json=False)
        self.assertGreaterEqual(res1["total_wiki_notes"], 2)
        self.assertEqual(res1["broken_links"], [])
        self.assertEqual(len(res1["table_invariant_violations"]), 1)
        self.assertEqual(res1["fixed_files"], ["wiki/concepts/Code Masking.md"])

        fixed_text = code_note.read_text(encoding="utf-8")
        self.assertIn("`[[Ignore\\|Inline]]`", fixed_text)
        self.assertIn("[[Ignore\\|BacktickFence]]", fixed_text)
        self.assertIn("[[Ignore\\|TildeFence]]", fixed_text)
        self.assertIn("[[wiki/skill-impact|Skill Impact]]", fixed_text)
        self.assertIn("updated: 2026-10-01", fixed_text)

        # Second --fix run is a complete no-op (no churn, zero files touched)
        res2 = vault_lint.run_vault_lint(nested_parent, auto_fix=True, as_json=False)
        self.assertEqual(res2["fixed_files"], [])
        self.assertEqual(res2["table_invariant_violations"], [])
        self.assertTrue(res2["is_healthy"])
        # Ensure zero leftover .tmp files
        self.assertEqual(list((nested_parent / "wiki" / "concepts").glob("*.tmp")), [])

    def test_migrate_sources_and_wanted_pages_ranking(self) -> None:
        vault = self._create_clean_vault()
        mig_note = vault / "wiki" / "concepts" / "Legacy Migration.md"
        body = (
            "# Legacy Migration\n\n"
            "References [[High Priority Target]] and [[Low Priority Target]].\n"
        )
        mig_note.write_text(
            "---\n"
            'title: "Legacy Migration"\n'
            "type: concept\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-01\n"
            "sources:\n"
            '  - "raw/architecture-deck.pptx"\n'
            '  - "https://example.org/docs/guide.html"\n'
            "  - id: kept-id\n"
            '    resource: "https://example.org/kept"\n'
            "---\n\n" + body,
            encoding="utf-8",
        )
        # Add extra inbound links to High Priority Target so wanted_pages ranks it #1
        (vault / "wiki" / "concepts" / "Alpha Pattern.md").write_text(
            (vault / "wiki" / "concepts" / "Alpha Pattern.md").read_text(encoding="utf-8")
            + "\nSee also [[High Priority Target]] and [[Tie Target B]].\n",
            encoding="utf-8",
        )
        (vault / "wiki" / "concepts" / "Beta Pattern.md").write_text(
            (vault / "wiki" / "concepts" / "Beta Pattern.md").read_text(encoding="utf-8")
            + "\nSee also [[high priority target]] and [[Tie Target A]].\n",
            encoding="utf-8",
        )

        # Verify --fix --migrate-sources upgrades string entries and keeps body & existing dicts intact
        code1, out1, _ = self._run_cli([str(vault), "--fix", "--migrate-sources", "--json"])
        self.assertEqual(code1, 1)  # broken links still present -> wanted_pages populated
        rep1 = json.loads(out1)
        self.assertIn("wiki/concepts/Legacy Migration.md", rep1["migrated_sources_files"])
        self.assertIn("wiki/concepts/Legacy Migration.md", rep1["fixed_files"])
        self.assertEqual(rep1["legacy_sources_notes"], [])

        updated_mig = mig_note.read_text(encoding="utf-8")
        self.assertTrue(updated_mig.endswith(body))
        parsed_mig = vault_lint.okf.parse_okf_document(updated_mig, strict=False)
        self.assertEqual(
            parsed_mig["frontmatter"]["sources"],
            [
                {"id": "architecture-deck", "resource": "raw/architecture-deck.pptx"},
                {"id": "guide", "resource": "https://example.org/docs/guide.html"},
                {"id": "kept-id", "resource": "https://example.org/kept"},
            ],
        )

        # Idempotent second run
        res_idem = vault_lint.run_vault_lint(
            vault, auto_fix=True, migrate_sources=True, as_json=False
        )
        self.assertEqual(res_idem["migrated_sources_files"], [])
        self.assertEqual(res_idem["fixed_files"], [])

        # Verify wanted_pages ranking: High Priority Target (3), Low Priority Target (1), Tie Target A (1), Tie Target B (1)
        wanted = rep1["wanted_pages"]
        self.assertEqual(wanted[0]["inbound_count"], 3)
        self.assertEqual(wanted[0]["target"].lower(), "high priority target")
        self.assertEqual(len(wanted[0]["sources"]), 3)
        tie_targets = [w["target"] for w in wanted[1:]]
        self.assertEqual(
            tie_targets,
            ["Low Priority Target", "Tie Target A", "Tie Target B"],
        )

        # Verify human CLI output includes Wanted Pages
        _, human_out, _ = self._run_cli([str(vault)])
        self.assertIn("Wanted Pages", human_out)
        self.assertIn("3 inbound", human_out)

    def test_approve_human_containment_and_trust_tier_promotion(self) -> None:
        vault = self._create_clean_vault()
        target_rel = "wiki/concepts/Alpha Pattern.md"

        # Before approval: Alpha Pattern is unverified
        before = vault_lint.run_vault_lint(vault, as_json=False)
        self.assertEqual(before["trust_tier_counts"]["human-reviewed"], 0)

        # Approve via CLI with explicit --actor
        code_ok, out_ok, _ = self._run_cli(
            [str(vault), "--approve-human", target_rel, "--actor", "human:alice", "--json"]
        )
        self.assertEqual(code_ok, 0)
        res_ok = json.loads(out_ok)
        self.assertTrue(res_ok["success"])
        self.assertEqual(res_ok["actor"], "human:alice")
        self.assertEqual(res_ok["trust_tier"], "human-reviewed")

        # After approval: trust_tier_counts updates cleanly
        after = vault_lint.run_vault_lint(vault, as_json=False)
        self.assertEqual(after["trust_tier_counts"]["human-reviewed"], 1)

        # Default actor falls back to sanitized OS user
        with mock.patch.dict(os.environ, {"USER": "Bob Example@example.com"}, clear=False):
            code_def, out_def, _ = self._run_cli(
                [str(vault), "--approve-human", "wiki/concepts/Beta Pattern.md", "--json"]
            )
            self.assertEqual(code_def, 0)
            self.assertEqual(json.loads(out_def)["actor"], "human:Bob-Example")

        # Reject paths outside wiki/, symlinks, traversal, raw/, and root files with exit 2
        outside = self.tmp_dir / "outside.md"
        outside.write_text("---\ntitle: Out\ntype: concept\n---\n", encoding="utf-8")
        sym_in_wiki = vault / "wiki" / "concepts" / "sym.md"
        sym_in_wiki.symlink_to(outside)
        (vault / "raw" / "source.md").write_text(
            "---\ntitle: Raw\ntype: source-summary\n---\n", encoding="utf-8"
        )

        for bad_target in (
            "GEMINI.md",
            "index.md",
            "raw/source.md",
            "wiki/concepts/sym.md",
            "../outside.md",
            str(outside),
            "wiki/index.md",
            "wiki/concepts/DoesNotExist.md",
        ):
            code_bad, _, _ = self._run_cli([str(vault), "--approve-human", bad_target])
            self.assertEqual(code_bad, 2, msg=f"Expected exit 2 for {bad_target!r}")

        # Reject non-human actor and control characters in actor
        for bad_actor in ("process:bot", "human:a\x07b", "human:a\nb", "human:bad actor"):
            code_bot, _, _ = self._run_cli(
                [str(vault), "--approve-human", target_rel, "--actor", bad_actor]
            )
            self.assertEqual(code_bot, 2, msg=f"Expected exit 2 for actor {bad_actor!r}")

    def test_no_prefilled_human_verified_in_templates_and_skills(self) -> None:
        self.assertNotIn("by: human:", init_vault.DEFAULT_GEMINI_MD)
        self.assertIn(
            "generated: { by: knowledge-compiler/gemini-pro, at: YYYY-MM-DDTHH:MM:SSZ }",
            init_vault.DEFAULT_GEMINI_MD,
        )
        self.assertIn("--approve-human", init_vault.DEFAULT_GEMINI_MD)

        skill_roots = [REPO_ROOT / "skills"]
        if (REPO_ROOT / ".agents" / "skills").is_dir():
            skill_roots.append(REPO_ROOT / ".agents" / "skills")

        for s_root in skill_roots:
            for name in ("ingest", "distill-session", "vault-query"):
                txt = (s_root / name / "SKILL.md").read_text(encoding="utf-8")
                self.assertNotIn("by: human:", txt, msg=f"{s_root}/{name}/SKILL.md")
                self.assertNotIn("verified.by", txt, msg=f"{s_root}/{name}/SKILL.md")
                self.assertIn(
                    "knowledge-compiler/gemini-pro", txt, msg=f"{s_root}/{name}/SKILL.md"
                )
                self.assertIn("--approve-human", txt, msg=f"{s_root}/{name}/SKILL.md")

            kc_txt = (s_root / "knowledge-compiler" / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("--approve-human", kc_txt)
            self.assertNotIn("with `title`, `type`, `tags`, `status`, `generated`, `verified`", kc_txt)

            distill_txt = (s_root / "distill-session" / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("--apply", distill_txt)
            self.assertNotIn("--auto", distill_txt)

            lint_txt = (s_root / "vault-lint" / "SKILL.md").read_text(encoding="utf-8")
            for required_term in (
                "--strict",
                "--fix --migrate-sources",
                "--approve-human",
                "wanted_pages",
                "`0`",
                "`1`",
                "`2`",
            ):
                self.assertIn(required_term, lint_txt, msg=f"{s_root}/vault-lint/SKILL.md")

        # Also verify reference specs and standalone templates (including 3P ingest reference)
        ref_candidates = [
            REPO_ROOT / "skills" / "ingest" / "references" / "okf_spec.md",
            REPO_ROOT / ".agents" / "skills" / "ingest" / "references" / "okf_spec.md",
            REPO_ROOT / ".agents" / "skills" / "knowledge-compiler" / "references" / "okf_spec.md",
            REPO_ROOT / ".agents" / "skills" / "knowledge-compiler" / "assets" / "sample_vault_template" / "GEMINI.md",
            REPO_ROOT / "templates" / "GEMINI.md",
            REPO_ROOT / "docs" / "okf_spec.md",
        ]
        for ref_path in ref_candidates:
            if ref_path.is_file():
                ref_txt = ref_path.read_text(encoding="utf-8")
                self.assertNotIn("by: human:", ref_txt, msg=str(ref_path))
                self.assertNotIn("antigravity/gemini-pro", ref_txt, msg=str(ref_path))
                self.assertIn("knowledge-compiler/gemini-pro", ref_txt, msg=str(ref_path))
                self.assertIn("--approve-human", ref_txt, msg=str(ref_path))

    def test_fresh_init_vault_strict_crlf_utf8_indented_code_and_exception_guard(self) -> None:
        # 1. A fresh init_vault passes vault_lint --strict with exit 0
        fresh = self.tmp_dir / "FreshVault"
        init_vault.init_vault(fresh, quiet=True)
        code_fresh, out_fresh, _ = self._run_cli([str(fresh), "--strict", "--json"])
        self.assertEqual(code_fresh, 0, msg=out_fresh)
        rep_fresh = json.loads(out_fresh)
        self.assertTrue(rep_fresh["strict_passed"])
        self.assertEqual(rep_fresh["orphan_notes"], [])
        self.assertEqual(rep_fresh["missing_from_index"], [])

        # 2. 4-space indented code blocks mask wikilinks, pipes, and footnotes while keeping list links active
        indented_note = fresh / "wiki" / "concepts" / "Indented.md"
        indented_note.write_text(
            "---\n"
            "title: Indented\n"
            "type: concept\n"
            "sources:\n"
            "  - id: s1\n"
            "    resource: https://example.org\n"
            "---\n\n"
            "# Computation\n\n"
            "    SELECT [[FakeIndented]] AND [[Fake\\|Pipe]] FROM tbl -- [^fake_fn]\n\n"
            "- List parent\n"
            "  - [[wiki/skill-impact|Skill Impact]]\n",
            encoding="utf-8",
        )
        (fresh / "index.md").write_text(
            (fresh / "index.md").read_text(encoding="utf-8") + "\n- [[Indented]]\n",
            encoding="utf-8",
        )
        res_ind = vault_lint.run_vault_lint(fresh, auto_fix=False, as_json=False)
        self.assertEqual(res_ind["broken_links"], [])
        self.assertEqual(res_ind["table_invariant_violations"], [])
        self.assertEqual(res_ind["dangling_footnotes"], [])
        self.assertTrue(res_ind["is_healthy"])

        # 3. CRLF preserved across --fix, --migrate-sources, and --approve-human
        crlf_note = fresh / "wiki" / "concepts" / "CrlfNote.md"
        crlf_bytes = (
            "---\r\n"
            "title: CrlfNote\r\n"
            "type: concept\r\n"
            "sources:\r\n"
            "  - raw/source.md\r\n"
            "---\r\n\r\n"
            "| A | B |\r\n"
            "| --- | --- |\r\n"
            "| [[wiki/skill-impact\\|Skill]] | val |\r\n"
        ).encode("utf-8")
        crlf_note.write_bytes(crlf_bytes)
        (fresh / "index.md").write_text(
            (fresh / "index.md").read_text(encoding="utf-8") + "\n- [[CrlfNote]]\n",
            encoding="utf-8",
        )
        vault_lint.run_vault_lint(fresh, auto_fix=True, migrate_sources=True, as_json=False)
        app_crlf = vault_lint.approve_human_note(fresh, "wiki/concepts/CrlfNote.md", actor="human:alice")
        self.assertTrue(app_crlf["success"])
        after_crlf = crlf_note.read_bytes().decode("utf-8")
        self.assertNotRegex(after_crlf, r"(?<!\r)\n")
        self.assertIn("| [[wiki/skill-impact|Skill]] | val |\r\n", after_crlf)

        # 4. Invalid UTF-8 bytes fail closed on --approve-human and never drop bytes under --fix
        bad_utf8 = fresh / "wiki" / "concepts" / "BadUtf8.md"
        raw_bad_bytes = b"---\ntitle: Bad\ntype: concept\n---\n[[wiki/skill-impact\\|Bad]] \xff\xfe\n"
        bad_utf8.write_bytes(raw_bad_bytes)
        res_bad_utf8 = vault_lint.run_vault_lint(fresh, auto_fix=True, as_json=False)
        self.assertFalse(res_bad_utf8["is_healthy"])
        self.assertEqual(bad_utf8.read_bytes(), raw_bad_bytes)
        app_bad = vault_lint.approve_human_note(fresh, "wiki/concepts/BadUtf8.md", actor="human:alice")
        self.assertFalse(app_bad["success"])
        bad_utf8.unlink()

        # 5. Per-note exception in okf.validate_okf_concept records conformance error without crashing JSON output
        with mock.patch.object(
            vault_lint.okf, "validate_okf_concept", side_effect=OverflowError("boom")
        ):
            code_exc, out_exc, _ = self._run_cli([str(fresh), "--json"])
            self.assertEqual(code_exc, 1)
            rep_exc = json.loads(out_exc)
            self.assertFalse(rep_exc["is_healthy"])
            self.assertTrue(
                any("boom" in e["message"] for e in rep_exc["conformance_errors"])
            )

    def test_dual_mode_without_pyyaml_parity(self) -> None:
        vault = self._create_clean_vault("NoYamlVault")
        legacy = vault / "wiki" / "concepts" / "Legacy.md"
        legacy.write_text(
            "---\n"
            'title: "Legacy"\n'
            "type: concept\n"
            "sources:\n"
            '  - "raw/notes.md"\n'
            "---\n\n"
            "# Legacy\n",
            encoding="utf-8",
        )
        with mock.patch.dict(sys.modules, {"yaml": None}):
            res = vault_lint.run_vault_lint(
                vault, auto_fix=True, migrate_sources=True, as_json=False
            )
            self.assertTrue(res["is_healthy"])
            self.assertIn("wiki/concepts/Legacy.md", res["migrated_sources_files"])
            app = vault_lint.approve_human_note(
                vault, "wiki/concepts/Legacy.md", actor="human:stdlib-tester"
            )
            self.assertTrue(app["success"])
            self.assertEqual(app["trust_tier"], "human-reviewed")

    def test_linear_masking_on_adversarial_comments_fences_and_backticks(self) -> None:
        import time

        # 32,000 unclosed HTML comments (~224 KB), 32,000 unclosed fences (~160 KB),
        # and backtick runs of lengths 1..600 in a single paragraph (~181 KB).
        comments_body = "<!-- x\n" * 32000
        fences_body = "```x\n" * 32000
        backticks_body = " ".join("`" * n for n in range(1, 601))

        for label, payload in (
            ("comments", comments_body),
            ("fences", fences_body),
            ("backticks", backticks_body),
        ):
            t0 = time.monotonic()
            masked, restore_fn, _ = vault_lint._mask_markdown_code(payload)
            restored = restore_fn(masked)
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 2.0, msg=f"Masking {label} took too long: {elapsed:.2f}s")
            self.assertEqual(restored, payload)

        # Also verify multi-line comment + nested code restoration parity
        sample = "\n`inline [[A\\|B]]` and <!-- hidden [[C\\|D]] --> and [[Real\\|Link]]"
        masked_s, restore_s, _ = vault_lint._mask_markdown_code(sample)
        self.assertNotIn("[[A\\|B]]", masked_s)
        self.assertNotIn("[[C\\|D]]", masked_s)
        self.assertIn("[[Real\\|Link]]", masked_s)
        fixed_s = restore_s(masked_s.replace("[[Real\\|Link]]", "[[Real|Link]]"))
        self.assertEqual(
            fixed_s, "\n`inline [[A\\|B]]` and <!-- hidden [[C\\|D]] --> and [[Real|Link]]"
        )

        # Verify PUA sentinel collision resistance and fail-closed auto-fix skip when exhausted
        pua_sample = (
            "\ue000\ue200\ue400\U000f0000\U0010f000\U0010f010\U0010f001"
            " `code [[A\\|B]]` <!-- \U0010f000\U0010f010\U0010f001 --> [[Real\\|Link]]"
        )
        m_pua, r_pua, _ = vault_lint._mask_markdown_code(pua_sample)
        self.assertEqual(r_pua(m_pua), pua_sample)

        v_ex = self._create_clean_vault("ExhaustedSentinelVault")
        all_open = "".join(chr(b) for b in vault_lint._PUA_CANDIDATE_BASES)
        ex_note = v_ex / "wiki" / "concepts" / "Exhausted.md"
        raw_ex = (
            "---\n"
            "title: Exhausted\n"
            "type: concept\n"
            "---\n\n"
            f"{all_open} `\U0010f000\U0010f010\U0010f001` [[wiki/skill-impact\\|Skill]]\n"
        )
        ex_note.write_text(raw_ex, encoding="utf-8")
        res_ex = vault_lint.run_vault_lint(v_ex, auto_fix=True, as_json=False)
        self.assertTrue(
            any(w["rule"] == "sentinel_collision" for w in res_ex["workspace_profile_warnings"])
        )
        self.assertEqual(res_ex["fixed_files"], [])
        self.assertEqual(ex_note.read_text(encoding="utf-8"), raw_ex)

    def test_okf_v03_migration_idempotency_superseded_and_log_union(self) -> None:
        from scripts.hooks import auto_sync_vault

        vault = self.tmp_dir / "LegacyV02Vault"
        (vault / "raw").mkdir(parents=True)
        (vault / "wiki" / "concepts").mkdir(parents=True)
        (vault / "raw" / "briefing.pdf").write_text("dummy pdf", encoding="utf-8")

        # Legacy v0.2 root index.md (no okf_version), sub-index.md with frontmatter,
        # and log.md with frontmatter + out-of-order legacy headings
        (vault / "index.md").write_text(
            "---\ntitle: Legacy Vault\ncreated: 2026-10-01\n---\n\n"
            "# Master Index\n\n- [[Old Concept]]\n- [[New Concept]]\n",
            encoding="utf-8",
        )
        (vault / "wiki" / "index.md").write_text(
            "---\ntitle: Sub Index\n---\n\n# Wiki Sub Index\n",
            encoding="utf-8",
        )
        (vault / "log.md").write_text(
            "---\ntitle: Audit Log\ntype: meta\n---\n\n"
            "# Audit Log\n\n"
            "## [2026-10-01] init | Initialized vault\n"
            "- Created initial layout.\n\n"
            "## [2026-11-10] ingest | Added briefing\n"
            "- Compiled [[Old Concept]].\n",
            encoding="utf-8",
        )
        (vault / "wiki" / "concepts" / "New Concept.md").write_text(
            "---\n"
            "title: New Concept\n"
            "type: concept\n"
            "status: stable\n"
            "generated:\n"
            "  by: knowledge-compiler/1.2.0\n"
            "  at: 2026-11-17T12:00:00Z\n"
            "verified:\n"
            "  - by: human:reviewer\n"
            "    at: 2026-11-10T12:00:00Z\n"
            "---\n\n"
            "# New Concept\n\nReplaces [[Old Concept]].\n",
            encoding="utf-8",
        )
        (vault / "wiki" / "concepts" / "Old Concept.md").write_text(
            "---\n"
            "title: Old Concept\n"
            "type: concept\n"
            "status: deprecated\n"
            "superseded_by: wiki/concepts/New Concept.md\n"
            "sources:\n"
            "  - id: brief\n"
            "    resource: raw/briefing.pdf\n"
            "---\n\n"
            "# Old Concept\n\nGrounded in briefing.[^brief]\n",
            encoding="utf-8",
        )

        # First migration run upgrades index.md, log.md, wiki/index.md, and Old Concept.md
        code1, out1, _ = self._run_cli([str(vault), "--fix", "--migrate-v03", "--strict", "--json"])
        rep1 = json.loads(out1)
        self.assertEqual(code1, 0, msg=json.dumps(rep1, indent=2))
        self.assertEqual(rep1["bundle_okf_version"], "0.3")
        self.assertIn("index.md", rep1["migrated_v03_files"])
        self.assertIn("log.md", rep1["migrated_v03_files"])
        self.assertIn("wiki/index.md", rep1["migrated_v03_files"])
        self.assertIn("wiki/concepts/Old Concept.md", rep1["migrated_v03_files"])
        self.assertIn("wiki/concepts/New Concept.md", rep1["stale_verification_notes"])
        self.assertEqual(rep1["trust_tier_counts"]["unverified"], 2)

        idx_after = (vault / "index.md").read_text(encoding="utf-8")
        self.assertIn('okf_version: "0.3"', idx_after)
        log_after = (vault / "log.md").read_text(encoding="utf-8")
        self.assertFalse(log_after.startswith("---"))
        self.assertLess(log_after.index("## 2026-11-10"), log_after.index("## 2026-10-01"))
        self.assertFalse((vault / "wiki" / "index.md").read_text(encoding="utf-8").startswith("---"))
        old_after = (vault / "wiki" / "concepts" / "Old Concept.md").read_text(encoding="utf-8")
        self.assertIn("/raw/briefing.pdf", old_after)
        self.assertIn("/wiki/concepts/New Concept.md", old_after)

        # Second migration run is 100% idempotent
        code2, out2, _ = self._run_cli([str(vault), "--fix", "--migrate-v03", "--strict", "--json"])
        rep2 = json.loads(out2)
        self.assertEqual(code2, 0)
        self.assertEqual(rep2["migrated_v03_files"], [])
        self.assertEqual(rep2["fixed_files"], [])

        # Verify OKF v0.3 same-day bullet union in auto_sync_vault.merge_log_markdown
        ours = "# Audit Log\n\n## 2026-11-17\n\n- **sync** | Added Note A\n"
        theirs = "# Audit Log\n\n## 2026-11-17\n\n- **sync** | Added Note B\n"
        merged = auto_sync_vault.merge_log_markdown(ours, theirs)
        self.assertEqual(merged.count("## 2026-11-17"), 1)
        self.assertIn("Added Note A", merged)
        self.assertIn("Added Note B", merged)

    def test_shipped_starter_vault_is_strict_okf_v03_conformant(self) -> None:
        import vault_graph
        import vault_query

        starter = REPO_ROOT / "examples" / "starter-vault"
        self.assertTrue(starter.is_dir(), f"Missing shipped starter vault at {starter}")

        code, out, err = self._run_cli([str(starter), "--strict", "--json"])
        self.assertEqual(code, 0, msg=f"Starter vault failed strict lint:\n{out}\n{err}")
        rep = json.loads(out)
        self.assertTrue(rep["is_healthy"])
        self.assertTrue(rep["strict_passed"])
        self.assertEqual(rep["bundle_okf_version"], "0.3")
        self.assertEqual(rep["total_wiki_notes"], 21)
        self.assertEqual(rep["broken_links"], [])
        self.assertEqual(rep["orphan_notes"], [])
        self.assertEqual(rep["missing_from_index"], [])
        self.assertEqual(rep["conformance_errors"], [])
        self.assertGreaterEqual(rep["trust_tier_counts"]["machine-confirmed"], 1)

        for query_text in (
            "BigQuery partition pruning",
            "Pub/Sub dead-letter",
            "Workload Identity Federation",
            "canary rollout",
        ):
            q_res = vault_query.query_vault(starter, query_text, limit=5)
            self.assertGreaterEqual(
                q_res["total_results"],
                2,
                msg=f"Expected >= 2 matches for query {query_text!r}, got {q_res}",
            )
            scores = [r["score"] for r in q_res["results"]]
            self.assertEqual(scores, sorted(scores, reverse=True))

        graph = vault_graph.build_vault_graph(starter, ce_patterns_root=self.tmp_dir / "no_shared")
        cat_counts = graph["stats"]["categoryCounts"]
        for category in ("anchor", "raw", "source", "entity", "concept", "pattern", "synthesis"):
            self.assertGreaterEqual(
                cat_counts.get(category, 0),
                1,
                msg=f"Expected >= 1 node in category {category!r}, got {cat_counts}",
            )
        edge_counts = graph["stats"]["edgeTypeCounts"]
        for edge_type in (
            "CORROBORATES",
            "COMPLEMENTS",
            "EXTENDS",
            "CONTRADICTS",
            "SUPERSEDES",
            "LINKS_TO",
        ):
            self.assertGreaterEqual(
                edge_counts.get(edge_type, 0),
                1,
                msg=f"Expected >= 1 edge of type {edge_type!r}, got {edge_counts}",
            )


if __name__ == "__main__":
    unittest.main()
