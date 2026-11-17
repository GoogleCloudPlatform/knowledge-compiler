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
Unit tests for OKF v0.2 Vault Correction Engine (vault_correct.py).
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.vault_correct import (
    execute_vault_correction,
    is_historical_note,
    replace_restatements_with_link,
    update_frontmatter_date,
)


class TestVaultCorrectSuite(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="kc_correct_test_"))
        self.vault_root = self.test_dir / "TestVault"
        self.vault_root.mkdir(parents=True, exist_ok=True)

        # Create OKF folders
        (self.vault_root / "raw").mkdir(parents=True)
        (self.vault_root / "wiki" / "entities").mkdir(parents=True)
        (self.vault_root / "wiki" / "concepts").mkdir(parents=True)
        (self.vault_root / "wiki" / "sources").mkdir(parents=True)
        (self.vault_root / "wiki" / "synthesis").mkdir(parents=True)

        # Create GEMINI.md, index.md, log.md
        (self.vault_root / "GEMINI.md").write_text("# Test Vault\n", encoding="utf-8")
        (self.vault_root / "index.md").write_text("# Index\n", encoding="utf-8")
        (self.vault_root / "log.md").write_text(
            "# Operations Log\n\n## [2026-10-01] init\n- Initialized\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_historical_note_detection(self):
        # 1. Note in raw/
        raw_note = self.vault_root / "raw" / "deck.md"
        raw_note.write_text("raw text", encoding="utf-8")
        is_hist, reason = is_historical_note(raw_note, self.vault_root, {})
        self.assertTrue(is_hist)
        self.assertIn("record directory", reason)

        # 2. Note in wiki/sources/
        source_note = self.vault_root / "wiki" / "sources" / "Discovery Deck.md"
        source_note.write_text("source summary", encoding="utf-8")
        is_hist, reason = is_historical_note(source_note, self.vault_root, {})
        self.assertTrue(is_hist)
        self.assertIn("wiki/sources", reason)

        # 3. Date in filename
        dated_note = (
            self.vault_root / "wiki" / "concepts" / "Meeting 2026-10-08 Notes.md"
        )
        dated_note.write_text("notes", encoding="utf-8")
        is_hist, reason = is_historical_note(dated_note, self.vault_root, {})
        self.assertTrue(is_hist)
        self.assertIn("date provenance", reason)

        # 4. Status in frontmatter
        superseded_note = self.vault_root / "wiki" / "concepts" / "Old Arch.md"
        superseded_note.write_text("content", encoding="utf-8")
        is_hist, reason = is_historical_note(
            superseded_note, self.vault_root, {"status": "superseded"}
        )
        self.assertTrue(is_hist)
        self.assertIn("superseded", reason)

        # 5. Living concept note
        living_note = self.vault_root / "wiki" / "concepts" / "Agent Memory.md"
        living_note.write_text("content", encoding="utf-8")
        is_hist, _ = is_historical_note(
            living_note, self.vault_root, {"status": "stable"}
        )
        self.assertFalse(is_hist)

    def test_frontmatter_date_update(self):
        content = (
            "---\ntitle: Test\ncreated: 2026-08-01\nupdated: 2026-08-01\n---\n# Body\n"
        )
        updated = update_frontmatter_date(content, "2026-10-12")
        self.assertIn("updated: 2026-10-12", updated)
        self.assertIn("created: 2026-08-01", updated)

    def test_replace_restatement_with_wikilink(self):
        text = (
            "We determined that the customer spend is $30,000/mo on Aurora.\n"
            "```markdown\n"
            "Do not replace $30,000/mo in code blocks.\n"
            "```\n"
            "Summary: $30,000/mo total.\n"
        )
        new_text, count = replace_restatements_with_link(
            content=text,
            stale_patterns=["$30,000/mo"],
            authoritative_title="Acme Database Fleet",
        )
        self.assertEqual(count, 2)
        self.assertIn("[[Acme Database Fleet]]", new_text)
        self.assertIn("Do not replace $30,000/mo in code blocks.", new_text)

    def test_full_correction_sweep_execution(self):
        # Setup 3 notes:
        # 1. Authoritative: wiki/entities/Acme Corp.md
        auth_file = self.vault_root / "wiki" / "entities" / "Acme Corp.md"
        auth_file.write_text(
            "---\ntitle: Acme Corp\ntype: entity\nstatus: stable\ncreated: 2026-08-01\nupdated: 2026-08-01\n---\n"
            "# Acme Corp\nDatabase spend is currently $50,000/mo across MySQL.\n",
            encoding="utf-8",
        )

        # 2. Restatement: wiki/synthesis/TCO Modernization.md
        restate_file = self.vault_root / "wiki" / "synthesis" / "TCO Modernization.md"
        restate_file.write_text(
            "---\ntitle: TCO Modernization\ntype: synthesis\nstatus: stable\ncreated: 2026-08-05\nupdated: 2026-08-05\n---\n"
            "# TCO\nAcme has $50,000/mo in MySQL database infrastructure.\n",
            encoding="utf-8",
        )

        # 3. Historical Record: wiki/sources/Acme Discovery (2026-08-01).md
        hist_file = (
            self.vault_root / "wiki" / "sources" / "Acme Discovery (2026-08-01).md"
        )
        hist_text = (
            "---\ntitle: Discovery Transcript\ntype: source-summary\nstatus: stable\n---\n"
            "# Discovery\nClient stated $50,000/mo during initial kickoff.\n"
        )
        hist_file.write_text(hist_text, encoding="utf-8")

        # Run correction sweep
        results = execute_vault_correction(
            vault_root=self.vault_root,
            fact="Acme Corp database spend is actually $32,000/mo across MySQL",
            stale_claim="$50,000/mo",
            target_authoritative="Acme Corp",
            dry_run=False,
            auto=False,
        )

        # Check results structure
        self.assertEqual(len(results["authoritative_updated"]), 1)
        self.assertEqual(len(results["restatements_refactored"]), 1)
        self.assertEqual(len(results["historical_preserved"]), 1)

        # Check Authoritative note was updated with new fact
        auth_updated = auth_file.read_text(encoding="utf-8")
        self.assertIn("$32,000/mo", auth_updated)

        # Check Restatement was refactored to a wikilink
        restate_updated = restate_file.read_text(encoding="utf-8")
        self.assertIn("[[Acme Corp]]", restate_updated)
        self.assertNotIn("$50,000/mo", restate_updated)

        # Check Historical note was strictly PRESERVED
        hist_current = hist_file.read_text(encoding="utf-8")
        self.assertEqual(hist_current, hist_text)

        # Check log.md recorded the operation
        log_content = (self.vault_root / "log.md").read_text(encoding="utf-8")
        self.assertIn("correct | Acme Corp", log_content)
        self.assertIn("Preserved Historical Records", log_content)

    def test_dry_run_leaves_files_untouched(self):
        auth_file = self.vault_root / "wiki" / "entities" / "Beta Inc.md"
        orig_content = (
            "---\ntitle: Beta Inc\ntype: entity\nstatus: stable\ncreated: 2026-08-01\nupdated: 2026-08-01\n---\n"
            "# Beta Inc\nDatabase is Postgres 14.\n"
        )
        auth_file.write_text(orig_content, encoding="utf-8")

        results = execute_vault_correction(
            vault_root=self.vault_root,
            fact="Beta Inc uses Postgres 16",
            stale_claim="Postgres 14",
            target_authoritative="Beta Inc",
            dry_run=True,
            auto=False,
        )

        self.assertEqual(len(results["authoritative_updated"]), 1)
        self.assertEqual(auth_file.read_text(encoding="utf-8"), orig_content)


if __name__ == "__main__":
    unittest.main()
