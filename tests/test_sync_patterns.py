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
Unit tests for Federated Pattern Exchange & Sanitization Engine (sync_patterns.py).
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

# Add scripts directory to path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import sync_patterns  # noqa: E402


class TestSyncPatterns(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="kc_patterns_test_")
        self.mock_vault = Path(self.test_dir) / "MockVault"
        self.mock_shared_repo = Path(self.test_dir) / "MockSharedRepo"

        # Create Mock Vault structure
        (self.mock_vault / "wiki" / "concepts").mkdir(parents=True)
        (self.mock_vault / "wiki" / "patterns").mkdir(parents=True)
        (self.mock_vault / "wiki" / "entities").mkdir(parents=True)
        (self.mock_vault / "wiki" / "synthesis").mkdir(parents=True)
        (self.mock_vault / "raw").mkdir(parents=True)
        (self.mock_vault / "tables").mkdir(parents=True)

        (self.mock_vault / "GEMINI.md").write_text("# Mock Schema\n", encoding="utf-8")
        (self.mock_vault / "index.md").write_text(
            "# Mock Index\n\n## 🔬 Core Concepts & Frameworks\n\n## 🛠 Invariants & Engineering Patterns\n",
            encoding="utf-8",
        )
        (self.mock_vault / "log.md").write_text("# Mock Log\n", encoding="utf-8")

        # Initialize mock shared repo via init_patterns_repo
        sync_patterns.init_patterns_repo(self.mock_shared_repo, init_git=False)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_init_patterns_repo(self):
        """Test repository scaffolding contains all required OKF v0.2 components."""
        self.assertTrue((self.mock_shared_repo / "GEMINI.md").exists())
        self.assertTrue((self.mock_shared_repo / "README.md").exists())
        self.assertTrue((self.mock_shared_repo / "index.md").exists())
        self.assertTrue((self.mock_shared_repo / "log.md").exists())
        self.assertTrue(
            (self.mock_shared_repo / ".github" / "workflows" / "lint.yml").exists()
        )
        self.assertTrue((self.mock_shared_repo / "wiki" / "concepts").is_dir())
        self.assertTrue((self.mock_shared_repo / "wiki" / "patterns").is_dir())

    def test_sanitize_markdown(self):
        """Test customer de-identification, local path scrubbing, and frontmatter cleaning."""
        (self.mock_vault / "tables" / "customers.md").write_text(
            "| Customer Account | Industry | Notes |\n"
            "| :--- | :--- | :--- |\n"
            "| **[[AcmeCorp]]** | Enterprise Commercial Account | Active |\n"
            "| **[[Northwind|NW]]** | Global Retail & Supply Chain Enterprise | Active |\n",
            encoding="utf-8",
        )
        raw_content = """---
title: "Dual Run Migration"
type: concept
sources:
  - "/home/alice/ObsidianVault/raw/AcmeCorp_Meeting.pptx"
  - "https://cloud.google.com/architecture/dual-run"
generated:
  by: antigravity/gemini-pro
verified:
  - by: human:alice
---

# Dual Run Migration

We deployed [[Dual Run]] for [[AcmeCorp]] and [[Northwind|NW]] in production.
Inspect trace at `/home/alice/project/logs/trace.log`.
"""
        sanitized, scrub_notes = sync_patterns.sanitize_markdown(
            raw_content, vault_root=self.mock_vault
        )

        # Assert customer wikilinks replaced with generic terms
        self.assertNotIn("[[AcmeCorp]]", sanitized)
        self.assertIn("Enterprise Commercial Account", sanitized)
        self.assertNotIn("[[Northwind|NW]]", sanitized)
        self.assertIn("Global Retail & Supply Chain Enterprise", sanitized)

        # Assert local filesystem paths scrubbed
        self.assertNotIn("/home/alice/project", sanitized)
        self.assertIn("/workspace/project/logs/trace.log", sanitized)

        # Assert raw customer deck scrubbed from sources frontmatter
        self.assertNotIn("AcmeCorp_Meeting.pptx", sanitized)
        self.assertIn("https://cloud.google.com/architecture/dual-run", sanitized)

        # Assert human author sanitized
        self.assertIn("by: human:cloud-ce", sanitized)
        self.assertGreater(len(scrub_notes), 3)

    def test_audit_vault_detection(self):
        """Test audit correctly categorizes clean, scrub-needed, and blocked files."""
        # 1. Clean concept
        clean_note = self.mock_vault / "wiki" / "concepts" / "CleanConcept.md"
        clean_note.write_text(
            "---\ntitle: CleanConcept\ntype: concept\n---\n# Clean Concept\nPure architecture pattern.\n",
            encoding="utf-8",
        )

        # 2. Scrub needed concept (has customer reference)
        scrub_note = self.mock_vault / "wiki" / "concepts" / "ScrubConcept.md"
        scrub_note.write_text(
            "---\ntitle: ScrubConcept\ntype: concept\n---\n# Scrub Concept\nTested with [[AcmeCorp]].\n",
            encoding="utf-8",
        )

        # 3. Blocked concept (has performance rating / promo packet keyword)
        blocked_note = self.mock_vault / "wiki" / "concepts" / "BlockedConcept.md"
        blocked_note.write_text(
            "---\ntitle: Blocked\ntype: concept\n---\n# Performance\nThis was submitted for performance rating and promo packet.\n",
            encoding="utf-8",
        )

        audit_res = sync_patterns.audit_vault(self.mock_vault)
        clean_files = [item["file"] for item in audit_res["clean"]]
        scrub_files = [item["file"] for item in audit_res["scrub_needed"]]
        blocked_files = [item["file"] for item in audit_res["blocked"]]

        self.assertIn("wiki/concepts/CleanConcept.md", clean_files)
        self.assertIn("wiki/concepts/ScrubConcept.md", scrub_files)
        self.assertIn("wiki/concepts/BlockedConcept.md", blocked_files)

    def test_share_security_enforcement(self):
        """Test sharing raises SecurityException when trying to share private/raw/eval notes."""
        # Test sharing from raw/
        raw_file = self.mock_vault / "raw" / "customer_deck.md"
        raw_file.write_text("# Private Customer Presentation\n", encoding="utf-8")
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                raw_file, self.mock_shared_repo, vault_root=self.mock_vault
            )

        # Test sharing from wiki/entities/
        entity_file = self.mock_vault / "wiki" / "entities" / "AcmeCorp.md"
        entity_file.write_text(
            "---\ntitle: AcmeCorp\ntags: [customer]\n---\n# Customer Dossier\n",
            encoding="utf-8",
        )
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                entity_file, self.mock_shared_repo, vault_root=self.mock_vault
            )

        # Test sharing note with performance rating content
        eval_note = self.mock_vault / "wiki" / "concepts" / "PerfNote.md"
        eval_note.write_text(
            "# My performance rating and promo packet\n", encoding="utf-8"
        )
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                eval_note, self.mock_shared_repo, vault_root=self.mock_vault
            )

    def test_share_pattern_success(self):
        """Test successfully sharing and sanitizing a pattern into target repository."""
        concept_file = self.mock_vault / "wiki" / "concepts" / "A2A Protocol.md"
        concept_file.write_text(
            """---
title: "A2A Protocol"
type: concept
tags:
  - architecture/agent
sources:
  - "https://a2a-protocol.org"
---

# A2A Protocol

Demonstrated interoperability with [[AcmeCorp]].
""",
            encoding="utf-8",
        )

        res = sync_patterns.share_pattern(
            concept_file,
            self.mock_shared_repo,
            vault_root=self.mock_vault,
            dry_run=False,
        )

        self.assertTrue(res["success"])
        target_file = self.mock_shared_repo / "wiki" / "concepts" / "A2A Protocol.md"
        self.assertTrue(target_file.exists())

        # Verify content was sanitized
        content = target_file.read_text(encoding="utf-8")
        self.assertNotIn("[[AcmeCorp]]", content)
        self.assertIn("Enterprise Commercial Account", content)

        # Verify index.md updated
        index_content = (self.mock_shared_repo / "index.md").read_text(encoding="utf-8")
        self.assertIn("A2A Protocol", index_content)

        # Verify log.md updated
        log_content = (self.mock_shared_repo / "log.md").read_text(encoding="utf-8")
        self.assertIn("A2A Protocol", log_content)

    def test_pull_patterns(self):
        """Test pulling patterns from shared repo into local vault."""
        # Create a new pattern in shared repo
        shared_pattern = (
            self.mock_shared_repo / "wiki" / "patterns" / "CircuitBreaker.md"
        )
        shared_pattern.write_text(
            """---
title: "Circuit Breaker"
type: pattern
---

# Circuit Breaker Invariant
Prevents infinite LLM recursion loops.
""",
            encoding="utf-8",
        )

        res = sync_patterns.pull_patterns(
            self.mock_shared_repo,
            vault_root=self.mock_vault,
            dry_run=False,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["pulled_count"], 1)

        local_file = self.mock_vault / "wiki" / "patterns" / "CircuitBreaker.md"
        self.assertTrue(local_file.exists())
        self.assertIn(
            "Circuit Breaker Invariant", local_file.read_text(encoding="utf-8")
        )
        log_text = (self.mock_vault / "log.md").read_text(encoding="utf-8")
        self.assertIn("[[CircuitBreaker]]", log_text)
        self.assertNotIn("shared patterns]]", log_text)

        # Verify local newer note with private customer link is NOT clobbered by older shared note
        newer_local = self.mock_vault / "wiki" / "concepts" / "ShiftLeft.md"
        newer_local.write_text(
            "---\ntitle: ShiftLeft\ntype: concept\nupdated: 2026-10-28\n---\n# ShiftLeft\nUsed at [[AcmeCorp]].\n",
            encoding="utf-8",
        )
        older_shared = self.mock_shared_repo / "wiki" / "concepts" / "ShiftLeft.md"
        older_shared.write_text(
            "---\ntitle: ShiftLeft\ntype: concept\nupdated: 2026-08-26\n---\n# ShiftLeft\nSanitized.\n",
            encoding="utf-8",
        )
        res2 = sync_patterns.pull_patterns(
            self.mock_shared_repo,
            vault_root=self.mock_vault,
            dry_run=False,
        )
        self.assertEqual(res2["pulled_count"], 0)
        self.assertEqual(res2["skipped_count"], 1)
        self.assertIn("[[AcmeCorp]]", newer_local.read_text(encoding="utf-8"))

    def test_private_wiki_entities_and_dynamic_archetype_sanitization(self):
        """Test path-prefixed wiki/entities/, dynamic industry archetypes, workstation paths, and code-span safety."""
        (self.mock_vault / "tables" / "customers.md").write_text(
            "| Customer Account | Industry | Notes |\n"
            "| :--- | :--- | :--- |\n"
            "| **[[QuantumFin Corp|QFin]]** | Capital Markets & Fintech | Active |\n"
            "| **[[CyberForensics Inc]]** | Multi-Tenant SaaS ISV | Active |\n"
            "| **[[Apex Equity|PE Sponsor]]** | Private Equity Sponsor | Active |\n",
            encoding="utf-8",
        )
        (self.mock_vault / "wiki" / "entities" / "BioGenix.md").write_text(
            "---\ntitle: BioGenix\ntype: entity\ntags:\n  - entity/customer\n  - industry/biotech\naliases:\n  - BioGenix Labs\n---\n# BioGenix\n",
            encoding="utf-8",
        )
        (self.mock_vault / "wiki" / "entities" / "Cloud Run.md").write_text(
            "---\ntitle: Cloud Run\ntype: entity\ntags:\n  - gcp/serverless\n---\n# Cloud Run\n",
            encoding="utf-8",
        )
        (
            self.mock_vault
            / "wiki"
            / "synthesis"
            / "CyberForensics Inc - GCP Migration Strategy.md"
        ).write_text(
            "---\ntitle: CyberForensics Inc - GCP Migration Strategy\ntype: synthesis\n---\n",
            encoding="utf-8",
        )

        concept_note = self.mock_vault / "wiki" / "concepts" / "Zero Trust C2C.md"
        concept_note.write_text(
            "---\n"
            'title: "Zero Trust C2C"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-28\n"
            "tags:\n"
            "  - migration\n"
            "sources:\n"
            '  - "/usr/local/corp/home/alice/ObsidianVault/raw/client_deck.pptx"\n'
            '  - "https://cloud.google.com/architecture"\n'
            "corroborates:\n"
            '  - "[[CyberForensics Inc - GCP Migration Strategy]]"\n'
            "---\n\n"
            "# Zero Trust C2C\n\n"
            "Validated with [[wiki/entities/CyberForensics Inc]], [[wiki/entities/Apex Equity|PE Sponsor]], "
            "[[wiki/entities/QuantumFin Corp|QFin]], [[BioGenix Labs]], and [[wiki/entities/StealthClient]].\n"
            "Runs on [[wiki/entities/Cloud Run|Google Cloud Run]] at `/usr/local/corp/home/alice/repo/app.py`.\n\n"
            "```markdown\n"
            "Keep literal syntax example: [[wiki/entities/ExampleAccount]]\n"
            "```\n",
            encoding="utf-8",
        )

        res = sync_patterns.share_pattern(
            concept_note,
            self.mock_shared_repo,
            vault_root=self.mock_vault,
            dry_run=False,
        )
        self.assertTrue(res["success"])

        out_text = (
            self.mock_shared_repo / "wiki" / "concepts" / "Zero Trust C2C.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Multi-Tenant SaaS ISV", out_text)
        self.assertIn("Private Equity Sponsor", out_text)
        self.assertIn("Enterprise Capital Markets & Fintech Organization", out_text)
        self.assertIn("Enterprise Biotech Organization", out_text)
        self.assertIn("Enterprise Commercial Account", out_text)
        self.assertIn("Runs on Google Cloud Run at `/workspace/repo/app.py`.", out_text)
        self.assertNotIn("CyberForensics", out_text)
        self.assertNotIn("Apex Equity", out_text)
        self.assertNotIn("QuantumFin", out_text)
        self.assertNotIn("BioGenix", out_text)
        self.assertNotIn("StealthClient", out_text)
        self.assertNotIn("/usr/local/corp/home/", out_text)
        self.assertNotIn("corroborates:", out_text)
        # Code block example must remain untouched
        self.assertIn("Keep literal syntax example: [[wiki/entities/ExampleAccount]]", out_text)


if __name__ == "__main__":
    unittest.main()
