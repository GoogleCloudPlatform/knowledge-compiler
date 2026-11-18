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
"""Hermetic test suite for CE Knowledge Compiler utilities."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "hooks"))

import analyze_trace  # noqa: E402
import auto_sync_vault  # noqa: E402
import compile_graph_html  # noqa: E402
import extract_source  # noqa: E402
import federation_provider  # noqa: E402
import init_vault  # noqa: E402
import install_plugin  # noqa: E402
import log_tool_failure  # noqa: E402
import sanitize_check  # noqa: E402
import session_sync  # noqa: E402
import sync_patterns  # noqa: E402
import vault_graph  # noqa: E402
import vault_lint  # noqa: E402


class TestKnowledgeCompilerSuite(unittest.TestCase):
    """Hermetic unit tests for Knowledge Compiler suite."""


    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="kc_test_")
        self._orig_env = dict(os.environ)
        iso_home = Path(self.test_dir) / "home"
        iso_home.mkdir(parents=True, exist_ok=True)
        iso_state = Path(self.test_dir) / "state"
        iso_state.mkdir(parents=True, exist_ok=True)
        iso_cache = Path(self.test_dir) / "cache"
        iso_cache.mkdir(parents=True, exist_ok=True)
        iso_plugin_data = Path(self.test_dir) / "plugin_data"
        iso_plugin_data.mkdir(parents=True, exist_ok=True)
        iso_patterns = Path(self.test_dir) / "empty_patterns"
        iso_patterns.mkdir(parents=True, exist_ok=True)
        iso_vault = Path(self.test_dir) / "empty_vault"
        iso_vault.mkdir(parents=True, exist_ok=True)

        os.environ["HOME"] = str(iso_home)
        os.environ["XDG_STATE_HOME"] = str(iso_state)
        os.environ["XDG_CACHE_HOME"] = str(iso_cache)
        os.environ["PLUGIN_DATA"] = str(iso_plugin_data)
        os.environ["OBSIDIAN_VAULT_PATH"] = str(iso_vault)
        os.environ["OKF_PATTERNS_PATH"] = str(iso_patterns)

        self._mock_patchers = [
            mock.patch.object(
                vault_graph,
                "OWNER_TOKEN_PATH",
                iso_plugin_data / ".vault_graph_token",
            ),
        ]
        for p in self._mock_patchers:
            p.start()

    def tearDown(self):
        for p in reversed(getattr(self, "_mock_patchers", [])):
            try:
                p.stop()
            except Exception:
                pass
        os.environ.clear()
        os.environ.update(self._orig_env)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_init_vault(self):
        """Test vault initialization creates full OKF v0.2 topology."""
        vault_path = Path(self.test_dir) / "TestVault"
        result = init_vault.init_vault(vault_path)
        self.assertTrue(result["success"])

        expected_dirs = [
            "raw/assets",
            "wiki/sources",
            "wiki/entities",
            "wiki/concepts",
            "wiki/patterns",
            "wiki/synthesis",
            "bases",
        ]
        for rel_dir in expected_dirs:
            self.assertTrue(
                (vault_path / rel_dir).is_dir(), f"Missing directory: {rel_dir}"
            )

        expected_files = [
            "purpose.md",
            "GEMINI.md",
            "index.md",
            "log.md",
            "wiki/skill-impact.md",
            "bases/Architecture Catalog.base",
            "bases/Customer & Entity Directory.base",
            "bases/Recently Touched.base",
            "bases/Sources & Synthesis.base",
        ]
        for rel_file in expected_files:
            self.assertTrue(
                (vault_path / rel_file).is_file(), f"Missing file: {rel_file}"
            )

    def test_lint_and_pipe_fixing(self):
        """Test table pipe invariant repair via vault_lint."""
        vault_path = Path(self.test_dir) / "TestVault"
        init_vault.init_vault(vault_path)

        # Create a file with escaped pipe in wikilink inside a table
        sample_markdown = (
            "# Concept Note\n\n"
            "| Concept | Relation |\n"
            "| --- | --- |\n"
            "| [[Spanner\\|Google Cloud Spanner]] | Relational DB |\n"
        )
        test_file = vault_path / "wiki" / "concepts" / "spanner.md"
        test_file.write_text(sample_markdown, encoding="utf-8")

        # Run vault lint with auto_fix enabled
        result = vault_lint.run_vault_lint(vault_path, auto_fix=True)
        self.assertIn("table_invariant_violations", result)
        self.assertEqual(len(result["table_invariant_violations"]), 1)
        self.assertIn("wiki/concepts/spanner.md", result["fixed_files"])

        repaired_content = test_file.read_text(encoding="utf-8")
        self.assertIn("[[Spanner|Google Cloud Spanner]]", repaired_content)
        self.assertNotIn("\\[[Spanner\\|", repaired_content)

    def test_extract_source_markdown(self):
        """Test source processing on a markdown file."""
        vault_path = Path(self.test_dir) / "TestVault"
        init_vault.init_vault(vault_path)

        doc_path = Path(self.test_dir) / "discovery_briefing.md"
        doc_path.write_text(
            "# Customer Discovery\n\nNotes on architecture requirements.",
            encoding="utf-8",
        )

        results = extract_source.process_target(str(doc_path), vault_root=vault_path)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["success"])
        self.assertTrue((vault_path / "raw" / "discovery_briefing.md").exists())

    def test_analyze_trace(self):
        """Test WikiSkill trace analysis on execution logs."""
        transcript_file = Path(self.test_dir) / "transcript.jsonl"
        lines = [
            json.dumps({"type": "USER_INPUT", "content": "Deploy to Cloud Run"}),
            json.dumps(
                {
                    "type": "PLANNER_RESPONSE",
                    "status": "ERROR",
                    "content": "Encountered error in tool execution",
                }
            ),
            json.dumps(
                {
                    "type": "USER_INPUT",
                    "content": "That failed, use gcloud run deploy instead",
                }
            ),
        ]
        transcript_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = analyze_trace.analyze_transcript(str(transcript_file))
        self.assertEqual(report["total_steps"], 3)
        self.assertEqual(report["tool_error_count"], 1)
        self.assertEqual(report["user_correction_count"], 1)

    def test_log_tool_failure_hook(self):
        """Test PostToolUse hook logs errors to error_traces.jsonl and detects harness."""
        trace_file = Path(self.test_dir) / "error_traces.jsonl"
        payload = {
            "stepIdx": 4,
            "toolName": "run_command",
            "transcriptPath": "/home/user/.gemini/antigravity/brain/123/transcript.jsonl",
            "args": {"CommandLine": "gcloud auth login"},
            "error": "command not found: gcloud",
        }
        log_tool_failure.process_hook(payload, trace_file)
        self.assertTrue(trace_file.exists())
        lines = trace_file.read_text(encoding="utf-8").strip().split("\n")
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["tool_name"], "run_command")
        self.assertEqual(record["harness"], "antigravity")
        self.assertEqual(record["error"], "command not found: gcloud")

    def test_install_global_plugin_and_harness_detection(self):
        """Test global plugin installation and Primary/Antigravity harness detection."""
        mock_home = Path(self.test_dir) / "mock_home"
        (mock_home / ".gemini" / "antigravity").mkdir(parents=True)

        det = install_plugin.detect_installed_harnesses(home_dir=mock_home)
        self.assertTrue(det["antigravity"])

        # Seed a legacy standalone sidecar directory to verify automatic deduplication
        legacy_sidecar = mock_home / ".gemini" / "config" / "sidecars" / "vault_graph"
        legacy_sidecar.mkdir(parents=True)
        (legacy_sidecar / "sidecar.json").write_text("{}", encoding="utf-8")

        target_plugin = (
            mock_home / ".gemini" / "config" / "plugins" / "knowledge-compiler"
        )
        res = install_plugin.install_global_plugin(
            target_plugin_dir=target_plugin, home_dir=mock_home
        )
        self.assertTrue(res["success"])
        self.assertTrue((target_plugin / "plugin.json").is_file())
        self.assertTrue(
            (target_plugin / ".antigravity-plugin" / "plugin.json").is_file()
        )
        self.assertTrue((target_plugin / ".gemini-plugin" / "plugin.json").is_file())
        self.assertTrue((target_plugin / "hooks.json").is_file())
        self.assertTrue((target_plugin / "rules" / "AGENTS.md").is_file())
        self.assertTrue((target_plugin / "scripts" / "vault_lint.py").is_file())
        self.assertTrue((target_plugin / "scripts" / "vault_correct.py").is_file())
        self.assertTrue((target_plugin / "scripts" / "vault_graph.py").is_file())
        self.assertTrue((target_plugin / "scripts" / "sync_patterns.py").is_file())
        self.assertTrue(
            (target_plugin / "sidecars" / "vault_graph" / "sidecar.json").is_file()
        )
        self.assertFalse(legacy_sidecar.exists())
        self.assertIn("ingest", res["copied_skills"])
        self.assertIn("vault-query", res["copied_skills"])
        self.assertIn("vault-graph", res["copied_skills"])

    def test_vault_graph_build_and_export(self):
        """Test WebGL vault graph builder, PageRank centrality, and standalone HTML export."""
        vault_path = Path(self.test_dir) / "GraphVault"
        init_vault.init_vault(vault_path)

        entity_note = vault_path / "wiki" / "entities" / "AcmeCorp.md"
        entity_note.write_text(
            "---\ntitle: Acme Corp\ntype: entity\ntags:\n  - industry/retail\n---\n"
            "# Acme Corp\n\nUses [[Cloud Spanner]] and [[Pattern Pipe]].\n",
            encoding="utf-8",
        )
        concept_note = vault_path / "wiki" / "concepts" / "Cloud Spanner.md"
        concept_note.write_text(
            "---\ntitle: Cloud Spanner\ntype: concept\ntags:\n  - gcp/database\n---\n"
            "# Cloud Spanner\n\nReferenced by [[Acme Corp]].\n",
            encoding="utf-8",
        )
        pattern_note = vault_path / "wiki" / "patterns" / "Pattern Pipe.md"
        pattern_note.write_text(
            "---\ntitle: Pattern Pipe\ntype: concept\n---\n# Pattern Pipe\n",
            encoding="utf-8",
        )

        graph = vault_graph.build_vault_graph(
            vault_path, ce_patterns_root=Path(self.test_dir) / "empty_patterns"
        )
        self.assertGreaterEqual(graph["stats"]["wikiNotes"], 4)
        self.assertGreaterEqual(graph["stats"]["totalEdges"], 3)
        self.assertEqual(graph["stats"]["categoryCounts"]["pattern"], 1)

        out_html = Path(self.test_dir) / "exported_graph.html"
        export_res = vault_graph.export_graph_html(vault_path, out_html)
        self.assertTrue(export_res["success"])
        self.assertTrue(out_html.is_file())
        html_text = out_html.read_text(encoding="utf-8")
        self.assertIn("WebGL2", html_text)
        self.assertIn("Acme Corp", html_text)

    def test_auto_sync_vault_hook(self):
        """Test Stop hook automatically commits dirty vault changes."""
        import subprocess

        vault_dir = Path(self.test_dir) / "MockVault"
        vault_dir.mkdir(parents=True)
        subprocess.run(
            ["git", "init"], cwd=str(vault_dir), check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@google.com"],
            cwd=str(vault_dir),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test Runner"],
            cwd=str(vault_dir),
            check=True,
            capture_output=True,
        )

        readme = vault_dir / "index.md"
        readme.write_text("# Master Index\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "-A"], cwd=str(vault_dir), check=True, capture_output=True
        )
        subprocess.run(
            ["git", "commit", "-m", "initial commit"],
            cwd=str(vault_dir),
            check=True,
            capture_output=True,
        )

        # Verify clean check
        res_clean = auto_sync_vault.sync_vault(vault_dir, conversation_id="conv-123")
        self.assertEqual(res_clean["status"], "clean")

        # Simulate agent modifying files in the vault
        new_note = vault_dir / "wiki" / "entities" / "NewCustomer.md"
        new_note.parent.mkdir(parents=True)
        new_note.write_text(
            "---\ntitle: NewCustomer\n---\n# NewCustomer\n", encoding="utf-8"
        )

        # Run sync_vault on dirty vault with Primary harness provenance
        res_sync = auto_sync_vault.sync_vault(
            vault_dir, conversation_id="0f0be49d-test", harness="Primary"
        )
        self.assertEqual(res_sync["status"], "synced")
        self.assertTrue(res_sync["committed"])

        # Verify working tree is now clean
        status_proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(vault_dir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(status_proc.stdout.strip(), "")

        # Verify commit message has conversation id and harness provenance
        log_proc = subprocess.run(
            ["git", "log", "-n", "1", "--format=%s"],
            cwd=str(vault_dir),
            capture_output=True,
            text=True,
        )
        self.assertIn("0f0be49d", log_proc.stdout)
        self.assertIn("Primary session", log_proc.stdout)

    def test_portable_federation_isolation(self):
        import federation_provider
        with self.assertRaises(federation_provider.SecurityException):
            federation_provider.verify_ce_patterns_isolation(
                Path(self.test_dir) / 'ObsidianVault' / 'wiki' / 'concepts' / 'A.md',
                ce_patterns_root=Path(self.test_dir) / 'shared-okf-patterns',
                obsidian_vault_root=Path(self.test_dir) / 'ObsidianVault',
            )

    def test_vault_graph_epistemic_edges_and_unified_hub(self):
        """Test explicit-only 5-way epistemic edge extraction and unified Search Hub HTML output."""
        vault_path = Path(self.test_dir) / "EpistemicVault"
        init_vault.init_vault(vault_path)

        note_a = vault_path / "wiki" / "concepts" / "Pattern A.md"
        note_a.write_text(
            "---\n"
            "title: Pattern A\n"
            "type: concept\n"
            'corroborates: ["[[Pattern B]]"]\n'
            "---\n"
            "# Pattern A\n\n"
            "contradicts::[[Legacy Pattern]]\n\n"
            "Also references [[Pattern B]] in follow-up prose.\n",
            encoding="utf-8",
        )
        note_b = vault_path / "wiki" / "concepts" / "Pattern B.md"
        note_b.write_text(
            "---\ntitle: Pattern B\ntype: concept\n---\n# Pattern B\n",
            encoding="utf-8",
        )
        note_c = vault_path / "wiki" / "concepts" / "Legacy Pattern.md"
        note_c.write_text(
            "---\ntitle: Legacy Pattern\ntype: concept\n---\n# Legacy Pattern\n",
            encoding="utf-8",
        )
        note_prose = vault_path / "wiki" / "concepts" / "Pattern Prose.md"
        note_prose.write_text(
            "---\ntitle: Pattern Prose\ntype: concept\n---\n"
            "# Pattern Prose\n\n"
            "Compare [[Pattern B]] vs [[Legacy Pattern]].\n",
            encoding="utf-8",
        )

        graph = vault_graph.build_vault_graph(
            vault_path, ce_patterns_root=Path(self.test_dir) / "empty_patterns"
        )
        edge_types = graph["stats"]["edgeTypeCounts"]
        self.assertEqual(edge_types.get("CORROBORATES", 0), 1)
        self.assertEqual(edge_types.get("CONTRADICTS", 0), 1)
        self.assertGreaterEqual(edge_types.get("LINKS_TO", 0), 2)
        edge_map = {(e["source"], e["target"]): e["type"] for e in graph["edges"]}
        self.assertEqual(
            edge_map[("wiki/concepts/Pattern A.md", "wiki/concepts/Pattern B.md")],
            "CORROBORATES",
        )
        self.assertEqual(
            edge_map[("wiki/concepts/Pattern A.md", "wiki/concepts/Legacy Pattern.md")],
            "CONTRADICTS",
        )
        self.assertEqual(
            edge_map[("wiki/concepts/Pattern Prose.md", "wiki/concepts/Pattern B.md")],
            "LINKS_TO",
        )
        self.assertEqual(
            edge_map[("wiki/concepts/Pattern Prose.md", "wiki/concepts/Legacy Pattern.md")],
            "LINKS_TO",
        )
        self.assertIn("epistemicTypes", graph)

    def test_upstream_okf_version_checker(self):
        """Test upstream Open Knowledge Format (OKF) version parsing and comparison."""
        from unittest.mock import MagicMock, patch

        self.assertEqual(vault_lint._parse_version_tuple("0.3"), (0, 3))
        self.assertLess(
            vault_lint._parse_version_tuple("0.3"),
            vault_lint._parse_version_tuple("0.4"),
        )

        # Mock SPEC.md returning Version 0.3 (draft) -> up to date
        mock_spec_v03 = b"# Open Knowledge Format Specification\n\n**Version 0.3 (draft)**\n"
        mock_commit = b'{"sha": "e1b14f4123456", "commit": {"author": {"date": "2026-11-17T20:08:36Z"}, "message": "Release OKF v0.3"}}'

        def fake_urlopen_v03(req, timeout=5.0):
            m = MagicMock()
            url = req.full_url if hasattr(req, "full_url") else str(req)
            m.read.return_value = mock_spec_v03 if "SPEC.md" in url else mock_commit
            m.__enter__.return_value = m
            return m

        with patch("urllib.request.urlopen", side_effect=fake_urlopen_v03):
            rep = vault_lint.check_upstream_okf_version()
            self.assertEqual(rep["upstream_version"], "0.3")
            self.assertEqual(rep["status"], "up_to_date")
            self.assertTrue(rep["is_up_to_date"])
            self.assertFalse(rep["newer_version_available"])
            self.assertEqual(rep["latest_commit_sha"], "e1b14f4")

        # Mock SPEC.md returning Version 0.4 (update available)
        mock_spec_v04 = b"# Open Knowledge Format Specification\n\n**Version 0.4**\n"

        def fake_urlopen_v04(req, timeout=5.0):
            m = MagicMock()
            url = req.full_url if hasattr(req, "full_url") else str(req)
            m.read.return_value = mock_spec_v04 if "SPEC.md" in url else mock_commit
            m.__enter__.return_value = m
            return m

        with patch("urllib.request.urlopen", side_effect=fake_urlopen_v04):
            rep2 = vault_lint.check_upstream_okf_version()
            self.assertEqual(rep2["upstream_version"], "0.4")
            self.assertEqual(rep2["status"], "update_available")
            self.assertFalse(rep2["is_up_to_date"])
            self.assertTrue(rep2["newer_version_available"])


    def test_sanitize_check_strict_dlp_and_links(self):
        """Test sanitize_check.py strict DLP, account ID, pipe, and broken-link detection."""
        ce_repo = Path(self.test_dir) / "shared-okf-patterns-strict"
        init_vault.init_vault(ce_repo)

        clean_note = ce_repo / "wiki" / "concepts" / "Clean FinOps Pattern.md"
        clean_note.write_text(
            "---\n"
            'title: "Clean FinOps Pattern"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-28\n"
            "tags:\n"
            "  - finops\n"
            "  - bigquery\n"
            "---\n\n"
            "# Clean FinOps Pattern\n\n"
            "Uses synthetic account `111122223333` and links to [[index|Master Index]].\n",
            encoding="utf-8",
        )

        res_clean = sanitize_check.run_sanitize_check(
            targets=[ce_repo],
            repo_root=ce_repo,
            strict=True,
        )
        self.assertTrue(res_clean["ok"], msg=str(res_clean["violations"]))
        self.assertEqual(res_clean["violation_count"], 0)

        dirty_note = ce_repo / "wiki" / "concepts" / "Dirty Pattern.md"
        dirty_note.write_text(
            "---\n"
            'title: "Dirty Pattern"\n'
            "type: concept\n"
            "status: active\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-28\n"
            "tags:\n"
            "  - finops\n"
            "---\n\n"
            "# Dirty Pattern\n\n"
            "Customer AcmeCorp in account 987654321098 and [[wiki/entities/Northwind]].\n"
            "| Col A | Col B |\n"
            "| --- | --- |\n"
            "| [[Clean FinOps Pattern\\|Escaped]] | /home/jdoe/secret |\n",
            encoding="utf-8",
        )

        res_dirty = sanitize_check.run_sanitize_check(
            targets=[ce_repo],
            repo_root=ce_repo,
            strict=True,
        )
        self.assertFalse(res_dirty["ok"])
        cats = {v["category"] for v in res_dirty["violations"]}
        self.assertIn("okf_frontmatter", cats)
        self.assertIn("customer_dlp", cats)
        self.assertIn("aws_account_id", cats)
        self.assertIn("private_vault_link", cats)
        self.assertIn("broken_wikilink", cats)
        self.assertIn("table_pipe_invariant", cats)
        self.assertIn("identity_or_path", cats)

    def test_compile_graph_html_and_epistemic_lint(self):
        """Test compile_graph_html.py exports HTML outside vault root and counts 5-way epistemic edges."""
        v_path = Path(self.test_dir) / "CompileVault"
        init_vault.init_vault(v_path)

        note_a = v_path / "wiki" / "concepts" / "Base Strategy.md"
        note_a.write_text(
            "---\n"
            'title: "Base Strategy"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-28\n"
            "complements:\n"
            '  - "[[Specialized C2C]]"\n'
            "---\n\n"
            "# Base Strategy\n\n"
            "Links to [[Specialized C2C]].\n",
            encoding="utf-8",
        )
        note_b = v_path / "wiki" / "concepts" / "Specialized C2C.md"
        note_b.write_text(
            "---\n"
            'title: "Specialized C2C"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-28\n"
            "extends:\n"
            '  - "[[Base Strategy]]"\n'
            "---\n\n"
            "# Specialized C2C\n\n"
            "Extends [[Base Strategy]].\n",
            encoding="utf-8",
        )
        idx = v_path / "index.md"
        idx.write_text(
            idx.read_text(encoding="utf-8")
            + "\n- [[Base Strategy]]\n- [[Specialized C2C]]\n- [[wiki/skill-impact|Skill Impact]]\n",
            encoding="utf-8",
        )

        out_html = Path(self.test_dir) / "compiled_graph.html"
        res = compile_graph_html.compile_and_verify(v_path, out_html)
        self.assertTrue(out_html.is_file())
        self.assertTrue(res["lint"]["is_healthy"])
        self.assertEqual(len(res["lint"]["orphan_notes"]), 0)
        self.assertEqual(res["lint"]["epistemic_edge_counts"]["COMPLEMENTS"], 1)
        self.assertEqual(res["lint"]["epistemic_edge_counts"]["EXTENDS"], 1)

    def test_sanitize_check_private_entity_detection_and_auto_rewrite(self):
        """Test sanitize_check.py detects private wiki/entities/ links and auto-rewrites to archetype prose."""
        ce_repo = Path(self.test_dir) / "shared-okf-patterns-rewrite"
        init_vault.init_vault(ce_repo)

        base_note = ce_repo / "wiki" / "concepts" / "Shared Base.md"
        base_note.write_text(
            "---\n"
            'title: "Shared Base"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-28\n"
            "tags:\n"
            "  - architecture\n"
            "---\n\n"
            "# Shared Base\n",
            encoding="utf-8",
        )

        staged_note = ce_repo / "wiki" / "concepts" / "Staged Pattern.md"
        staged_note.write_text(
            "---\n"
            'title: "Staged Pattern"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-28\n"
            "tags:\n"
            "  - finops\n"
            "complements:\n"
            '  - "[[Shared Base]]"\n'
            '  - "[[wiki/entities/AcmeCorp]]"\n'
            "---\n\n"
            "# Staged Pattern\n\n"
            "Deployed for [[wiki/entities/Northwind|Northwind]] and [[Contoso]] on [[wiki/entities/Cloud Run|Cloud Run]].\n"
            "| Pattern | Customer |\n"
            "| --- | --- |\n"
            "| [[Shared Base\\|Base]] | [[wiki/entities/Fabrikam]] |\n",
            encoding="utf-8",
        )

        # 1. Even with strict=False, private wiki/entities/ links MUST be flagged
        res_non_strict = sanitize_check.run_sanitize_check(
            targets=[staged_note],
            repo_root=ce_repo,
            strict=False,
            fix=False,
        )
        self.assertFalse(res_non_strict["ok"])
        non_strict_cats = {v["category"] for v in res_non_strict["violations"]}
        self.assertIn("private_vault_link", non_strict_cats)

        # 2. Running with fix=True + strict=True converts private entity links to archetype prose and passes 100%
        res_fixed = sanitize_check.run_sanitize_check(
            targets=[ce_repo],
            repo_root=ce_repo,
            strict=True,
            fix=True,
        )
        self.assertTrue(res_fixed["ok"], msg=str(res_fixed["violations"]))
        self.assertEqual(res_fixed["violation_count"], 0)
        self.assertIn("wiki/concepts/Staged Pattern.md", res_fixed["fixed_files"])

        healed = staged_note.read_text(encoding="utf-8")
        self.assertIn("Global Retail & Supply Chain Enterprise", healed)
        self.assertIn("Multinational Financial Services Institution", healed)
        self.assertIn("Industrial Manufacturing Conglomerate", healed)
        self.assertIn("on Cloud Run.", healed)
        self.assertIn("[[Shared Base|Base]]", healed)
        self.assertNotIn("Northwind", healed)
        self.assertNotIn("Contoso", healed)
        self.assertNotIn("Fabrikam", healed)
        self.assertNotIn("wiki/entities/", healed)

    def test_sanitize_check_and_migrate_sources_multiline_okf(self):
        """Verify sanitize_check preserves multi-line {id, resource} blocks and vault_lint prints migration banner on healthy vaults."""
        shared_repo = Path(self.test_dir) / "shared-okf-patterns"
        init_vault.init_vault(shared_repo)

        base_note = shared_repo / "wiki" / "concepts" / "Shared Foundation.md"
        base_note.write_text(
            "---\n"
            'title: "Shared Foundation"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-11-11\n"
            "tags:\n"
            "  - architecture\n"
            "---\n\n"
            "# Shared Foundation\n",
            encoding="utf-8",
        )

        # 1. Mixed private & public multi-line {id, resource, title} (indent-2 + indent-0 + quoted human: + epistemic)
        ml_note = shared_repo / "wiki" / "concepts" / "MultiLine Shared Note.md"
        ml_note.write_text(
            "---\n"
            'title: "MultiLine Shared Note"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-11-11\n"
            "tags:\n"
            "  - architecture\n"
            "verified:\n"
            '  - by: "human:Jane Doe"\n'
            "    at: \"2026-11-11T00:00:00Z\"\n"
            "sources:\n"
            "  - id: raw-client-deck\n"
            '    resource: "raw/client_deck.pptx"\n'
            '    title: "Internal Slides"\n'
            "  - id: local-notes\n"
            '    resource: "/home/jdoe/ObsidianVault/notes.md"\n'
            '    title: "Local Notes"\n'
            "  - id: acmecorp-q3\n"
            '    resource: "https://example.org/acmecorp-case"\n'
            '    title: "Customer Ref"\n'
            "  - id: gcp-arch\n"
            '    resource: "https://cloud.google.com/architecture"\n'
            '    title: "Google Cloud Architecture Center"\n'
            "corroborates:\n"
            "- id: priv-corr\n"
            '  target: "[[wiki/entities/AcmeCorp]]"\n'
            "- id: pub-corr\n"
            '  target: "[[Shared Foundation]]"\n'
            "---\n\n"
            "# MultiLine Shared Note\n\n"
            "Builds on [[Shared Foundation]].\n",
            encoding="utf-8",
        )

        # Clean multi-line {id, resource} note must remain byte-for-byte untouched
        clean_ml_note = shared_repo / "wiki" / "concepts" / "Clean MultiLine Note.md"
        clean_ml_raw = (
            "---\n"
            'title: "Clean MultiLine Note"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-11-11\n"
            "tags:\n"
            "  - architecture\n"
            "verified:\n"
            "  - by: human:cloud-ce\n"
            "sources:\n"
            "  - id: gcp-docs\n"
            '    resource: "https://cloud.google.com/docs"\n'
            '    title: "Cloud Docs"\n'
            "---\n\n"
            "# Clean MultiLine Note\n\n"
            "Builds on [[Shared Foundation]].\n"
        )
        clean_ml_note.write_text(clean_ml_raw, encoding="utf-8")

        res1 = sanitize_check.run_sanitize_check(
            targets=[shared_repo],
            repo_root=shared_repo,
            strict=True,
            fix=True,
        )
        self.assertTrue(res1["ok"], msg=str(res1["violations"]))
        self.assertEqual(res1["violation_count"], 0)
        self.assertIn("wiki/concepts/MultiLine Shared Note.md", res1["fixed_files"])
        self.assertNotIn("wiki/concepts/Clean MultiLine Note.md", res1["fixed_files"])
        self.assertEqual(clean_ml_note.read_text(encoding="utf-8"), clean_ml_raw)

        healed = ml_note.read_text(encoding="utf-8")
        self.assertNotIn("Jane Doe", healed)
        self.assertIn('by: "human:cloud-ce"', healed)
        self.assertNotIn("raw-client-deck", healed)
        self.assertNotIn("Internal Slides", healed)
        self.assertNotIn("local-notes", healed)
        self.assertNotIn("Local Notes", healed)
        self.assertNotIn("acmecorp-q3", healed)
        self.assertNotIn("Customer Ref", healed)
        self.assertNotIn("priv-corr", healed)
        self.assertNotIn("AcmeCorp", healed)
        self.assertIn("  - id: gcp-arch\n    resource: \"https://cloud.google.com/architecture\"\n    title: \"Google Cloud Architecture Center\"", healed)
        self.assertIn("- id: pub-corr\n  target: \"[[Shared Foundation]]\"", healed)

        # Second strict pass must be a strict no-op (idempotency)
        res2 = sanitize_check.run_sanitize_check(
            targets=[shared_repo],
            repo_root=shared_repo,
            strict=True,
            fix=True,
        )
        self.assertTrue(res2["ok"], msg=str(res2["violations"]))
        self.assertEqual(res2["violation_count"], 0)
        self.assertEqual(res2["fixed_files"], [])

        # 2. Verify vault_lint --fix --migrate-sources prints migration summary even when 100% HEALTHY!
        clean_vault = Path(self.test_dir) / "clean-vault-migrate"
        init_vault.init_vault(clean_vault)
        seed = clean_vault / "wiki" / "concepts" / "Seed Concept.md"
        seed.write_text(
            "---\n"
            'title: "Seed Concept"\n'
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-11-11\n"
            "tags:\n"
            "  - architecture\n"
            "sources:\n"
            '  - "https://cloud.google.com/docs"\n'
            "---\n\n"
            "# Seed Concept\n\n"
            "Linked from [[index|Master Index]].\n",
            encoding="utf-8",
        )
        idx = clean_vault / "index.md"
        idx.write_text(
            idx.read_text(encoding="utf-8") + "\n- [[Seed Concept]]\n",
            encoding="utf-8",
        )

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            vault_lint.main([str(clean_vault), "--fix", "--migrate-sources"])
        out_txt = buf.getvalue()
        self.assertIn("Migrated Legacy String Sources to {id, resource}", out_txt)
        self.assertIn("wiki/concepts/Seed Concept.md", out_txt)
        self.assertIn("100% HEALTHY!", out_txt)

    def test_v070_manifest_and_learn_companion_invariants(self):
        repo_root = Path(__file__).resolve().parent.parent
        self.assertTrue((repo_root / 'rules' / 'AGENTS.md').exists())

    def _init_git_identity(self, repo_dir: Path) -> None:
        import subprocess

        subprocess.run(
            ["git", "config", "user.email", "ce-test@example.com"],
            cwd=str(repo_dir),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "CE Test Runner"],
            cwd=str(repo_dir),
            check=True,
            capture_output=True,
        )

    def test_local_only_vault_without_origin_remote(self):
        """Verify CEs using a local-only vault (no origin remote) commit cleanly without errors."""
        import subprocess

        local_vault = Path(self.test_dir) / "LocalOnlyCEVault"
        init_vault.init_vault(local_vault)
        subprocess.run(
            ["git", "init", "-b", "main"],
            cwd=str(local_vault),
            check=True,
            capture_output=True,
        )
        self._init_git_identity(local_vault)

        stop_res = auto_sync_vault.sync_vault(
            local_vault, conversation_id="localce1", harness="Antigravity"
        )
        self.assertEqual(stop_res["status"], "synced")
        self.assertTrue(stop_res["local_only"])
        self.assertTrue(stop_res["committed"])
        self.assertFalse(stop_res["pushed"])

        start_res = session_sync.sync_session_start(
            vault_path=local_vault,
            ce_patterns_path=Path(self.test_dir) / "nonexistent-patterns",
            compiler_repo_path=Path(self.test_dir) / "nonexistent-compiler",
            auto_reinstall_plugin=False,
        )
        self.assertEqual(start_res["vault"]["status"], "local_only")
        self.assertEqual(start_res["notices"], [])

    def test_concurrent_dual_harness_stop_and_session_start_okf_union_rebase(self):
        """Simulate Primary and Antigravity concurrently editing log.md, index.md, and notes."""
        import subprocess

        bare_origin = Path(self.test_dir) / "origin_vault.git"
        subprocess.run(
            ["git", "init", "--bare", "-b", "main", str(bare_origin)],
            check=True,
            capture_output=True,
        )

        primary_vault = Path(self.test_dir) / "PrimaryVault"
        subprocess.run(
            ["git", "clone", str(bare_origin), str(primary_vault)],
            check=True,
            capture_output=True,
        )
        self._init_git_identity(primary_vault)
        init_vault.init_vault(primary_vault)

        shared_note = primary_vault / "wiki" / "concepts" / "Cloud Arch.md"
        shared_note.write_text(
            "---\n"
            'title: "Cloud Arch"\n'
            "type: concept\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-20\n"
            "status: stable\n"
            "---\n\n"
            "# Cloud Arch\n\n"
            "## Section A\nInitial A.\n\n\n\n\n"
            "## Section B\nInitial B.\n",
            encoding="utf-8",
        )
        (primary_vault / "index.md").write_text(
            "---\ntitle: \"Vault Index\"\ntype: meta\nupdated: 2026-10-20\n---\n\n"
            "# Master Vault Index\n\n"
            "## Core Concepts\n"
            "- [[Cloud Arch]]: Shared base concept.\n",
            encoding="utf-8",
        )
        (primary_vault / "log.md").write_text(
            "---\ntitle: \"Vault Activity Log\"\ntype: meta\nupdated: 2026-10-20\n---\n\n"
            "# Vault Activity Log\n\n"
            "## [2026-10-20] init | Baseline Vault\n- Initial commit.\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "-A"], cwd=str(primary_vault), check=True)
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=str(primary_vault),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "push", "-u", "origin", "main"],
            cwd=str(primary_vault),
            check=True,
            capture_output=True,
        )

        # Clone second workstation (Antigravity) from the exact same base commit
        agy_vault = Path(self.test_dir) / "AntigravityVault"
        subprocess.run(
            ["git", "clone", str(bare_origin), str(agy_vault)],
            check=True,
            capture_output=True,
        )
        self._init_git_identity(agy_vault)

        # 1. Primary edits Section A (bumping updated: 2026-10-28), adds Note J, prepends log.md, updates index.md
        (primary_vault / "wiki" / "concepts" / "Note J.md").write_text(
            "---\ntitle: \"Note J\"\ntype: concept\ncreated: 2026-10-28\nupdated: 2026-10-28\nstatus: stable\n---\n# Note J\nLinks to [[Cloud Arch]].\n",
            encoding="utf-8",
        )
        shared_note.write_text(
            shared_note.read_text(encoding="utf-8")
            .replace("updated: 2026-10-20", "updated: 2026-10-28")
            .replace("Initial A.", "Updated Section A from Primary."),
            encoding="utf-8",
        )
        (primary_vault / "index.md").write_text(
            "---\ntitle: \"Vault Index\"\ntype: meta\nupdated: 2026-10-28\n---\n\n"
            "# Master Vault Index\n\n"
            "## Core Concepts\n"
            "- [[Cloud Arch]]: Shared base concept.\n"
            "- [[Note J]]: Added on Primary.\n",
            encoding="utf-8",
        )
        (primary_vault / "log.md").write_text(
            "---\ntitle: \"Vault Activity Log\"\ntype: meta\nupdated: 2026-10-28\n---\n\n"
            "# Vault Activity Log\n\n"
            "## [2026-10-28] sync | Primary Turn\n- Added [[Note J]].\n\n"
            "## [2026-10-20] init | Baseline Vault\n- Initial commit.\n",
            encoding="utf-8",
        )
        j_res = auto_sync_vault.sync_vault(
            primary_vault, conversation_id="primary01", harness="Primary"
        )
        self.assertTrue(j_res["pushed"])

        # 2. Concurrently (without pulling!), Antigravity edits Section B (bumping updated: 2026-10-29),
        #    adds Note A, prepends log.md at the exact same top position, and adds Note A to index.md
        (agy_vault / "wiki" / "concepts" / "Note A.md").write_text(
            "---\ntitle: \"Note A\"\ntype: concept\ncreated: 2026-10-29\nupdated: 2026-10-29\nstatus: stable\n---\n# Note A\nLinks to [[Cloud Arch]].\n",
            encoding="utf-8",
        )
        agy_shared = agy_vault / "wiki" / "concepts" / "Cloud Arch.md"
        agy_shared.write_text(
            agy_shared.read_text(encoding="utf-8")
            .replace("updated: 2026-10-20", "updated: 2026-10-29")
            .replace("Initial B.", "Updated Section B from Antigravity."),
            encoding="utf-8",
        )
        (agy_vault / "index.md").write_text(
            "---\ntitle: \"Vault Index\"\ntype: meta\nupdated: 2026-10-29\n---\n\n"
            "# Master Vault Index\n\n"
            "## Core Concepts\n"
            "- [[Cloud Arch]]: Shared base concept.\n"
            "- [[Note A]]: Added on Antigravity.\n",
            encoding="utf-8",
        )
        (agy_vault / "log.md").write_text(
            "---\ntitle: \"Vault Activity Log\"\ntype: meta\nupdated: 2026-10-29\n---\n\n"
            "# Vault Activity Log\n\n"
            "## [2026-10-29] sync | Antigravity Turn\n- Added [[Note A]].\n\n"
            "## [2026-10-20] init | Baseline Vault\n- Initial commit.\n",
            encoding="utf-8",
        )

        a_res = auto_sync_vault.sync_vault(
            agy_vault, conversation_id="agy00001", harness="Antigravity"
        )
        self.assertTrue(a_res["committed"])
        self.assertTrue(a_res["rebased"])
        self.assertTrue(a_res["pushed"])
        self.assertFalse(a_res["conflict_aborted"])

        # Verify zero conflict markers and both sets of updates preserved
        merged_log = (agy_vault / "log.md").read_text(encoding="utf-8")
        merged_idx = (agy_vault / "index.md").read_text(encoding="utf-8")
        merged_shared = agy_shared.read_text(encoding="utf-8")
        for doc in (merged_log, merged_idx, merged_shared):
            self.assertNotIn("<<<<<<<", doc)
        self.assertIn("Antigravity Turn", merged_log)
        self.assertIn("Primary Turn", merged_log)
        self.assertLess(
            merged_log.index("Antigravity Turn"), merged_log.index("Primary Turn")
        )
        self.assertIn("[[Note J]]", merged_idx)
        self.assertIn("[[Note A]]", merged_idx)
        self.assertIn("Updated Section A from Primary.", merged_shared)
        self.assertIn("Updated Section B from Antigravity.", merged_shared)
        self.assertIn("updated: 2026-10-29", merged_shared)

        # 3. Next session on Primary automatically fast-forwards to the unified commit on SessionStart!
        s_res = session_sync.sync_session_start(
            vault_path=primary_vault,
            ce_patterns_path=Path(self.test_dir) / "none1",
            compiler_repo_path=Path(self.test_dir) / "none2",
            auto_reinstall_plugin=False,
        )
        self.assertEqual(s_res["vault"]["status"], "fast_forward")
        self.assertEqual(s_res["notices"], [])
        self.assertTrue((primary_vault / "wiki" / "concepts" / "Note A.md").is_file())

    def test_same_line_prose_conflict_aborts_cleanly_and_shared_repo_has_zero_personal_paths(
        self,
    ):
        """Verify same-line prose conflicts abort with 0 markers and shared code has 0 personal repo names."""
        import subprocess

        bare_origin = Path(self.test_dir) / "conflict_origin.git"
        subprocess.run(
            ["git", "init", "--bare", "-b", "main", str(bare_origin)],
            check=True,
            capture_output=True,
        )

        v1 = Path(self.test_dir) / "V1"
        subprocess.run(
            ["git", "clone", str(bare_origin), str(v1)],
            check=True,
            capture_output=True,
        )
        self._init_git_identity(v1)
        note1 = v1 / "wiki" / "concepts" / "Quota.md"
        note1.parent.mkdir(parents=True, exist_ok=True)
        note1.write_text(
            "---\ntitle: Quota\ntype: concept\nupdated: 2026-10-20\n---\n# Quota\nLimit is 100 RPS.\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "-A"], cwd=str(v1), check=True)
        subprocess.run(
            ["git", "commit", "-m", "base"],
            cwd=str(v1),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "push", "-u", "origin", "main"],
            cwd=str(v1),
            check=True,
            capture_output=True,
        )

        v2 = Path(self.test_dir) / "V2"
        subprocess.run(
            ["git", "clone", str(bare_origin), str(v2)],
            check=True,
            capture_output=True,
        )
        self._init_git_identity(v2)

        # V1 changes "Limit is 100 RPS." -> "Limit is 500 RPS." and pushes
        note1.write_text(
            "---\ntitle: Quota\ntype: concept\nupdated: 2026-10-28\n---\n# Quota\nLimit is 500 RPS.\n",
            encoding="utf-8",
        )
        self.assertTrue(auto_sync_vault.sync_vault(v1, harness="Primary")["pushed"])

        # V2 changes the exact same line -> "Limit is 1000 RPS."
        note2 = v2 / "wiki" / "concepts" / "Quota.md"
        note2.write_text(
            "---\ntitle: Quota\ntype: concept\nupdated: 2026-10-28\n---\n# Quota\nLimit is 1000 RPS.\n",
            encoding="utf-8",
        )
        res2 = auto_sync_vault.sync_vault(v2, harness="Antigravity")
        self.assertTrue(res2["committed"])
        self.assertFalse(res2["pushed"])
        self.assertTrue(res2["conflict_aborted"])
        self.assertFalse(auto_sync_vault.is_rebase_in_progress(v2))
        self.assertNotIn("<<<<<<<", note2.read_text(encoding="utf-8"))

        # SessionStart on V2 also aborts cleanly and emits a Turn-1 systemMessage
        ss_res = session_sync.sync_session_start(
            vault_path=v2,
            ce_patterns_path=Path(self.test_dir) / "none1",
            compiler_repo_path=Path(self.test_dir) / "none2",
            auto_reinstall_plugin=False,
        )
        self.assertEqual(ss_res["vault"]["status"], "conflict_aborted")
        hook_out = session_sync.format_session_start_output(ss_res)
        self.assertIn("injectSteps", hook_out)
        self.assertNotIn("<<<<<<<", note2.read_text(encoding="utf-8"))

        # Enforce CE org boundary: zero personal backup repo names in shared compiler hooks/installer/rules
        repo_root = Path(__file__).resolve().parent.parent
        shared_files = [
            repo_root / "scripts" / "hooks" / "auto_sync_vault.py",
            repo_root / "scripts" / "hooks" / "session_sync.py",
            repo_root / "scripts" / "install_plugin.py",
            repo_root / "hooks.json",
            repo_root / "rules" / "AGENTS.md",
        ]
        for sf in shared_files:
            content = sf.read_text(encoding="utf-8")
            self.assertNotIn("personal-env-backup-repo", content, msg=str(sf))
            self.assertNotIn("jdoe/personal-obsidian-vault", content, msg=str(sf))

    def test_session_sync_preinvocation_agy_continue_and_intra_turn_guard(self):
        """Verify PreInvocation gating for agy -c (--continue), intra-turn loopbacks, and cooldowns."""
        stamp_dir = Path(self.test_dir) / "stamps"
        stamp_dir.mkdir(parents=True, exist_ok=True)
        vault_target = Path(self.test_dir) / "TargetVault"

        # 1. Brand-new session (`agy`) Turn 1: SessionStart fires -> runs!
        run_ss, reason_ss = session_sync.check_startup_sync_gate(
            {"conversationId": "conv-alpha"},
            vault_target,
            session_dedup_seconds=5.0,
            preinvocation_cooldown_seconds=180.0,
            stamp_dir=stamp_dir,
        )
        self.assertTrue(run_ss)
        self.assertEqual(reason_ss, "ready")

        # 2. Immediately following Turn 1 PreInvocation (invocationNum == 0) on same conversation -> skipped!
        run_pi0, reason_pi0 = session_sync.check_startup_sync_gate(
            {"conversationId": "conv-alpha", "invocationNum": 0},
            vault_target,
            session_dedup_seconds=5.0,
            preinvocation_cooldown_seconds=180.0,
            stamp_dir=stamp_dir,
        )
        self.assertFalse(run_pi0)
        self.assertEqual(reason_pi0, "cooldown")

        # 3. Intra-turn tool-call loopbacks (invocationNum == 1, 2) -> skipped immediately!
        run_loop, reason_loop = session_sync.check_startup_sync_gate(
            {"conversationId": "conv-alpha", "invocationNum": 1},
            vault_target,
            session_dedup_seconds=0.0,
            preinvocation_cooldown_seconds=0.0,
            stamp_dir=stamp_dir,
        )
        self.assertFalse(run_loop)
        self.assertEqual(reason_loop, "intra_turn_loopback")

        # 4. Resuming a different conversation via `agy -c` / `/resume` (conv-beta, invocationNum == 0) -> runs!
        run_cont, reason_cont = session_sync.check_startup_sync_gate(
            {"conversationId": "conv-beta", "invocationNum": 0},
            vault_target,
            session_dedup_seconds=5.0,
            preinvocation_cooldown_seconds=180.0,
            stamp_dir=stamp_dir,
        )
        self.assertTrue(run_cont)
        self.assertEqual(reason_cont, "ready")

        # 5. Duplicate workspace+global PreInvocation hook for conv-beta 10ms later -> deduplicated!
        run_dup, reason_dup = session_sync.check_startup_sync_gate(
            {"conversationId": "conv-beta", "invocationNum": 0},
            vault_target,
            session_dedup_seconds=5.0,
            preinvocation_cooldown_seconds=180.0,
            stamp_dir=stamp_dir,
        )
        self.assertFalse(run_dup)
        self.assertEqual(reason_dup, "cooldown")

        # 6. Resuming conv-beta after cooldown window expires -> runs!
        run_exp, reason_exp = session_sync.check_startup_sync_gate(
            {"conversationId": "conv-beta", "invocationNum": 0},
            vault_target,
            session_dedup_seconds=5.0,
            preinvocation_cooldown_seconds=0.0,
            stamp_dir=stamp_dir,
        )
        self.assertTrue(run_exp)
        self.assertEqual(reason_exp, "ready")

        # 7. Verify install_plugin.py registers both SessionStart and PreInvocation
        self.assertIn(
            "PreInvocation",
            install_plugin.GLOBAL_HOOKS_CONFIG["vault-session-start"],
        )

    def test_docs_hygiene_3p(self):
        repo_root = Path(__file__).resolve().parent.parent
        self.assertTrue((repo_root / 'LICENSE').exists())
        self.assertTrue((repo_root / 'SECURITY.md').exists())

    def test_v080_stdlib_ooxml_fallback_and_marketplace_bundle(self):
        """Verify stdlib OOXML (.pptx, .docx, .xlsx) fallback and v0.8.0 Marketplace bundle hygiene."""
        import zipfile

        # 1. Synthetic .pptx extracted via stdlib fallback
        pptx_path = Path(self.test_dir) / "sample_deck.pptx"
        with zipfile.ZipFile(pptx_path, "w") as zf:
            zf.writestr(
                "ppt/slides/slide1.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                "<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Slide 1 Architecture</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>"
                "</p:sld>",
            )
            zf.writestr(
                "ppt/notesSlides/notesSlide1.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<p:notes xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                "<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Speaker note detail</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>"
                "</p:notes>",
            )
        pptx_lines = extract_source._extract_pptx_stdlib(
            pptx_path, "sample_deck", "abc123sha", 0
        )
        pptx_text = "\n".join(pptx_lines)
        self.assertIn("slides_count: 1", pptx_text)
        self.assertIn("Slide 1 Architecture", pptx_text)
        self.assertIn("Speaker note detail", pptx_text)

        # 2. Synthetic .docx extracted via stdlib fallback
        docx_path = Path(self.test_dir) / "sample_doc.docx"
        with zipfile.ZipFile(docx_path, "w") as zf:
            zf.writestr(
                "word/document.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                "<w:body><w:p><w:r><w:t>Executive Summary Paragraph</w:t></w:r></w:p></w:body>"
                "</w:document>",
            )
        docx_paras, docx_tables = extract_source._extract_docx_stdlib(docx_path)
        self.assertIn("Executive Summary Paragraph", "\n".join(docx_paras))
        self.assertEqual(docx_tables, [])

        # 3. Synthetic .xlsx extracted via stdlib fallback
        xlsx_path = Path(self.test_dir) / "sample_sheet.xlsx"
        with zipfile.ZipFile(xlsx_path, "w") as zf:
            zf.writestr(
                "xl/sharedStrings.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                "<si><t>Service</t></si><si><t>Spanner</t></si>"
                "</sst>",
            )
            zf.writestr(
                "xl/workbook.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheets><sheet name="TCO" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>'
                "</workbook>",
            )
            zf.writestr(
                "xl/worksheets/sheet1.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheetData><row r="1"><c t="s"><v>0</v></c><c t="s"><v>1</v></c></row></sheetData>'
                "</worksheet>",
            )
        xlsx_sheets = extract_source._extract_xlsx_stdlib(xlsx_path)
        self.assertEqual(xlsx_sheets, [("TCO", [["Service", "Spanner"]])])

        # 4. Verify Marketplace SKILL.md frontmatter compliance (no < or >, has Use when / Don't use for)
        repo_root = Path(__file__).resolve().parent.parent
        for skill_md in sorted((repo_root / "skills").glob("*/SKILL.md")):
            raw_text = skill_md.read_text(encoding="utf-8")
            parts = raw_text.split("---", 2)
            fm = vault_lint.parse_simple_yaml(parts[1]) if len(parts) >= 3 else {}
            desc = str(fm.get("description", ""))
            self.assertLess(len(desc), 1024, msg=str(skill_md))
            self.assertNotIn("<", desc, msg=str(skill_md))
            self.assertNotIn(">", desc, msg=str(skill_md))
            self.assertIn("Use when", desc, msg=str(skill_md))
            self.assertIn("Don't use for", desc, msg=str(skill_md))

    def test_v090_clean_room_bundle_verified(self):
        repo_root = Path(__file__).resolve().parent.parent
        self.assertTrue((repo_root / 'plugin.json').exists())
        self.assertTrue((repo_root / 'hooks.json').exists())
        self.assertFalse((repo_root / 'scripts' / 'build_oss_release.py').exists())

    def test_local_git_pattern_provider_export_pattern(self):
        """Verify LocalGitPatternProvider.export_pattern() keyword argument parity with share_pattern."""
        vault_path = Path(self.test_dir) / "ExportVault"
        init_vault.init_vault(vault_path)
        target_repo = Path(self.test_dir) / "ExportTargetRepo"
        target_repo.mkdir(parents=True)
        (target_repo / "wiki" / "concepts").mkdir(parents=True)

        note_file = vault_path / "wiki" / "concepts" / "Clean Design.md"
        note_file.write_text(
            "---\n"
            "title: Clean Design\n"
            "type: concept\n"
            "tags:\n"
            "  - architecture\n"
            "---\n"
            "# Clean Design\n\n"
            "This is a generic concept note describing loosely-coupled architecture.\n",
            encoding="utf-8",
        )

        provider = federation_provider.LocalGitPatternProvider(
            patterns_root=target_repo, vault_root=vault_path
        )
        res = provider.export_pattern(note_file)
        self.assertTrue(res["success"])
        exported = target_repo / "wiki" / "concepts" / "Clean Design.md"
        self.assertTrue(exported.is_file())
        self.assertIn("Clean Design", exported.read_text(encoding="utf-8"))

    def test_share_pattern_fail_closed_egress_gate(self):
        """Verify mandatory in-code egress security gate in share_pattern() blocks leaks fail-closed."""
        vault_path = Path(self.test_dir) / "SecurityVault"
        init_vault.init_vault(vault_path)
        target_repo = Path(self.test_dir) / "SecurityTargetRepo"
        target_repo.mkdir(parents=True)

        # Baseline clean note must succeed
        clean_note = vault_path / "wiki" / "concepts" / "Safe Pattern.md"
        clean_note.write_text(
            "---\n"
            "title: Safe Pattern\n"
            "type: concept\n"
            "tags:\n"
            "  - gcp/compute\n"
            "---\n"
            "# Safe Pattern\n\n"
            "Contact author@example.com for details.\n"
            "Public unit rates like $0.046/vCPU-hr and $0.50 per query are allowed.\n",
            encoding="utf-8",
        )
        res = sync_patterns.share_pattern(
            pattern_file=clean_note, target_repo_path=target_repo, vault_root=vault_path
        )
        self.assertTrue(res["success"])

        # Test cases that MUST be rejected fail-closed
        leak_cases = [
            # Frontmatter title customer leak
            ("---\ntitle: Migration for AcmeCorp\ntype: concept\n---\n# Architecture\n", "title customer"),
            # Frontmatter aliases customer leak
            ("---\ntitle: High Availability\ntype: concept\naliases:\n  - Northwind\n---\n# Arch\n", "alias customer"),
            # Frontmatter tags customer leak
            ("---\ntitle: Resiliency\ntype: concept\ntags:\n  - customer-contoso\n---\n# Arch\n", "tags customer"),
            # Body customer leak
            ("---\ntitle: Scalability\ntype: concept\n---\n# Arch\nBuilt for Fabrikam.\n", "body customer"),
            # Code block customer leak
            ("---\ntitle: Pipeline\ntype: concept\n---\n```python\n# client = AcmeCorp()\n```\n", "code block customer"),
            # Google API key (constructed dynamically to avoid static git-secrets false positives)
            (f"---\ntitle: Keys\ntype: concept\n---\napi_key = '{'AIza'}{'SyD12345678901234567890'}'\n", "API key"),
            # OAuth access token
            (f"---\ntitle: Auth\ntype: concept\n---\ntoken = '{'ya29'}.{'a0AfH6SMAAAAAA1234567890'}'\n", "OAuth token"),
            # Private key block
            (f"---\ntitle: TLS\ntype: concept\n---\n-----BEGIN {'RSA PRIVATE'} KEY-----\nMIIEowIBAAKCAQEA0\n", "private key"),
            # GCS bucket path
            ("---\ntitle: Storage\ntype: concept\n---\nUpload to gs://my-secret-bucket-data.\n", "GCS bucket"),
            # Exact unbucketed decimal currency
            ("---\ntitle: Spend\ntype: concept\n---\nTotal spend was $12,345.67 per month.\n", "unbucketed currency"),
            # Shadow-view evasion: zero-width character in secret
            ("---\ntitle: ZeroWidth\ntype: concept\n---\nAI\u200bzaSyD12345678901234567890\n", "zero-width evasion"),
            # Shadow-view evasion: HTML comment in customer name
            ("---\ntitle: CommentEvasion\ntype: concept\n---\nAc<!-- comment -->meCorp architecture.\n", "comment evasion"),
        ]


        for content, label in leak_cases:
            bad_note = vault_path / "wiki" / "concepts" / "LeakTest.md"
            bad_note.write_text(content, encoding="utf-8")
            with self.assertRaises(sync_patterns.SecurityException, msg=f"Failed to reject {label}"):
                sync_patterns.share_pattern(
                    pattern_file=bad_note, target_repo_path=target_repo, vault_root=vault_path
                )
            # Verify fail-closed zero write
            self.assertFalse(
                (target_repo / "wiki" / "concepts" / "LeakTest.md").exists(),
                f"Leaked destination file written for {label}",
            )

        # 1. Note with customer name in stem/filename MUST be rejected before any write
        denylist_file = vault_path / "denylist.json"
        denylist_file.write_text(json.dumps({"customers": ["Initech", "Hooli (EMEA)"]}), encoding="utf-8")
        cust_stem_note = vault_path / "wiki" / "concepts" / "Initech Landing Zone.md"
        cust_stem_note.write_text(
            "---\ntitle: Clean Title\ntype: concept\n---\n# Architecture\nClean body.\n",
            encoding="utf-8",
        )
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                pattern_file=cust_stem_note, target_repo_path=target_repo, vault_root=vault_path
            )
        self.assertFalse((target_repo / "wiki" / "concepts" / "Initech Landing Zone.md").exists())

        # 2. Customer names from tables/customers.md (wikilink and plain text rows)
        cust_tbl = vault_path / "tables" / "customers.md"
        cust_tbl.parent.mkdir(parents=True, exist_ok=True)
        cust_tbl.write_text(
            "| Customer Account | Segment |\n| :--- | :--- |\n| [[wiki/entities/Cyberdyne|Cyberdyne Systems]] | Enterprise |\n| Massive Dynamic | Tech |\n",
            encoding="utf-8",
        )
        tbl_leak = vault_path / "wiki" / "concepts" / "TblLeak.md"
        tbl_leak.write_text(
            "---\ntitle: TblLeak\ntype: concept\n---\nConsulted with Cyberdyne Systems on deployment.\n",
            encoding="utf-8",
        )
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                pattern_file=tbl_leak, target_repo_path=target_repo, vault_root=vault_path
            )
        self.assertFalse((target_repo / "wiki" / "concepts" / "TblLeak.md").exists())

        # 3. Multi-word customer name across line wrap
        wrap_leak = vault_path / "wiki" / "concepts" / "WrapLeak.md"
        wrap_leak.write_text(
            "---\ntitle: WrapLeak\ntype: concept\n---\nDeployed Massive\nDynamic enterprise setup.\n",
            encoding="utf-8",
        )
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                pattern_file=wrap_leak, target_repo_path=target_repo, vault_root=vault_path
            )
        self.assertFalse((target_repo / "wiki" / "concepts" / "WrapLeak.md").exists())

        # 4. Customer name ending with non-word character
        hooli_leak = vault_path / "wiki" / "concepts" / "HooliLeak.md"
        hooli_leak.write_text(
            "---\ntitle: HooliLeak\ntype: concept\n---\nMigrating Hooli (EMEA) to GKE clusters.\n",
            encoding="utf-8",
        )
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                pattern_file=hooli_leak, target_repo_path=target_repo, vault_root=vault_path
            )
        self.assertFalse((target_repo / "wiki" / "concepts" / "HooliLeak.md").exists())

        # 5. Quoted author handle gets sanitized to human:cloud-ce without leaking handle
        author_note = vault_path / "wiki" / "concepts" / "AuthorNote.md"
        author_note.write_text(
            "---\n"
            "title: Author Note\n"
            "type: concept\n"
            "tags:\n  - gcp/compute\n"
            "verified:\n"
            '  by: "human:jdoe"\n'
            "---\n"
            "# Author Note\n\nClean architecture.\n",
            encoding="utf-8",
        )
        auth_res = sync_patterns.share_pattern(
            pattern_file=author_note, target_repo_path=target_repo, vault_root=vault_path
        )
        self.assertTrue(auth_res["success"])
        shared_text = (target_repo / "wiki" / "concepts" / "AuthorNote.md").read_text(encoding="utf-8")
        self.assertIn("human:cloud-ce", shared_text)
        self.assertNotIn("jdoe", shared_text)

        # 6. Obfuscated and underscore note stems rejected fail-closed
        obf_cases = [
            "Initech_LZ.md",
            "Ini\u200btech LZ.md",
            "Ｉｎｉｔｅｃｈ LZ.md",
            "Ini\u00adtech LZ.md",
            "Ini\u202etech LZ.md",
        ]
        for obf_name in obf_cases:
            obf_note = vault_path / "wiki" / "concepts" / obf_name
            obf_note.write_text(
                "---\ntitle: Obf\ntype: concept\n---\n# Architecture\nClean body.\n",
                encoding="utf-8",
            )
            with self.assertRaises(sync_patterns.SecurityException, msg=f"Failed to reject obf stem {obf_name!r}"):
                sync_patterns.share_pattern(
                    pattern_file=obf_note, target_repo_path=target_repo, vault_root=vault_path
                )
            self.assertFalse((target_repo / "wiki" / "concepts" / obf_name).exists())

        # 7. Customer in parent directory rejected fail-closed
        parent_cust_dir = vault_path / "wiki" / "concepts" / "Initech"
        parent_cust_dir.mkdir(parents=True, exist_ok=True)
        parent_cust_note = parent_cust_dir / "CleanNote.md"
        parent_cust_note.write_text(
            "---\ntitle: Clean\ntype: concept\n---\n# Architecture\nClean body.\n",
            encoding="utf-8",
        )
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                pattern_file=parent_cust_note, target_repo_path=target_repo, vault_root=vault_path
            )

        # 8. Short entity alias (NWB <= 3 chars) blocks both prose and note stem
        nwb_entity = vault_path / "wiki" / "entities" / "Northwind Bank.md"
        nwb_entity.parent.mkdir(parents=True, exist_ok=True)
        nwb_entity.write_text(
            "---\ntitle: Northwind Bank\ntype: entity\naliases:\n  - NWB\n---\nEntity dossier.\n",
            encoding="utf-8",
        )
        nwb_prose = vault_path / "wiki" / "concepts" / "NWBProse.md"
        nwb_prose.write_text(
            "---\ntitle: NWBProse\ntype: concept\n---\nClient NWB migrated to GCP.\n",
            encoding="utf-8",
        )
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                pattern_file=nwb_prose, target_repo_path=target_repo, vault_root=vault_path
            )
        nwb_stem = vault_path / "wiki" / "concepts" / "NWB LZ.md"
        nwb_stem.write_text(
            "---\ntitle: Clean Title\ntype: concept\n---\nClean body.\n",
            encoding="utf-8",
        )
        with self.assertRaises(sync_patterns.SecurityException):
            sync_patterns.share_pattern(
                pattern_file=nwb_stem, target_repo_path=target_repo, vault_root=vault_path
            )

        # 9. Extended frontmatter identity sanitization (author, owner, full name)
        fm_ident_note = vault_path / "wiki" / "concepts" / "IdentNote.md"
        fm_ident_note.write_text(
            "---\n"
            "title: Ident Note\n"
            "name: hub-and-spoke-vpc\n"
            "type: concept\n"
            'author: "Jane Doe"\n'
            'owner: "John Smith"\n'
            "authors: [jdoe, Jane Doe]\n"
            "contributor:\n"
            '  name: "Alice Walker"\n'
            "verified:\n"
            '  by: "human:Jane Doe"\n'
            "generated:\n"
            '  by: "agent:jdoe-bot"\n'
            "---\n"
            "# Architecture\nClean body.\n",
            encoding="utf-8",
        )
        ident_res = sync_patterns.share_pattern(
            pattern_file=fm_ident_note, target_repo_path=target_repo, vault_root=vault_path
        )
        self.assertTrue(ident_res["success"])
        ident_shared = (target_repo / "wiki" / "concepts" / "IdentNote.md").read_text(encoding="utf-8")
        self.assertNotIn("Jane Doe", ident_shared)
        self.assertNotIn("John Smith", ident_shared)
        self.assertNotIn("Alice Walker", ident_shared)
        self.assertNotIn("jdoe-bot", ident_shared)
        self.assertIn("name: hub-and-spoke-vpc", ident_shared)
        self.assertIn("Google Cloud CE", ident_shared)
        self.assertIn("human:cloud-ce", ident_shared)
        self.assertIn("agent:knowledge-compiler", ident_shared)

        # 10. Robust alias parsing handles multi-line flow lists, null, ~, quoted commas, and YAML 1.1 bools (F2)
        f2_multiline = "---\naliases: [\n  NWB,\n  Initech\n]\n---"
        self.assertEqual(sync_patterns._extract_aliases_from_frontmatter(f2_multiline), ["NWB", "Initech"])
        f2_null = "---\naliases: null\n---"
        self.assertEqual(sync_patterns._extract_aliases_from_frontmatter(f2_null), [])
        f2_tilde = "---\naliases: ~\n---"
        self.assertEqual(sync_patterns._extract_aliases_from_frontmatter(f2_tilde), [])
        f2_comma = '---\naliases: ["Acme, Inc", FinCorp]\n---'
        self.assertEqual(sync_patterns._extract_aliases_from_frontmatter(f2_comma), ["Acme, Inc", "FinCorp"])
        f2_bools = '---\naliases: [ON, Yes, "-"]\n---'
        self.assertEqual(sync_patterns._extract_aliases_from_frontmatter(f2_bools), ["ON", "Yes"])

        # Multi-line flow authors list sanitization
        fm_multi_flow = (
            "---\n"
            "title: Flow Pattern\n"
            "authors: [\n"
            "  jdoe,\n"
            '  "Jane Doe"\n'
            "]\n"
            "---\n"
            "# Content\n"
        )
        sanitized_multi, _ = sync_patterns.sanitize_markdown(fm_multi_flow)
        self.assertNotIn("Jane Doe", sanitized_multi)
        self.assertNotIn("jdoe", sanitized_multi)
        self.assertIn("human:cloud-ce", sanitized_multi)

        # 11. Corrupt denylist fails closed with ValueError
        corrupt_denylist = vault_path / "corrupt_denylist"
        corrupt_denylist.mkdir(parents=True, exist_ok=True)
        (corrupt_denylist / "denylist.json").write_text("{ corrupt json ", encoding="utf-8")
        with self.assertRaises(ValueError):
            sync_patterns.load_custom_denylist(corrupt_denylist)

        # Verify unredacted workstation path is detected directly by verify_pattern_egress_security
        path_findings = sync_patterns.verify_pattern_egress_security(
            "Reference path: /usr/local/google/home/jdoe/repo"
        )
        self.assertTrue(
            any("workstation path" in f.lower() for f in path_findings),
            f"Expected workstation path detection, got {path_findings}",
        )

    def test_pyproject_extract_extra_parity(self):
        """Verify root pyproject.toml [extract] extra and dependencies match 3P release constraints."""
        pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
        self.assertTrue(pyproject_path.is_file())
        content = pyproject_path.read_text(encoding="utf-8")

        self.assertIn("extract = [", content)
        expected_pins = [
            "python-pptx>=0.6.21,<2.0.0",
            "pypdf>=4.0.0,<8.0.0",
            "python-docx>=1.0.0,<2.0.0",
            "openpyxl>=3.1.0,<4.0.0",
        ]
        for pin in expected_pins:
            self.assertIn(f'"{pin}"', content, f"Missing expected extract pin: {pin}")

        if "all = [" in content:
            all_block = content.split("all = [")[1].split("]")[0]
            for pin in expected_pins:
                self.assertIn(f'"{pin}"', all_block, f"Missing extract pin from 'all': {pin}")


if __name__ == "__main__":
    unittest.main()
