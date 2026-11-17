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
"""Verification tests for Knowledge Compiler v1.1.0 features (Tracks 1-4)."""

from __future__ import annotations

import contextlib
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_trace  # noqa: E402
import init_vault  # noqa: E402
import install_plugin  # noqa: E402
import sync_patterns  # noqa: E402
import vault_graph  # noqa: E402
import vault_hooks  # noqa: E402
import vault_lint  # noqa: E402
import wikiskill_eval  # noqa: E402


def _run_vault_lint_cli(argv: list[str]) -> int:
    try:
        res = vault_lint.main(argv)
        return int(res) if isinstance(res, int) else 0
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1


def _restore_write_bits(root_dir: Path) -> None:
    if not root_dir.exists():
        return
    for cur_root, dirs, files in os.walk(root_dir, topdown=True):
        with contextlib.suppress(OSError):
            os.chmod(cur_root, 0o755)
        for d in dirs:
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(cur_root, d), 0o755)
        for f in files:
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(cur_root, f), 0o644)


def _strip_write_bits(root_dir: Path) -> None:
    for cur_root, dirs, files in os.walk(root_dir, topdown=False):
        for f in files:
            os.chmod(os.path.join(cur_root, f), 0o444)
        for d in dirs:
            os.chmod(os.path.join(cur_root, d), 0o555)
    os.chmod(root_dir, 0o555)


class TestV110Features(unittest.TestCase):
    """Comprehensive offline tests for Track 1-4 v1.1.0 capabilities."""

    def setUp(self) -> None:
        self.tmp_obj = tempfile.TemporaryDirectory(prefix="kc_v110_")
        self.tmp_dir = Path(self.tmp_obj.name)

    def tearDown(self) -> None:
        _restore_write_bits(self.tmp_dir)
        self.tmp_obj.cleanup()

    # ------------------------------------------------------------------
    # Track 1: Frictionless Hook Enablement & EROFS User-Scope Fallback
    # ------------------------------------------------------------------

    def test_vault_hooks_writable_plugin_and_cleanup(self) -> None:
        home_dir = self.tmp_dir / "home"
        cfg_dir = home_dir / ".gemini" / "config"
        cfg_dir.mkdir(parents=True)
        plugin_dir = self.tmp_dir / "plugin"
        plugin_dir.mkdir(parents=True)

        res_install = install_plugin.install_global_plugin(
            repo_root=REPO_ROOT,
            target_plugin_dir=plugin_dir,
            home_dir=home_dir,
        )
        self.assertTrue(res_install["success"])

        # Seed unrelated hook + stale kc-user-session-start mirror
        user_hooks = cfg_dir / "hooks.json"
        user_hooks.write_text(
            json.dumps(
                {
                    "personal-env-backup-sync": {"enabled": True, "SessionStart": []},
                    "kc-user-session-start": {"enabled": True, "SessionStart": []},
                }
            ),
            encoding="utf-8",
        )

        res_enable = vault_hooks.set_hooks_state(
            "enable",
            hooks_group="sync",
            scope="auto",
            plugin_dir=plugin_dir,
            config_dir=cfg_dir,
            home_dir=home_dir,
        )
        self.assertTrue(res_enable["success"])
        self.assertEqual(res_enable["applied_scope"], "plugin")
        self.assertTrue(res_enable["hooks"]["vault-session-start"]["plugin_enabled"])
        self.assertTrue(res_enable["hooks"]["vault-stop-hook"]["plugin_enabled"])
        self.assertFalse(res_enable["hooks"]["wikiskill-error-recorder"]["effective_enabled"])

        u_after = json.loads(user_hooks.read_text(encoding="utf-8"))
        self.assertIn("personal-env-backup-sync", u_after)
        self.assertNotIn("kc-user-session-start", u_after)

        # Upgrade preserves previously enabled hooks
        install_plugin.install_global_plugin(
            repo_root=REPO_ROOT,
            target_plugin_dir=plugin_dir,
            home_dir=home_dir,
        )
        hooks_after_upgrade = json.loads((plugin_dir / "hooks.json").read_text(encoding="utf-8"))
        self.assertTrue(hooks_after_upgrade["vault-session-start"]["enabled"])
        self.assertTrue(hooks_after_upgrade["vault-stop-hook"]["enabled"])
        self.assertFalse(hooks_after_upgrade["wikiskill-error-recorder"]["enabled"])

        # Explicit install_global_plugin(..., disable_hooks="all") disables all
        res_dis = install_plugin.install_global_plugin(
            repo_root=REPO_ROOT,
            target_plugin_dir=plugin_dir,
            home_dir=home_dir,
            disable_hooks="all",
        )
        self.assertFalse(res_dis["hooks_status"]["hooks"]["vault-session-start"]["effective_enabled"])

    def test_vault_hooks_readonly_erofs_fallback_preserves_unrelated(self) -> None:
        home_dir = self.tmp_dir / "home_ro"
        cfg_dir = home_dir / ".gemini" / "config"
        cfg_dir.mkdir(parents=True)
        user_hooks = cfg_dir / "hooks.json"
        user_hooks.write_text(
            json.dumps(
                {"personal-env-backup-sync": {"enabled": True, "SessionStart": [{"type": "command", "command": "true"}]}}
            ),
            encoding="utf-8",
        )

        plugin_dir = self.tmp_dir / "ro_plugin"
        install_plugin.install_global_plugin(
            repo_root=REPO_ROOT,
            target_plugin_dir=plugin_dir,
            home_dir=home_dir,
        )
        _strip_write_bits(plugin_dir)
        try:
            # Explicit plugin scope must fail cleanly when read-only
            err_plugin = vault_hooks.set_hooks_state(
                "enable",
                scope="plugin",
                plugin_dir=plugin_dir,
                config_dir=cfg_dir,
                home_dir=home_dir,
            )
            self.assertFalse(err_plugin["success"])
            self.assertTrue(err_plugin["is_readonly_plugin"])

            # Auto scope falls back cleanly to non-colliding kc-user-* keys
            res_auto = vault_hooks.set_hooks_state(
                "enable",
                hooks_group="all",
                scope="auto",
                plugin_dir=plugin_dir,
                config_dir=cfg_dir,
                home_dir=home_dir,
            )
            self.assertTrue(res_auto["success"], msg=res_auto)
            self.assertEqual(res_auto["applied_scope"], "user")
            self.assertTrue(res_auto["hooks"]["vault-session-start"]["effective_enabled"])
            self.assertTrue(res_auto["hooks"]["vault-stop-hook"]["effective_enabled"])
            self.assertTrue(res_auto["hooks"]["wikiskill-error-recorder"]["effective_enabled"])

            u_data = json.loads(user_hooks.read_text(encoding="utf-8"))
            self.assertIn("personal-env-backup-sync", u_data)
            self.assertTrue(u_data["kc-user-session-start"]["enabled"])
            self.assertTrue(u_data["kc-user-stop-hook"]["enabled"])
            self.assertTrue(u_data["kc-user-wikiskill-recorder"]["enabled"])

            # Selective disable + full disable keep unrelated hook intact
            vault_hooks.set_hooks_state(
                "disable",
                hooks_group="wikiskill",
                scope="auto",
                plugin_dir=plugin_dir,
                config_dir=cfg_dir,
                home_dir=home_dir,
            )
            u_mid = json.loads(user_hooks.read_text(encoding="utf-8"))
            self.assertNotIn("kc-user-wikiskill-recorder", u_mid)
            self.assertIn("kc-user-session-start", u_mid)
            self.assertIn("personal-env-backup-sync", u_mid)

            vault_hooks.set_hooks_state(
                "disable",
                hooks_group="all",
                scope="auto",
                plugin_dir=plugin_dir,
                config_dir=cfg_dir,
                home_dir=home_dir,
            )
            u_end = json.loads(user_hooks.read_text(encoding="utf-8"))
            self.assertNotIn("kc-user-session-start", u_end)
            self.assertNotIn("kc-user-stop-hook", u_end)
            self.assertIn("personal-env-backup-sync", u_end)
        finally:
            _restore_write_bits(plugin_dir)

    # ------------------------------------------------------------------
    # Track 2: Graduated /wikiskill (`analyze_trace --propose` & `wikiskill_eval`)
    # ------------------------------------------------------------------

    def test_analyze_trace_propose_redacts_secrets_and_sets_0600(self) -> None:
        fake_google_key = "AIza" + "SyDummySecretToken12345678901234567"
        fake_gh_token = "ghp_" + "1234567890abcdef1234567890abcdef"
        fake_bearer = "Bearer " + "eyJhbGciOiJIUzI1NiJ9.dummy"

        transcript = self.tmp_dir / "transcript.jsonl"
        rows = [
            {
                "type": "TOOL_RESULT",
                "status": "ERROR",
                "content": f"Permission error with {fake_google_key} and {fake_bearer}",
                "tool_calls": [{"name": "run_command", "arguments": {"CommandLine": f"curl -H '{fake_gh_token}'"}}],
            },
            {
                "type": "TOOL_RESULT",
                "status": "ERROR",
                "content": f"Permission error again with {fake_google_key}",
                "tool_calls": [{"name": "run_command", "arguments": {}}],
            },
            {
                "type": "USER_INPUT",
                "source": "USER_EXPLICIT",
                "content": "No, always use `--json` flag instead of plain text parsing.",
            },
        ]
        transcript.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

        proposal_dir = self.tmp_dir / "state" / "proposals"
        report = analyze_trace.analyze_transcript(
            transcript,
            propose=True,
            proposal_dir=proposal_dir,
        )
        self.assertGreaterEqual(len(report["proposals"]), 2)
        prop_file = Path(report["proposal_file"])
        self.assertTrue(prop_file.is_file())
        md_file = proposal_dir / "latest_proposals.md"
        self.assertTrue(md_file.is_file())

        self.assertEqual(stat.S_IMODE(proposal_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(prop_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(md_file.stat().st_mode), 0o600)

        for raw_txt in (
            prop_file.read_text(encoding="utf-8"),
            md_file.read_text(encoding="utf-8"),
        ):
            self.assertNotIn(fake_google_key, raw_txt)
            self.assertNotIn(fake_gh_token, raw_txt)
            self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", raw_txt)
            self.assertIn("[REDACTED]", raw_txt)

    def test_wikiskill_eval_asymmetric_rollback_isolation_and_cas(self) -> None:
        vault = self.tmp_dir / "WikiSkillVault"
        init_vault.init_vault(vault, quiet=True)

        base_skill = self.tmp_dir / "base_SKILL.md"
        base_skill.write_text(
            "---\nname: sample-skill\ndescription: Baseline test skill.\n---\n"
            "# Sample Skill\n\nStep 1: Run vault_lint --fix.\n",
            encoding="utf-8",
        )
        cand_accept = self.tmp_dir / "cand_accept_SKILL.md"
        cand_accept.write_text(
            "---\nname: sample-skill\ndescription: Improved test skill.\n---\n"
            "# Sample Skill\n\nStep 1: Run vault_lint --fix.\nStep 2: Pass --json for structured checks.\n",
            encoding="utf-8",
        )
        cand_regress = self.tmp_dir / "cand_regress_SKILL.md"
        cand_regress.write_text(
            "---\nname: sample-skill\ndescription: Regressed test skill.\n---\n"
            "# Sample Skill\n\nStep 1: Pass --json for structured checks.\n",
            encoding="utf-8",
        )
        cand_cheat = self.tmp_dir / "cand_cheat_SKILL.md"
        cand_cheat.write_text(
            "---\nname: sample-skill\ndescription: Cheating skill.\n---\n"
            "# Sample Skill\n\nRead [[wiki/patterns/secret_pattern]] and run vault_lint --fix and --json.\n",
            encoding="utf-8",
        )

        suite_path = self.tmp_dir / "eval_suite.json"
        suite_path.write_text(
            json.dumps(
                {
                    "cases": [
                        {"id": "c1", "required_patterns": ["vault_lint --fix"], "forbidden_patterns": []},
                        {"id": "c2", "required_patterns": ["--json"], "forbidden_patterns": []},
                    ]
                }
            ),
            encoding="utf-8",
        )

        base_before = base_skill.read_bytes()
        cand_before = cand_accept.read_bytes()

        rep_acc, rc_acc = wikiskill_eval.evaluate_skill_update(
            base_skill,
            cand_accept,
            suite_path,
            vault_path=vault,
            apply_impact=True,
        )
        self.assertEqual(rc_acc, 0)
        self.assertEqual(rep_acc["decision"], "ACCEPTED")
        self.assertEqual(rep_acc["baseline_passed"], 1)
        self.assertEqual(rep_acc["candidate_passed"], 2)
        self.assertEqual(base_skill.read_bytes(), base_before)
        self.assertEqual(cand_accept.read_bytes(), cand_before)
        impact_md = (vault / "wiki" / "skill-impact.md").read_text(encoding="utf-8")
        self.assertIn("Accepted", impact_md)

        # Regression -> REJECTED (exit 1)
        rep_reg, rc_reg = wikiskill_eval.evaluate_skill_update(
            base_skill,
            cand_regress,
            suite_path,
            vault_path=vault,
            apply_impact=True,
        )
        self.assertEqual(rc_reg, 1)
        self.assertEqual(rep_reg["decision"], "REJECTED")
        self.assertIn("c1", rep_reg["regressions"])
        self.assertIn("Rejected", (vault / "wiki" / "skill-impact.md").read_text(encoding="utf-8"))

        # Isolation violation -> REJECTED (exit 1)
        rep_cheat, rc_cheat = wikiskill_eval.evaluate_skill_update(
            base_skill,
            cand_cheat,
            suite_path,
        )
        self.assertEqual(rc_cheat, 1)
        self.assertEqual(rep_cheat["decision"], "REJECTED")
        self.assertGreaterEqual(len(rep_cheat["isolation_violations"]), 1)

        # CAS conflict check on skill-impact.md
        orig_sha = wikiskill_eval.hashlib.sha256

        def _tamper_sha(data: bytes = b""):  # type: ignore[no-untyped-def]
            # First call reads pre-write hash, mutate file so post-check mismatches
            impact = vault / "wiki" / "skill-impact.md"
            if impact.exists():
                with mock.patch.object(wikiskill_eval, "hashlib") as _m:
                    _m.sha256 = orig_sha
                    impact.write_text(impact.read_text(encoding="utf-8") + "\n<!-- race -->\n", encoding="utf-8")
            return orig_sha(data)

        with mock.patch.object(wikiskill_eval.hashlib, "sha256", side_effect=_tamper_sha):
            rc_cli = wikiskill_eval.main(
                [
                    "--baseline-skill",
                    str(base_skill),
                    "--candidate-skill",
                    str(cand_accept),
                    "--eval-suite",
                    str(suite_path),
                    "--vault",
                    str(vault),
                    "--apply-impact",
                    "--json",
                ]
            )
            self.assertEqual(rc_cli, 2)

    # ------------------------------------------------------------------
    # Track 3: Graph Intelligence (`vault_lint.py` D3 + D4)
    # ------------------------------------------------------------------

    def test_vault_lint_synthesis_drift_and_backward_compat(self) -> None:
        vault = self.tmp_dir / "DriftVault"
        init_vault.init_vault(vault, quiet=True)
        (vault / "wiki" / "concepts" / "Engine.md").write_text(
            "---\n"
            "title: Engine\n"
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-20\n"
            "tags:\n  - core/engine\n"
            "sources:\n  - id: s1\n    resource: \"https://example.com/engine\"\n"
            "---\n# Engine\n\nUpdated architecture spec.\n",
            encoding="utf-8",
        )
        (vault / "wiki" / "synthesis" / "Overview.md").write_text(
            "---\n"
            "title: Overview\n"
            "type: synthesis\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-05\n"
            "tags:\n  - core/overview\n"
            "sources:\n  - id: s1\n    resource: \"https://example.com/overview\"\n"
            "---\n# Overview\n\nSynthesizes [[Engine]].\n",
            encoding="utf-8",
        )
        idx = vault / "index.md"
        idx.write_text(
            idx.read_text(encoding="utf-8") + "\n* [[wiki/concepts/Engine]]\n* [[wiki/synthesis/Overview]]\n",
            encoding="utf-8",
        )

        # Default --strict ignores synthesis drift so existing workflows stay backward compatible
        with contextlib.redirect_stdout(io.StringIO()):
            rep_default = vault_lint.run_vault_lint(vault, strict=True, strict_drift=False)
        self.assertEqual(len(rep_default["stale_syntheses"]), 1)
        self.assertEqual(rep_default["stale_syntheses"][0]["file"], "wiki/synthesis/Overview.md")
        self.assertTrue(rep_default["strict_passed"])

        # Explicit --strict-drift fails exit 1
        with contextlib.redirect_stdout(io.StringIO()):
            rc_drift = _run_vault_lint_cli([str(vault), "--strict-drift", "--json"])
        self.assertEqual(rc_drift, 1)

    def test_vault_lint_unlinked_mentions_exact_lines_and_masking(self) -> None:
        vault = self.tmp_dir / "MentionsVault"
        init_vault.init_vault(vault, quiet=True)
        (vault / "wiki" / "concepts" / "BatchRouter.md").write_text(
            "---\n"
            "title: BatchRouter\n"
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-10\n"
            "tags:\n  - net/router\n"
            "---\n# BatchRouter\n\nCanonical router note.\n",
            encoding="utf-8",
        )
        # Body puts fenced code BEFORE the plain-text mention to verify line number accounting
        (vault / "wiki" / "concepts" / "Pipeline.md").write_text(
            "---\n"
            "title: Pipeline\n"
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-10\n"
            "tags:\n  - net/pipeline\n"
            "---\n"
            "# Pipeline and BatchRouter Heading\n\n"
            "```bash\n"
            "echo BatchRouter inside code block\n"
            "echo second line in code block\n"
            "```\n\n"
            "Line 17 mentions BatchRouter directly in prose.\n",
            encoding="utf-8",
        )
        with contextlib.redirect_stdout(io.StringIO()):
            rep = vault_lint.run_vault_lint(vault, include_mentions=True)
        mentions = rep.get("unlinked_mentions", [])
        self.assertEqual(len(mentions), 1, msg=mentions)
        self.assertEqual(mentions[0]["file"], "wiki/concepts/Pipeline.md")
        self.assertEqual(mentions[0]["target"], "wiki/concepts/BatchRouter.md")
        self.assertEqual(mentions[0]["matched_term"], "BatchRouter")
        # Count actual 1-based line number of the prose match
        expected_line = next(
            idx
            for idx, ln in enumerate(
                (vault / "wiki" / "concepts" / "Pipeline.md").read_text(encoding="utf-8").splitlines(),
                1,
            )
            if "Line 17 mentions BatchRouter" in ln
        )
        self.assertEqual(mentions[0]["line"], expected_line)

    def test_vault_lint_dedup_manifest_cas_and_protected_files(self) -> None:
        vault = self.tmp_dir / "DedupVault"
        init_vault.init_vault(vault, quiet=True)
        keep_p = vault / "wiki" / "concepts" / "Vector Search.md"
        merge_p = vault / "wiki" / "concepts" / "Vector Search Engine.md"
        caller_p = vault / "wiki" / "concepts" / "Caller.md"
        ranker_p = vault / "wiki" / "concepts" / "Ranker.md"
        source_p = vault / "wiki" / "sources" / "Deck.md"
        raw_p = vault / "raw" / "RawNote.txt"
        skill_p = vault / "SKILL.md"

        keep_p.write_text(
            "---\n"
            "title: Vector Search\n"
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-01\n"
            "updated: 2026-10-10\n"
            "tags:\n  - ai/search\n"
            "sources:\n  - id: s1\n    resource: \"https://example.com/vs\"\n"
            "---\n# Vector Search\n\nCore dense retrieval note.\n",
            encoding="utf-8",
        )
        merge_p.write_text(
            "---\n"
            "title: Vector Search Engine\n"
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-02\n"
            "updated: 2026-10-12\n"
            "aliases:\n  - Vector Search\n"
            "tags:\n  - ai/retrieval\n"
            "sources:\n  - id: s2\n    resource: \"https://example.com/vse\"\n"
            "---\n# Vector Search Engine\n\n## Benchmarks\nAchieves 15ms p99 recall.\n",
            encoding="utf-8",
        )
        caller_p.write_text(
            "---\n"
            "title: Caller\n"
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-03\n"
            "updated: 2026-10-10\n"
            "tags:\n  - ai/app\n"
            "---\n# Caller\n\nUses [[Vector Search Engine|VSE]] and `[[Vector Search Engine]]` in code.\n",
            encoding="utf-8",
        )
        ranker_p.write_text(
            "---\n"
            "title: Ranker\n"
            "type: concept\n"
            "status: stable\n"
            "created: 2026-10-03\n"
            "updated: 2026-10-10\n"
            "tags:\n  - ai/ranking\n"
            "---\n# Ranker\n\nBuilt on [[Vector Search]], [[Vector Search|dense retrieval]], [[Vector Search|ANN]], [[Vector Search|HNSW]], [[Vector Search|semantic search]], and [[Vector Search#Notes]].\n",
            encoding="utf-8",
        )
        source_p.write_text(
            "---\ntitle: Deck\ntype: source\nstatus: stable\ncreated: 2026-10-01\nupdated: 2026-10-01\n---\n"
            "# Deck\nOriginal mention [[Vector Search Engine]].\n",
            encoding="utf-8",
        )
        raw_p.write_text("Raw [[Vector Search Engine]] provenance.\n", encoding="utf-8")
        skill_p.write_text(
            "---\nname: local-skill\ndescription: Local skill.\n---\nKeep [[Vector Search Engine]].\n",
            encoding="utf-8",
        )
        idx_p = vault / "index.md"
        idx_p.write_text(
            idx_p.read_text(encoding="utf-8")
            + "\n* [[wiki/concepts/Vector Search]]\n* [[wiki/concepts/Vector Search Engine]]\n"
            + "* [[wiki/concepts/Caller]]\n* [[wiki/concepts/Ranker]]\n",
            encoding="utf-8",
        )

        src_before = source_p.read_bytes()
        raw_before = raw_p.read_bytes()
        skill_before = skill_p.read_bytes()

        manifest_path = self.tmp_dir / "dedup_manifest.json"
        with contextlib.redirect_stdout(io.StringIO()):
            rc_gen = _run_vault_lint_cli([str(vault), "--dedup-manifest", str(manifest_path), "--json"])
        self.assertEqual(rc_gen, 0)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(manifest["proposals"]), 1)
        self.assertEqual(manifest["proposals"][0]["keep_target"], "wiki/concepts/Vector Search.md")
        self.assertEqual(manifest["proposals"][0]["merge_source"], "wiki/concepts/Vector Search Engine.md")
        self.assertFalse(manifest["proposals"][0]["approved"])

        # Unapproved manifest performs zero mutations
        with contextlib.redirect_stdout(io.StringIO()):
            res_noop = vault_lint.apply_dedup_manifest(vault, manifest_path)
        self.assertEqual(res_noop["applied_count"], 0)
        self.assertTrue(merge_p.exists())

        # Approved manifest + tampered merge_source triggers CAS conflict (exit 2) with zero writes
        manifest["proposals"][0]["approved"] = True
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        merge_orig = merge_p.read_text(encoding="utf-8")
        merge_p.write_text(merge_orig + "\nConcurrent edit.\n", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            rc_cas = _run_vault_lint_cli([str(vault), "--apply-manifest", str(manifest_path), "--json"])
        self.assertEqual(rc_cas, 2)
        self.assertTrue(merge_p.exists())

        # Regenerate fresh manifest, approve, and apply
        with contextlib.redirect_stdout(io.StringIO()):
            rc_regen = _run_vault_lint_cli([str(vault), "--dedup-manifest", str(manifest_path), "--json"])
        self.assertEqual(rc_regen, 0)
        manifest2 = json.loads(manifest_path.read_text(encoding="utf-8"))
        for prop in manifest2["proposals"]:
            prop["approved"] = True
        manifest_path.write_text(json.dumps(manifest2), encoding="utf-8")

        with contextlib.redirect_stdout(io.StringIO()):
            rc_app = _run_vault_lint_cli([str(vault), "--apply-manifest", str(manifest_path), "--json"])
        self.assertEqual(rc_app, 0)

        self.assertFalse(merge_p.exists())
        keep_txt = keep_p.read_text(encoding="utf-8")
        self.assertIn("ai/retrieval", keep_txt)
        self.assertIn("Vector Search Engine", keep_txt)
        self.assertIn("15ms p99 recall", keep_txt)

        caller_txt = caller_p.read_text(encoding="utf-8")
        self.assertIn("[[Vector Search|VSE]]", caller_txt)
        self.assertIn("`[[Vector Search Engine]]`", caller_txt)
        self.assertIn("## [", (vault / "log.md").read_text(encoding="utf-8"))
        self.assertIn("dedup |", (vault / "log.md").read_text(encoding="utf-8"))

        # Protected files remain byte-for-byte untouched
        self.assertEqual(source_p.read_bytes(), src_before)
        self.assertEqual(raw_p.read_bytes(), raw_before)
        self.assertEqual(skill_p.read_bytes(), skill_before)

    # ------------------------------------------------------------------
    # Track 4: Pattern PR Worktree & Lazy Graph `/api/note`
    # ------------------------------------------------------------------

    def test_open_pattern_pr_egress_block_dry_run_and_worktree(self) -> None:
        vault = self.tmp_dir / "ShareVault"
        init_vault.init_vault(vault, quiet=True)

        bad_concept = vault / "wiki" / "concepts" / "LeakyPattern.md"
        bad_token = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz123456"
        bad_concept.write_text(
            f"---\ntitle: LeakyPattern\ntype: concept\nstatus: stable\ntags:\n  - sec/test\n---\nToken: {bad_token}\n",
            encoding="utf-8",
        )
        good_concept = vault / "wiki" / "concepts" / "CleanPattern.md"
        good_concept.write_text(
            "---\ntitle: CleanPattern\ntype: concept\nstatus: stable\ncreated: 2026-10-01\nupdated: 2026-11-11\n"
            "tags:\n  - arch/clean\nsources:\n  - id: doc\n    resource: \"https://example.com/clean\"\n---\n"
            "# CleanPattern\n\nReusable architecture blueprint.\n",
            encoding="utf-8",
        )

        # Bare git remote + clean target patterns clone
        bare_remote = self.tmp_dir / "patterns_remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare_remote)], check=True)

        patterns_repo = self.tmp_dir / "shared_patterns"
        subprocess.run(["git", "clone", "-q", str(bare_remote), str(patterns_repo)], check=True)
        subprocess.run(["git", "checkout", "-q", "-b", "main"], cwd=str(patterns_repo), check=True)
        subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=str(patterns_repo), check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(patterns_repo), check=True)
        init_vault.init_vault(patterns_repo, quiet=True)
        subprocess.run(["git", "add", "-A"], cwd=str(patterns_repo), check=True)
        subprocess.run(["git", "commit", "-q", "--no-verify", "-m", "Init patterns"], cwd=str(patterns_repo), check=True)
        subprocess.run(["git", "push", "-q", "-u", "origin", "main"], cwd=str(patterns_repo), check=True)

        # 1. Fail-closed egress security gate blocks leaky pattern before push/PR
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(sync_patterns.SecurityException):
                sync_patterns.open_pattern_pr(
                    pattern_file=bad_concept,
                    target_repo_path=patterns_repo,
                    vault_root=vault,
                )

        # 2. Dry-run previews PR metadata without mutating repo or remote
        with contextlib.redirect_stdout(io.StringIO()):
            dry_res = sync_patterns.open_pattern_pr(
                pattern_file=good_concept,
                target_repo_path=patterns_repo,
                vault_root=vault,
                dry_run=True,
            )
        self.assertTrue(dry_res["success"])
        self.assertTrue(dry_res["dry_run"])
        self.assertFalse((patterns_repo / "wiki" / "concepts" / "CleanPattern.md").exists())

        # 3. Live isolated worktree share + commit + push + mocked gh pr create
        real_run = subprocess.run

        def _mock_subprocess_run(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
            if isinstance(cmd, (list, tuple)) and cmd and cmd[0] == "gh":
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout="https://example.com/org/shared-patterns/pull/42\n",
                    stderr="",
                )
            return real_run(cmd, *args, **kwargs)

        with mock.patch.object(sync_patterns.subprocess, "run", side_effect=_mock_subprocess_run):
            with contextlib.redirect_stdout(io.StringIO()):
                pr_res = sync_patterns.open_pattern_pr(
                    pattern_file=good_concept,
                    target_repo_path=patterns_repo,
                    vault_root=vault,
                    branch_name="docs/share-clean-pattern",
                )
        self.assertTrue(pr_res["success"])
        self.assertEqual(pr_res["pr_url"], "https://example.com/org/shared-patterns/pull/42")

        # Primary clone remains untouched on main without untracked shared file
        cur_branch = real_run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(patterns_repo),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(cur_branch, "main")
        self.assertFalse((patterns_repo / "wiki" / "concepts" / "CleanPattern.md").exists())

        # Remote actually received the pushed branch commit
        remote_heads = real_run(
            ["git", "ls-remote", "--heads", str(bare_remote), "docs/share-clean-pattern"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertTrue(remote_heads)

    def test_vault_graph_slim_html_and_lazy_api_note(self) -> None:
        vault = self.tmp_dir / "GraphLazyVault"
        init_vault.init_vault(vault, quiet=True)
        sentinel_md = "UNIQUE_LAZY_MARKDOWN_BODY_SENTINEL_V110"
        note_path = vault / "wiki" / "concepts" / "LazyNode.md"
        note_path.write_text(
            f"---\ntitle: LazyNode\ntype: concept\nstatus: stable\ncreated: 2026-10-01\nupdated: 2026-11-11\n"
            f"tags:\n  - ui/perf\n---\n# LazyNode\n\n{sentinel_md}\n",
            encoding="utf-8",
        )

        # Offline export must still embed full markdown for portable file:// usage
        export_res = vault_graph.export_graph_html(
            vault, self.tmp_dir / "offline_export.html"
        )
        export_html = Path(export_res["output_path"]).read_text(encoding="utf-8")
        self.assertIn(sentinel_md, export_html)

        # HTTP server must serve slim HTML on GET / and return full markdown on GET /api/note
        token_path = self.tmp_dir / ".graph_owner_token"
        with mock.patch.object(vault_graph, "OWNER_TOKEN_PATH", token_path):
            with mock.patch.object(vault_graph, "_LEGACY_OWNER_TOKEN_PATH", token_path):
                owner_token = "test-v110-owner-token"
                cache = vault_graph.VaultGraphCache(max_entries=2)
                handler_cls = vault_graph.create_graph_request_handler(
                    vault_root=vault,
                    port=0,
                    sidecar_mode=False,
                    owner_token=owner_token,
                    cache=cache,
                )
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
                actual_port = server.server_address[1]
                server.RequestHandlerClass = vault_graph.create_graph_request_handler(
                    vault_root=vault,
                    port=actual_port,
                    sidecar_mode=False,
                    owner_token=owner_token,
                    cache=cache,
                )
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    headers = {
                        "Host": f"127.0.0.1:{actual_port}",
                        "Authorization": f"Bearer {owner_token}",
                    }

                    conn = http.client.HTTPConnection("127.0.0.1", actual_port, timeout=10)
                    conn.request("GET", "/", headers=headers)
                    resp_root = conn.getresponse()
                    root_html = resp_root.read().decode("utf-8")
                    self.assertEqual(resp_root.status, 200)
                    self.assertIn('"lazyMarkdown": true', root_html)
                    self.assertNotIn(sentinel_md, root_html)
                    conn.close()

                    conn = http.client.HTTPConnection("127.0.0.1", actual_port, timeout=10)
                    conn.request("GET", "/api/graph?slim=1", headers=headers)
                    resp_slim = conn.getresponse()
                    slim_json = json.loads(resp_slim.read().decode("utf-8"))
                    self.assertEqual(resp_slim.status, 200)
                    lazy_nd = next(n for n in slim_json["nodes"] if n["id"] == "wiki/concepts/LazyNode.md")
                    self.assertTrue(lazy_nd.get("lazyMarkdown"))
                    self.assertEqual(lazy_nd.get("markdown"), "")
                    conn.close()

                    conn = http.client.HTTPConnection("127.0.0.1", actual_port, timeout=10)
                    conn.request(
                        "GET",
                        "/api/note?id=wiki/concepts/LazyNode.md&include_ace=0",
                        headers=headers,
                    )
                    resp_note = conn.getresponse()
                    note_json = json.loads(resp_note.read().decode("utf-8"))
                    self.assertEqual(resp_note.status, 200)
                    self.assertIn(sentinel_md, note_json["markdown"])
                    conn.close()

                    conn = http.client.HTTPConnection("127.0.0.1", actual_port, timeout=10)
                    conn.request("GET", "/api/note", headers=headers)
                    self.assertEqual(conn.getresponse().status, 400)
                    conn.close()

                    conn = http.client.HTTPConnection("127.0.0.1", actual_port, timeout=10)
                    conn.request("GET", "/api/note?id=../../etc/passwd", headers=headers)
                    self.assertEqual(conn.getresponse().status, 404)
                    conn.close()
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
