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
"""Unit tests for OKF v0.2 core parser, stdlib YAML parity, and semantic helpers (okf.py)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import okf  # noqa: E402
import sync_patterns  # noqa: E402
import vault_correct  # noqa: E402


class TestOKFConformanceAndYAMLParity(unittest.TestCase):
    """Verify OKF v0.2 parser safety, PyYAML vs stdlib parity, and semantic helpers."""

    def test_size_cap_16kib_enforced_in_both_modes(self) -> None:
        oversized_yaml = "title: Oversized\ntype: concept\npadding: \"" + ("x" * 16500) + "\"\n"
        for use_pyyaml in (True, False):
            with self.assertRaises(okf.OKFParseError):
                okf.parse_frontmatter(
                    oversized_yaml, strict=True, use_pyyaml=use_pyyaml
                )
            self.assertEqual(
                okf.parse_frontmatter(
                    oversized_yaml, strict=False, use_pyyaml=use_pyyaml
                ),
                {},
            )
            doc = f"---\n{oversized_yaml}---\n# Body\n"
            parsed_doc = okf.parse_okf_document(
                doc, strict=False, use_pyyaml=use_pyyaml
            )
            self.assertFalse(parsed_doc["has_frontmatter"])
            self.assertTrue(
                any("16 KiB" in err for err in parsed_doc["errors"]),
                parsed_doc["errors"],
            )

    def test_rejects_yaml_anchors_aliases_and_merge_keys_in_both_modes(self) -> None:
        malicious_payloads = [
            "a: &a [lol, lol, lol]\nb: *a\n",
            "base: &base\n  type: concept\n<<: *base\n",
            "tags:\n  - &item1 foo\n  - *item1\n",
            "generated: { by: &a agent, ref: *a }\n",
            "title: *alias_ref\ntype: concept\n",
        ]
        for payload in malicious_payloads:
            for use_pyyaml in (True, False):
                with self.assertRaises(
                    okf.OKFParseError,
                    msg=f"Failed to reject payload ({use_pyyaml=}): {payload!r}",
                ):
                    okf.parse_frontmatter(
                        payload, strict=True, use_pyyaml=use_pyyaml
                    )

        # Legitimate '&', '*', '<<:', and unquoted apostrophes must succeed
        safe_yaml = (
            'title: "Research & Development * 2 <<: not a merge"\n'
            "subtitle: Retail & Supply Chain Architecture\n"
            "author_note: Andrej Karpathy's Compiled LLM-Wiki\n"
            "type: concept\n"
            "description: |\n"
            "  * bullet inside block scalar\n"
            "  &anchor_lookalike inside block scalar\n"
            "  <<: inside block scalar\n"
        )
        for use_pyyaml in (True, False):
            parsed = okf.parse_frontmatter(
                safe_yaml, strict=True, use_pyyaml=use_pyyaml
            )
            self.assertEqual(
                parsed["title"], "Research & Development * 2 <<: not a merge"
            )
            self.assertEqual(
                parsed["subtitle"], "Retail & Supply Chain Architecture"
            )
            self.assertEqual(
                parsed["author_note"], "Andrej Karpathy's Compiled LLM-Wiki"
            )
            self.assertIn("* bullet inside block scalar", parsed["description"])

    def test_malformed_yaml_rejected_in_both_modes(self) -> None:
        malformed_cases = [
            'title: "unclosed double quote\ntype: concept\n',
            "title: 'unclosed single quote\ntype: concept\n",
            "tags: [one, two\ntype: concept\n",
            "generated: { by: agent\ntype: concept\n",
            "tags: [one, two}\ntype: concept\n",
            "- item1\n- item2\n",
            "\ttitle: tab indented\ntype: concept\n",
            "title missing colon on line\ntype: concept\n",
            "null\n",
            "~\n",
        ]
        for bad_yaml in malformed_cases:
            for use_pyyaml in (True, False):
                with self.assertRaises(
                    okf.OKFParseError,
                    msg=f"Expected OKFParseError ({use_pyyaml=}) for:\n{bad_yaml}",
                ):
                    okf.parse_frontmatter(
                        bad_yaml, strict=True, use_pyyaml=use_pyyaml
                    )

        # Unclosed frontmatter fence
        unclosed_doc = "---\ntitle: Unclosed\ntype: concept\n# No closing fence\n"
        for use_pyyaml in (True, False):
            with self.assertRaises(okf.OKFParseError):
                okf.parse_okf_document(
                    unclosed_doc, strict=True, use_pyyaml=use_pyyaml
                )
            res = okf.validate_okf_concept(unclosed_doc, use_pyyaml=use_pyyaml)
            self.assertFalse(res["valid"])

    def test_pyyaml_and_stdlib_100_percent_structural_parity(self) -> None:
        complex_yaml = (
            "# Leading comment\n"
            'title: "Cloud Run: Serverless\\"Engine\\"" # inline comment\n'
            "single_quoted: 'It''s a # hash inside quotes'\n"
            "type: Attested Computation\n"
            "count: 42\n"
            "ratio: 0.875\n"
            "enabled: true\n"
            "disabled: false\n"
            "empty_val: null\n"
            "tilde_val: ~\n"
            "aliases: [\n"
            "  NWB,\n"
            '  "Acme, Inc",\n'
            "  ON,\n"
            "  Off,\n"
            "  Yes,\n"
            "  No\n"
            "]\n"
            "inline_tags: [gcp/cloud-run, \"serverless, v2\"]\n"
            "generated: { by: knowledge-compiler/1.0.0, at: 2026-06-20T22:53:05Z }\n"
            "executor:\n"
            "  resource: https://cloud.google.com/run#section\n"
            "  receipt: [sha256:aaa, sha256:bbb]\n"
            "sources:\n"
            "  - id: ga4\n"
            "    resource: https://analytics.google.com/ga4\n"
            "    usage_count: 5000\n"
            "  - { id: bq, resource: https://cloud.google.com/bigquery, required: true }\n"
            "verified:\n"
            "  - by: human:alice\n"
            "    at: 2026-10-02T12:00:00Z\n"
            "literal_block: |-\n"
            "  SELECT *\n"
            "  FROM dataset.table\n"
            "folded_block: >-\n"
            "  First line\n"
            "  folded into one.\n"
        )
        parsed_pyyaml = okf.parse_frontmatter(
            complex_yaml, strict=True, use_pyyaml=True
        )
        parsed_stdlib = okf.parse_frontmatter(
            complex_yaml, strict=True, use_pyyaml=False
        )
        self.assertEqual(parsed_pyyaml, parsed_stdlib)
        self.assertEqual(
            parsed_stdlib["aliases"],
            ["NWB", "Acme, Inc", "ON", "Off", "Yes", "No"],
        )
        self.assertEqual(
            parsed_stdlib["inline_tags"], ["gcp/cloud-run", "serverless, v2"]
        )
        self.assertEqual(
            parsed_stdlib["generated"],
            {"by": "knowledge-compiler/1.0.0", "at": "2026-06-20T22:53:05Z"},
        )
        self.assertEqual(
            parsed_stdlib["executor"],
            {
                "resource": "https://cloud.google.com/run#section",
                "receipt": ["sha256:aaa", "sha256:bbb"],
            },
        )
        self.assertEqual(parsed_stdlib["sources"][0]["usage_count"], 5000)
        self.assertEqual(parsed_stdlib["sources"][1]["required"], True)
        self.assertEqual(
            parsed_stdlib["literal_block"], "SELECT *\nFROM dataset.table"
        )
        self.assertEqual(
            parsed_stdlib["folded_block"], "First line folded into one."
        )

    def test_extract_string_list_and_sync_patterns_fallback_parity(self) -> None:
        cases = [
            ("---\naliases: [\n  NWB,\n  Initech\n]\n---", ["NWB", "Initech"]),
            ("---\naliases: null\n---", []),
            ("---\naliases: ~\n---", []),
            ('---\naliases: ["Acme, Inc", FinCorp]\n---', ["Acme, Inc", "FinCorp"]),
            ('---\naliases: [ON, Off, Yes, No, "-"]\n---', ["ON", "Off", "Yes", "No"]),
            ("---\naliases: SingleAlias\n---", ["SingleAlias"]),
        ]
        orig_yaml = sync_patterns.yaml
        try:
            for raw_fm, expected in cases:
                sync_patterns.yaml = orig_yaml
                self.assertEqual(
                    sync_patterns._extract_aliases_from_frontmatter(raw_fm),
                    expected,
                )
                sync_patterns.yaml = None
                self.assertEqual(
                    sync_patterns._extract_aliases_from_frontmatter(raw_fm),
                    expected,
                )
        finally:
            sync_patterns.yaml = orig_yaml

    def test_vault_correct_fallback_with_nested_mappings_and_lists(self) -> None:
        doc = (
            "---\n"
            "title: Cloud Run Limits\n"
            "type: concept\n"
            "tags:\n"
            "  - gcp/cloud-run\n"
            "  - serverless\n"
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
        orig_yaml = vault_correct.yaml
        try:
            vault_correct.yaml = None
            fm, body = vault_correct.parse_frontmatter(doc)
            self.assertEqual(fm["sources"][0]["id"], "cr-docs")
            self.assertEqual(fm["generated"]["by"], "knowledge-compiler/0.9.0")
            self.assertEqual(fm["verified"][0]["by"], "human:reviewer")
            self.assertEqual(body, "# Cloud Run Limits\n")
        finally:
            vault_correct.yaml = orig_yaml

    def test_normalize_verified_and_derive_trust_tier(self) -> None:
        # Bare mapping per OKF v0.2 §5.2 & §11
        bare_fm = {
            "type": "concept",
            "verified": {"by": "human:alice", "at": "2026-10-02T00:00:00Z"},
        }
        norm = okf.normalize_verified_list(bare_fm["verified"])
        self.assertEqual(
            norm, [{"by": "human:alice", "at": "2026-10-02T00:00:00Z"}]
        )
        self.assertEqual(okf.derive_trust_tier(bare_fm), "human-reviewed")

        # Machine-confirmed
        machine_fm = {
            "type": "concept",
            "verified": [{"by": "process:ci-runner", "at": "2026-10-02T00:00:00Z"}],
        }
        self.assertEqual(okf.derive_trust_tier(machine_fm), "machine-confirmed")

        # Mixed machine + human -> human-reviewed
        mixed_fm = {
            "type": "concept",
            "verified": [
                {"by": "process:ci-runner"},
                {"by": "human:reviewer"},
            ],
        }
        self.assertEqual(okf.derive_trust_tier(mixed_fm), "human-reviewed")

        # Empty or invalid `human:` -> unverified
        self.assertEqual(okf.derive_trust_tier({"type": "concept"}), "unverified")
        self.assertEqual(
            okf.derive_trust_tier(
                {"type": "concept", "verified": [{"by": "human:"}]}
            ),
            "unverified",
        )

    def test_is_stale_date_and_timezone_cases(self) -> None:
        ref = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        self.assertTrue(
            okf.is_stale({"stale_after": "2026-06-15"}, now=ref)
        )
        self.assertTrue(
            okf.is_stale({"stale_after": "2026-06-15T12:00:00Z"}, now=ref)
        )
        self.assertFalse(
            okf.is_stale({"stale_after": "2026-06-15T12:00:01Z"}, now=ref)
        )
        # +02:00 offset: 14:00+02:00 == 12:00Z -> stale at 12:00Z
        self.assertTrue(
            okf.is_stale({"stale_after": "2026-06-15T14:00:00+02:00"}, now=ref)
        )
        self.assertFalse(
            okf.is_stale({"stale_after": "2026-06-15T15:00:00+02:00"}, now=ref)
        )
        self.assertFalse(okf.is_stale({}, now=ref))

    def test_canonical_content_hash_ignores_volatile_timestamps(self) -> None:
        doc_v1 = (
            "---\n"
            "title: Service Mesh\n"
            "type: concept\n"
            "updated: 2026-10-01\n"
            "generated:\n"
            "  by: agent/1.0\n"
            "  at: 2026-10-01T00:00:00Z\n"
            "---\n"
            "# Service Mesh\nBody text.\n"
        )
        doc_v2 = (
            "---\r\n"
            "title: Service Mesh\r\n"
            "type: concept\r\n"
            "updated: 2026-11-10\r\n"
            "generated:\r\n"
            "  by: agent/1.0\r\n"
            "  at: 2026-11-10T19:00:00Z\r\n"
            "---\r\n"
            "# Service Mesh\r\nBody text.\r\n"
        )
        doc_changed = (
            "---\n"
            "title: Service Mesh\n"
            "type: concept\n"
            "updated: 2026-11-10\n"
            "---\n"
            "# Service Mesh\nModified body text.\n"
        )
        self.assertEqual(
            okf.canonical_content_hash(doc_v1),
            okf.canonical_content_hash(doc_v2),
        )
        self.assertNotEqual(
            okf.canonical_content_hash(doc_v1),
            okf.canonical_content_hash(doc_changed),
        )

    def test_validate_okf_concept_footnotes_and_attested_computation(self) -> None:
        valid_note = (
            "---\n"
            "title: GA4 Pipeline\n"
            "type: concept\n"
            "sources:\n"
            "  - id: ga4\n"
            "    resource: https://analytics.google.com\n"
            "verified: { by: human:alice, at: 2026-10-01T00:00:00Z }\n"
            "---\n"
            "# GA4 Pipeline\n"
            "Claim backed by source [^ga4] and local footnote [^note1].\n"
            "Code `[^ignored_in_code]` is ignored.\n\n"
            "[^note1]: Local explanation.\n"
        )
        res = okf.validate_okf_concept(valid_note)
        self.assertTrue(res["valid"], res["errors"])
        self.assertEqual(res["trust_tier"], "human-reviewed")
        self.assertEqual(res["missing_footnotes"], [])

        # Dangling footnote
        dangling_note = (
            "---\n"
            "title: Broken Citation\n"
            "type: concept\n"
            "sources:\n"
            "  - id: ga4\n"
            "    resource: https://analytics.google.com\n"
            "---\n"
            "Claim citing missing source [^unknown_src].\n"
        )
        res_dangling = okf.validate_okf_concept(dangling_note)
        self.assertFalse(res_dangling["valid"])
        self.assertEqual(res_dangling["missing_footnotes"], ["unknown_src"])

        # Legacy string sources: valid=True with legacy_sources=True warning
        legacy_note = (
            "---\n"
            "title: Legacy Note\n"
            "type: concept\n"
            "sources:\n"
            "  - raw/deck.pptx\n"
            "---\n"
            "# Legacy Note\n"
        )
        res_legacy = okf.validate_okf_concept(legacy_note)
        self.assertTrue(res_legacy["valid"])
        self.assertTrue(res_legacy["legacy_sources"])

        # Dict source missing resource -> invalid
        bad_src_note = (
            "---\n"
            "title: Bad Source\n"
            "type: concept\n"
            "sources:\n"
            "  - id: only-id\n"
            "---\n"
            "# Bad Source\n"
        )
        self.assertFalse(okf.validate_okf_concept(bad_src_note)["valid"])

        # Attested Computation (§10.2)
        attested_bad = (
            "---\n"
            "title: Revenue Query\n"
            "type: Attested Computation\n"
            "---\n"
            "# Revenue Query\n"
        )
        res_att_bad = okf.validate_okf_concept(attested_bad)
        self.assertFalse(res_att_bad["valid"])
        self.assertEqual(len(res_att_bad["errors"]), 2)

        attested_good = (
            "---\n"
            "title: Revenue Query\n"
            "type: Attested Computation\n"
            "runtime: bigquery\n"
            "---\n"
            "# Revenue Query\n\n"
            "## Computation\n"
            "```sql\nSELECT 1;\n```\n"
        )
        self.assertTrue(okf.validate_okf_concept(attested_good)["valid"])

    def test_migrate_legacy_sources_and_stamp_human_verification(self) -> None:
        note = (
            "---\n"
            "title: Migration Pattern\n"
            "type: concept\n"
            "sources:\n"
            '  - "raw/Architecture_Deck.pptx"\n'
            "  - id: existing-doc\n"
            "    resource: https://cloud.google.com/docs\n"
            "status: stable\n"
            "---\n"
            "# Migration Pattern\nExact body bytes.\n"
        )
        migrated, changed = okf.migrate_legacy_sources_in_frontmatter(note)
        self.assertTrue(changed)
        self.assertTrue(migrated.endswith("# Migration Pattern\nExact body bytes.\n"))
        val = okf.validate_okf_concept(migrated)
        self.assertTrue(val["valid"], val["errors"])
        self.assertFalse(val["legacy_sources"])
        self.assertEqual(len(val["frontmatter"]["sources"]), 2)
        self.assertEqual(
            val["frontmatter"]["sources"][0],
            {"id": "architecture-deck", "resource": "raw/Architecture_Deck.pptx"},
        )
        self.assertEqual(
            val["frontmatter"]["sources"][1],
            {"id": "existing-doc", "resource": "https://cloud.google.com/docs"},
        )

        # Second run is strictly idempotent
        migrated_again, changed_again = okf.migrate_legacy_sources_in_frontmatter(
            migrated
        )
        self.assertFalse(changed_again)
        self.assertEqual(migrated_again, migrated)

        # Stamp human verification
        stamped = okf.stamp_human_verification(
            migrated, actor="alice", at_iso="2026-11-10T19:00:00Z"
        )
        self.assertTrue(stamped.endswith("# Migration Pattern\nExact body bytes.\n"))
        val_stamped = okf.validate_okf_concept(stamped)
        self.assertTrue(val_stamped["valid"], val_stamped["errors"])
        self.assertEqual(val_stamped["trust_tier"], "human-reviewed")
        self.assertEqual(
            val_stamped["frontmatter"]["verified"],
            [{"by": "human:alice", "at": "2026-11-10T19:00:00Z"}],
        )

    def test_round1_fault_tolerant_alias_extraction_for_egress(self) -> None:
        quirky_frontmatters = [
            "type: entity\ntitle: Zorblatt's '25 Roadmap Account\naliases: [ZBX]\n",
            "type: entity\ntitle: Zorblatt\ndescription: Strategic, *top-tier* account\naliases: [ZBX]\n",
            "type: entity\ntitle: Zorblatt\ndescription: 'Multi-line\n  quoted description'\naliases: [ZBX]\n",
            "type: entity\ntitle: Zorblatt\naliases: [ZBX]\nmeta:\n\tx: 1\n",
            "type: entity\ntitle: Zorblatt\nx: &a 1\naliases: [ZBX]\n",
            "type: entity\ntitle: Zorblatt\naliases: [ZBX]\nrelated: [a, b\n",
            "\ufeff---\ntype: entity\ntitle: Zorblatt\naliases: [ZBX]\n---\n",
        ]
        for fm in quirky_frontmatters:
            for use_yaml in (True, False):
                self.assertEqual(
                    okf.extract_string_list(fm, "aliases", use_pyyaml=use_yaml),
                    ["ZBX"],
                    f"Failed on fm={fm!r} use_pyyaml={use_yaml}",
                )

    def test_round1_billion_laughs_bombs_rejected(self) -> None:
        bombs = [
            "type: Concept\nx:\n- k: |\n    t\n  a0: &a0 [lol,lol]\n  a1: &a1 [*a0,*a0]\n",
            'type: Concept\nx: [p "q, &a0 [lol,lol], &a1 [*a0,*a0], z" w]\n',
            "type: Concept\nx: [it 's, &a0 [lol,lol], &a1 [*a0,*a0], z' w]\n",
        ]
        for fm in bombs:
            for use_yaml in (True, False):
                with self.assertRaises(okf.OKFParseError):
                    okf.parse_frontmatter(fm, strict=True, use_pyyaml=use_yaml)

    def test_round1_plain_scalar_quotes_asterisks_and_multiline_parity(self) -> None:
        samples = [
            "title: Trends of the '90s\n",
            "height: 5' 10\" tall\n",
            'summary: He said "hi and left\n',
            "description: Fast, *really* fast\n",
            "description: A - *emphasized* point\n",
            "description: see [*note*] here\n",
            "title: Sales, &Marketing\n",
            "title: set {&x} of things\n",
            'description: "double quoted\n  continued line"\nafter: x\n',
            "description: 'single quoted\n  continued line'\nafter: x\n",
            "d: one\n\n  two\ne: x\n",
            "? complex\n: value\n",
            "m:\n  - - a\n    - b\n",
            "d: |2\n    two-indented\n",
            "items:\n  - |\n    lit\n  - >-\n    fold\n    ed\n",
            "v: 1.0\nw: 1.0.0\nx: v1\ny: 1e3\nd: 1.5e+3\n",
            'tags: [a "b, c" d]\n',
        ]
        for fm in samples:
            p_yaml = okf.parse_frontmatter(fm, strict=True, use_pyyaml=True)
            p_std = okf.parse_frontmatter(fm, strict=True, use_pyyaml=False)
            self.assertEqual(p_yaml, p_std, f"Parity mismatch on {fm!r}")

    def test_round1_stale_after_overflow_and_control_chars(self) -> None:
        self.assertIsNone(okf.parse_iso_datetime("9999-12-31T23:59:59-01:00"))
        self.assertIsNone(okf.parse_iso_datetime("0001-01-01T00:00:00+01:00"))
        self.assertIsNone(okf.parse_iso_datetime("2026-01-01T00:00:00Z\nstatus: bad"))
        self.assertFalse(okf.is_stale({"stale_after": "9999-12-31T23:59:59-01:00"}))

    def test_round1_migrate_and_stamp_nested_fields_and_injections(self) -> None:
        doc = (
            "---\n"
            "type: Concept\n"
            "sources:\n"
            "  - raw/a.pdf\n"
            "  - id: ga4\n"
            "    resource: https://example.com/x\n"
            "    usage_window: { from: 2026-06-01T00:00:00Z, to: 2026-06-30T00:00:00Z }\n"
            "    tags: [a, b]\n"
            '  - "raw/x.pdf\\rverified: { by: human:mallory, at: 2026-01-01T00:00:00Z }"\n'
            "  - '123'\n"
            "  - 'yes'\n"
            "---\n"
            "# Body\n"
        )
        for use_yaml in (True, False):
            migrated, changed = okf.migrate_legacy_sources_in_frontmatter(
                doc, use_pyyaml=use_yaml
            )
            self.assertTrue(changed)
            v = okf.validate_okf_concept(migrated, use_pyyaml=use_yaml)
            self.assertTrue(v["valid"], v["errors"])
            self.assertEqual(v["trust_tier"], "unverified")
            sources = v["frontmatter"]["sources"]
            self.assertEqual(
                sources[1]["usage_window"],
                {"from": "2026-06-01T00:00:00Z", "to": "2026-06-30T00:00:00Z"},
            )
            self.assertEqual(sources[1]["tags"], ["a", "b"])

        # Reject invalid actors and timestamps in stamp_human_verification
        base_doc = "---\ntype: Concept\n---\n# Body\n"
        for bad_actor in (
            "process:bot",
            "human:",
            "human:alice\nstatus: deprecated",
            "human:alice\rstatus: deprecated",
            "human:alice\u2028status: deprecated",
            'human:al"ice}, {by: human:root',
        ):
            with self.assertRaises(okf.OKFParseError):
                okf.stamp_human_verification(base_doc, bad_actor)

    def test_round1_linear_body_stripping_and_deep_nesting_caps(self) -> None:
        # Deep nesting > 64 rejected cleanly with OKFParseError
        deep_flow = "---\ntype: Concept\ntags: " + "[" * 100 + "]" * 100 + "\n---\n"
        res_deep = okf.validate_okf_concept(deep_flow)
        self.assertFalse(res_deep["valid"])

        # Large unclosed fences, HTML comments, and backtick runs complete in linear time
        large_body_doc = (
            "---\ntype: Concept\n---\n\n"
            + "<!-- unclosed\n" * 4000
            + "```unclosed\n" * 4000
            + " ".join("`" * k + "x" for k in range(1, 300))
            + "\n"
        )
        res_large = okf.validate_okf_concept(large_body_doc)
        self.assertTrue(res_large["valid"])

    def test_round2_p1_a2_and_p1_h_parity_and_node_property_aliases(self) -> None:
        # P1-A2: aliases with YAML node properties (&anchor, *alias, !!seq), nested lists/dicts, duplicates
        node_prop_fms = [
            "title: Zorblatt\naliases: &al [ZBX]\n",
            "title: Zorblatt\naliases: &al ZBX\n",
            "title: Zorblatt\naliases: [&x ZBX, &y Zorb]\n",
            "title: Zorblatt\nnames: &al [ZBX]\naliases: *al\n",
            "title: Zorblatt\naliases: !!seq [ZBX]\n",
            "title: Zorblatt\naliases: [ZBX]\naliases:\n",
            "title: Zorblatt\naliases: [[ZBX], Zorb]\n",
            "title: Zorblatt\naliases: {short: ZBX}\n",
            'title: Zorblatt\naliases: ["Z\\u0042X"]\n',
            "title: Z\nnames: &al\n  - ZBX\n  - Zorb\naliases: *al\n",
            "title: Z\nothers: [&z ZBX, q]\naliases: [*z]\n",
            "title: Z\nmeta: {short: &s ZBX}\naliases: [*s]\n",
            "title: Z\nmeta:\n  short: &s ZBX\naliases: [*s]\n",
            "title: Z\nbase: &b {aliases: [ZBX]}\n<<: *b\n",
            "title: Z\nbase: &b\n  aliases: [ZBX]\n<<: *b\n",
            "title: Z\nnames: &al [\n  ZBX,\n  Zorb\n]\naliases: *al\n",
            "title: Z\na: &x ZBX\nb: &y [*x]\naliases: *y\n",
            "title: Z\nn1: &n ZBX\naliases:\n  - *n\n  - Zorb\n",
            "title: Z\n&k aliases: [ZBX]\n",
            "title: Z\n!!str aliases: [ZBX]\n",
            "title: Z\n? aliases\n: [ZBX]\n",
            "  title: Z\n  aliases: [ZBX]\n",
            'aliases: [&a0 Zorb, &a1 "ZBX, Inc"]\n',
        ]
        for fm in node_prop_fms:
            for use_yaml in (True, False):
                extracted = okf.extract_string_list(fm, "aliases", use_pyyaml=use_yaml)
                self.assertTrue(
                    "ZBX" in extracted or "ZBX, Inc" in extracted,
                    f"Missing 'ZBX' for fm={fm!r} use_pyyaml={use_yaml} (got {extracted})",
                )

        # P1-H: '?' inside plain scalars in flow collections + folded scalar blank line before indented line
        parity_fms = [
            "type: Concept\nsources: [https://docs.example.com/d/1abc/edit?usp=sharing]\n",
            "type: Concept\ntags: [faq, what-next?]\n",
            "type: Concept\nparameters: ['new line',\n  what?,\n  '%']\n",
            "type: Concept\ndescription: >+\n  first line\n\n    more indented\n",
        ]
        for fm in parity_fms:
            p_yaml = okf.parse_frontmatter(fm, strict=True, use_pyyaml=True)
            p_std = okf.parse_frontmatter(fm, strict=True, use_pyyaml=False)
            self.assertEqual(p_yaml, p_std, f"Parity mismatch on {fm!r}")

    def test_round3_p1_a4_alias_bomb_and_cycle_resistance(self) -> None:
        # Billion-laughs 9^9 alias bomb inside entity frontmatter must resolve in <0.1s without expanding
        w = 9
        laughs_lines = [
            "title: Zorblatt Industries",
            "a0: &a0 [" + ",".join(["lol"] * w) + "]",
        ]
        for i in range(1, 10):
            laughs_lines.append(f"a{i}: &a{i} [" + ",".join([f"*a{i-1}"] * w) + "]")
        laughs_fm = "\n".join(laughs_lines) + "\naliases: *a9\n"
        self_cycle_fm = "title: Z\naliases: &a [*a, ZBX]\n"
        merge_chain_fm = (
            "title: Z\nb0: &b0 {aliases: [ZBX]}\n"
            + "".join(f"b{i}: &b{i}\n  <<: *b{i-1}\n  x{i}: {i}\n" for i in range(1, 30))
            + "<<: *b29\n"
        )
        for use_yaml in (True, False):
            self.assertEqual(
                okf.extract_string_list(laughs_fm, "aliases", use_pyyaml=use_yaml),
                ["lol"],
            )
            self.assertIn(
                "ZBX",
                okf.extract_string_list(self_cycle_fm, "aliases", use_pyyaml=use_yaml),
            )
            self.assertIn(
                "ZBX",
                okf.extract_string_list(merge_chain_fm, "aliases", use_pyyaml=use_yaml),
            )

    def test_round4_p1_a5_and_hash_prefixed_aliases(self) -> None:
        # 1. Quoted aliases starting with or containing '#' (#185)
        hash_fm = 'title: Z\naliases: ["#1 Zorb", "Zorb #1", "C# Corp"]\n'
        # 2. Second anchor on the same flow line (P1-A5)
        second_anchor_fm = "title: Z\nothers: [&q Qorp, &z ZBX]\naliases: [*z]\n"
        # 3. Indented mapping keys with a column-0 comment line (P1-A5)
        comment_indent_fm = "# managed\n  title: Zorblatt\n  aliases: [ZBX]\n"
        # 4. JSON root with >140 wikilinks (280+ brackets) and >16 KB summary (P1-A5)
        wlinks = ", ".join(f'"[[Note{i}]]"' for i in range(140))
        json_root_fm = (
            f'{{"title":"Zorblatt","related":[{wlinks}],'
            f'"summary":"{"x" * 17000}","aliases":["ZBX"]}}\n'
        )
        # 5. >4,096 duplicate items before target alias (P1-A5)
        dup_fm = "title: Z\naliases: [" + ", ".join(["Dup"] * 4100 + ["ZBX"]) + "]\n"
        # 6. 600-deep reverse anchor chain without RecursionError (P1-A5)
        rev_chain_fm = (
            "title: Z\naliases: *a0\n"
            + "".join(f"a{i}: &a{i} [*a{i + 1}]\n" for i in range(600))
            + "a600: &a600 [x]\naliases: [ZBX]\n"
        )
        # 7. P1-A6: >1 KiB frontmatter with alias ref + block scalar item or quoted '*' + multiline quoted item
        pad_1300 = 'summary: "' + ("lorem ipsum dolor sit amet " * 45) + '"\n'
        a6_literal_fm = (
            "title: Zorblatt Industries\n"
            + pad_1300
            + "n0: &z0 Zeta Group\naliases:\n  - *z0\n  - |-\n      ZBX\n"
        )
        a6_quoted_star_fm = (
            "title: Zorblatt Industries\n"
            + pad_1300
            + 'aliases: [\n  "ZBX\n    #1",\n  "E*Zorb"\n]\n'
        )
        a6_anchor_hash_fm = 'title: Z\naliases: [&y "Zorb #1", "ZBX"]\n'
        for use_yaml in (True, False):
            self.assertEqual(
                okf.extract_string_list(hash_fm, "aliases", use_pyyaml=use_yaml),
                ["#1 Zorb", "Zorb #1", "C# Corp"],
            )
            self.assertIn(
                "ZBX #1",
                okf.extract_string_list(a6_quoted_star_fm, "aliases", use_pyyaml=use_yaml),
            )
            for fm in (
                second_anchor_fm,
                comment_indent_fm,
                json_root_fm,
                dup_fm,
                rev_chain_fm,
                a6_literal_fm,
                a6_anchor_hash_fm,
            ):
                self.assertIn(
                    "ZBX",
                    okf.extract_string_list(fm, "aliases", use_pyyaml=use_yaml),
                    f"Missing ZBX for use_pyyaml={use_yaml} on fm={fm[:80]!r}",
                )


if __name__ == "__main__":
    unittest.main()
