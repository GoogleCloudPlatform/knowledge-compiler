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
"""compile_graph_html.py - Standalone OKF v0.2 WebGL Graph Compiler & Epistemic Verifier.

Compiles the 2D/3D hardware-accelerated WebGL Knowledge Graph HTML artifact
(without writing files into the vault root, preserving the Vault Root Cleanliness
Invariant) and validates zero broken links, zero orphans, and 5-way typed
epistemic edge distribution.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import vault_graph  # noqa: E402
import vault_lint  # noqa: E402


def compile_and_verify(vault_path: Path, output_html: Path) -> dict:
    """Export standalone WebGL graph HTML and run OKF v0.2 lint verification."""
    export_res = vault_graph.export_graph_html(vault_path, output_html)
    buf = io.StringIO()
    with redirect_stdout(buf):
        lint_res = vault_lint.run_vault_lint(vault_path, auto_fix=False, as_json=True)
    return {
        "export": export_res,
        "lint": lint_res,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compile standalone OKF v0.2 WebGL HTML graph and verify 100% graph health."
    )
    parser.add_argument(
        "vault",
        nargs="?",
        default=None,
        help="Path to Obsidian Vault root (defaults to $OBSIDIAN_VAULT_PATH or ~/ObsidianVault).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(Path(tempfile.gettempdir()) / "Obsidian_Vault_WebGL_Graph.html"),
        help="Output HTML path outside the vault root (default: /tmp/Obsidian_Vault_WebGL_Graph.html).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON compilation and health summary.",
    )
    args = parser.parse_args()

    vault_root = vault_graph.resolve_default_vault(args.vault)
    out_path = Path(args.output).expanduser().resolve()

    # Enforce Vault Root Cleanliness Invariant: never write exported HTML inside the vault root
    if out_path.parent == vault_root:
        raise ValueError(
            f"Vault Root Cleanliness Invariant violation: refusing to write '{out_path.name}' "
            f"directly inside vault root '{vault_root}'. Choose /tmp or an artifact path."
        )

    res = compile_and_verify(vault_root, out_path)
    st = res["export"]["stats"]
    lint = res["lint"]
    edge_counts = st.get("edgeTypeCounts", {})

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print("=" * 68)
        print("🌐 OKF v0.2 WebGL Graph HTML Compilation & Epistemic Health Report")
        print("=" * 68)
        print(f"📁 Vault Path         : {vault_root}")
        print(f"📦 Compiled HTML      : {res['export']['output_path']} ({out_path.stat().st_size:,} bytes)")
        print(f"📚 Wiki Notes         : {st['wikiNotes']} (Total Multi-Plane Graph Nodes: {st['totalFiles']})")
        print(f"🔗 Total Graph Edges  : {st['totalEdges']}")
        print(
            "🧭 5-Way Epistemic    : "
            f"CORROBORATES={edge_counts.get('CORROBORATES', 0)}, "
            f"COMPLEMENTS={edge_counts.get('COMPLEMENTS', 0)}, "
            f"EXTENDS={edge_counts.get('EXTENDS', 0)}, "
            f"CONTRADICTS={edge_counts.get('CONTRADICTS', 0)}, "
            f"SUPERSEDES={edge_counts.get('SUPERSEDES', 0)}, "
            f"LINKS_TO={edge_counts.get('LINKS_TO', 0)}"
        )
        print(f"❌ Broken Wikilinks   : {len(lint['broken_links'])}")
        print(f"🏝️ Orphan Wiki Notes  : {len(lint['orphan_notes'])}")
        print(f"📐 Missing Frontmatter: {len(lint['missing_frontmatter'])}")
        print(f"📊 Table Pipe Errors  : {len(lint['table_invariant_violations'])}")
        print("-" * 68)
        if (
            lint["is_healthy"]
            and len(lint["orphan_notes"]) == 0
            and len(lint["missing_from_index"]) == 0
        ):
            print("✨ 100% GRAPH HEALTH VERIFIED (Zero Broken Links, Zero Orphans, OKF v0.2 Compliant)")
        else:
            print("⚠️ Graph health issues detected — inspect vault_lint.py output.")
        print("=" * 68)

    if not lint["is_healthy"] or len(lint["orphan_notes"]) > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
