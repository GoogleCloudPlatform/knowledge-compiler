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
"""Unit tests for explicit epistemic edges, O(N) masking, mtime graph cache, and 0600 exports."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import errno
import http.client
import http.server
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import compile_graph_html  # noqa: E402
import init_vault  # noqa: E402
import vault_graph  # noqa: E402

_REMOTE_PARAM_NAME = next(
    (
        p
        for p in inspect.signature(vault_graph.build_vault_graph).parameters
        if p.startswith("include_")
    ),
    "include_remote_tier",
)

_REMOTE_GROUP_KEY = next(
    (
        k
        for k in vault_graph.CATEGORY_META
        if k
        not in {
            "entity",
            "concept",
            "pattern",
            "synthesis",
            "ce_pattern",
            "source",
            "anchor",
            "raw",
        }
    ),
    "remote_tier",
)

_DISCOVER_REMOTE_FN_NAME = next(
    (
        name
        for name in dir(vault_graph)
        if name.startswith("discover_") and name.endswith("_nodes")
    ),
    "discover_remote_tier_nodes",
)


def _find_node_binary() -> Path | None:
    which_node = shutil.which("node")
    if which_node:
        p = Path(which_node)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    candidates = sorted(
        Path("/var/tmp").glob(
            "sar.server.*/server_impl.runfiles/*/third_party/*/cmd/hub/server/node_basic"
        )
    )
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


class TestGraphCacheAndExplicitEdges(unittest.TestCase):
    """Verify explicit-only epistemic edges, O(N) masking, VaultGraphCache, and 0600 exports."""

    def setUp(self) -> None:
        self._tmp_dir = Path(tempfile.mkdtemp(prefix="kc_graph_cache_"))
        self._orig_env = dict(os.environ)

        home_dir = self._tmp_dir / "home"
        cache_dir = self._tmp_dir / "xdg_cache"
        state_dir = self._tmp_dir / "xdg_state"
        data_dir = self._tmp_dir / "xdg_data"
        plugin_data_dir = self._tmp_dir / "plugin_data"
        patterns_dir = self._tmp_dir / "empty_patterns"
        for d in (home_dir, cache_dir, state_dir, data_dir, plugin_data_dir, patterns_dir):
            d.mkdir(parents=True, exist_ok=True)

        os.environ["HOME"] = str(home_dir)
        os.environ["XDG_CACHE_HOME"] = str(cache_dir)
        os.environ["XDG_STATE_HOME"] = str(state_dir)
        os.environ["XDG_DATA_HOME"] = str(data_dir)
        os.environ["PLUGIN_DATA"] = str(plugin_data_dir)
        os.environ["OKF_PATTERNS_PATH"] = str(patterns_dir)

        self._tok_patch = mock.patch.object(
            vault_graph,
            "OWNER_TOKEN_PATH",
            plugin_data_dir / ".vault_graph_token",
        )
        self._tok_patch.start()
        self._patterns_dir = patterns_dir

    def tearDown(self) -> None:
        self._tok_patch.stop()
        os.environ.clear()
        os.environ.update(self._orig_env)
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def _create_note(
        self, vault_root: Path, rel_path: str, content: str
    ) -> Path:
        p = vault_root / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_explicit_only_5_way_epistemic_edges_and_precedence(self) -> None:
        """All 5 epistemic edges come strictly from YAML frontmatter or inline rel::[[Target]]."""
        vault = self._tmp_dir / "EpistemicOnlyVault"
        init_vault.init_vault(vault)

        for name in ("B", "C", "D", "E", "F", "G", "H"):
            self._create_note(
                vault,
                f"wiki/concepts/{name}.md",
                f"---\ntitle: {name}\ntype: concept\n---\n# {name}\n",
            )

        self._create_note(
            vault,
            "wiki/concepts/A.md",
            "---\n"
            "title: A\n"
            "type: concept\n"
            'corroborates: "[[B#Section|Alias B]]"\n'
            "complements:\n"
            '  - "[[C]]"\n'
            'extends: ["[[D]]"]\n'
            "---\n"
            "# A\n\n"
            "Plain follow-up reference to [[B]] and [[C]].\n"
            "Inline contradicts:: [[E|Legacy E]] and also [[F]].\n"
            "Plain link first to [[G]], later supersedes::[[G#Old]].\n"
            "Untyped prose: Cloud Run vs [[H]] trade-off benchmark corroborates [[F]] supersedes [[H]].\n",
        )

        graph = vault_graph.build_vault_graph(vault, ce_patterns_root=self._patterns_dir)
        edge_map = {(e["source"], e["target"]): e["type"] for e in graph["edges"]}

        self.assertEqual(edge_map[("wiki/concepts/A.md", "wiki/concepts/B.md")], "CORROBORATES")
        self.assertEqual(edge_map[("wiki/concepts/A.md", "wiki/concepts/C.md")], "COMPLEMENTS")
        self.assertEqual(edge_map[("wiki/concepts/A.md", "wiki/concepts/D.md")], "EXTENDS")
        self.assertEqual(edge_map[("wiki/concepts/A.md", "wiki/concepts/E.md")], "CONTRADICTS")
        self.assertEqual(edge_map[("wiki/concepts/A.md", "wiki/concepts/G.md")], "SUPERSEDES")
        self.assertEqual(edge_map[("wiki/concepts/A.md", "wiki/concepts/F.md")], "LINKS_TO")
        self.assertEqual(edge_map[("wiki/concepts/A.md", "wiki/concepts/H.md")], "LINKS_TO")

        # Direct callable unit checks for infer_epistemic_edge_type
        self.assertEqual(
            vault_graph.infer_epistemic_edge_type("Cloud Run vs GKE"), "LINKS_TO"
        )
        self.assertEqual(
            vault_graph.infer_epistemic_edge_type("trade-off between [[A]] and [[B]]"),
            "LINKS_TO",
        )
        self.assertEqual(
            vault_graph.infer_epistemic_edge_type("benchmark of [[C]]"), "LINKS_TO"
        )
        self.assertEqual(
            vault_graph.infer_epistemic_edge_type("corroborates [[C]]"), "LINKS_TO"
        )
        self.assertEqual(
            vault_graph.infer_epistemic_edge_type("supersedes [[D]]"), "LINKS_TO"
        )
        self.assertEqual(
            vault_graph.infer_epistemic_edge_type("contradicts::[[Target]]"),
            "CONTRADICTS",
        )
        self.assertEqual(
            vault_graph.infer_epistemic_edge_type("non-contradicts::[[Target]]"),
            "LINKS_TO",
        )
        self.assertEqual(
            vault_graph.infer_epistemic_edge_type("", explicit_type="extends"),
            "EXTENDS",
        )

    def test_unquoted_yaml_wikilinks_and_shared_pattern_edges(self) -> None:
        """Unquoted YAML frontmatter [[Targets]] work; untyped shared-pattern links are LINKS_TO."""
        vault = self._tmp_dir / "UnquotedYamlVault"
        init_vault.init_vault(vault)
        shared_dir = self._tmp_dir / "shared_patterns"
        (shared_dir / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)

        for name in ("Y5", "Y6", "Y8", "Y9", "LocalRef", "PlainPat"):
            self._create_note(
                vault,
                f"wiki/concepts/{name}.md",
                f"---\ntitle: {name}\ntype: concept\n---\n# {name}\n",
            )

        self._create_note(
            vault,
            "wiki/concepts/Y.md",
            "---\n"
            "title: Y\n"
            "type: concept\n"
            "supersedes: [[Y5]]\n"
            "corroborates: [[Y9|alias]]\n"
            "contradicts:\n"
            "  - [[Y6]]\n"
            "extends: [[Y8#Section|Alias8]]\n"
            "---\n"
            "# Y\n\nPlain body mention [[Y5]] and [[Y9]].\n",
        )
        self._create_note(
            shared_dir,
            "wiki/concepts/SharedGuide.md",
            "---\ntitle: Shared Guide\ntype: concept\nstatus: stable\n---\n"
            "# Shared Guide\n\nUntyped [[PlainPat]] and explicit corroborates::[[LocalRef]].\n",
        )
        self._create_note(
            shared_dir,
            "wiki/patterns/PlainPat.md",
            "---\ntitle: PlainPat\ntype: pattern\nstatus: stable\n---\n# PlainPat\n",
        )

        graph = vault_graph.build_vault_graph(vault, ce_patterns_root=shared_dir)
        edge_map = {(e["source"], e["target"]): e["type"] for e in graph["edges"]}
        self.assertEqual(edge_map.get(("wiki/concepts/Y.md", "wiki/concepts/Y5.md")), "SUPERSEDES")
        self.assertEqual(edge_map.get(("wiki/concepts/Y.md", "wiki/concepts/Y9.md")), "CORROBORATES")
        self.assertEqual(edge_map.get(("wiki/concepts/Y.md", "wiki/concepts/Y6.md")), "CONTRADICTS")
        self.assertEqual(edge_map.get(("wiki/concepts/Y.md", "wiki/concepts/Y8.md")), "EXTENDS")

        shared_id = "shared://wiki/concepts/SharedGuide.md"
        if not any(n["id"] == shared_id for n in graph["nodes"]):
            shared_ids = [n["id"] for n in graph["nodes"] if "SharedGuide.md" in n["id"]]
            self.assertTrue(shared_ids, "Expected SharedGuide pattern node in graph")
            shared_id = shared_ids[0]
        self.assertEqual(
            edge_map.get((shared_id, "wiki/concepts/PlainPat.md")),
            "LINKS_TO",
        )
        self.assertEqual(
            edge_map.get((shared_id, "wiki/concepts/LocalRef.md")),
            "CORROBORATES",
        )
        plain_pat_shared_ids = [n["id"] for n in graph["nodes"] if "PlainPat.md" in n["id"] and n["id"] != "wiki/concepts/PlainPat.md"]
        self.assertTrue(plain_pat_shared_ids, "Expected shared PlainPat node")
        self.assertEqual(
            edge_map.get((plain_pat_shared_ids[0], "wiki/concepts/PlainPat.md")),
            "LINKS_TO",
        )

    def test_masking_code_comments_ignored_gemini_and_200kb_adversarial_notes(self) -> None:
        """Code blocks, inline code, HTML comments, and .gemini/ are excluded; 200KB notes stay O(N)."""
        vault = self._tmp_dir / "AdversarialVault"
        init_vault.init_vault(vault)

        self._create_note(
            vault,
            "wiki/concepts/Target.md",
            "---\ntitle: Target\ntype: concept\n---\n# Target\n",
        )
        self._create_note(
            vault,
            ".gemini/internal.md",
            "---\ntitle: Hidden Gemini Dir\ntype: concept\n---\ncorroborates::[[Target]]\n",
        )
        self._create_note(
            vault,
            "wiki/concepts/Masked.md",
            "---\ntitle: Masked\ntype: concept\n---\n"
            "```markdown\n"
            "contradicts::[[Target]]\n"
            "```\n\n"
            "~~~yaml\n"
            "supersedes::[[Target]]\n"
            "~~~\n\n"
            "> ```\n"
            "> extends::[[Target]]\n"
            "> ```\n\n"
            "Inline `corroborates::[[Target]]` and ``complements::[[Target]]``.\n"
            "<!-- contradicts::[[Target]] -->\n",
        )
        self._create_note(
            vault,
            "wiki/concepts/BeforeTarget.md",
            "---\ntitle: BeforeTarget\ntype: concept\n---\n# BeforeTarget\n",
        )
        self._create_note(
            vault,
            "wiki/concepts/AfterTarget.md",
            "---\ntitle: AfterTarget\ntype: concept\n---\n# AfterTarget\n",
        )
        self._create_note(
            vault,
            "wiki/concepts/AfterTilde.md",
            "---\ntitle: AfterTilde\ntype: concept\n---\n# AfterTilde\n",
        )
        self._create_note(
            vault,
            "wiki/concepts/AfterFences.md",
            "---\ntitle: AfterFences\ntype: concept\n---\n"
            "Before [[BeforeTarget]]\n"
            "```python\n"
            "contradicts::[[Target]]\n"
            "```\n\n"
            "After [[AfterTarget]]\n"
            "~~~yaml\n"
            "supersedes::[[Target]]\n"
            "~~~\n\n"
            "extends::[[AfterTilde]]\n",
        )
        self._create_note(
            vault,
            "wiki/concepts/Glued.md",
            "---\ntitle: Glued\ntype: concept\n---\n"
            "contradicts::<!-- hidden -->[[Target]]\n",
        )

        # 200 KB+ adversarial notes with unclosed fences, comments, backticks, and brackets
        adv_comments = "---\ntitle: AdvComments\ntype: concept\n---\n" + ("<!-- x\n" * 30000)
        adv_fences = "---\ntitle: AdvFences\ntype: concept\n---\n```\n" + ("a" * 205_000)
        adv_ticks = "---\ntitle: AdvTicks\ntype: concept\n---\n" + " ".join(
            "`" * n for n in range(1, 500)
        )
        adv_open_br = "---\ntitle: AdvOpenBrackets\ntype: concept\n---\n" + ("[" * 200_000)
        adv_dbl_br = "---\ntitle: AdvDoubleBrackets\ntype: concept\n---\n" + ("[[" * 100_000)
        adv_pipe_br = "---\ntitle: AdvPipeBrackets\ntype: concept\n---\n" + ("[[a|" * 50_000)
        adv_inline_ep = (
            "---\ntitle: AdvInlineEp\ntype: concept\n---\n"
            + ("contradicts:: [[" * 12_500)
        )
        self._create_note(vault, "wiki/concepts/AdvComments.md", adv_comments)
        self._create_note(vault, "wiki/concepts/AdvFences.md", adv_fences)
        self._create_note(vault, "wiki/concepts/AdvTicks.md", adv_ticks)
        self._create_note(vault, "wiki/concepts/AdvOpenBr.md", adv_open_br)
        self._create_note(vault, "wiki/concepts/AdvDblBr.md", adv_dbl_br)
        self._create_note(vault, "wiki/concepts/AdvPipeBr.md", adv_pipe_br)
        self._create_note(vault, "wiki/concepts/AdvInlineEp.md", adv_inline_ep)

        t0 = time.perf_counter()
        graph = vault_graph.build_vault_graph(vault, ce_patterns_root=self._patterns_dir)
        _ = vault_graph.infer_epistemic_edge_type("contradicts:: [[" * 12_500)
        _ = vault_graph.infer_epistemic_edge_type("corroborates::" + (" " * 200_000) + "x")
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 2.0, f"Adversarial 200KB graph build took {elapsed:.2f}s")

        node_ids = {n["id"] for n in graph["nodes"]}
        self.assertNotIn(".gemini/internal.md", node_ids)

        edge_map = {(e["source"], e["target"]): e["type"] for e in graph["edges"]}
        self.assertNotIn(("wiki/concepts/Masked.md", "wiki/concepts/Target.md"), edge_map)
        self.assertEqual(
            edge_map.get(("wiki/concepts/AfterFences.md", "wiki/concepts/BeforeTarget.md")),
            "LINKS_TO",
        )
        self.assertEqual(
            edge_map.get(("wiki/concepts/AfterFences.md", "wiki/concepts/AfterTarget.md")),
            "LINKS_TO",
        )
        self.assertEqual(
            edge_map.get(("wiki/concepts/AfterFences.md", "wiki/concepts/AfterTilde.md")),
            "EXTENDS",
        )
        self.assertNotIn(("wiki/concepts/AfterFences.md", "wiki/concepts/Target.md"), edge_map)
        self.assertEqual(
            edge_map.get(("wiki/concepts/Glued.md", "wiki/concepts/Target.md")),
            "LINKS_TO",
        )

    def test_fingerprint_invalidation_lru_eviction_and_mutation_isolation(self) -> None:
        """VaultGraphCache invalidates on edit/add/delete/rename/toggle and isolates callers."""
        vault = self._tmp_dir / "CacheVault"
        init_vault.init_vault(vault)
        patterns = self._tmp_dir / "shared_patterns"
        (patterns / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)

        note_a = self._create_note(
            vault,
            "wiki/concepts/Alpha.md",
            "---\ntitle: Alpha\ntype: concept\n---\n# Alpha\n",
        )
        self._create_note(
            vault,
            ".gemini/ignored.md",
            "---\ntitle: Ignored\ntype: concept\n---\n# Ignored\n",
        )

        cache = vault_graph.VaultGraphCache(max_entries=2)
        fp0 = vault_graph.compute_vault_graph_fingerprint(vault, ce_patterns_root=patterns)
        self.assertEqual(len(fp0), 9)

        # Changing ignored .gemini file must NOT change fingerprint
        self._create_note(
            vault,
            ".gemini/ignored.md",
            "---\ntitle: Ignored Updated\ntype: concept\n---\n# Ignored Updated\n",
        )
        self.assertEqual(
            vault_graph.compute_vault_graph_fingerprint(vault, ce_patterns_root=patterns),
            fp0,
        )

        # Cold build -> miss; warm hit -> zero file reads
        g1 = vault_graph.build_vault_graph_cached(
            vault, ce_patterns_root=patterns, cache=cache
        )
        self.assertEqual(cache.stats()["misses"], 1)
        self.assertEqual(cache.stats()["hits"], 0)

        with mock.patch.object(Path, "read_text", side_effect=AssertionError("unexpected disk read")):
            g2 = vault_graph.build_vault_graph_cached(
                vault, ce_patterns_root=patterns, cache=cache
            )
        self.assertEqual(cache.stats()["hits"], 1)

        # Mutating caller dict must NOT bleed into cached state
        g2["nodes"].append({"id": "injected"})
        g2["nodes"][0]["label"] = "MUTATED"
        if isinstance(g2["nodes"][0].get("tags"), list):
            g2["nodes"][0]["tags"].append("mutated-tag")
        g2["stats"]["categoryCounts"]["concept"] = 9999

        g3 = vault_graph.build_vault_graph_cached(
            vault, ce_patterns_root=patterns, cache=cache
        )
        self.assertEqual(len(g3["nodes"]), len(g1["nodes"]))
        self.assertNotEqual(g3["nodes"][0]["label"], "MUTATED")
        self.assertNotEqual(g3["stats"]["categoryCounts"]["concept"], 9999)

        # (a) Edit note while clamping mtime back via os.utime -> size change invalidates!
        orig_stat = os.stat(note_a)
        note_a.write_text(
            "---\ntitle: Alpha\ntype: concept\n---\n# Alpha with extra content bytes\n",
            encoding="utf-8",
        )
        os.utime(note_a, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
        fp_edit_size = vault_graph.compute_vault_graph_fingerprint(vault, ce_patterns_root=patterns)
        self.assertNotEqual(fp_edit_size, fp0)

        # (b) Same-size edit with restored mtime invalidates via st_ctime_ns
        time.sleep(0.01)
        note_a.write_text(
            "---\ntitle: Alpha\ntype: concept\n---\n# Alpho\n",
            encoding="utf-8",
        )
        os.utime(note_a, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
        new_stat_same = os.stat(note_a)
        self.assertEqual(new_stat_same.st_size, orig_stat.st_size)
        self.assertEqual(new_stat_same.st_mtime_ns, orig_stat.st_mtime_ns)
        fp_edit_ctime = vault_graph.compute_vault_graph_fingerprint(
            vault, ce_patterns_root=patterns
        )
        self.assertNotEqual(fp_edit_ctime, fp0)

        # (c) Edit note with bumped st_mtime_ns
        note_a.write_text(
            "---\ntitle: Alpha\ntype: concept\n---\n# Alpha\n",
            encoding="utf-8",
        )
        os.utime(note_a, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns + 1_000_000))
        fp_edit_mtime = vault_graph.compute_vault_graph_fingerprint(vault, ce_patterns_root=patterns)
        self.assertNotEqual(fp_edit_mtime, fp0)

        # (c) Add file -> invalidates
        note_b = self._create_note(
            vault,
            "wiki/concepts/Beta.md",
            "---\ntitle: Beta\ntype: concept\n---\n# Beta\n",
        )
        fp_add = vault_graph.compute_vault_graph_fingerprint(vault, ce_patterns_root=patterns)
        self.assertNotEqual(fp_add, fp_edit_mtime)

        # (d) Rename file preserving mtime -> path digest invalidates
        beta_stat = os.stat(note_b)
        note_b_renamed = vault / "wiki" / "concepts" / "BetaRenamed.md"
        os.rename(note_b, note_b_renamed)
        os.utime(note_b_renamed, ns=(beta_stat.st_atime_ns, beta_stat.st_mtime_ns))
        fp_rename = vault_graph.compute_vault_graph_fingerprint(vault, ce_patterns_root=patterns)
        self.assertNotEqual(fp_rename, fp_add)

        # (e) Delete file -> invalidates
        note_b_renamed.unlink()
        fp_del = vault_graph.compute_vault_graph_fingerprint(vault, ce_patterns_root=patterns)
        self.assertNotEqual(fp_del, fp_rename)

        # (f) Update shared patterns repo -> invalidates
        self._create_note(
            patterns,
            "wiki/concepts/SharedPat.md",
            "---\ntitle: SharedPat\ntype: concept\n---\n# Shared\n",
        )
        fp_pat = vault_graph.compute_vault_graph_fingerprint(vault, ce_patterns_root=patterns)
        self.assertNotEqual(fp_pat, fp_del)

        # (g) Toggle remote parameter -> invalidates
        fp_remote = vault_graph.compute_vault_graph_fingerprint(
            vault, ce_patterns_root=patterns, **{_REMOTE_PARAM_NAME: True}
        )
        self.assertNotEqual(fp_remote, fp_pat)

        # Verify bounded LRU eviction (max_entries=2)
        cache.clear()
        vault_graph.build_vault_graph_cached(vault, ce_patterns_root=patterns, cache=cache)
        self._create_note(vault, "wiki/concepts/E1.md", "---\ntitle: E1\ntype: concept\n---\n")
        vault_graph.build_vault_graph_cached(vault, ce_patterns_root=patterns, cache=cache)
        self._create_note(vault, "wiki/concepts/E2.md", "---\ntitle: E2\ntype: concept\n---\n")
        vault_graph.build_vault_graph_cached(vault, ce_patterns_root=patterns, cache=cache)
        self.assertEqual(cache.stats()["entries"], 2)

    def test_2000_note_warm_latency_and_concurrent_http_server(self) -> None:
        """Warm cache and ThreadingHTTPServer handle 2,000 notes rapidly and safely under 16 threads."""
        vault = self._tmp_dir / "Scale2000Vault"
        init_vault.init_vault(vault)
        concepts_dir = vault / "wiki" / "concepts"
        for i in range(2000):
            nxt = (i + 1) % 2000
            (concepts_dir / f"Note_{i:04d}.md").write_text(
                f"---\ntitle: Note {i:04d}\ntype: concept\n---\n"
                f"# Note {i:04d}\nSee [[Note_{nxt:04d}]].\n",
                encoding="utf-8",
            )

        cache = vault_graph.VaultGraphCache(max_entries=4)
        cold_graph = vault_graph.build_vault_graph_cached(
            vault, ce_patterns_root=self._patterns_dir, cache=cache
        )
        self.assertGreaterEqual(cold_graph["stats"]["totalFiles"], 2000)

        warm_times_ms: list[float] = []
        for _ in range(3):
            t0 = time.perf_counter()
            warm_graph = vault_graph.build_vault_graph_cached(
                vault, ce_patterns_root=self._patterns_dir, cache=cache
            )
            warm_times_ms.append((time.perf_counter() - t0) * 1000.0)
            self.assertEqual(warm_graph["stats"]["totalFiles"], cold_graph["stats"]["totalFiles"])
        self.assertLess(
            min(warm_times_ms),
            100.0,
            f"Expected fast warm cache hit on 2,000 notes, got {warm_times_ms}",
        )

        # Concurrent HTTP requests via ThreadingHTTPServer
        owner_token = "x" * 40
        server_cache = vault_graph.VaultGraphCache(max_entries=4)
        build_calls: list[int] = []
        orig_build = vault_graph.build_vault_graph

        def _counting_build(*args: object, **kwargs: object) -> dict[str, object]:
            build_calls.append(1)
            return orig_build(*args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(vault_graph, "build_vault_graph", side_effect=_counting_build):
            handler_cls = vault_graph.create_graph_request_handler(
                vault_root=vault,
                port=0,
                sidecar_mode=False,
                owner_token=owner_token,
                cache=server_cache,
            )
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
            port = srv.server_address[1]
            srv.RequestHandlerClass = vault_graph.create_graph_request_handler(
                vault_root=vault,
                port=port,
                sidecar_mode=False,
                owner_token=owner_token,
                cache=server_cache,
            )
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                barrier = threading.Barrier(16)

                def _worker(idx: int) -> tuple[int, int]:
                    barrier.wait(timeout=10)
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                    route = (
                        "/api/graph"
                        if idx % 3 == 0
                        else ("/index.html" if idx % 3 == 1 else "/")
                    )
                    conn.request(
                        "GET",
                        route,
                        headers={
                            "Host": f"127.0.0.1:{port}",
                            "Authorization": f"Bearer {owner_token}",
                        },
                    )
                    resp = conn.getresponse()
                    body = resp.read()
                    conn.close()
                    if route == "/api/graph":
                        parsed = json.loads(body.decode("utf-8"))
                        return resp.status, parsed["stats"]["totalFiles"]
                    return resp.status, len(body)

                with ThreadPoolExecutor(max_workers=16) as pool:
                    results = list(pool.map(_worker, range(16)))
                for status, metric in results:
                    self.assertEqual(status, 200)
                    self.assertGreater(metric, 2000)

                # All 16 concurrent threads shared ONE cold build!
                self.assertEqual(len(build_calls), 1)

                # Warm /api/graph latency check
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                t0 = time.perf_counter()
                conn.request(
                    "GET",
                    "/api/graph",
                    headers={
                        "Host": f"127.0.0.1:{port}",
                        "Authorization": f"Bearer {owner_token}",
                    },
                )
                resp = conn.getresponse()
                raw = resp.read()
                api_ms = (time.perf_counter() - t0) * 1000.0
                conn.close()
                self.assertEqual(resp.status, 200)
                self.assertGreater(len(raw), 10_000)
                self.assertLess(api_ms, 100.0, f"Warm GET /api/graph took {api_ms:.2f}ms")
            finally:
                srv.shutdown()
                srv.server_close()

    def test_xdg_default_export_0600_vault_containment_and_symlinks(self) -> None:
        """Default HTML export uses $XDG_CACHE_HOME (0700 dir, 0600 file), blocks vault tree & symlinks."""
        vault = self._tmp_dir / "ExportSecVault"
        init_vault.init_vault(vault)

        # 1. Default path uses $XDG_CACHE_HOME/knowledge-compiler/exports/... with 0700 dir
        default_out = vault_graph.resolve_default_export_html_path()
        expected_out = (
            Path(os.environ["XDG_CACHE_HOME"]).resolve()
            / "knowledge-compiler"
            / "exports"
            / "Obsidian_Vault_WebGL_Graph.html"
        )
        self.assertEqual(default_out, expected_out)
        self.assertEqual(stat.S_IMODE(os.stat(default_out.parent).st_mode), 0o700)

        # Relative $XDG_CACHE_HOME must be ignored per XDG Base Directory spec
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "relative/cache"}, clear=False):
            rel_fallback = vault_graph.resolve_default_export_html_path()
            self.assertEqual(
                rel_fallback,
                Path(os.environ["HOME"]).resolve()
                / ".cache"
                / "knowledge-compiler"
                / "exports"
                / "Obsidian_Vault_WebGL_Graph.html",
            )

        # 2. compile_graph_html CLI with no -o exports to $XDG_CACHE_HOME with 0600 permissions
        with mock.patch.object(sys, "argv", ["compile_graph_html.py", str(vault), "--json"]):
            rc = compile_graph_html.main()
        self.assertEqual(rc, 0)
        self.assertTrue(default_out.is_file())
        self.assertEqual(stat.S_IMODE(os.lstat(default_out).st_mode), 0o600)

        # 3. vault_graph CLI --export with no path arg also defaults to $XDG_CACHE_HOME (0600)
        default_out.unlink()
        with mock.patch.object(sys, "argv", ["vault_graph.py", str(vault), "--export"]):
            vault_graph.main()
        self.assertTrue(default_out.is_file())
        self.assertEqual(stat.S_IMODE(os.lstat(default_out).st_mode), 0o600)

        # 4. EROFS fallback creates 0700 temp directory when $XDG_CACHE_HOME cannot be created
        ro_cache = self._tmp_dir / "ro_cache"
        with (
            mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(ro_cache)}, clear=False),
            mock.patch.object(
                Path,
                "mkdir",
                autospec=True,
                side_effect=[OSError(errno.EROFS, "Read-only file system"), None],
            ),
        ):
            fallback_path = vault_graph.resolve_default_export_html_path()
            self.assertEqual(
                fallback_path.name, "Obsidian_Vault_WebGL_Graph.html"
            )
            self.assertTrue(str(fallback_path).startswith(str(Path(tempfile.gettempdir()).resolve())))

        # 5. Strict Vault Containment Guard blocks root AND nested subdirs inside vault
        sub_out = vault / "wiki" / "concepts" / "nested_graph.html"
        for bad_target in (vault, vault / "graph.html", sub_out):
            with self.assertRaises(ValueError):
                vault_graph.export_graph_html(vault, bad_target)
            if bad_target != vault:
                self.assertFalse(bad_target.exists())

        with (
            mock.patch.object(
                sys, "argv", ["compile_graph_html.py", str(vault), "-o", str(sub_out)]
            ),
            self.assertRaises(ValueError),
        ):
            compile_graph_html.main()

        # 6. Pre-planted symlinks (both dangling and pointing outside vault) are rejected
        outside_victim = self._tmp_dir / "victim.html"
        outside_victim.write_text("ORIGINAL_VICTIM", encoding="utf-8")
        symlink_out = self._tmp_dir / "evil_symlink.html"
        symlink_out.symlink_to(outside_victim)
        with self.assertRaises(ValueError):
            vault_graph.export_graph_html(vault, symlink_out)
        self.assertEqual(outside_victim.read_text(encoding="utf-8"), "ORIGINAL_VICTIM")

        dangling_link = self._tmp_dir / "dangling_symlink.html"
        dangling_link.symlink_to(self._tmp_dir / "nonexistent_target.html")
        with self.assertRaises(ValueError):
            vault_graph.export_graph_html(vault, dangling_link)

    def test_html_contains_identifier_aware_client_tokenizer(self) -> None:
        """Rendered HTML embeds the CamelCase / hyphen / slash / underscore JS search tokenizer."""
        vault = self._tmp_dir / "JSTokenizerVault"
        init_vault.init_vault(vault)
        graph = vault_graph.build_vault_graph(vault, ce_patterns_root=self._patterns_dir)
        html_out = vault_graph.render_graph_html(graph, sidecar_mode=False)
        self.assertIn("function _splitIdentifierSegment(", html_out)
        self.assertIn("function tokenizeForSearch(", html_out)
        self.assertIn("function nodeMatchesQuickFilter(", html_out)

    def test_shared_pattern_frontmatter_epistemic_edges_and_uri_targets(self) -> None:
        """Shared pattern YAML epistemic fields and URI targets with .md resolve cleanly."""
        vault = self._tmp_dir / "SharedPatternEpistemicVault"
        init_vault.init_vault(vault)

        self._create_note(
            vault,
            "wiki/concepts/Alpha Concept.md",
            "---\ntitle: Alpha Concept\ntype: concept\n---\n# Alpha Concept\n",
        )
        self._create_note(
            vault,
            "wiki/concepts/Beta Concept.md",
            "---\ntitle: Beta Concept\ntype: concept\n---\n# Beta Concept\n",
        )

        self._create_note(
            self._patterns_dir,
            "wiki/concepts/Shared Pattern One.md",
            "---\n"
            "title: Shared Pattern One\n"
            "type: concept\n"
            "status: stable\n"
            'corroborates: ["[[Alpha Concept]]"]\n'
            'complements: ["[[Beta Concept]]"]\n'
            "---\n"
            "# Shared Pattern One\n\n"
            "Pattern body referencing [[Alpha Concept]].\n",
        )

        catalog = vault_graph.list_ce_patterns_catalog(self._patterns_dir)
        self.assertEqual(len(catalog), 1)
        pat_uri = catalog[0]["id"]
        self.assertTrue(pat_uri.endswith("wiki/concepts/Shared Pattern One.md"))

        mocked_remote_node = {
            "id": "remote://l0/architectures/shared-pattern-one",
            "label": "Remote Shared Pattern One",
            "tier": "L0",
            "source_tier": "bundle",
            "maturity_score": 0.95,
            "concept_uid": "cid_test01",
            "tags": ["tier/l0"],
            "excerpt": "Test remote pattern node",
            "markdown": "# Remote Shared Pattern One\n\nRemote body.\n",
            "products": [],
            "epistemic_edges": [
                {"target": pat_uri, "type": "CORROBORATES"},
                {"target": "wiki/concepts/Alpha Concept.md", "type": "EXTENDS"},
            ],
        }

        with mock.patch.object(
            vault_graph,
            _DISCOVER_REMOTE_FN_NAME,
            return_value=[mocked_remote_node],
        ):
            graph = vault_graph.build_vault_graph(
                vault,
                ce_patterns_root=self._patterns_dir,
                **{_REMOTE_PARAM_NAME: True},
            )

        cat_counts = graph["stats"]["categoryCounts"]
        self.assertGreaterEqual(cat_counts.get("ce_pattern", 0), 1)
        self.assertGreaterEqual(cat_counts.get(_REMOTE_GROUP_KEY, 0), 1)

        edge_map = {(e["source"], e["target"]): e["type"] for e in graph["edges"]}
        self.assertEqual(
            edge_map.get((pat_uri, "wiki/concepts/Alpha Concept.md")),
            "CORROBORATES",
        )
        self.assertEqual(
            edge_map.get((pat_uri, "wiki/concepts/Beta Concept.md")),
            "COMPLEMENTS",
        )
        self.assertEqual(
            edge_map.get(("remote://l0/architectures/shared-pattern-one", pat_uri)),
            "CORROBORATES",
        )
        self.assertEqual(
            edge_map.get(
                (
                    "remote://l0/architectures/shared-pattern-one",
                    "wiki/concepts/Alpha Concept.md",
                )
            ),
            "EXTENDS",
        )

        node_by_id = {n["id"]: n for n in graph["nodes"]}
        self.assertGreaterEqual(node_by_id[pat_uri]["inDegree"], 1)

    def test_lazy_remote_toggle_executes_js_edge_merge_and_webgl_buffer_growth(
        self,
    ) -> None:
        """Lazy remote toggle merges edges/stats, resizes WebGL buffers, and toggles cleanly."""
        node_bin = _find_node_binary()
        self.assertIsNotNone(
            node_bin,
            "Node binary is required to verify lazy graph merge and WebGL buffer resize JS.",
        )
        assert node_bin is not None

        vault = self._tmp_dir / "LazyRemoteJsVault"
        init_vault.init_vault(vault)
        self._create_note(
            vault,
            "wiki/concepts/Alpha.md",
            "---\ntitle: Alpha\ntype: concept\n---\n# Alpha\n\nSee [[Beta]].\n",
        )
        self._create_note(
            vault,
            "wiki/concepts/Beta.md",
            "---\ntitle: Beta\ntype: concept\n---\n# Beta\n\nLinked to [[index]].\n",
        )
        graph = vault_graph.build_vault_graph(
            vault,
            ce_patterns_root=self._patterns_dir,
            **{_REMOTE_PARAM_NAME: False},
        )
        graph["hasRemoteTier"] = True
        html_out = vault_graph.render_graph_html(graph, sidecar_mode=False)

        scripts = re.findall(r"<script(?:\s+[^>]*)?>([\s\S]*?)</script>", html_out)
        self.assertEqual(len(scripts), 2)
        payload_js, app_js = scripts[0], scripts[1]

        local_nodes_count = len(graph["nodes"])
        local_edges_count = len(graph["edges"])
        local_inbound_index = sum(
            1 for e in graph["edges"] if e.get("target") == "index.md"
        )

        # Build remote payload > 1000 nodes (1600) and > 4000 edges (4600) to force WebGL Float32Array growth
        remote_nodes = [
            {
                "id": f"remote://l0/concept-{i}",
                "label": f"[Remote L0] Concept {i}",
                "baseName": f"Concept {i}",
                "group": _REMOTE_GROUP_KEY,
                "color": "#A142F4",
                "badge": "Remote",
                "type": "remote-l0",
                "status": "L0 • bundle",
                "updated": "Maturity 0.90",
                "tags": ["tier/l0"],
                "aliases": [f"cid_rem_{i}"],
                "inDegree": 0,
                "outDegree": 0,
                "degree": 0,
                "pagerank": 0.1,
                "isOrphan": False,
                "excerpt": f"Excerpt {i}",
                "markdown": f"# Concept {i}",
                "sourcePlane": _REMOTE_GROUP_KEY,
                "canPromoteToAce": False,
                "ceRelPath": "",
                "products": [],
                "layer": "L0",
                "x": float((i % 40) * 10 - 200),
                "y": float((i // 40) * 10 - 200),
                "z": float(((i * 17) % 200) - 100),
            }
            for i in range(1600)
        ]

        fresh_edges: list[dict[str, str]] = []
        upgraded_alpha_beta = False
        for edge in graph["edges"]:
            copied = dict(edge)
            if (
                copied.get("source") == "wiki/concepts/Alpha.md"
                and copied.get("target") == "wiki/concepts/Beta.md"
            ):
                copied["type"] = "CORROBORATES"
                copied["color"] = "#10B981"
                upgraded_alpha_beta = True
            fresh_edges.append(copied)
        self.assertTrue(upgraded_alpha_beta)

        for i in range(120):
            fresh_edges.append(
                {
                    "source": f"remote://l0/concept-{i}",
                    "target": "index.md",
                    "type": "CORROBORATES",
                    "color": "#10B981",
                }
            )
        for j in range(4480):
            src_idx = j % 1600
            step = 1 + (j // 1600)
            dst_idx = (src_idx + step) % 1600
            fresh_edges.append(
                {
                    "source": f"remote://l0/concept-{src_idx}",
                    "target": f"remote://l0/concept-{dst_idx}",
                    "type": "COMPLEMENTS",
                    "color": "#4285F4",
                }
            )

        edge_type_counts: dict[str, int] = dict(graph["stats"]["edgeTypeCounts"])
        edge_type_counts["LINKS_TO"] = max(0, edge_type_counts.get("LINKS_TO", 0) - 1)
        edge_type_counts["CORROBORATES"] = edge_type_counts.get("CORROBORATES", 0) + 121
        edge_type_counts["COMPLEMENTS"] = edge_type_counts.get("COMPLEMENTS", 0) + 4480

        cat_counts = dict(graph["stats"]["categoryCounts"])
        cat_counts[_REMOTE_GROUP_KEY] = cat_counts.get(_REMOTE_GROUP_KEY, 0) + 1600

        fresh_graph = {
            "vaultPath": graph["vaultPath"],
            "vaultName": graph["vaultName"],
            "hasRemoteTier": True,
            "categories": graph["categories"],
            "epistemicTypes": graph["epistemicTypes"],
            "stats": {
                "totalFiles": local_nodes_count + 1600,
                "wikiNotes": graph["stats"]["wikiNotes"],
                "totalEdges": local_edges_count + 4600,
                "orphanNotes": graph["stats"]["orphanNotes"],
                "categoryCounts": cat_counts,
                "edgeTypeCounts": edge_type_counts,
            },
            "tags": graph["tags"],
            "nodes": [*graph["nodes"], *remote_nodes],
            "edges": fresh_edges,
        }

        harness_js = f"""
const vm = require("vm");
const freshGraph = {json.dumps(fresh_graph)};
const payloadScript = {json.dumps(payload_js)};
const appScript = {json.dumps(app_js)};

class FakeWebGL2RenderingContext {{}}

const elements = new Map();
const rafQueue = [];
let bufSeq = 0;
let boundBuf = null;
let drawCalls = [];
let bufferUploads = [];
let fetchCalls = 0;

const ctx2d = {{
  font: "",
  textAlign: "left",
  textBaseline: "top",
  fillStyle: "",
  strokeStyle: "",
  lineWidth: 1,
  globalAlpha: 1,
  measureText: (s) => ({{ width: String(s || "").length * 6.5 }}),
  save() {{}},
  restore() {{}},
  setTransform() {{}},
  clearRect() {{}},
  fillRect() {{}},
  strokeRect() {{}},
  fillText() {{}},
  beginPath() {{}},
  moveTo() {{}},
  lineTo() {{}},
  stroke() {{}},
  fill() {{}},
  arc() {{}},
  ellipse() {{}},
  translate() {{}},
  rotate() {{}},
}};

const glMock = Object.assign(Object.create(FakeWebGL2RenderingContext.prototype), {{
  LINES: 1,
  POINTS: 0,
  VERTEX_SHADER: 35633,
  FRAGMENT_SHADER: 35632,
  COMPILE_STATUS: 35713,
  LINK_STATUS: 35714,
  COLOR_BUFFER_BIT: 16384,
  BLEND: 3042,
  SRC_ALPHA: 770,
  ONE_MINUS_SRC_ALPHA: 771,
  ARRAY_BUFFER: 34962,
  DYNAMIC_DRAW: 35048,
  FLOAT: 5126,
  createShader() {{ return {{}}; }},
  shaderSource() {{}},
  compileShader() {{}},
  getShaderParameter() {{ return true; }},
  getShaderInfoLog() {{ return ""; }},
  createProgram() {{ return {{}}; }},
  attachShader() {{}},
  linkProgram() {{}},
  getProgramParameter() {{ return true; }},
  getProgramInfoLog() {{ return ""; }},
  createBuffer() {{ return {{ id: ++bufSeq }}; }},
  bindBuffer(_target, buf) {{ boundBuf = buf; }},
  bufferData(_target, data) {{
    const len = data ? data.length : 0;
    const tail = [];
    for (let i = Math.max(0, len - 6); i < len; i++) tail.push(data[i]);
    bufferUploads.push({{
      bufferId: boundBuf ? boundBuf.id : 0,
      length: len,
      lastVal: len > 0 ? data[len - 1] : 0,
      tailFinite: tail.length === 6 && tail.every((v) => Number.isFinite(v)),
    }});
  }},
  viewport() {{}},
  clearColor() {{}},
  clear() {{}},
  enable() {{}},
  blendFunc() {{}},
  useProgram() {{}},
  getAttribLocation() {{ return 0; }},
  getUniformLocation() {{ return {{}}; }},
  enableVertexAttribArray() {{}},
  vertexAttribPointer() {{}},
  uniform1f() {{}},
  drawArrays(mode, first, count) {{
    drawCalls.push({{ mode, first, count }});
  }},
}});

function makeEl(id, tag) {{
  const listeners = new Map();
  const classes = new Set();
  const attrs = new Map();
  const styleStore = {{
    setProperty(k, v) {{ styleStore[k] = v; }},
  }};
  let textVal = "";
  let htmlVal = "";
  const children = [];
  const el = {{
    id: id || "",
    tagName: tag || "DIV",
    width: 1280,
    height: 800,
    value: "",
    checked:
      id === "chk-orphans" ||
      id === "chk-arrows" ||
      id === "chk-plane-local" ||
      id === "chk-plane-ce",
    disabled: false,
    isContentEditable: false,
    children,
    style: styleStore,
    className: "",
    classList: {{
      add: (...c) => c.forEach((x) => classes.add(x)),
      remove: (...c) => c.forEach((x) => classes.delete(x)),
      toggle: (c, force) => {{
        if (force === undefined) {{
          if (classes.has(c)) classes.delete(c);
          else classes.add(c);
        }} else if (force) {{
          classes.add(c);
        }} else {{
          classes.delete(c);
        }}
      }},
      contains: (c) => classes.has(c),
    }},
    get textContent() {{ return textVal; }},
    set textContent(v) {{ textVal = String(v == null ? "" : v); }},
    get innerHTML() {{ return htmlVal; }},
    set innerHTML(v) {{ htmlVal = String(v == null ? "" : v); children.length = 0; }},
    appendChild(ch) {{ children.push(ch); return ch; }},
    remove() {{}},
    setAttribute(k, v) {{ attrs.set(k, String(v)); }},
    getAttribute(k) {{ return attrs.has(k) ? attrs.get(k) : null; }},
    addEventListener(type, fn) {{
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    }},
    dispatchEvent(evt) {{
      const fns = listeners.get(evt.type) || [];
      fns.forEach((fn) => fn.call(el, evt));
    }},
    click() {{
      el.dispatchEvent({{
        type: "click",
        target: el,
        currentTarget: el,
        preventDefault() {{}},
      }});
    }},
    focus() {{}},
    blur() {{}},
    setPointerCapture() {{}},
    querySelector() {{ return null; }},
    querySelectorAll() {{ return []; }},
    getBoundingClientRect() {{
      if (id === "top-bar") {{
        return {{ left: 0, top: 0, right: 1280, bottom: 48, width: 1280, height: 48 }};
      }}
      return {{ left: 0, top: 0, right: 1280, bottom: 800, width: 1280, height: 800 }};
    }},
    getContext(kind) {{
      if (kind === "2d") return ctx2d;
      if ((kind === "webgl2" || kind === "webgl") && id === "gl-canvas") return glMock;
      return null;
    }},
  }};
  return el;
}}

function getEl(id) {{
  if (!elements.has(id)) {{
    elements.set(id, makeEl(id, "DIV"));
  }}
  return elements.get(id);
}}

class FakeResizeObserver {{
  observe() {{}}
  disconnect() {{}}
}}

const doc = {{
  documentElement: makeEl("html", "HTML"),
  activeElement: null,
  getElementById: (id) => getEl(id),
  createElement: (tag) => makeEl("", String(tag || "DIV").toUpperCase()),
  querySelector: () => null,
  querySelectorAll: () => [],
}};

const vmCtx = {{
  document: doc,
  devicePixelRatio: 1,
  addEventListener() {{}},
  removeEventListener() {{}},
  ResizeObserver: FakeResizeObserver,
  WebGL2RenderingContext: FakeWebGL2RenderingContext,
  performance: {{ now: () => 100 }},
  requestAnimationFrame: (cb) => {{
    rafQueue.push(cb);
    return rafQueue.length;
  }},
  setTimeout,
  clearTimeout,
  URL,
  navigator: {{ clipboard: {{ writeText: async () => {{}} }} }},
  alert() {{}},
  console,
  fetch: async (url) => {{
    if (String(url).startsWith("/api/graph?include_")) {{
      fetchCalls++;
      return {{ ok: true, json: async () => freshGraph }};
    }}
    return {{ ok: false, json: async () => null }};
  }},
}};
vmCtx.window = vmCtx;
vmCtx.globalThis = vmCtx;
vmCtx.self = vmCtx;

vm.createContext(vmCtx);
vm.runInContext(payloadScript, vmCtx);
vm.runInContext(appScript, vmCtx);

function runAnimate(ts) {{
  drawCalls = [];
  bufferUploads = [];
  for (let i = rafQueue.length - 1; i >= 0; i--) {{
    const cb = rafQueue[i];
    if (cb && cb.name === "animate") {{
      rafQueue.splice(i, 1);
      cb(ts);
      break;
    }}
  }}
  return {{
    drawCalls: drawCalls.slice(),
    bufferUploads: bufferUploads.slice(),
  }};
}}

async function flushMicrotasks() {{
  for (let i = 0; i < 8; i++) {{
    await new Promise((resolve) => setImmediate(resolve));
  }}
}}

(async () => {{
  const snapshot = (label) => ({{
    label,
    fetchCalls,
    drawerCollapsed: getEl("right-drawer").classList.contains("collapsed"),
    readerBtnActive: getEl("btn-toggle-inspector").classList.contains("active"),
    statsPill: getEl("vault-stats-pill").textContent,
    visibleCounts: getEl("visible-counts").textContent,
    countInbound: getEl("count-inbound").textContent,
    metricIn: getEl("metric-in").textContent,
    inspectorPath: getEl("inspector-path").textContent,
    epistemicHtml: getEl("epistemic-filters").children.map((c) => c.innerHTML).join("|"),
  }});

  const initial = snapshot("initial");
  const toggleBtn = getEl("btn-toggle-ace");

  getEl("btn-close-drawer").click();
  const afterClose = snapshot("afterClose");

  toggleBtn.click();
  const syncOn1 = snapshot("syncOn1");
  await flushMicrotasks();
  const afterOn1 = snapshot("afterOn1");
  const frameOn1 = runAnimate(1000);

  toggleBtn.click();
  await flushMicrotasks();
  const afterOff = snapshot("afterOff");
  const frameOff = runAnimate(2000);

  toggleBtn.click();
  await flushMicrotasks();
  const afterOn2 = snapshot("afterOn2");

  getEl("btn-scope-local").click();
  const afterLocalScope = snapshot("afterLocalScope");
  getEl("btn-scope-global").click();

  getEl("search-input").value = "Concept 10";
  getEl("search-input").dispatchEvent({{ type: "input" }});
  getEl("search-results").children[0].click();
  const afterSelectRemote = snapshot("afterSelectRemote");

  getEl("btn-toggle-inspector").click();
  toggleBtn.click();
  await flushMicrotasks();
  const afterRemoteOff = snapshot("afterRemoteOff");

  console.log(JSON.stringify({{
    initial,
    afterClose,
    syncOn1,
    afterOn1,
    frameOn1,
    afterOff,
    frameOff,
    afterOn2,
    afterLocalScope,
    afterSelectRemote,
    afterRemoteOff,
  }}));
}})().catch((err) => {{
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
}});
"""
        harness_path = self._tmp_dir / "verify_graph_runtime.js"
        harness_path.write_text(harness_js, encoding="utf-8")
        proc = subprocess.run(
            [str(node_bin), str(harness_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"Node VM harness failed (rc={proc.returncode}):\nSTDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}",
        )
        res = json.loads(proc.stdout)

        init_s = res["initial"]
        close_s = res["afterClose"]
        sync_on1_s = res["syncOn1"]
        on1_s = res["afterOn1"]
        off_s = res["afterOff"]
        on2_s = res["afterOn2"]
        local_scope_s = res["afterLocalScope"]
        select_remote_s = res["afterSelectRemote"]
        remote_off_s = res["afterRemoteOff"]

        self.assertEqual(init_s["inspectorPath"], "index.md")
        self.assertFalse(init_s["drawerCollapsed"])
        self.assertTrue(init_s["readerBtnActive"])
        self.assertEqual(init_s["fetchCalls"], 0)
        self.assertIn(f"{local_edges_count} Links", init_s["statsPill"])
        self.assertEqual(init_s["visibleCounts"], f"{local_nodes_count} Nodes / {local_edges_count} Edges")
        self.assertEqual(int(init_s["countInbound"]), local_inbound_index)
        self.assertEqual(int(init_s["metricIn"]), local_inbound_index)

        # Closing the reader drawer leaves it collapsed until explicit inspection
        self.assertTrue(close_s["drawerCollapsed"])
        self.assertFalse(close_s["readerBtnActive"])

        # After lazy remote ON (sync + async merge): stats & counts update, drawer stays closed
        self.assertTrue(sync_on1_s["drawerCollapsed"])
        self.assertFalse(sync_on1_s["readerBtnActive"])
        self.assertTrue(on1_s["drawerCollapsed"])
        self.assertFalse(on1_s["readerBtnActive"])
        self.assertEqual(on1_s["fetchCalls"], 1)
        self.assertIn(f"{local_edges_count + 4600} Links", on1_s["statsPill"])
        expected_on_nodes = local_nodes_count + 1600
        expected_on_edges = local_edges_count + 4600
        self.assertEqual(
            on1_s["visibleCounts"],
            f"{expected_on_nodes} Nodes / {expected_on_edges} Edges",
        )
        self.assertEqual(int(on1_s["countInbound"]), local_inbound_index + 120)
        self.assertEqual(int(on1_s["metricIn"]), local_inbound_index + 120)
        self.assertEqual(on1_s["epistemicHtml"].count("LINKS_TO"), 1)
        self.assertIn(f">{edge_type_counts['LINKS_TO']}<", on1_s["epistemicHtml"])

        line_draws_on = [d for d in res["frameOn1"]["drawCalls"] if d["mode"] == 1]
        point_draws_on = [d for d in res["frameOn1"]["drawCalls"] if d["mode"] == 0]
        self.assertEqual(len(line_draws_on), 1)
        self.assertGreaterEqual(line_draws_on[0]["count"], 9200)
        self.assertEqual(len(point_draws_on), 1)
        self.assertEqual(point_draws_on[0]["count"], expected_on_nodes)

        edge_uploads_on = [u for u in res["frameOn1"]["bufferUploads"] if u["bufferId"] == 1]
        node_uploads_on = [u for u in res["frameOn1"]["bufferUploads"] if u["bufferId"] == 2]
        self.assertEqual(len(edge_uploads_on), 1)
        self.assertEqual(edge_uploads_on[0]["length"], expected_on_edges * 12)
        self.assertTrue(edge_uploads_on[0]["tailFinite"])
        self.assertGreater(edge_uploads_on[0]["lastVal"], 0.0)
        self.assertEqual(len(node_uploads_on), 1)
        self.assertEqual(node_uploads_on[0]["length"], expected_on_nodes * 8)

        # After toggling OFF: reverts to local stats & inbound counts, hides remote nodes/edges, drawer stays closed
        self.assertTrue(off_s["drawerCollapsed"])
        self.assertFalse(off_s["readerBtnActive"])
        self.assertIn(f"{local_edges_count} Links", off_s["statsPill"])
        self.assertEqual(off_s["visibleCounts"], f"{local_nodes_count} Nodes / {local_edges_count} Edges")
        self.assertEqual(int(off_s["countInbound"]), local_inbound_index)
        self.assertEqual(int(off_s["metricIn"]), local_inbound_index)
        line_draws_off = [d for d in res["frameOff"]["drawCalls"] if d["mode"] == 1]
        if line_draws_off:
            self.assertEqual(line_draws_off[0]["count"], local_edges_count * 2)

        # Second toggle ON and local scope toggle: zero extra fetches, drawer stays closed
        self.assertEqual(on2_s["fetchCalls"], 1)
        self.assertEqual(on2_s["visibleCounts"], on1_s["visibleCounts"])
        self.assertEqual(on2_s["statsPill"], on1_s["statsPill"])
        self.assertTrue(on2_s["drawerCollapsed"])
        self.assertFalse(on2_s["readerBtnActive"])
        self.assertTrue(local_scope_s["drawerCollapsed"])
        self.assertFalse(local_scope_s["readerBtnActive"])

        # Explicit selection of a remote node opens the drawer, and closing + toggling OFF falls back quietly
        self.assertFalse(select_remote_s["drawerCollapsed"])
        self.assertTrue(select_remote_s["readerBtnActive"])
        self.assertEqual(select_remote_s["inspectorPath"], "remote://l0/concept-10")
        self.assertTrue(remote_off_s["drawerCollapsed"])
        self.assertFalse(remote_off_s["readerBtnActive"])
        self.assertEqual(remote_off_s["inspectorPath"], "index.md")
        self.assertEqual(remote_off_s["visibleCounts"], f"{local_nodes_count} Nodes / {local_edges_count} Edges")

    def test_promote_modal_executes_without_reference_error_and_shows_published_state(
        self,
    ) -> None:
        """Promote modal resolves lazy markdown without ReferenceError and renders published badge."""
        node_bin = _find_node_binary()
        self.assertIsNotNone(
            node_bin,
            "Node binary is required to verify promote modal JS behavior.",
        )
        assert node_bin is not None

        vault = self._tmp_dir / "PromoteModalVault"
        init_vault.init_vault(vault)
        patterns = self._tmp_dir / "PromoteModalPatterns"
        (patterns / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
        (patterns / "wiki" / "concepts" / "Sample Shared Pattern.md").write_text(
            "---\n"
            "title: Sample Shared Pattern\n"
            "type: concept\n"
            "status: stable\n"
            "---\n\n"
            "# Sample Shared Pattern\n\n"
            "Reusable architecture pattern.\n",
            encoding="utf-8",
        )
        graph = vault_graph.build_vault_graph(
            vault,
            ce_patterns_root=patterns,
            **{_REMOTE_PARAM_NAME: False},
        )
        graph["hasRemoteTier"] = True
        pat_node = next(
            nd for nd in graph["nodes"] if nd.get("sourcePlane") == "ce_patterns"
        )
        pat_node["canPromoteToAce"] = True
        pat_node["remotePublished"] = True
        pat_node["remoteConceptId"] = "architectures/sample-shared-pattern"
        pat_node["remoteConceptUid"] = "cid_test01"
        pat_node["remoteCohort"] = "bundle_export"
        pat_node["remoteRevision"] = 1

        slim_graph = vault_graph._build_slim_graph_dict(graph)
        html_out = vault_graph.render_graph_html(slim_graph, sidecar_mode=False)
        scripts = re.findall(r"<script(?:\s+[^>]*)?>([\s\S]*?)</script>", html_out)
        self.assertEqual(len(scripts), 2)
        payload_js, app_js = scripts[0], scripts[1]

        harness_js = f"""
const vm = require("vm");
const payloadScript = {json.dumps(payload_js)};
const appScript = {json.dumps(app_js)};
const elements = new Map();
const fetchLog = [];

function makeEl(id, tag) {{
  const listeners = new Map();
  const classes = new Set();
  const attrs = new Map();
  const styleStore = {{ setProperty(k, v) {{ styleStore[k] = v; }} }};
  let textVal = "";
  let htmlVal = "";
  const children = [];
  const el = {{
    id: id || "",
    tagName: tag || "DIV",
    width: 1280,
    height: 800,
    value: "",
    title: "",
    checked: true,
    disabled: false,
    isContentEditable: false,
    children,
    style: styleStore,
    className: "",
    classList: {{
      add: (...c) => c.forEach((x) => classes.add(x)),
      remove: (...c) => c.forEach((x) => classes.delete(x)),
      toggle: (c, force) => {{
        if (force === undefined) {{
          if (classes.has(c)) classes.delete(c);
          else classes.add(c);
        }} else if (force) {{
          classes.add(c);
        }} else {{
          classes.delete(c);
        }}
      }},
      contains: (c) => classes.has(c),
    }},
    get textContent() {{ return textVal; }},
    set textContent(v) {{ textVal = String(v == null ? "" : v); }},
    get innerHTML() {{ return htmlVal; }},
    set innerHTML(v) {{ htmlVal = String(v == null ? "" : v); children.length = 0; }},
    appendChild(ch) {{ children.push(ch); return ch; }},
    remove() {{}},
    setAttribute(k, v) {{ attrs.set(k, String(v)); }},
    getAttribute(k) {{ return attrs.has(k) ? attrs.get(k) : null; }},
    addEventListener(type, fn) {{
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    }},
    dispatchEvent(evt) {{
      const fns = listeners.get(evt.type) || [];
      return Promise.all(fns.map((fn) => fn.call(el, evt)));
    }},
    click() {{
      return el.dispatchEvent({{
        type: "click",
        target: el,
        currentTarget: el,
        preventDefault() {{}},
      }});
    }},
    focus() {{}},
    blur() {{}},
    setPointerCapture() {{}},
    querySelector() {{ return null; }},
    querySelectorAll() {{ return []; }},
    getBoundingClientRect() {{
      return {{ left: 0, top: 0, right: 1280, bottom: 800, width: 1280, height: 800 }};
    }},
    getContext(kind) {{
      if (kind === "2d") {{
        return {{
          font: "", textAlign: "left", textBaseline: "top",
          measureText: (s) => ({{ width: String(s || "").length * 6.5 }}),
          save() {{}}, restore() {{}}, setTransform() {{}}, clearRect() {{}},
          fillRect() {{}}, strokeRect() {{}}, fillText() {{}}, beginPath() {{}},
          moveTo() {{}}, lineTo() {{}}, stroke() {{}}, fill() {{}}, arc() {{}},
          ellipse() {{}}, translate() {{}}, rotate() {{}},
        }};
      }}
      return null;
    }},
  }};
  return el;
}}
function getEl(id) {{
  if (!elements.has(id)) elements.set(id, makeEl(id, "DIV"));
  return elements.get(id);
}}

const vmCtx = {{
  document: {{
    documentElement: makeEl("html", "HTML"),
    activeElement: null,
    getElementById: getEl,
    createElement: (t) => makeEl("", t),
    querySelector: () => null,
    querySelectorAll: () => [],
  }},
  devicePixelRatio: 1,
  addEventListener() {{}},
  removeEventListener() {{}},
  ResizeObserver: class {{ observe() {{}} disconnect() {{}} }},
  performance: {{ now: () => 100 }},
  requestAnimationFrame: () => 1,
  setTimeout,
  clearTimeout,
  URL,
  navigator: {{ clipboard: {{ writeText: async () => {{}} }} }},
  alert(msg) {{ throw new Error("Unexpected alert: " + msg); }},
  console,
  fetch: async (url) => {{
    const u = String(url);
    fetchLog.push(u);
    if (u.startsWith("/api/note?")) {{
      return {{
        ok: true,
        json: async () => ({{ markdown: "# Sample Shared Pattern\\n\\nBody." }}),
      }};
    }}
    if (u.includes("-promote")) {{
      return {{
        ok: true,
        json: async () => ({{
          passed_all_gates: true,
          already_published: true,
          published_receipt: {{
            concept_id: "architectures/sample-shared-pattern",
            concept_uid: "cid_test01",
            cohort: "bundle_export",
            revision_number: 1,
          }},
          gates: {{
            gate_1_ontology: "PASSED (OKF v0.2)",
            gate_2_isolation: "PASSED (isolated)",
            gate_3_dlp_firewall: "PASSED (0 hits)",
            gate_4_link_allowlist: "PASSED (allowlist)",
          }},
          candidate_submission: {{
            id: "00000000-0000-0000-0000-000000000001",
            default_id: "sample-shared-pattern",
            content: "# Sample Shared Pattern",
          }},
        }}),
      }};
    }}
    return {{ ok: false, json: async () => null }};
  }},
}};
vmCtx.window = vmCtx;
vmCtx.globalThis = vmCtx;
vmCtx.self = vmCtx;
vm.createContext(vmCtx);
vm.runInContext(payloadScript, vmCtx);
vm.runInContext(appScript, vmCtx);

(async () => {{
  getEl("search-input").value = "Sample Shared Pattern";
  getEl("search-input").dispatchEvent({{ type: "input" }});
  const srChildren = getEl("search-results").children;
  if (!srChildren.length) throw new Error("Expected search result for Sample Shared Pattern");
  await srChildren[0].click();
  await new Promise((r) => setTimeout(r, 40));
  const btn = getEl("btn-promote-ace-drawer");
  const btnText = btn.textContent;
  const hasPubClass = btn.classList.contains("published");
  await btn.click();
  await new Promise((r) => setTimeout(r, 80));
  const modalHtml = getEl("modal-promote-body").innerHTML;
  console.log(JSON.stringify({{ btnText, hasPubClass, modalHtml, fetchLog }}));
}})().catch((err) => {{
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
}});
"""
        harness_path = self._tmp_dir / "verify_promote_modal.js"
        harness_path.write_text(harness_js, encoding="utf-8")
        proc = subprocess.run(
            [str(node_bin), str(harness_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"Node promote modal VM test failed:\nSTDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}",
        )
        res = json.loads(proc.stdout)
        self.assertIn("(cid_test01)", res["btnText"])
        self.assertTrue(res["hasPubClass"])
        self.assertNotIn("Running 4-Gate", res["modalHtml"])
        self.assertIn("Already Published in", res["modalHtml"])
        self.assertIn("cid_test01", res["modalHtml"])
        self.assertIn("Gate 1 (Source Isolation)", res["modalHtml"])
        self.assertTrue(any(u.startswith("/api/note?") for u in res["fetchLog"]))

    def test_reader_renders_inline_svg_mermaid_tables_and_lightbox(self) -> None:
        """Reader renders zero-CDN inline SVG Mermaid diagrams, GFM tables, XSS guards, and lightbox."""
        node_bin = _find_node_binary()
        self.assertIsNotNone(
            node_bin,
            "Node binary is required to verify reader Mermaid and table rendering.",
        )
        assert node_bin is not None

        vault = self._tmp_dir / "MermaidReaderVault"
        init_vault.init_vault(vault)
        self._create_note(
            vault,
            "wiki/concepts/Alpha Concept.md",
            "---\ntitle: Alpha Concept\ntype: concept\nstatus: stable\n---\n# Alpha Concept\n\nTarget note body.\n",
        )
        sample_md = (
            "---\n"
            "title: WikiSkill Flowchart Sample\n"
            "type: source-summary\n"
            "status: stable\n"
            "---\n\n"
            "# WikiSkill Architecture\n\n"
            "```mermaid\n"
            "flowchart TD\n"
            '    subgraph RawLayer ["Layer 1: Raw Layer (Immutable Traces)"]\n'
            '        Traces["Execution Traces τ_i<br>(x_i, o_0, a_0, ..., y_i)"]\n'
            "    end\n"
            '    subgraph WikiLayer ["Layer 2: Persistent Wiki Layer (LLM-Maintained)"]\n'
            '        IndexMD["wiki/index.md (Index)"]\n'
            '        Patterns["wiki/patterns/*.md (Error & Strategy Patterns)"]\n'
            '        LogsMD["wiki/logs.md (Evolution History)"]\n'
            '        ImpactMD["wiki/skill-impact.md (Diffs, Scores & Rejections)"]\n'
            "    end\n"
            '    subgraph SkillLayer ["Layer 3: Executable Skills Layer"]\n'
            '        PurposeMD["skills/PURPOSE.md (Pattern Mappings)"]\n'
            '        ActiveSkills["skills/*.md (Modular Procedural Skills)"]\n'
            "    end\n"
            '    subgraph Agents ["Evolutionary Agents"]\n'
            '        InfAgent["Inference Agent M_I<br>(Isolated from Wiki during Rollouts)"]\n'
            '        Maintainer["Wiki Maintainer M_W<br>(Extracts Patterns & Updates Wiki)"]\n'
            '        Proposer["Skill Proposer M_P<br>(ReAct Agent Synthesizes Skill Diffs)"]\n'
            '        Gate["Validation Gating & Rollback<br>(R_val > R_best)"]\n'
            "    end\n"
            "    ActiveSkills --> InfAgent\n"
            "    InfAgent -->|Task Rollouts| Traces\n"
            "    Traces --> Maintainer\n"
            "    Maintainer -->|Compiles & Updates| Patterns\n"
            "    Maintainer -->|Appends| LogsMD\n"
            "    IndexMD --> Proposer\n"
            "    ImpactMD --> Proposer\n"
            "    Patterns -. Read on demand .-> Proposer\n"
            "    Traces -. Read on demand .-> Proposer\n"
            "    Proposer -->|Atomic Proposal P_k| Gate\n"
            "    Gate -->|Accepted: Keep S_k| ActiveSkills\n"
            "    Gate -->|Rejected: Rollback S_k-1| ActiveSkills\n"
            "    Gate -->|Audit Trail: Never Rolled Back| ImpactMD\n"
            "```\n\n"
            "```mermaid\n"
            "sequenceDiagram\n"
            "    autonumber\n"
            "    participant Client as Client App\n"
            "    participant Server as Agent Server\n"
            "    Note over Client,Server: Initial Discovery\n"
            "    loop Async Stream\n"
            "        Client->>Server: Request payload\n"
            "        Server-->>Client: Status update\n"
            "    end\n"
            "    Server->>Server: Validate schema\n"
            "```\n\n"
            "```mermaid\n"
            "pie title Task Breakdown\n"
            '    "Success" : 75\n'
            '    "Retry" : 25\n'
            "```\n\n"
            "```mermaid\n"
            "gantt\n"
            "    title Fallback Gantt\n"
            "    section Plan\n"
            "    Phase 1 :a1, 2026-01-01, 5d\n"
            "```\n\n"
            "| Model | Score | Link |\n"
            "| :--- | ---: | :--- |\n"
            "| **Flash** | `68.1%` | [[Alpha Concept|Alpha]] |\n"
            '| XSS | 0% | <img src=x onerror=alert(1)> |\n\n'
            "```mermaid\n"
            "flowchart LR\n"
            '    EvilA["<img src=x onerror=alert(1)>"] -->|\"><script>evil()</script>| EvilB["Clean"]\n'
            "```\n"
        )
        self._create_note(
            vault,
            "wiki/sources/Sample Mermaid Source.md",
            sample_md,
        )

        graph = vault_graph.build_vault_graph(vault, **{_REMOTE_PARAM_NAME: False})
        html_out = vault_graph.render_graph_html(graph, sidecar_mode=False)
        scripts = re.findall(r"<script(?:\s+[^>]*)?>([\s\S]*?)</script>", html_out)
        self.assertEqual(len(scripts), 2)
        payload_js, app_js = scripts[0], scripts[1]

        harness_js = f"""
const vm = require("vm");
const payloadScript = {json.dumps(payload_js)};
const appScript = {json.dumps(app_js)};
const elements = new Map();

function buildPseudoChildren(htmlStr) {{
  const wlEls = [];
  const expandBtns = [];
  const viewports = [];
  const wlRe = /<a class="md-wikilink" data-wikilink="([^"]*)">/g;
  let wm;
  while ((wm = wlRe.exec(htmlStr)) !== null) {{
    const attrVal = wm[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
    const aListeners = new Map();
    wlEls.push({{
      getAttribute: (k) => (k === "data-wikilink" ? attrVal : null),
      addEventListener: (t, fn) => {{
        if (!aListeners.has(t)) aListeners.set(t, []);
        aListeners.get(t).push(fn);
      }},
      click: () => Promise.all((aListeners.get("click") || []).map((fn) => fn({{ preventDefault() {{}} }}))),
    }});
  }}
  const cardRe = /<div class="md-mermaid-card" data-mermaid-uid="([^"]*)">[\\s\\S]*?<div class="md-mermaid-viewport"[^>]*>([\\s\\S]*?)<\\/div>/g;
  let cm;
  while ((cm = cardRe.exec(htmlStr)) !== null) {{
    const uid = cm[1];
    const svgHtml = cm[2];
    const vpEl = {{ innerHTML: svgHtml }};
    const cardEl = {{
      getAttribute: (k) => (k === "data-mermaid-uid" ? uid : null),
      querySelector: (sel) => (sel === ".md-mermaid-viewport" ? vpEl : null),
    }};
    const btnListeners = new Map();
    const btnEl = {{
      closest: (sel) => (sel === ".md-mermaid-card" ? cardEl : null),
      addEventListener: (t, fn) => {{
        if (!btnListeners.has(t)) btnListeners.set(t, []);
        btnListeners.get(t).push(fn);
      }},
      click: () => Promise.all((btnListeners.get("click") || []).map((fn) => fn({{ preventDefault() {{}} }}))),
    }};
    expandBtns.push(btnEl);
    const vpListeners = new Map();
    viewports.push({{
      closest: (sel) => (sel === ".md-mermaid-card" ? cardEl : null),
      addEventListener: (t, fn) => {{
        if (!vpListeners.has(t)) vpListeners.set(t, []);
        vpListeners.get(t).push(fn);
      }},
    }});
  }}
  return {{ wlEls, expandBtns, viewports }};
}}

function makeEl(id, tag) {{
  const listeners = new Map();
  const classes = new Set();
  const attrs = new Map();
  const styleStore = {{ setProperty(k, v) {{ styleStore[k] = v; }} }};
  let textVal = "";
  let htmlVal = "";
  let pseudo = {{ wlEls: [], expandBtns: [], viewports: [] }};
  const children = [];
  const el = {{
    id: id || "",
    tagName: tag || "DIV",
    width: 1280,
    height: 800,
    value: "",
    title: "",
    checked: true,
    disabled: false,
    isContentEditable: false,
    children,
    style: styleStore,
    className: "",
    classList: {{
      add: (...c) => c.forEach((x) => classes.add(x)),
      remove: (...c) => c.forEach((x) => classes.delete(x)),
      toggle: (c, force) => {{
        if (force === undefined) {{
          if (classes.has(c)) classes.delete(c);
          else classes.add(c);
        }} else if (force) {{
          classes.add(c);
        }} else {{
          classes.delete(c);
        }}
      }},
      contains: (c) => classes.has(c),
    }},
    get textContent() {{ return textVal; }},
    set textContent(v) {{ textVal = String(v == null ? "" : v); }},
    get innerHTML() {{ return htmlVal; }},
    set innerHTML(v) {{
      htmlVal = String(v == null ? "" : v);
      children.length = 0;
      if (id === "inspector-markdown") pseudo = buildPseudoChildren(htmlVal);
    }},
    appendChild(ch) {{ children.push(ch); return ch; }},
    remove() {{}},
    setAttribute(k, v) {{ attrs.set(k, String(v)); }},
    getAttribute(k) {{ return attrs.has(k) ? attrs.get(k) : null; }},
    addEventListener(type, fn) {{
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    }},
    dispatchEvent(evt) {{
      const fns = listeners.get(evt.type) || [];
      return Promise.all(fns.map((fn) => fn.call(el, evt)));
    }},
    click() {{
      return el.dispatchEvent({{
        type: "click",
        target: el,
        currentTarget: el,
        preventDefault() {{}},
      }});
    }},
    focus() {{}},
    blur() {{}},
    setPointerCapture() {{}},
    querySelector() {{ return null; }},
    querySelectorAll(sel) {{
      if (sel === ".md-wikilink") return pseudo.wlEls;
      if (sel === ".md-mermaid-expand, .md-mermaid-viewport") return [...pseudo.expandBtns, ...pseudo.viewports];
      return [];
    }},
    getBoundingClientRect() {{
      return {{ left: 0, top: 0, right: 1280, bottom: 800, width: 1280, height: 800 }};
    }},
    getContext(kind) {{
      if (kind === "2d") {{
        return {{
          font: "", textAlign: "left", textBaseline: "top",
          measureText: (s) => ({{ width: String(s || "").length * 6.5 }}),
          save() {{}}, restore() {{}}, setTransform() {{}}, clearRect() {{}},
          fillRect() {{}}, strokeRect() {{}}, fillText() {{}}, beginPath() {{}},
          moveTo() {{}}, lineTo() {{}}, stroke() {{}}, fill() {{}}, arc() {{}},
          ellipse() {{}}, translate() {{}}, rotate() {{}},
        }};
      }}
      return null;
    }},
  }};
  return el;
}}
function getEl(id) {{
  if (!elements.has(id)) elements.set(id, makeEl(id, "DIV"));
  return elements.get(id);
}}

const vmCtx = {{
  document: {{
    documentElement: makeEl("html", "HTML"),
    activeElement: null,
    getElementById: getEl,
    createElement: (t) => makeEl("", t),
    querySelector: () => null,
    querySelectorAll: () => [],
  }},
  devicePixelRatio: 1,
  addEventListener() {{}},
  removeEventListener() {{}},
  ResizeObserver: class {{ observe() {{}} disconnect() {{}} }},
  performance: {{ now: () => 100 }},
  requestAnimationFrame: () => 1,
  setTimeout,
  clearTimeout,
  URL,
  navigator: {{ clipboard: {{ writeText: async () => {{}} }} }},
  alert(msg) {{ throw new Error("Unexpected alert: " + msg); }},
  console,
}};
vmCtx.window = vmCtx;
vmCtx.globalThis = vmCtx;
vmCtx.self = vmCtx;
vm.createContext(vmCtx);
vm.runInContext(payloadScript, vmCtx);
vm.runInContext(appScript, vmCtx);

(async () => {{
  getEl("search-input").value = "Sample Mermaid Source";
  getEl("search-input").dispatchEvent({{ type: "input" }});
  const srChildren = getEl("search-results").children;
  if (!srChildren.length) throw new Error("Expected search result for Sample Mermaid Source");
  await srChildren[0].click();
  await new Promise((r) => setTimeout(r, 30));

  const mdHtml = getEl("inspector-markdown").innerHTML;
  const expandBtns = getEl("inspector-markdown").querySelectorAll(".md-mermaid-expand, .md-mermaid-viewport");
  if (!expandBtns.length) throw new Error("Expected rendered Mermaid expand button");

  await expandBtns[0].click();
  const lbOpen = getEl("mermaid-lightbox-modal").classList.contains("visible");
  const lbHtml = getEl("modal-mermaid-body").innerHTML;
  await getEl("btn-close-mermaid-modal").click();
  const lbClosedAfter = getEl("mermaid-lightbox-modal").classList.contains("visible");

  const wlEls = getEl("inspector-markdown").querySelectorAll(".md-wikilink");
  if (!wlEls.length) throw new Error("Expected wikilink inside table cell");
  await wlEls[0].click();
  const navigatedTitle = getEl("inspector-title").textContent;

  console.log(JSON.stringify({{ mdHtml, lbOpen, lbHtml, lbClosedAfter, navigatedTitle }}));
}})().catch((err) => {{
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
}});
"""
        harness_path = self._tmp_dir / "verify_mermaid_reader.js"
        harness_path.write_text(harness_js, encoding="utf-8")
        proc = subprocess.run(
            [str(node_bin), str(harness_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"Node mermaid reader VM test failed:\nSTDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}",
        )
        res = json.loads(proc.stdout)
        md_html = res["mdHtml"]
        # 1. Zero fallback raw flowchart/sequence/pie blocks outside collapsible View Source details
        self.assertNotIn('<pre class="md-mermaid-fallback"><code>flowchart TD', md_html)
        self.assertNotIn('<pre><code>flowchart TD', md_html.split('<details')[0])
        self.assertNotIn('>Server-<', md_html)
        self.assertIn("aria-label=\"Mermaid Flowchart\"", md_html)
        self.assertIn("aria-label=\"Mermaid Sequence Diagram\"", md_html)
        self.assertIn("aria-label=\"Mermaid Pie Chart\"", md_html)
        # 2. All 4 subgraphs, comparison text, wildcard protection, and edge labels rendered
        for expected in (
            "Layer 1: Raw Layer (Immutable Traces)",
            "Layer 2: Persistent Wiki Layer (LLM-Maintained)",
            "Layer 3: Executable Skills Layer",
            "Evolutionary Agents",
            "wiki/patterns/*.md",
            "skills/*.md",
            "(R_val &gt; R_best)",
            "Task Rollouts",
            "Read on demand",
            "Initial Discovery",
            "Task Breakdown",
        ):
            self.assertIn(expected, md_html)
        self.assertNotIn("<em>.md", md_html)
        # 3. GFM table rendered with alignment, code span, bold, and clickable wikilink
        self.assertIn("<table><thead><tr>", md_html)
        self.assertIn('text-align:right;', md_html)
        self.assertIn("<strong>Flash</strong>", md_html)
        self.assertIn("<code>68.1%</code>", md_html)
        self.assertEqual(res["navigatedTitle"], "Alpha Concept")
        # 4. Strict XSS neutralization & zero SVG2 feDropShadow filters
        self.assertNotIn("<script", md_html.lower())
        self.assertNotIn("<img ", md_html.lower())
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", md_html)
        self.assertIn("&quot;&gt;&lt;script&gt;evil()&lt;/script&gt;", md_html)
        self.assertNotIn("<feDropShadow", md_html)
        # 5. Lightbox modal opens with unique _lb SVG marker ids & closes cleanly
        self.assertTrue(res["lbOpen"])
        self.assertIn("<svg", res["lbHtml"])
        self.assertIn("_lb", res["lbHtml"])
        self.assertFalse(res["lbClosedAfter"])
        # 6. Unsupported gantt gracefully falls back to <pre>
        self.assertIn('<pre class="md-mermaid-fallback"><code>gantt', md_html)

    def test_okf_v03_superseded_by_graph_edge(self) -> None:
        """OKF v0.3 `superseded_by` frontmatter path field emits a SUPERSEDES graph edge."""
        vault = self._tmp_dir / "SupersededEdgeVault"
        init_vault.init_vault(vault, quiet=True)
        self._create_note(
            vault,
            "wiki/concepts/Replacement.md",
            "---\ntitle: Replacement\ntype: concept\nstatus: stable\n---\n# Replacement\n",
        )
        self._create_note(
            vault,
            "wiki/concepts/Legacy.md",
            "---\n"
            "title: Legacy\n"
            "type: concept\n"
            "status: deprecated\n"
            "superseded_by: /wiki/concepts/Replacement.md\n"
            "---\n"
            "# Legacy\n",
        )
        graph = vault_graph.build_vault_graph(vault, ce_patterns_root=self._patterns_dir)
        edge_map = {(e["source"], e["target"]): e["type"] for e in graph["edges"]}
        self.assertEqual(
            edge_map.get(("wiki/concepts/Legacy.md", "wiki/concepts/Replacement.md")),
            "SUPERSEDES",
        )

    def test_fresh_init_vault_relative_markdown_links_and_starter_flag(self) -> None:
        """Fresh init_vault links all 5 anchors via relative Markdown links with 0 orphans and sets isStarterVault."""
        vault = self._tmp_dir / "FreshStarterVault"
        init_vault.init_vault(vault, quiet=True)
        graph = vault_graph.build_vault_graph(
            vault,
            ce_patterns_root=self._patterns_dir,
            has_sample_vault=True,
        )
        self.assertTrue(graph["isStarterVault"])
        self.assertTrue(graph["hasSampleVault"])
        self.assertFalse(graph["isSampleMode"])
        self.assertEqual(graph["stats"]["orphanNotes"], 0)
        edge_pairs = {(e["source"], e["target"]) for e in graph["edges"]}
        self.assertIn(("index.md", "purpose.md"), edge_pairs)
        self.assertIn(("index.md", "wiki/skill-impact.md"), edge_pairs)
        self.assertIn(("index.md", "GEMINI.md"), edge_pairs)
        self.assertIn(("index.md", "log.md"), edge_pairs)

        # Adding one real concept note flips isStarterVault to False and ignores external/escaped links
        self._create_note(
            vault,
            "wiki/concepts/FirstNote.md",
            "---\ntitle: First Note\ntype: concept\nstatus: stable\n---\n"
            "See [Purpose](../purpose.md), [Web](https://example.com/a.md), "
            "[Escape](../../../etc/passwd.md), and `[Ignored](../log.md)`.\n"
            "```markdown\n[Fenced](../GEMINI.md)\n```\n",
        )
        graph2 = vault_graph.build_vault_graph(
            vault,
            ce_patterns_root=self._patterns_dir,
            has_sample_vault=True,
        )
        self.assertFalse(graph2["isStarterVault"])
        edge_pairs2 = {(e["source"], e["target"]) for e in graph2["edges"]}
        self.assertIn(("wiki/concepts/FirstNote.md", "purpose.md"), edge_pairs2)
        self.assertNotIn(("wiki/concepts/FirstNote.md", "log.md"), edge_pairs2)
        self.assertNotIn(("wiki/concepts/FirstNote.md", "GEMINI.md"), edge_pairs2)

    def test_remote_tier_hierarchy_edges_connect_empty_vault_constellation(self) -> None:
        """Multi-tier remote nodes link L3 -> L2 -> L1 -> L0 even when the user's vault has zero concepts."""
        vault = self._tmp_dir / "RemoteHierarchyVault"
        init_vault.init_vault(vault, quiet=True)
        fake_remote_nodes = [
            {
                "id": "remote://l3/root-golden",
                "concept_uid": "cid_l3_001",
                "label": "[L3] Enterprise Agent Golden Path",
                "tier": "L3",
                "source_tier": "tier_1",
                "maturity_score": 0.96,
                "products": ["Cloud Run", "Vertex AI"],
                "tags": ["agents"],
                "excerpt": "L3 root synthesis",
                "markdown": "# L3 Root",
                "epistemic_edges": [],
            },
            {
                "id": "remote://l2/cluster-agents",
                "concept_uid": "cid_l2_001",
                "label": "[L2] Agent Runtime Cluster",
                "tier": "L2",
                "source_tier": "tier_1",
                "maturity_score": 0.92,
                "products": ["Cloud Run"],
                "tags": ["agents"],
                "excerpt": "L2 cluster",
                "markdown": "# L2 Cluster",
                "epistemic_edges": [],
            },
            {
                "id": "remote://l1/product-cloud-run",
                "concept_uid": "cid_l1_001",
                "label": "[L1] Product Slice: Cloud Run",
                "tier": "L1",
                "source_tier": "tier_1",
                "maturity_score": 0.90,
                "products": ["Cloud Run"],
                "tags": ["serverless"],
                "excerpt": "L1 slice",
                "markdown": "# L1 Cloud Run",
                "epistemic_edges": [],
            },
            {
                "id": "remote://l0/cloud-run-sidecar",
                "concept_uid": "cid_l0_001",
                "label": "[L0] Cloud Run Sidecar Auth",
                "tier": "L0",
                "source_tier": "tier_2",
                "maturity_score": 0.85,
                "products": ["Cloud Run"],
                "tags": ["serverless"],
                "excerpt": "L0 concept",
                "markdown": "# L0 Concept",
                "epistemic_edges": [],
            },
        ]
        with mock.patch.object(
            vault_graph,
            _DISCOVER_REMOTE_FN_NAME,
            return_value=fake_remote_nodes,
        ):
            graph = vault_graph.build_vault_graph(
                vault,
                ce_patterns_root=self._patterns_dir,
                **{_REMOTE_PARAM_NAME: True},
            )
        remote_nodes = [n for n in graph["nodes"] if n["group"] == _REMOTE_GROUP_KEY]
        self.assertEqual(len(remote_nodes), 4)
        self.assertTrue(all(n["degree"] > 0 for n in remote_nodes))
        edge_map = {(e["source"], e["target"]): e["type"] for e in graph["edges"]}
        self.assertEqual(
            edge_map.get(("remote://l3/root-golden", "remote://l2/cluster-agents")),
            "EXTENDS",
        )
        self.assertEqual(
            edge_map.get(("remote://l2/cluster-agents", "remote://l1/product-cloud-run")),
            "COMPLEMENTS",
        )
        self.assertEqual(
            edge_map.get(("remote://l0/cloud-run-sidecar", "remote://l1/product-cloud-run")),
            "CORROBORATES",
        )

    def test_sample_vault_readonly_http_endpoints_and_ui_onboarding_switch(self) -> None:
        """Live server exposes read-only /api/graph?source=sample and /api/note?source=sample without mutating user vault."""
        sample_root = vault_graph.resolve_sample_vault_root()
        if sample_root is None:
            self.skipTest("Bundled examples/starter-vault not found")

        vault = self._tmp_dir / "FirstRunUserVault"
        init_vault.init_vault(vault, quiet=True)
        before_files = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*") if p.is_file())

        tok = "tok_sample_preview_guard_0123456789abcdef"
        handler_cls = vault_graph.create_graph_request_handler(
            vault_root=vault,
            port=0,
            sidecar_mode=True,
            ui_token=tok,
            cache=vault_graph.VaultGraphCache(max_entries=6),
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # 1. Unauthenticated /api/graph?source=sample is rejected (401 in sidecar mode)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/api/graph?source=sample&slim=1")
            unauth = conn.getresponse()
            unauth.read()
            self.assertEqual(unauth.status, 401)

            headers = {"X-Sidecar-Token": tok, "X-KC-Request": "1"}
            # 2. Initial HTML reflects fresh starter vault with sample toggle available
            conn.request("GET", "/", headers=headers)
            resp_html = conn.getresponse()
            html_doc = resp_html.read().decode("utf-8")
            self.assertEqual(resp_html.status, 200)
            self.assertIn('"isStarterVault": true', html_doc)
            self.assertIn('"hasSampleVault": true', html_doc)
            self.assertIn('id="onboarding-card"', html_doc)
            self.assertIn('id="btn-toggle-sample"', html_doc)

            # 3. GET /api/graph?source=sample&slim=1 returns 26-node, 257-edge clean-room sample vault
            conn.request("GET", "/api/graph?source=sample&slim=1", headers=headers)
            resp_sample = conn.getresponse()
            sample_payload = json.loads(resp_sample.read().decode("utf-8"))
            self.assertEqual(resp_sample.status, 200)
            self.assertTrue(sample_payload["isSampleMode"])
            self.assertFalse(sample_payload["isStarterVault"])
            self.assertGreaterEqual(len(sample_payload["nodes"]), 26)
            self.assertGreaterEqual(sample_payload["stats"]["totalEdges"], 250)
            self.assertEqual(sample_payload["stats"]["orphanNotes"], 0)
            self.assertTrue(all(n.get("lazyMarkdown") for n in sample_payload["nodes"]))

            # 4. GET /api/note?source=sample&id=... returns full Markdown including Mermaid block
            showcase_id = "wiki/synthesis/Google Cloud Serverless Analytics Reference.md"
            conn.request(
                "GET",
                f"/api/note?id={vault_graph.urllib.parse.quote(showcase_id)}&source=sample",
                headers=headers,
            )
            resp_note = conn.getresponse()
            note_payload = json.loads(resp_note.read().decode("utf-8"))
            self.assertEqual(resp_note.status, 200)
            self.assertEqual(note_payload["id"], showcase_id)
            self.assertIn("```mermaid", note_payload["markdown"])

            # 5. GET /api/graph?source=vault&slim=1 returns the user's untouched 6-node vault (incl. wiki/index.md)
            conn.request("GET", "/api/graph?source=vault&slim=1", headers=headers)
            resp_user = conn.getresponse()
            user_payload = json.loads(resp_user.read().decode("utf-8"))
            self.assertEqual(resp_user.status, 200)
            self.assertFalse(user_payload["isSampleMode"])
            self.assertTrue(user_payload["isStarterVault"])
            self.assertEqual(len(user_payload["nodes"]), 6)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()

        # Verify zero files were written into the user's personal vault
        after_files = sorted(p.relative_to(vault).as_posix() for p in vault.rglob("*") if p.is_file())
        self.assertEqual(before_files, after_files)

        # 6. Browser DOM VM verification of onboarding card -> Sample Vault -> Back to My Vault
        node_bin = _find_node_binary()
        if node_bin is None:
            return

        scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", html_doc)
        payload_js = next(s for s in scripts if "INITIAL_GRAPH_DATA" in s)
        app_js = next(s for s in scripts if "replaceGraphDataset" in s)

        harness_js = f"""
const vm = require("vm");
const payloadScript = {json.dumps(payload_js)};
const appScript = {json.dumps(app_js)};
const samplePayload = {json.dumps(sample_payload)};
const userPayload = {json.dumps(user_payload)};
const notePayload = {json.dumps(note_payload)};
const fetchedUrls = [];

const elements = new Map();
function makeClassList() {{
  const set = new Set();
  return {{
    add: (...cs) => cs.forEach(c => set.add(c)),
    remove: (...cs) => cs.forEach(c => set.delete(c)),
    contains: (c) => set.has(c),
    toggle: (c, force) => {{
      if (typeof force === "boolean") {{
        if (force) set.add(c); else set.delete(c);
        return force;
      }}
      if (set.has(c)) {{ set.delete(c); return false; }}
      set.add(c); return true;
    }},
  }};
}}
function makeEl(id, tag = "DIV") {{
  const listeners = new Map();
  const el = {{
    id,
    tagName: tag,
    value: "",
    checked: false,
    disabled: false,
    style: {{ setProperty() {{}} }},
    classList: makeClassList(),
    children: [],
    textContent: "",
    innerHTML: "",
    width: 1200,
    height: 800,
    getBoundingClientRect: () => ({{ left: 0, top: 0, width: 1200, height: 800, bottom: 56 }}),
    getContext: (kind) => kind === "2d" ? ({{
      save() {{}}, restore() {{}}, scale() {{}}, clearRect() {{}}, beginPath() {{}},
      moveTo() {{}}, lineTo() {{}}, arc() {{}}, ellipse() {{}}, stroke() {{}}, fill() {{}},
      translate() {{}}, rotate() {{}}, fillText() {{}}, strokeText() {{}}, setLineDash() {{}},
      measureText: (t) => ({{ width: String(t || "").length * 7 }}),
      fillRect() {{}},
    }}) : null,
    appendChild(child) {{ this.children.push(child); return child; }},
    addEventListener(ev, fn) {{
      if (!listeners.has(ev)) listeners.set(ev, []);
      listeners.get(ev).push(fn);
    }},
    dispatchEvent(ev) {{
      const fns = listeners.get(ev.type) || [];
      fns.forEach(fn => fn(ev));
    }},
    click() {{ this.dispatchEvent({{ type: "click", preventDefault() {{}}, stopPropagation() {{}} }}); }},
    querySelector: () => null,
    querySelectorAll: () => [],
    getAttribute: () => "",
  }};
  return el;
}}
function getEl(id) {{
  if (!elements.has(id)) elements.set(id, makeEl(id, "DIV"));
  return elements.get(id);
}}

const vmCtx = {{
  document: {{
    documentElement: makeEl("html", "HTML"),
    activeElement: null,
    getElementById: getEl,
    createElement: (t) => makeEl("", t),
    querySelector: () => null,
    querySelectorAll: () => [],
  }},
  devicePixelRatio: 1,
  addEventListener() {{}},
  removeEventListener() {{}},
  ResizeObserver: class {{ observe() {{}} disconnect() {{}} }},
  performance: {{ now: () => 100 }},
  requestAnimationFrame: () => 1,
  setTimeout,
  clearTimeout,
  URL,
  Headers: class {{ constructor() {{}} has() {{ return false; }} set() {{}} }},
  fetch: async (url) => {{
    fetchedUrls.push(String(url));
    if (String(url).includes("/api/graph?source=sample")) {{
      return {{ ok: true, json: async () => JSON.parse(JSON.stringify(samplePayload)) }};
    }}
    if (String(url).includes("/api/graph?source=vault")) {{
      return {{ ok: true, json: async () => JSON.parse(JSON.stringify(userPayload)) }};
    }}
    if (String(url).includes("/api/note?") && String(url).includes("source=sample")) {{
      return {{ ok: true, json: async () => JSON.parse(JSON.stringify(notePayload)) }};
    }}
    return {{ ok: false, json: async () => ({{}}) }};
  }},
  navigator: {{ clipboard: {{ writeText: async () => {{}} }} }},
  alert(msg) {{ throw new Error("Unexpected alert: " + msg); }},
  console,
}};
vmCtx.window = vmCtx;
vmCtx.globalThis = vmCtx;
vmCtx.self = vmCtx;
vm.createContext(vmCtx);
vm.runInContext(payloadScript, vmCtx);
vm.runInContext(appScript, vmCtx);

(async () => {{
  const initialOnboardVisible = getEl("onboarding-card").classList.contains("visible");
  const initialDrawerCollapsed = getEl("right-drawer").classList.contains("collapsed");
  const initialSampleBtnDisplay = getEl("btn-toggle-sample").style.display;

  getEl("btn-onboard-sample").click();
  await new Promise(r => setTimeout(r, 40));

  const sampleBannerVisible = getEl("sample-mode-banner").classList.contains("visible");
  const sampleOnboardVisible = getEl("onboarding-card").classList.contains("visible");
  const sampleStatsText = getEl("vault-stats-pill").textContent;
  const sampleTitle = getEl("vault-title").textContent;
  const sampleDrawerCollapsed = getEl("right-drawer").classList.contains("collapsed");
  const sampleMdHtml = getEl("inspector-markdown").innerHTML;

  getEl("btn-return-my-vault").click();
  await new Promise(r => setTimeout(r, 40));

  const backBannerVisible = getEl("sample-mode-banner").classList.contains("visible");
  const backOnboardVisible = getEl("onboarding-card").classList.contains("visible");
  const backStatsText = getEl("vault-stats-pill").textContent;

  console.log(JSON.stringify({{
    initialOnboardVisible,
    initialDrawerCollapsed,
    initialSampleBtnDisplay,
    sampleBannerVisible,
    sampleOnboardVisible,
    sampleStatsText,
    sampleTitle,
    sampleDrawerCollapsed,
    hasMermaidSvg: sampleMdHtml.includes("Mermaid"),
    backBannerVisible,
    backOnboardVisible,
    backStatsText,
    fetchedUrls,
  }}));
}})().catch((err) => {{
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
}});
"""
        harness_path = self._tmp_dir / "verify_sample_onboarding.js"
        harness_path.write_text(harness_js, encoding="utf-8")
        proc = subprocess.run(
            [str(node_bin), str(harness_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"Node onboarding VM test failed:\nSTDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}",
        )
        vm_res = json.loads(proc.stdout)
        self.assertTrue(vm_res["initialOnboardVisible"])
        self.assertTrue(vm_res["initialDrawerCollapsed"])
        self.assertEqual(vm_res["initialSampleBtnDisplay"], "inline-block")
        self.assertTrue(vm_res["sampleBannerVisible"])
        self.assertFalse(vm_res["sampleOnboardVisible"])
        self.assertIn("Sample Vault (21 Notes)", vm_res["sampleTitle"])
        self.assertIn("295 Links", vm_res["sampleStatsText"])
        self.assertFalse(vm_res["sampleDrawerCollapsed"])
        self.assertTrue(vm_res["hasMermaidSvg"])
        self.assertFalse(vm_res["backBannerVisible"])
        self.assertTrue(vm_res["backOnboardVisible"])
        self.assertIn("6 Notes", vm_res["backStatsText"])
        self.assertTrue(any("source=sample" in u for u in vm_res["fetchedUrls"]))
        self.assertTrue(any("source=vault" in u for u in vm_res["fetchedUrls"]))

    def test_sample_vault_json_bundle_fallback(self) -> None:
        """Space-free assets/starter_vault.json bundle serves /api/graph?source=sample and /api/note?source=sample when examples/ is absent."""
        sample_root = vault_graph.resolve_sample_vault_root()
        if sample_root is None:
            self.skipTest("Bundled examples/starter-vault not found")

        bundle_out = self._tmp_dir / "assets" / "starter_vault.json"
        res = vault_graph.export_sample_vault_bundle(sample_root, bundle_out)
        self.assertTrue(res["success"])
        self.assertGreaterEqual(res["nodes"], 26)
        self.assertGreaterEqual(res["edges"], 250)
        raw_txt = bundle_out.read_text(encoding="utf-8")
        self.assertNotIn(str(sample_root), raw_txt)

        vault = self._tmp_dir / "BundleFallbackVault"
        init_vault.init_vault(vault, quiet=True)
        tok = "tok_bundle_fallback_guard_0123456789abcdef"
        with (
            mock.patch.object(vault_graph, "resolve_sample_vault_root", return_value=None),
            mock.patch.object(vault_graph, "resolve_sample_vault_bundle", return_value=bundle_out),
        ):
            handler_cls = vault_graph.create_graph_request_handler(
                vault_root=vault,
                port=0,
                sidecar_mode=True,
                ui_token=tok,
                cache=vault_graph.VaultGraphCache(max_entries=6),
            )
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                headers = {"X-Sidecar-Token": tok, "X-KC-Request": "1"}
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("GET", "/api/graph?source=sample&slim=1", headers=headers)
                r1 = conn.getresponse()
                p1 = json.loads(r1.read().decode("utf-8"))
                self.assertEqual(r1.status, 200)
                self.assertTrue(p1["isSampleMode"])
                self.assertGreaterEqual(len(p1["nodes"]), 26)
                self.assertTrue(all(n.get("lazyMarkdown") for n in p1["nodes"]))

                showcase_id = "wiki/synthesis/Google Cloud Serverless Analytics Reference.md"
                conn.request(
                    "GET",
                    f"/api/note?id={vault_graph.urllib.parse.quote(showcase_id)}&source=sample",
                    headers=headers,
                )
                r2 = conn.getresponse()
                p2 = json.loads(r2.read().decode("utf-8"))
                self.assertEqual(r2.status, 200)
                self.assertIn("```mermaid", p2["markdown"])
                conn.close()
            finally:
                server.shutdown()
                server.server_close()

    def test_x_kc_epistemic_edges_subindex_anchor_and_md_link_excerpt(self) -> None:
        """Verify x-kc-* frontmatter edges, legacy compat, wiki/index.md anchor classification, and Markdown link excerpt unwrapping."""
        import vault_query

        vault = self._tmp_dir / "x_kc_graph_vault"
        init_vault.init_vault(vault, quiet=True)
        # Fresh init_vault (with wiki/index.md) must remain a starter vault with wiki/index.md classified as anchor
        fresh_graph = vault_graph.build_vault_graph(
            vault, ce_patterns_root=self._tmp_dir / "no_shared"
        )
        self.assertTrue(fresh_graph["isStarterVault"])
        wiki_idx_node = next(
            (n for n in fresh_graph["nodes"] if n["id"] == "wiki/index.md"), None
        )
        self.assertIsNotNone(wiki_idx_node)
        self.assertEqual(wiki_idx_node["group"], "anchor")

        # Add notes using x-kc-* paths, legacy bare keys, and inline rel::[Label](path.md)
        (vault / "wiki" / "concepts" / "Target Concept.md").write_text(
            "---\ntitle: Target Concept\ntype: concept\nstatus: stable\n---\n\n"
            "# Target Concept\n\nTarget body.\n",
            encoding="utf-8",
        )
        (vault / "wiki" / "concepts" / "Legacy Concept.md").write_text(
            "---\ntitle: Legacy Concept\ntype: concept\nstatus: stable\n"
            'extends:\n  - "[[Target Concept]]"\n---\n\n'
            "# Legacy Concept\n\nLegacy body.\n",
            encoding="utf-8",
        )
        (vault / "wiki" / "patterns" / "Modern Pattern.md").write_text(
            "---\ntitle: Modern Pattern\ntype: pattern\nstatus: stable\n"
            'x-kc-corroborates:\n  - "/wiki/concepts/Target Concept.md"\n---\n\n'
            "# Modern Pattern\n\n"
            "complements::[Legacy Concept](../concepts/Legacy%20Concept.md) with clean prose.\n",
            encoding="utf-8",
        )

        g = vault_graph.build_vault_graph(
            vault, ce_patterns_root=self._tmp_dir / "no_shared"
        )
        self.assertFalse(g["isStarterVault"])
        edge_map = {(e["source"], e["target"]): e["type"] for e in g["edges"]}
        self.assertEqual(
            edge_map.get(("wiki/patterns/Modern Pattern.md", "wiki/concepts/Target Concept.md")),
            "CORROBORATES",
        )
        self.assertEqual(
            edge_map.get(("wiki/patterns/Modern Pattern.md", "wiki/concepts/Legacy Concept.md")),
            "COMPLEMENTS",
        )
        self.assertEqual(
            edge_map.get(("wiki/concepts/Legacy Concept.md", "wiki/concepts/Target Concept.md")),
            "EXTENDS",
        )

        # Verify Markdown links unwrap cleanly to display labels in both graph & BM25 excerpts
        modern_node = next(
            n for n in g["nodes"] if n["id"] == "wiki/patterns/Modern Pattern.md"
        )
        self.assertIn("Legacy Concept", modern_node["excerpt"])
        self.assertNotIn("../concepts/", modern_node["excerpt"])
        q_excerpt = vault_query._build_plain_excerpt(
            "See [BigQuery](../entities/BigQuery.md) and [Guide](GKE%20Autopilot.md)."
        )
        self.assertIn("BigQuery", q_excerpt)
        self.assertIn("Guide", q_excerpt)
        self.assertNotIn("../entities/", q_excerpt)
        self.assertNotIn("%20", q_excerpt)


if __name__ == "__main__":
    unittest.main()
