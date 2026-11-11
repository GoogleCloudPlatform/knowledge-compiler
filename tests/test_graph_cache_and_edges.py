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
import shutil
import stat
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


if __name__ == "__main__":
    unittest.main()
