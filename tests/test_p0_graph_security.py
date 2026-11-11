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
"""Hermetic P0 security and isolation unit tests for scripts/vault_graph.py."""

from __future__ import annotations

import errno
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
from typing import Any
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import vault_graph  # noqa: E402


def _attr_name(*candidates: str) -> str:
    """Return the first attribute name that exists on vault_graph."""
    for name in candidates:
        if hasattr(vault_graph, name):
            return name
    return candidates[0]


DISCOVER_FN_ATTR = _attr_name(
    "discover_remote_tier_nodes",
    "discover_remote_tier_nodes",
)
PREPARE_FN_ATTR = _attr_name(
    "prepare_pattern_for_remote_tier",
    "prepare_pattern_for_remote_tier",
)
PREFLIGHT_FN_ATTR = _attr_name(
    "run_remote_tier_preflight",
    "run_remote_tier_preflight",
)
SUBMIT_FN_ATTR = _attr_name(
    "submit_to_remote_tier",
    "submit_to_remote_tier",
)
BRIDGE_FLAG_ATTR = _attr_name(
    "HAS_1P_FED_BRIDGE",
    "HAS_1P_FED_BRIDGE",
)


def _create_sample_vault(base_dir: Path) -> tuple[Path, Path]:
    """Create a minimal hermetic vault and patterns directory."""
    vault_dir = base_dir / "vault"
    patterns_dir = base_dir / "patterns"
    (vault_dir / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
    (patterns_dir / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
    (vault_dir / "GEMINI.md").write_text("# Vault\n", encoding="utf-8")
    (vault_dir / "wiki" / "concepts" / "sample.md").write_text(
        "---\n"
        "title: Sample Concept\n"
        "type: concept\n"
        "status: active\n"
        "tags: [security, graph]\n"
        "---\n\n"
        "Sample body linking to [[Other Concept]].\n",
        encoding="utf-8",
    )
    (patterns_dir / "wiki" / "concepts" / "safe.md").write_text(
        "---\n"
        "title: Safe Pattern\n"
        "type: concept\n"
        "status: active\n"
        "---\n\n"
        "Canonical pattern body.\n",
        encoding="utf-8",
    )
    return vault_dir, patterns_dir


class TestP0GraphSecurity(unittest.TestCase):
    """Hermetic unit tests for P0 security, CSP, auth, and isolation in vault_graph.py."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self._isolated_root = Path(self._tmp_ctx.name)
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "HOME": str(self._isolated_root / "home"),
                "XDG_DATA_HOME": str(self._isolated_root / "xdg_data"),
                "XDG_STATE_HOME": str(self._isolated_root / "xdg_state"),
                "PLUGIN_DATA": str(self._isolated_root / "plugin_data"),
            },
            clear=False,
        )
        self._env_patch.start()
        self._tok_patch = mock.patch.object(
            vault_graph,
            "OWNER_TOKEN_PATH",
            self._isolated_root / "plugin_data" / ".vault_graph_token",
        )
        self._tok_patch.start()

    def tearDown(self) -> None:
        self._tok_patch.stop()
        self._env_patch.stop()
        self._tmp_ctx.cleanup()

    def test_render_graph_html_escapes_script_breakout_and_line_separators(self) -> None:
        """P0-1: Stored XSS payloads (</SCRIPT>, <!--, &, U+2028, U+2029) must never break out of <script>."""
        malicious_payload = (
            "</script><script>alert('xss')</script>"
            "</SCRIPT >"
            "<!--<script>evil()</script>-->"
            "&param=1\u2028LINE_SEP\u2029PARA_SEP"
        )
        graph_data: dict[str, Any] = {
            "vaultPath": "/tmp/vault",
            "hasRemoteTier": False,
            "stats": {
                "totalFiles": 1,
                "wikiNotes": 1,
                "totalEdges": 0,
                "orphanNotes": 1,
                "groups": {"concept": 1},
                "planes": {"local_vault": 1},
                "epistemicEdges": {},
            },
            "nodes": [
                {
                    "id": "wiki/concepts/xss.md",
                    "label": malicious_payload,
                    "group": "concept",
                    "type": "concept",
                    "status": "active",
                    "updated": "2026-01-01",
                    "tags": [malicious_payload],
                    "aliases": [],
                    "excerpt": malicious_payload,
                    "markdown": malicious_payload,
                    "inDegree": 0,
                    "outDegree": 0,
                    "degree": 0,
                    "pageRank": 1.0,
                    "isOrphan": True,
                    "x": 0.0,
                    "y": 0.0,
                    "z": 0.0,
                }
            ],
            "edges": [],
        }

        html_out = vault_graph.render_graph_html(
            graph_data, sidecar_mode=False, csp_nonce="test-nonce-xyz"
        )

        self.assertNotIn("</script><script>alert", html_out)
        self.assertNotIn("</SCRIPT >", html_out)
        self.assertNotIn("<!--<script>", html_out)
        self.assertNotIn("\u2028", html_out)
        self.assertNotIn("\u2029", html_out)

        match = re.search(
            r"const INITIAL_GRAPH_DATA = (\{.*?\});\s*</script>",
            html_out,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(
            match, "Expected INITIAL_GRAPH_DATA JSON literal in rendered HTML"
        )
        assert match is not None
        raw_json_literal = match.group(1)
        self.assertIn("\\u003c", raw_json_literal)
        self.assertIn("\\u003e", raw_json_literal)
        self.assertIn("\\u0026", raw_json_literal)
        self.assertIn("\\u2028", raw_json_literal)
        self.assertIn("\\u2029", raw_json_literal)

        parsed = json.loads(raw_json_literal)
        self.assertEqual(parsed["nodes"][0]["label"], malicious_payload)
        self.assertEqual(parsed["nodes"][0]["markdown"], malicious_payload)

    def test_render_graph_html_csp_nonce_no_session_token_no_inline_onclick(self) -> None:
        """P0-1: HTML must use CSP nonces, omit window.__KC_SESSION_TOKEN, and avoid inline onclick attributes."""
        graph_data = {
            "vaultPath": "/tmp/vault",
            "hasRemoteTier": False,
            "stats": {
                "totalFiles": 0,
                "wikiNotes": 0,
                "totalEdges": 0,
                "orphanNotes": 0,
            },
            "nodes": [],
            "edges": [],
        }
        nonce = "strict-nonce-987654321"
        html_with_nonce = vault_graph.render_graph_html(
            graph_data, sidecar_mode=True, csp_nonce=nonce
        )

        self.assertNotIn("__CSP_NONCE__", html_with_nonce)
        self.assertIn(
            f'<script nonce="{nonce}" src="/preload.js"></script>', html_with_nonce
        )
        self.assertIn(f'<script nonce="{nonce}">', html_with_nonce)
        self.assertNotIn("__KC_SESSION_TOKEN", html_with_nonce)
        self.assertIsNone(
            re.search(r"\bonclick\s*=", html_with_nonce, flags=re.IGNORECASE)
        )
        self.assertIn("function sanitizeHttpsUrl(", html_with_nonce)
        self.assertIn('parsed.protocol === "https:"', html_with_nonce)

        html_standalone = vault_graph.render_graph_html(
            graph_data, sidecar_mode=False, csp_nonce=None
        )
        self.assertNotIn("__CSP_NONCE__", html_standalone)
        self.assertNotIn("__KC_SESSION_TOKEN", html_standalone)

    def test_owner_token_hardening_permissions_env_len_and_erofs(self) -> None:
        """P0-1: Owner token creation enforces len>=32, 0600 permissions, UID/mode check, and EROFS fallback."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            token_file = tmp_path / ".vault_graph_token"
            with mock.patch.object(vault_graph, "OWNER_TOKEN_PATH", token_file):
                # 1. Env token shorter than 32 chars must raise ValueError
                with mock.patch.dict(
                    os.environ, {"VAULT_GRAPH_OWNER_TOKEN": "too-short-token"}, clear=False
                ):
                    with self.assertRaisesRegex(ValueError, "at least 32 characters"):
                        vault_graph.get_or_create_owner_token(port=8765)

                # 2. Valid >= 32 char env token is returned directly
                valid_env_tok = "a" * 36
                with mock.patch.dict(
                    os.environ, {"VAULT_GRAPH_OWNER_TOKEN": valid_env_tok}, clear=False
                ):
                    self.assertEqual(
                        vault_graph.get_or_create_owner_token(port=8765), valid_env_tok
                    )

                # 3. Atomic creation with 0600 permissions when env var is unset
                env_without_tok = {
                    k: v
                    for k, v in os.environ.items()
                    if k != "VAULT_GRAPH_OWNER_TOKEN"
                }
                with mock.patch.dict(os.environ, env_without_tok, clear=True):
                    generated_tok = vault_graph.get_or_create_owner_token(port=8765)
                    self.assertGreaterEqual(len(generated_tok), 32)
                    self.assertTrue(token_file.exists())
                    st = os.lstat(token_file)
                    self.assertEqual(st.st_mode & 0o077, 0)
                    self.assertTrue(vault_graph._is_secure_token_file(token_file))

                    # 4. Insecure permissions (0644) must be rejected and rotated back to 0600
                    token_file.write_text("b" * 40 + "\n", encoding="utf-8")
                    os.chmod(token_file, 0o644)
                    self.assertFalse(vault_graph._is_secure_token_file(token_file))
                    rotated_tok = vault_graph.get_or_create_owner_token(port=8765)
                    self.assertNotEqual(rotated_tok, "b" * 40)
                    self.assertEqual(os.lstat(token_file).st_mode & 0o077, 0)

                    # 5. Foreign st_uid must be rejected by _is_secure_token_file
                    fake_stat = os.stat_result(
                        (
                            st.st_mode,
                            st.st_ino,
                            st.st_dev,
                            st.st_nlink,
                            st.st_uid + 1,
                            st.st_gid,
                            st.st_size,
                            st.st_atime,
                            st.st_mtime,
                            st.st_ctime,
                        )
                    )
                    with mock.patch("os.lstat", return_value=fake_stat):
                        self.assertFalse(vault_graph._is_secure_token_file(token_file))

                    # 6. Read-only filesystem (EROFS) falls back to ephemeral token and logs unlock URL to stderr
                    ro_token_file = tmp_path / "ro_dir" / ".vault_graph_token"
                    stderr_capture = io.StringIO()

                    def _raise_erofs(*_args: Any, **_kwargs: Any) -> int:
                        raise OSError(errno.EROFS, "Read-only file system")

                    with (
                        mock.patch.object(vault_graph, "OWNER_TOKEN_PATH", ro_token_file),
                        mock.patch.object(sys, "stderr", stderr_capture),
                        mock.patch("os.open", side_effect=_raise_erofs),
                    ):
                        ephemeral = vault_graph.get_or_create_owner_token(port=9123)
                    self.assertGreaterEqual(len(ephemeral), 32)
                    err_output = stderr_capture.getvalue()
                    self.assertIn(
                        f"http://127.0.0.1:9123/?token={ephemeral}", err_output
                    )

    def test_build_vault_graph_relative_path_ignore_and_symlinks(self) -> None:
        """P0-1: Vault inside notes.github.io or .agents parent path is not skipped; symlinks are ignored."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            parent_dir = tmp_path / "notes.github.io" / ".agents-parent" / "my-vault"
            patterns_dir = tmp_path / "patterns-empty"
            (parent_dir / "wiki" / "concepts").mkdir(parents=True, exist_ok=True)
            (parent_dir / ".git").mkdir(parents=True, exist_ok=True)
            patterns_dir.mkdir(parents=True, exist_ok=True)

            (parent_dir / "GEMINI.md").write_text("# Vault Root\n", encoding="utf-8")
            valid_note = parent_dir / "wiki" / "concepts" / "valid_note.md"
            valid_note.write_text(
                "---\ntitle: Valid Note\ntype: concept\n---\n\nValid content.\n",
                encoding="utf-8",
            )
            (parent_dir / ".git" / "hidden.md").write_text(
                "---\ntitle: Hidden Git Note\n---\n", encoding="utf-8"
            )

            outside_secret = tmp_path / "outside_secret.md"
            outside_secret.write_text(
                "---\ntitle: Outside Secret\n---\n", encoding="utf-8"
            )
            symlink_file = parent_dir / "wiki" / "concepts" / "symlink_note.md"
            symlink_file.symlink_to(outside_secret)

            outside_dir = tmp_path / "outside_dir"
            outside_dir.mkdir(parents=True, exist_ok=True)
            (outside_dir / "escaped.md").write_text(
                "---\ntitle: Escaped\n---\n", encoding="utf-8"
            )
            symlink_dir = parent_dir / "wiki" / "linked_dir"
            symlink_dir.symlink_to(outside_dir, target_is_directory=True)

            graph = vault_graph.build_vault_graph(
                parent_dir, ce_patterns_root=patterns_dir
            )
            node_ids = {n["id"] for n in graph["nodes"]}

            self.assertIn("wiki/concepts/valid_note.md", node_ids)
            self.assertNotIn(".git/hidden.md", node_ids)
            self.assertNotIn("wiki/concepts/symlink_note.md", node_ids)
            self.assertNotIn("wiki/linked_dir/escaped.md", node_ids)

    def test_build_vault_graph_remote_tier_off_by_default_and_has_remote_tier_flag(
        self,
    ) -> None:
        """P0-4b & P0-5a: Remote tier discovery is never called when include flag is False, and hasRemoteTier is exported."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            vault_dir, patterns_dir = _create_sample_vault(tmp_path)
            calls: list[int] = []

            def _fake_discover() -> list[dict[str, Any]]:
                calls.append(1)
                return []

            with (
                mock.patch.dict(
                    os.environ, {"OKF_PATTERNS_PATH": str(patterns_dir)}, clear=False
                ),
                mock.patch.object(vault_graph, DISCOVER_FN_ATTR, _fake_discover),
            ):
                graph_default = vault_graph.build_vault_graph(
                    vault_dir, ce_patterns_root=patterns_dir
                )
                self.assertEqual(len(calls), 0)
                self.assertIn("hasRemoteTier", graph_default)
                self.assertIsInstance(graph_default["hasRemoteTier"], bool)

                include_kw = {
                    "include_remote_tier": True,
                }
                vault_graph.build_vault_graph(
                    vault_dir, ce_patterns_root=patterns_dir, **include_kw
                )
                self.assertEqual(len(calls), 1)

    def test_http_server_cookie_csrf_csp_size_cap_and_note_path_isolation(self) -> None:
        """P0-1, P0-3b, P0-4b: Verify HTTP handler timeout, CSP, cookie CSRF, 413 cap, and server-side notePath isolation."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            vault_dir, patterns_dir = _create_sample_vault(tmp_path)
            discover_calls: list[int] = []

            def _fake_discover() -> list[dict[str, Any]]:
                discover_calls.append(1)
                return []

            owner_token = "t" * 40
            with (
                mock.patch.dict(
                    os.environ, {"OKF_PATTERNS_PATH": str(patterns_dir)}, clear=False
                ),
                mock.patch.object(vault_graph, DISCOVER_FN_ATTR, _fake_discover),
            ):
                handler_cls = vault_graph.create_graph_request_handler(
                    vault_root=vault_dir,
                    port=0,
                    sidecar_mode=False,
                    owner_token=owner_token,
                )
                self.assertEqual(handler_cls.timeout, 10)
                self.assertEqual(handler_cls.MAX_POST_BODY_BYTES, 1_048_576)

                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
                port = server.server_address[1]
                server.RequestHandlerClass = vault_graph.create_graph_request_handler(
                    vault_root=vault_dir,
                    port=port,
                    sidecar_mode=False,
                    owner_token=owner_token,
                )
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()

                try:
                    # 1. Unauthenticated GET / -> 403 + nosniff + CSP
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
                    resp = conn.getresponse()
                    resp.read()
                    self.assertEqual(resp.status, 403)
                    self.assertEqual(
                        resp.getheader("X-Content-Type-Options"), "nosniff"
                    )
                    self.assertIn(
                        "default-src 'none'",
                        resp.getheader("Content-Security-Policy") or "",
                    )
                    conn.close()

                    # 2. Authenticated GET /?token=... -> 200, Set-Cookie, CSP nonce, zero discover calls
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.request(
                        "GET",
                        f"/?token={owner_token}",
                        headers={"Host": f"127.0.0.1:{port}"},
                    )
                    resp = conn.getresponse()
                    html_body = resp.read().decode("utf-8")
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(len(discover_calls), 0)
                    self.assertNotIn("__KC_SESSION_TOKEN", html_body)
                    self.assertEqual(
                        resp.getheader("X-Content-Type-Options"), "nosniff"
                    )
                    csp_hdr = resp.getheader("Content-Security-Policy") or ""
                    self.assertIn(
                        "default-src 'none'; script-src 'self' 'nonce-", csp_hdr
                    )
                    self.assertIn("frame-ancestors 'self'; base-uri 'none'", csp_hdr)
                    set_cookie = resp.getheader("Set-Cookie") or ""
                    self.assertIn(f"kc_owner_token={owner_token}", set_cookie)
                    self.assertIn("Max-Age=604800", set_cookie)
                    self.assertIn("HttpOnly", set_cookie)
                    self.assertIn("SameSite=Strict", set_cookie)
                    conn.close()

                    # 3. GET /api/graph?include_ace=1 -> triggers discovery once
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.request(
                        "GET",
                        "/api/graph?include_ace=1",
                        headers={
                            "Host": f"127.0.0.1:{port}",
                            "Cookie": f"kc_owner_token={owner_token}",
                        },
                    )
                    resp = conn.getresponse()
                    graph_json = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(
                        resp.getheader("X-Content-Type-Options"), "nosniff"
                    )
                    self.assertEqual(len(discover_calls), 1)
                    self.assertIn("hasRemoteTier", graph_json)
                    conn.close()

                    # 4. POST with cookie ONLY (missing X-KC-Request: 1) -> 401 (CSRF blocked)
                    payload = json.dumps({"query": "Sample"}).encode("utf-8")
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.request(
                        "POST",
                        "/api/federated-query",
                        body=payload,
                        headers={
                            "Host": f"127.0.0.1:{port}",
                            "Content-Type": "application/json",
                            "Cookie": f"kc_owner_token={owner_token}",
                        },
                    )
                    resp = conn.getresponse()
                    resp.read()
                    self.assertEqual(resp.status, 401)
                    conn.close()

                    # 5. POST with cookie + X-KC-Request: 1 -> 200
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.request(
                        "POST",
                        "/api/federated-query",
                        body=payload,
                        headers={
                            "Host": f"127.0.0.1:{port}",
                            "Content-Type": "application/json",
                            "Cookie": f"kc_owner_token={owner_token}",
                            "X-KC-Request": "1",
                        },
                    )
                    resp = conn.getresponse()
                    resp.read()
                    self.assertEqual(resp.status, 200)
                    conn.close()

                    # 6. POST with explicit Authorization: Bearer header (CLI/tests) -> 200
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.request(
                        "POST",
                        "/api/federated-query",
                        body=payload,
                        headers={
                            "Host": f"127.0.0.1:{port}",
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {owner_token}",
                        },
                    )
                    resp = conn.getresponse()
                    resp.read()
                    self.assertEqual(resp.status, 200)
                    conn.close()

                    # 7. POST with Content-Length > 1_048_576 -> 413 Payload Too Large
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.putrequest("POST", "/api/federated-query")
                    conn.putheader("Host", f"127.0.0.1:{port}")
                    conn.putheader("Content-Type", "application/json")
                    conn.putheader("Authorization", f"Bearer {owner_token}")
                    conn.putheader("Content-Length", str(1_048_577))
                    conn.endheaders()
                    resp = conn.getresponse()
                    resp.read()
                    self.assertEqual(resp.status, 413)
                    conn.close()

                    # 8. POST with negative Content-Length -> 413
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.putrequest("POST", "/api/federated-query")
                    conn.putheader("Host", f"127.0.0.1:{port}")
                    conn.putheader("Content-Type", "application/json")
                    conn.putheader("Authorization", f"Bearer {owner_token}")
                    conn.putheader("Content-Length", "-10")
                    conn.endheaders()
                    resp = conn.getresponse()
                    resp.read()
                    self.assertEqual(resp.status, 413)
                    conn.close()

                    # 9. P0-3b: Server-side notePath isolation + (notePath, file sha) candidate cache across preflight & submit
                    captured_preflight: list[dict[str, str]] = []
                    captured_submit: list[dict[str, str]] = []
                    prepare_invocations: list[int] = []

                    def _fake_prepare(
                        note_path: Path,
                        ce_patterns_root: Path | None = None,
                        obsidian_vault_root: Path | None = None,
                        **_kwargs: Any,
                    ) -> dict[str, Any]:
                        prepare_invocations.append(1)
                        seq = len(prepare_invocations)
                        return {
                            "ok": True,
                            "concept_id": "safe-concept-id",
                            "submission_id": "sub-123",
                            "candidate_submission": {
                                "id": "sub-123",
                                "default_id": "safe-concept-id",
                                "content": f"SERVER_SANITIZED::{note_path.name}::v{seq}",
                            },
                        }

                    def _fake_preflight(
                        content: str, default_id: str = ""
                    ) -> dict[str, Any]:
                        captured_preflight.append(
                            {"content": content, "default_id": default_id}
                        )
                        return {
                            "ok": True,
                            "http_status": 200,
                            "response": {"preflightToken": "pf-tok"},
                        }

                    def _fake_submit(
                        submission_id: str,
                        content: str,
                        default_id: str = "",
                        preflight_token: str = "",
                    ) -> dict[str, Any]:
                        captured_submit.append(
                            {
                                "submission_id": submission_id,
                                "content": content,
                                "default_id": default_id,
                                "preflight_token": preflight_token,
                            }
                        )
                        return {
                            "ok": True,
                            "http_status": 200,
                            "response": {"status": "submitted"},
                        }

                    with (
                        mock.patch.object(vault_graph, BRIDGE_FLAG_ATTR, True),
                        mock.patch.object(vault_graph, PREPARE_FN_ATTR, _fake_prepare),
                        mock.patch.object(
                            vault_graph, PREFLIGHT_FN_ATTR, _fake_preflight
                        ),
                        mock.patch.object(vault_graph, SUBMIT_FN_ATTR, _fake_submit),
                    ):
                        # 9a. Missing notePath must return 400 even if browser sends raw "content"
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        conn.request(
                            "POST",
                            "/api/ace-live-preflight",
                            body=json.dumps(
                                {"content": "RAW_UNTRUSTED_BROWSER_TEXT"}
                            ).encode("utf-8"),
                            headers={
                                "Host": f"127.0.0.1:{port}",
                                "Content-Type": "application/json",
                                "Authorization": f"Bearer {owner_token}",
                            },
                        )
                        resp = conn.getresponse()
                        resp.read()
                        self.assertEqual(resp.status, 400)
                        self.assertEqual(len(captured_preflight), 0)
                        conn.close()

                        # 9b. Path traversal outside patterns root must return 403
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        conn.request(
                            "POST",
                            "/api/ace-live-preflight",
                            body=json.dumps(
                                {
                                    "notePath": "../vault/wiki/concepts/sample.md",
                                    "content": "RAW_UNTRUSTED_BROWSER_TEXT",
                                }
                            ).encode("utf-8"),
                            headers={
                                "Host": f"127.0.0.1:{port}",
                                "Content-Type": "application/json",
                                "Authorization": f"Bearer {owner_token}",
                            },
                        )
                        resp = conn.getresponse()
                        resp.read()
                        self.assertEqual(resp.status, 403)
                        self.assertEqual(len(captured_preflight), 0)
                        conn.close()

                        # 9c. Valid notePath inside patterns root ignores raw browser content and caches candidate across preflight & submit
                        for endpoint in (
                            "/api/ace-live-preflight",
                            "/api/ace-live-submit",
                        ):
                            conn = http.client.HTTPConnection(
                                "127.0.0.1", port, timeout=5
                            )
                            conn.request(
                                "POST",
                                endpoint,
                                body=json.dumps(
                                    {
                                        "notePath": "wiki/concepts/safe.md",
                                        "content": "MALICIOUS_RAW_BROWSER_OVERRIDE",
                                        "preflightToken": "pf-123",
                                    }
                                ).encode("utf-8"),
                                headers={
                                    "Host": f"127.0.0.1:{port}",
                                    "Content-Type": "application/json",
                                    "Authorization": f"Bearer {owner_token}",
                                },
                            )
                            resp = conn.getresponse()
                            resp.read()
                            self.assertEqual(resp.status, 200)
                            conn.close()

                        self.assertEqual(len(prepare_invocations), 1)
                        self.assertEqual(len(captured_preflight), 1)
                        self.assertEqual(
                            captured_preflight[0]["content"],
                            "SERVER_SANITIZED::safe.md::v1",
                        )
                        self.assertEqual(len(captured_submit), 1)
                        self.assertEqual(
                            captured_submit[0]["content"],
                            "SERVER_SANITIZED::safe.md::v1",
                        )
                        self.assertEqual(
                            captured_submit[0]["preflight_token"], "pf-123"
                        )

                        # 9d. Modifying note bytes on disk invalidates the (notePath, file sha) cache
                        (patterns_dir / "wiki" / "concepts" / "safe.md").write_text(
                            "---\ntitle: Safe Pattern Updated\ntype: concept\nstatus: active\n---\n\nUpdated body.\n",
                            encoding="utf-8",
                        )
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        conn.request(
                            "POST",
                            "/api/ace-live-preflight",
                            body=json.dumps(
                                {"notePath": "wiki/concepts/safe.md"}
                            ).encode("utf-8"),
                            headers={
                                "Host": f"127.0.0.1:{port}",
                                "Content-Type": "application/json",
                                "Authorization": f"Bearer {owner_token}",
                            },
                        )
                        resp = conn.getresponse()
                        resp.read()
                        self.assertEqual(resp.status, 200)
                        conn.close()
                        self.assertEqual(len(prepare_invocations), 2)
                        self.assertEqual(
                            captured_preflight[-1]["content"],
                            "SERVER_SANITIZED::safe.md::v2",
                        )
                finally:
                    server.shutdown()
                    server.server_close()

                # 10. Sidecar mode omits frame-ancestors so cross-origin AuxPane iframe embeds work
                ui_token = "s" * 40
                sidecar_server = http.server.ThreadingHTTPServer(
                    ("127.0.0.1", 0), handler_cls
                )
                s_port = sidecar_server.server_address[1]
                sidecar_server.RequestHandlerClass = (
                    vault_graph.create_graph_request_handler(
                        vault_root=vault_dir,
                        port=s_port,
                        sidecar_mode=True,
                        owner_token=owner_token,
                        ui_token=ui_token,
                    )
                )
                s_thread = threading.Thread(
                    target=sidecar_server.serve_forever, daemon=True
                )
                s_thread.start()
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", s_port, timeout=5)
                    conn.request(
                        "GET",
                        f"/?token={ui_token}",
                        headers={"Host": f"127.0.0.1:{s_port}"},
                    )
                    resp = conn.getresponse()
                    resp.read()
                    self.assertEqual(resp.status, 200)
                    sidecar_csp = resp.getheader("Content-Security-Policy") or ""
                    self.assertIn(
                        "default-src 'none'; script-src 'self' 'nonce-", sidecar_csp
                    )
                    self.assertNotIn("frame-ancestors", sidecar_csp)
                    self.assertIn("base-uri 'none'", sidecar_csp)
                    conn.close()
                finally:
                    sidecar_server.shutdown()
                    sidecar_server.server_close()


if __name__ == "__main__":
    unittest.main()
