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
"""Cross-platform Windows/macOS/Linux portability tests for sidecar launcher and hooks."""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import init_vault  # noqa: E402
import install_plugin  # noqa: E402
import vault_graph  # noqa: E402
import vault_hooks  # noqa: E402


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _http_request(
    port: int,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_headers, body
    finally:
        conn.close()


class TestWindowsSidecarPortability(unittest.TestCase):
    """Verify Node sidecar launcher, Windows token mode guard, and cross-platform hooks."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="kc_win_port_")
        self.tmp_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_sidecar_manifest_uses_bundled_node_launcher(self) -> None:
        sc_dir = REPO_ROOT / "sidecars" / "vault_graph"
        manifest = json.loads((sc_dir / "sidecar.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("command"), "node")
        self.assertEqual(manifest.get("args"), ["launcher.mjs"])
        self.assertTrue((sc_dir / "launcher.mjs").is_file())
        self.assertTrue((sc_dir / "server.py").is_file())
        self.assertTrue((sc_dir / "preload.js").is_file())

    def test_root_hooks_json_cross_platform_python_fallback_chain(self) -> None:
        hooks = json.loads((REPO_ROOT / "hooks.json").read_text(encoding="utf-8"))
        for key in ("vault-session-start", "vault-stop-hook", "wikiskill-error-recorder"):
            self.assertFalse(hooks[key]["enabled"])
        cmd = hooks["vault-session-start"]["SessionStart"][0]["command"]
        self.assertIn("-X utf8 -B scripts/hooks/session_sync.py", cmd)
        self.assertIn("py -3 -X utf8 -B scripts/hooks/session_sync.py", cmd)
        self.assertIn("python -X utf8 -B scripts/hooks/session_sync.py", cmd)
        self.assertTrue(cmd.endswith("|| exit 0"))

    def test_install_plugin_copies_node_launcher_and_windows_hooks(self) -> None:
        fake_home = self.tmp_dir / "home"
        fake_home.mkdir(parents=True)
        target_plugin = self.tmp_dir / "plugin_out"

        with mock.patch.object(install_plugin.sys, "platform", "win32"):
            res = install_plugin.install_global_plugin(
                repo_root=REPO_ROOT,
                target_plugin_dir=target_plugin,
                home_dir=fake_home,
            )
        self.assertTrue(res["success"])
        sc_dir = target_plugin / "sidecars" / "vault_graph"
        manifest = json.loads((sc_dir / "sidecar.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["command"], "node")
        self.assertEqual(manifest["args"], ["launcher.mjs"])
        self.assertTrue((sc_dir / "launcher.mjs").is_file())
        self.assertTrue((sc_dir / "server.py").is_file())
        self.assertTrue((sc_dir / "preload.js").is_file())

        hooks_cfg = json.loads((target_plugin / "hooks.json").read_text(encoding="utf-8"))
        win_cmd = hooks_cfg["vault-session-start"]["SessionStart"][0]["command"]
        self.assertNotIn("~/", win_cmd)
        self.assertIn("-X utf8 -B", win_cmd)
        self.assertIn("session_sync.py", win_cmd)

    def test_vault_hooks_windows_absolute_command_has_no_tilde(self) -> None:
        plugin_dir = self.tmp_dir / "my plugin"
        (plugin_dir / "scripts" / "hooks").mkdir(parents=True)
        with mock.patch.object(vault_hooks.sys, "platform", "win32"):
            entry = vault_hooks._build_hook_entry(
                "vault-stop-hook",
                enabled=True,
                plugin_dir=plugin_dir,
                workspace_relative=False,
            )
        cmd = entry["Stop"][0]["command"]
        self.assertNotIn("~/", cmd)
        self.assertIn("-X utf8 -B", cmd)
        self.assertIn("auto_sync_vault.py", cmd)

    def test_windows_token_file_mode_guard_allows_nt_regular_file(self) -> None:
        tok_file = self.tmp_dir / ".vault_graph_token"
        tok_file.write_text("a" * 40 + "\n", encoding="utf-8")
        os.chmod(tok_file, 0o644)
        # On POSIX, 0o644 must be rejected
        if sys.platform != "win32":
            self.assertFalse(vault_graph._is_secure_token_file(tok_file))
        # Simulated Windows (`sys.platform == "win32"`) must accept regular owned file
        with mock.patch.object(vault_graph.sys, "platform", "win32"):
            self.assertTrue(vault_graph._is_secure_token_file(tok_file))

    def test_node_launcher_syntax_live_python_and_zero_python_fallback(self) -> None:
        node_bin = (
            (os.environ.get("ANTIGRAVITY_NODE_PATH") or "").strip()
            or shutil.which("agy-node")
            or shutil.which("node")
        )
        if not node_bin or not Path(node_bin).is_file():
            self.skipTest("node binary not available on PATH or ANTIGRAVITY_NODE_PATH")

        launcher = REPO_ROOT / "sidecars" / "vault_graph" / "launcher.mjs"
        syntax_proc = subprocess.run(
            [node_bin, "--check", str(launcher)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(syntax_proc.returncode, 0, msg=syntax_proc.stderr)

        # 1. Verify live launch delegating to server.py + vault_graph.py
        vault_dir = self.tmp_dir / "Vault"
        init_vault.init_vault(vault_dir, quiet=True, init_git=False)
        port_live = _find_free_port()
        token = "test_sidecar_token_" + ("x" * 24)
        env_live = dict(os.environ)
        env_live.update(
            {
                "ANTIGRAVITY_SIDECAR_WEB_PORT": str(port_live),
                "ANTIGRAVITY_SIDECAR_UI_TOKEN": token,
                "KC_VAULT_PATH": str(vault_dir),
                "KC_PYTHON_BIN": sys.executable,
                "HOME": str(self.tmp_dir / "home_live"),
                "XDG_DATA_HOME": str(self.tmp_dir / "xdg_data_live"),
                "XDG_CACHE_HOME": str(self.tmp_dir / "xdg_cache_live"),
                "PLUGIN_DATA": str(self.tmp_dir / "plugin_data_live"),
            }
        )
        for d_key in ("HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "PLUGIN_DATA"):
            Path(env_live[d_key]).mkdir(parents=True, exist_ok=True)

        proc_live = subprocess.Popen(
            [node_bin, str(launcher)],
            cwd=str(launcher.parent),
            env=env_live,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            self.assertTrue(
                _wait_for_port(port_live, timeout_s=12.0),
                msg=f"launcher.mjs did not bind port {port_live}",
            )
            status_unauth, _, _ = _http_request(port_live, "GET", "/")
            self.assertEqual(status_unauth, 401)

            status_root, _, body_root = _http_request(
                port_live, "GET", f"/?token={token}"
            )
            self.assertEqual(status_root, 200)
            self.assertIn("preload.js", body_root)

            status_graph, _, body_graph = _http_request(
                port_live,
                "GET",
                "/api/graph?slim=1",
                headers={"X-Sidecar-Token": token},
            )
            self.assertEqual(status_graph, 200)
            graph_json = json.loads(body_graph)
            self.assertIn("nodes", graph_json)
            self.assertGreaterEqual(len(graph_json["nodes"]), 1)
        finally:
            proc_live.terminate()
            try:
                proc_live.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc_live.kill()
                proc_live.wait(timeout=5)

        # 2. Verify graceful zero-Python fallback server (no crash loop)
        port_fb = _find_free_port()
        env_fb = dict(env_live)
        env_fb["ANTIGRAVITY_SIDECAR_WEB_PORT"] = str(port_fb)
        env_fb["KC_PYTHON_BIN"] = str(self.tmp_dir / "missing_python_binary")

        proc_fb = subprocess.Popen(
            [node_bin, str(launcher)],
            cwd=str(launcher.parent),
            env=env_fb,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            self.assertTrue(
                _wait_for_port(port_fb, timeout_s=8.0),
                msg=f"fallback server did not bind port {port_fb}",
            )
            self.assertIsNone(proc_fb.poll(), "fallback launcher should stay running")

            status_401, _, _ = _http_request(port_fb, "GET", "/")
            self.assertEqual(status_401, 401)

            status_preload, hdrs_preload, body_preload = _http_request(
                port_fb, "GET", "/preload.js"
            )
            self.assertEqual(status_preload, 200)
            self.assertIn("window.sidecar", body_preload)
            self.assertIn("javascript", hdrs_preload.get("content-type", ""))

            status_page, hdrs_page, body_page = _http_request(
                port_fb, "GET", f"/?token={token}"
            )
            self.assertEqual(status_page, 200)
            self.assertIn("Python 3.10+ required", body_page)
            self.assertIn("nonce-", hdrs_page.get("content-security-policy", ""))

            status_health, _, body_health = _http_request(
                port_fb,
                "GET",
                "/api/health",
                headers={"X-Sidecar-Token": token},
            )
            self.assertEqual(status_health, 200)
            self.assertEqual(json.loads(body_health)["status"], "python_missing")

            status_csrf, _, _ = _http_request(
                port_fb,
                "POST",
                "/api/recheck",
                headers={"X-Sidecar-Token": token},
            )
            self.assertEqual(status_csrf, 403)

            status_recheck, _, body_recheck = _http_request(
                port_fb,
                "POST",
                "/api/recheck",
                headers={"X-Sidecar-Token": token, "X-KC-Request": "1"},
            )
            self.assertEqual(status_recheck, 200)
            self.assertFalse(json.loads(body_recheck)["ok"])
        finally:
            proc_fb.terminate()
            try:
                proc_fb.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc_fb.kill()
                proc_fb.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
