// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Cross-platform Node.js sidecar launcher for the Knowledge Compiler WebGL Graph.
 *
 * Uses the host IDE's bundled Node.js runtime on Windows, macOS, and Linux to:
 * 1. Locate a working Python 3.9+ interpreter (avoiding Windows Store stubs).
 * 2. Launch `server.py` with UTF-8 mode enabled (`PYTHONUTF8=1`) and hidden
 *    console windows on Windows.
 * 3. Serve a graceful, theme-adaptive setup page on `ANTIGRAVITY_SIDECAR_WEB_PORT`
 *    if Python 3.9+ is not installed yet, preventing supervisor crash loops and
 *    allowing live one-click re-detection without restarting the IDE.
 */

import { execFileSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const SIDECAR_DIR = path.dirname(__filename);
const SERVER_PY = path.join(SIDECAR_DIR, "server.py");
const PRELOAD_JS = path.join(SIDECAR_DIR, "preload.js");

const PYTHON_PROBE_CODE =
  "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}'); " +
  "raise SystemExit(0 if sys.version_info >= (3, 9) else 1)";

let activeChild = null;
let activeFallbackServer = null;
let shuttingDown = false;

/**
 * Scan standard Windows Python installation directories (newest Python 3.x first).
 * @returns {Array<{command: string, prefixArgs: string[], label: string}>}
 */
function collectWindowsInstallCandidates() {
  const roots = [
    process.env.LOCALAPPDATA
      ? path.join(process.env.LOCALAPPDATA, "Programs", "Python")
      : "",
    process.env.USERPROFILE
      ? path.join(
          process.env.USERPROFILE,
          "AppData",
          "Local",
          "Programs",
          "Python",
        )
      : "",
    process.env.ProgramFiles || "",
    process.env["ProgramFiles(x86)"] || "",
    "C:\\",
  ].filter(Boolean);

  const found = [];
  const seenDirs = new Set();

  for (const rootDir of roots) {
    const normRoot = rootDir.toLowerCase();
    if (seenDirs.has(normRoot)) continue;
    seenDirs.add(normRoot);

    let entries;
    try {
      entries = fs.readdirSync(rootDir, { withFileTypes: true });
    } catch {
      continue;
    }

    const pyDirs = entries
      .filter((ent) => ent.isDirectory() && /^Python3\d+$/i.test(ent.name))
      .map((ent) => ({
        name: ent.name,
        minor: Number.parseInt(ent.name.slice("Python3".length), 10) || 0,
      }))
      .sort((a, b) => b.minor - a.minor);

    for (const dirInfo of pyDirs) {
      const exePath = path.join(rootDir, dirInfo.name, "python.exe");
      try {
        if (fs.existsSync(exePath)) {
          found.push({
            command: exePath,
            prefixArgs: [],
            label: `${dirInfo.name}\\python.exe`,
          });
        }
      } catch {
        // Ignore inaccessible paths.
      }
    }
  }
  return found;
}

/**
 * Build ordered candidate list of Python 3.9+ interpreters for the current OS.
 * @returns {Array<{command: string, prefixArgs: string[], label: string}>}
 */
function collectPythonCandidates() {
  const override = (process.env.KC_PYTHON_BIN || "").trim();
  if (override) {
    return [{ command: override, prefixArgs: [], label: "KC_PYTHON_BIN" }];
  }

  const candidates = [];
  if (process.platform === "win32") {
    candidates.push(
      { command: "py", prefixArgs: ["-3"], label: "py -3" },
      { command: "python", prefixArgs: [], label: "python" },
      { command: "python3", prefixArgs: [], label: "python3" },
      ...collectWindowsInstallCandidates(),
    );
  } else {
    candidates.push(
      { command: "python3", prefixArgs: [], label: "python3" },
      { command: "python", prefixArgs: [], label: "python" },
    );
    const extraPaths =
      process.platform === "darwin"
        ? [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
          ]
        : ["/usr/bin/python3", "/usr/local/bin/python3"];
    for (const p of extraPaths) {
      try {
        if (fs.existsSync(p)) {
          candidates.push({ command: p, prefixArgs: [], label: p });
        }
      } catch {
        // Ignore inaccessible paths.
      }
    }
  }

  const deduped = [];
  const seen = new Set();
  for (const cand of candidates) {
    const keyCmd =
      process.platform === "win32" ? cand.command.toLowerCase() : cand.command;
    const key = `${keyCmd}\0${cand.prefixArgs.join("\0")}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(cand);
  }
  return deduped;
}

/**
 * Probe a candidate Python command and verify it runs Python 3.9+.
 * Rejects Microsoft Store stubs, Python 2, and blocked executables cleanly.
 * @param {{command: string, prefixArgs: string[], label: string}} cand
 * @returns {{command: string, prefixArgs: string[], label: string, version: string} | null}
 */
function probePythonCandidate(cand) {
  try {
    const out = execFileSync(
      cand.command,
      [...cand.prefixArgs, "-B", "-c", PYTHON_PROBE_CODE],
      {
        encoding: "utf8",
        timeout: 4000,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const version = String(out || "")
      .trim()
      .split(/\r?\n/)[0]
      ?.trim();
    const match = /^3\.(\d+)\.\d+$/.exec(version || "");
    if (!match || Number.parseInt(match[1], 10) < 9) {
      return null;
    }
    return { ...cand, version };
  } catch {
    return null;
  }
}

/**
 * Discover the first working Python 3.9+ interpreter on this machine.
 * @returns {{python: {command: string, prefixArgs: string[], label: string, version: string} | null, checked: string[]}}
 */
function discoverPython() {
  const candidates = collectPythonCandidates();
  const checked = [];
  for (const cand of candidates) {
    checked.push(cand.label);
    const verified = probePythonCandidate(cand);
    if (verified) {
      return { python: verified, checked };
    }
  }
  return { python: null, checked };
}

function resolvePort() {
  const raw = Number.parseInt(
    process.env.ANTIGRAVITY_SIDECAR_WEB_PORT || "8765",
    10,
  );
  if (Number.isFinite(raw) && raw > 0 && raw < 65536) {
    return raw;
  }
  return 8765;
}

function tokensMatch(a, b) {
  if (!a || !b) return false;
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const pair of cookieHeader.split(";")) {
    const idx = pair.indexOf("=");
    if (idx <= 0) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function getLocalHostnames() {
  const set = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
  try {
    const host = os.hostname().trim().toLowerCase();
    if (host) {
      set.add(host);
      const shortHost = host.split(".")[0];
      if (shortHost) set.add(shortHost);
    }
  } catch {
    // Ignore hostname errors.
  }
  return set;
}

const LOCAL_HOSTNAMES = getLocalHostnames();

function isLocalHostHeader(hostHeader) {
  if (!hostHeader) return false;
  try {
    const parsed = new URL(`http://${hostHeader.trim()}`);
    const hostname = parsed.hostname.toLowerCase();
    if (LOCAL_HOSTNAMES.has(hostname)) return true;
    if (hostname.endsWith(".linux.test")) return true;
    return false;
  } catch {
    return false;
  }
}

function isAllowedOrigin(originHeader) {
  if (!originHeader || originHeader === "null") return true;
  if (originHeader.startsWith("vscode-webview://")) return true;
  try {
    const parsed = new URL(originHeader);
    const hostname = parsed.hostname.toLowerCase();
    if (LOCAL_HOSTNAMES.has(hostname)) return true;
    if (hostname.endsWith(".linux.test")) return true;
    return false;
  } catch {
    return false;
  }
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function getInstallGuidance() {
  if (process.platform === "win32") {
    return {
      osLabel: "Windows",
      command: "winget install -e --id Python.Python.3.12",
      altNote:
        "Or download Python 3.12 from python.org (check 'Add python.exe to PATH'), or set KC_PYTHON_BIN to an existing python.exe.",
    };
  }
  if (process.platform === "darwin") {
    return {
      osLabel: "macOS",
      command: "brew install python@3.12",
      altNote:
        "Or install Xcode Command Line Tools (`xcode-select --install`), or set KC_PYTHON_BIN to an existing python3 binary.",
    };
  }
  return {
    osLabel: "Linux",
    command: "sudo apt install -y python3",
    altNote:
      "Install Python 3.10+ using your distribution package manager, or set KC_PYTHON_BIN to an existing python3 binary.",
  };
}

function renderFallbackHtml(nonce, checkedLabels) {
  const guide = getInstallGuidance();
  const checkedText = checkedLabels.length
    ? checkedLabels.join(", ")
    : "python3, python";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Knowledge Graph Setup</title>
  <script nonce="${nonce}" src="/preload.js"></script>
  <style nonce="${nonce}">
    :root {
      color-scheme: light dark;
      --kc-bg: var(--background, #0b1120);
      --kc-fg: var(--foreground, #e5e7eb);
      --kc-card: var(--card, #111827);
      --kc-card-fg: var(--card-foreground, #f3f4f6);
      --kc-border: var(--border, rgba(148, 163, 184, 0.24));
      --kc-muted: var(--muted-foreground, #94a3b8);
      --kc-primary: var(--primary, #38bdf8);
      --kc-primary-fg: var(--primary-foreground, #082f49);
      --kc-code-bg: var(--muted, rgba(15, 23, 42, 0.72));
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      background: var(--kc-bg);
      color: var(--kc-fg);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .card {
      width: 100%;
      max-width: 520px;
      background: var(--kc-card);
      color: var(--kc-card-fg);
      border: 1px solid var(--kc-border);
      border-radius: 14px;
      padding: 24px 26px;
      box-shadow: 0 18px 48px rgba(0, 0, 0, 0.35);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--kc-primary);
      margin-bottom: 10px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 19px;
      line-height: 1.3;
    }
    p {
      margin: 0 0 14px;
      font-size: 13.5px;
      line-height: 1.55;
      color: var(--kc-muted);
    }
    .cmd-box {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--kc-code-bg);
      border: 1px solid var(--kc-border);
      border-radius: 9px;
      padding: 10px 12px;
      margin: 14px 0;
    }
    code {
      flex: 1;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12.5px;
      word-break: break-all;
      color: var(--kc-card-fg);
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 16px;
    }
    button {
      border-radius: 8px;
      font-size: 12.5px;
      font-weight: 600;
      padding: 8px 14px;
      cursor: pointer;
      border: 1px solid var(--kc-border);
      background: transparent;
      color: var(--kc-card-fg);
    }
    button.primary {
      background: var(--kc-primary);
      color: var(--kc-primary-fg);
      border-color: transparent;
    }
    button:disabled {
      opacity: 0.6;
      cursor: wait;
    }
    .status {
      margin-top: 14px;
      font-size: 12.5px;
      min-height: 18px;
      color: var(--kc-muted);
    }
    .meta {
      margin-top: 16px;
      padding-top: 12px;
      border-top: 1px solid var(--kc-border);
      font-size: 11.5px;
      color: var(--kc-muted);
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="badge">Knowledge Compiler · ${escapeHtml(guide.osLabel)}</div>
    <h1>Python 3.10+ required for the Knowledge Graph</h1>
    <p>
      The Knowledge Graph sidecar started using the bundled Node.js runtime, but no working Python 3.9+ interpreter was found to run the local Open Knowledge Format graph engine.
    </p>
    <div class="cmd-box">
      <code id="install-cmd">${escapeHtml(guide.command)}</code>
      <button type="button" id="btn-copy">Copy</button>
    </div>
    <p>${escapeHtml(guide.altNote)}</p>
    <div class="actions">
      <button type="button" class="primary" id="btn-recheck">Re-check Python and Launch Graph</button>
    </div>
    <div class="status" id="status-line" role="status" aria-live="polite"></div>
    <div class="meta">Checked interpreters: ${escapeHtml(checkedText)}</div>
  </main>
  <script nonce="${nonce}">
    (function () {
      var params = new URLSearchParams(window.location.search);
      var sidecarToken = params.get("token") || "";
      if (sidecarToken && window.history && window.history.replaceState) {
        params.delete("token");
        var cleanSearch = params.toString();
        var cleanUrl = window.location.pathname + (cleanSearch ? "?" + cleanSearch : "") + window.location.hash;
        window.history.replaceState(null, "", cleanUrl);
      }

      var copyBtn = document.getElementById("btn-copy");
      var cmdEl = document.getElementById("install-cmd");
      var recheckBtn = document.getElementById("btn-recheck");
      var statusEl = document.getElementById("status-line");

      copyBtn.addEventListener("click", function () {
        var text = cmdEl.textContent || "";
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            copyBtn.textContent = "Copied";
            setTimeout(function () { copyBtn.textContent = "Copy"; }, 1600);
          }).catch(function () {
            statusEl.textContent = "Copy failed; select the command above manually.";
          });
        }
      });

      recheckBtn.addEventListener("click", function () {
        recheckBtn.disabled = true;
        statusEl.textContent = "Checking for Python 3.9+...";
        var headers = { "X-KC-Request": "1" };
        if (sidecarToken) headers["X-Sidecar-Token"] = sidecarToken;
        fetch("/api/recheck", { method: "POST", headers: headers })
          .then(function (resp) { return resp.json(); })
          .then(function (data) {
            if (data && data.ok) {
              statusEl.textContent = "Found Python " + (data.version || "") + ". Launching Knowledge Graph...";
              var reloadUrl = sidecarToken ? ("/?token=" + encodeURIComponent(sidecarToken)) : "/";
              setTimeout(function () { window.location.replace(reloadUrl); }, 900);
            } else {
              recheckBtn.disabled = false;
              statusEl.textContent = (data && data.message) || "Python 3.9+ not detected yet. Install Python and try again.";
            }
          })
          .catch(function () {
            recheckBtn.disabled = false;
            statusEl.textContent = "Could not reach sidecar launcher. Reload the panel and try again.";
          });
      });
    })();
  </script>
</body>
</html>
`;
}

function sendSecurityHeaders(res, nonce) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  if (nonce) {
    res.setHeader(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'nonce-${nonce}' 'self'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:`,
    );
  }
}

/**
 * Start a lightweight stdlib HTTP setup UI when Python 3.9+ is missing.
 * @param {string[]} checkedLabels
 */
function startFallbackServer(checkedLabels) {
  const port = resolvePort();
  const uiToken = (process.env.ANTIGRAVITY_SIDECAR_UI_TOKEN || "").trim();

  function isAuthorized(req, urlObj) {
    if (!uiToken) return true;
    const qTok = (urlObj.searchParams.get("token") || "").trim();
    if (tokensMatch(qTok, uiToken)) return true;
    const hdrTok = String(req.headers["x-sidecar-token"] || "").trim();
    if (tokensMatch(hdrTok, uiToken)) return true;
    const authHdr = String(req.headers.authorization || "").trim();
    if (authHdr.toLowerCase().startsWith("bearer ")) {
      if (tokensMatch(authHdr.slice(7).trim(), uiToken)) return true;
    }
    const cookies = parseCookies(String(req.headers.cookie || ""));
    if (tokensMatch(cookies.kc_sidecar_token || "", uiToken)) return true;
    return false;
  }

  let currentChecked = checkedLabels;

  const server = http.createServer((req, res) => {
    if (!isLocalHostHeader(String(req.headers.host || ""))) {
      res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("403 Forbidden: invalid Host header\n");
      return;
    }

    const urlObj = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    const pathname = urlObj.pathname;

    if (req.method === "GET" && pathname === "/preload.js") {
      let body = "window.sidecar = window.sidecar || {};\n";
      try {
        if (fs.existsSync(PRELOAD_JS)) {
          body = fs.readFileSync(PRELOAD_JS, "utf8");
        }
      } catch {
        // Use minimal default preload shim.
      }
      sendSecurityHeaders(res, null);
      res.writeHead(200, {
        "Content-Type": "application/javascript; charset=utf-8",
      });
      res.end(body);
      return;
    }

    if (!isAuthorized(req, urlObj)) {
      sendSecurityHeaders(res, null);
      res.writeHead(401, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("401 Unauthorized: missing or invalid sidecar token\n");
      return;
    }

    if (req.method === "GET" && pathname === "/api/health") {
      sendSecurityHeaders(res, null);
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(
        JSON.stringify({
          status: "python_missing",
          platform: process.platform,
          checked: currentChecked,
        }),
      );
      return;
    }

    if (req.method === "POST" && pathname === "/api/recheck") {
      if (
        String(req.headers["x-kc-request"] || "") !== "1" ||
        !isAllowedOrigin(req.headers.origin)
      ) {
        sendSecurityHeaders(res, null);
        res.writeHead(403, {
          "Content-Type": "application/json; charset=utf-8",
        });
        res.end(JSON.stringify({ ok: false, message: "Forbidden origin" }));
        return;
      }

      const probe = discoverPython();
      currentChecked = probe.checked;
      sendSecurityHeaders(res, null);
      if (!probe.python) {
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
        });
        res.end(
          JSON.stringify({
            ok: false,
            message:
              "Python 3.9+ is still not detected. After installing Python, click Re-check again.",
            checked: probe.checked,
          }),
        );
        return;
      }

      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(
        JSON.stringify({
          ok: true,
          version: probe.python.version,
          label: probe.python.label,
        }),
      );
      res.on("finish", () => {
        activeFallbackServer = null;
        if (typeof server.closeAllConnections === "function") {
          server.closeAllConnections();
        }
        server.close(() => {
          if (!shuttingDown) {
            launchPythonServer(probe.python);
          }
        });
      });
      return;
    }

    if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
      const nonce = crypto.randomBytes(16).toString("base64");
      sendSecurityHeaders(res, nonce);
      const qTok = (urlObj.searchParams.get("token") || "").trim();
      if (uiToken && tokensMatch(qTok, uiToken)) {
        res.setHeader(
          "Set-Cookie",
          `kc_sidecar_token=${uiToken}; HttpOnly; SameSite=Strict; Path=/`,
        );
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderFallbackHtml(nonce, currentChecked));
      return;
    }

    sendSecurityHeaders(res, null);
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not Found\n");
  });

  activeFallbackServer = server;
  server.listen(port, "127.0.0.1", () => {
    process.stderr.write(
      `[vault-graph-launcher] Python 3.9+ not found (checked: ${checkedLabels.join(", ")}). ` +
        `Serving setup guidance on http://127.0.0.1:${port}\n`,
    );
  });
}

/**
 * Spawn `server.py` using the verified Python 3.9+ interpreter.
 * @param {{command: string, prefixArgs: string[], label: string, version: string}} py
 */
function launchPythonServer(py) {
  if (!fs.existsSync(SERVER_PY)) {
    process.stderr.write(
      `[vault-graph-launcher] Missing server entrypoint: ${SERVER_PY}\n`,
    );
    process.exit(1);
  }

  process.stderr.write(
    `[vault-graph-launcher] Launching server.py with ${py.label} (Python ${py.version})\n`,
  );

  const child = spawn(
    py.command,
    [...py.prefixArgs, "-B", "-u", SERVER_PY],
    {
      cwd: SIDECAR_DIR,
      env: {
        ...process.env,
        PYTHONUTF8: "1",
        PYTHONIOENCODING: "utf-8",
        PYTHONDONTWRITEBYTECODE: "1",
      },
      stdio: "inherit",
      windowsHide: true,
    },
  );
  activeChild = child;

  child.on("error", (err) => {
    activeChild = null;
    process.stderr.write(
      `[vault-graph-launcher] Failed to launch Python (${py.label}): ${err.message}\n`,
    );
    if (!shuttingDown) {
      startFallbackServer([py.label]);
    }
  });

  child.on("exit", (code, signal) => {
    activeChild = null;
    if (shuttingDown) {
      process.exit(0);
    }
    if (signal) {
      process.exit(signal === "SIGINT" || signal === "SIGTERM" ? 0 : 1);
    }
    process.exit(typeof code === "number" ? code : 0);
  });
}

function handleShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  if (activeFallbackServer) {
    if (typeof activeFallbackServer.closeAllConnections === "function") {
      activeFallbackServer.closeAllConnections();
    }
    activeFallbackServer.close(() => process.exit(0));
    return;
  }
  if (activeChild && !activeChild.killed) {
    try {
      activeChild.kill(process.platform === "win32" ? undefined : signal);
    } catch {
      process.exit(0);
    }
    setTimeout(() => process.exit(0), 2500).unref();
    return;
  }
  process.exit(0);
}

process.on("SIGINT", () => handleShutdown("SIGINT"));
process.on("SIGTERM", () => handleShutdown("SIGTERM"));

const { python, checked } = discoverPython();
if (python) {
  launchPythonServer(python);
} else {
  startFallbackServer(checked);
}
