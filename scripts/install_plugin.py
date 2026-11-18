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
"""install_plugin.py - Global Plugin Installer for Antigravity CLI Harnesses.

Auto-detects installed CLI harnesses on the workstation and installs the
Knowledge Compiler plugin (`plugin.json`, `hooks.json`, `rules/AGENTS.md`,
`skills/`, and `scripts/`) into the global plugin directory.
"""
from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
from pathlib import Path

_GLOBAL_PLUGIN_REL = ".agent/plugins/knowledge-compiler"
_LEGACY_HARNESS_KEY = "antigravity_cli"

PLUGIN_MANIFEST = {
    "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
    "name": "knowledge-compiler",
    "displayName": "Knowledge Compiler",
    "version": "1.2.0",
    "description": (
        "Compile PDFs, slides, docs, and agent sessions into a local Open Knowledge Format "
        "(OKF v0.3) Markdown wiki with a 2D/3D WebGL graph and linter."
    ),
    "category": "productivity",
    "logo": "assets/logo.svg",
    "author": {"name": "Google LLC"},
    "license": "Apache-2.0",
    "homepage": "https://github.com/GoogleCloudPlatform/knowledge-compiler",
    "repository": "https://github.com/GoogleCloudPlatform/knowledge-compiler",
    "keywords": [
        "knowledge-compiler",
        "open-knowledge-format",
        "okf",
        "llm-wiki",
        "context-engineering",
        "knowledge-graph",
        "obsidian",
        "wikiskill",
        "agent-memory",
        "markdown",
        "google-cloud",
    ],
    "suggestedPrompts": [
        "Initialize an OKF v0.3 knowledge vault in ./vault and compile the current session into it",
        "Ingest a PDF, slide deck, or markdown folder into my knowledge vault and update index.md",
        "Audit my knowledge vault for broken wikilinks, frontmatter errors, and orphan notes",
    ],
}

MARKETPLACE_PLUGIN_MANIFEST = dict(PLUGIN_MANIFEST)

LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" fill="none">
  <rect width="64" height="64" rx="14" fill="#0B1120"/>
  <g stroke="#334155" stroke-width="2" stroke-linecap="round">
    <line x1="32" y1="32" x2="16" y2="18"/>
    <line x1="32" y1="32" x2="48" y2="18"/>
    <line x1="32" y1="32" x2="16" y2="46"/>
    <line x1="32" y1="32" x2="48" y2="46"/>
    <line x1="16" y1="18" x2="48" y2="18" stroke-dasharray="3 3"/>
    <line x1="16" y1="46" x2="48" y2="46" stroke-dasharray="3 3"/>
  </g>
  <circle cx="16" cy="18" r="6" fill="#4285F4"/>
  <circle cx="48" cy="18" r="6" fill="#10B981"/>
  <circle cx="16" cy="46" r="6" fill="#F59E0B"/>
  <circle cx="48" cy="46" r="6" fill="#A855F7"/>
  <circle cx="32" cy="32" r="9" fill="#38BDF8" stroke="#0B1120" stroke-width="2.5"/>
</svg>
"""

REPO_HOOKS_CONFIG = {
    "vault-session-start": {
        "enabled": False,
        "SessionStart": [
            {
                "type": "command",
                "command": "python3 -B scripts/hooks/session_sync.py || exit 0",
                "timeout": 15,
            }
        ],
        "PreInvocation": [
            {
                "type": "command",
                "command": "python3 -B scripts/hooks/session_sync.py || exit 0",
                "timeout": 15,
            }
        ],
    },
    "vault-stop-hook": {
        "enabled": False,
        "Stop": [
            {
                "type": "command",
                "command": "python3 -B scripts/hooks/auto_sync_vault.py || exit 0",
                "timeout": 15,
            }
        ],
    },
    "wikiskill-error-recorder": {
        "enabled": False,
        "PostToolUse": [
            {
                "matcher": ".*",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python3 -B scripts/hooks/log_tool_failure.py || exit 0",
                        "timeout": 10,
                    }
                ],
            }
        ],
    },
}

GLOBAL_HOOKS_CONFIG = {
    "vault-session-start": {
        "enabled": False,
        "SessionStart": [
            {
                "type": "command",
                "command": f"python3 -B ~/{_GLOBAL_PLUGIN_REL}/scripts/hooks/session_sync.py || exit 0",
                "timeout": 15,
            }
        ],
        "PreInvocation": [
            {
                "type": "command",
                "command": f"python3 -B ~/{_GLOBAL_PLUGIN_REL}/scripts/hooks/session_sync.py || exit 0",
                "timeout": 15,
            }
        ],
    },
    "vault-stop-hook": {
        "enabled": False,
        "Stop": [
            {
                "type": "command",
                "command": f"python3 -B ~/{_GLOBAL_PLUGIN_REL}/scripts/hooks/auto_sync_vault.py || exit 0",
                "timeout": 15,
            }
        ],
    },
    "wikiskill-error-recorder": {
        "enabled": False,
        "PostToolUse": [
            {
                "matcher": ".*",
                "hooks": [
                    {
                        "type": "command",
                        "command": f"python3 -B ~/{_GLOBAL_PLUGIN_REL}/scripts/hooks/log_tool_failure.py || exit 0",
                        "timeout": 10,
                    }
                ],
            }
        ],
    },
}


def detect_installed_harnesses(home_dir: Path | None = None) -> dict:
    """Detect which CLI harnesses are installed on the machine."""
    home = (home_dir or Path.home()).expanduser().resolve()

    legacy_candidates = [
        home / ".gemini" / _LEGACY_HARNESS_KEY,
        home / f".{_LEGACY_HARNESS_KEY}",
        home / ".config" / _LEGACY_HARNESS_KEY,
        home / f".{_LEGACY_HARNESS_KEY}-server",
    ]
    antigravity_candidates = [
        home / ".gemini" / "antigravity",
        home / ".antigravitycli",
        home / ".local" / "bin" / "agy",
    ]

    legacy_found = [str(p) for p in legacy_candidates if p.exists()]
    antigravity_found = [str(p) for p in antigravity_candidates if p.exists()]

    return {
        _LEGACY_HARNESS_KEY: len(legacy_found) > 0,
        "antigravity": len(antigravity_found) > 0,
        f"{_LEGACY_HARNESS_KEY}_paths": legacy_found,
        "antigravity_paths": antigravity_found,
        "global_plugin_root": str(home / _GLOBAL_PLUGIN_REL),
    }


def install_global_plugin(
    repo_root: Path | None = None,
    target_plugin_dir: Path | None = None,
    home_dir: Path | None = None,
    preserve_existing_hooks: bool = True,
    enable_hooks: str | bool | None = None,
    disable_hooks: str | bool | None = None,
) -> dict:
    """Install or update the global Knowledge Compiler plugin."""
    root = (repo_root or Path(__file__).resolve().parent.parent).resolve()
    detection = detect_installed_harnesses(home_dir=home_dir)

    if target_plugin_dir is None:
        plugin_dir = Path(detection["global_plugin_root"])
    else:
        plugin_dir = target_plugin_dir.expanduser().resolve()

    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "logs").mkdir(parents=True, exist_ok=True)

    # 1. Write plugin.json at manifest locations checked by plugins.go
    manifest_paths = [
        plugin_dir / "plugin.json",
        plugin_dir / ".antigravity-plugin" / "plugin.json",
        plugin_dir / ".gemini-plugin" / "plugin.json",
    ]
    manifest_json = json.dumps(PLUGIN_MANIFEST, indent=2) + "\n"
    for mp in manifest_paths:
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(manifest_json, encoding="utf-8")

    # 1b. Write assets/logo.svg (prefer repo animated crystal SVG if present)
    assets_dir = plugin_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    repo_logo = root / "assets" / "logo.svg"
    if repo_logo.is_file():
        shutil.copy2(repo_logo, assets_dir / "logo.svg")
    else:
        (assets_dir / "logo.svg").write_text(LOGO_SVG, encoding="utf-8")

    # 2. Write hooks.json at plugin root (preserving user-enabled hook states across upgrades)
    hooks_path = plugin_dir / "hooks.json"
    hooks_cfg = copy.deepcopy(GLOBAL_HOOKS_CONFIG)
    if preserve_existing_hooks and hooks_path.is_file() and not hooks_path.is_symlink():
        try:
            prev_hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
            if isinstance(prev_hooks, dict):
                for h_id, h_entry in hooks_cfg.items():
                    prev_entry = prev_hooks.get(h_id)
                    if isinstance(prev_entry, dict) and isinstance(
                        prev_entry.get("enabled"), bool
                    ):
                        h_entry["enabled"] = prev_entry["enabled"]
        except Exception:
            pass
    hooks_path.write_text(
        json.dumps(hooks_cfg, indent=2) + "\n", encoding="utf-8"
    )

    # 2b. Copy root STABILITY.md if present
    stability_src = root / "STABILITY.md"
    if stability_src.is_file():
        shutil.copy2(stability_src, plugin_dir / "STABILITY.md")

    # 3. Sync rules/AGENTS.md
    rules_src = (
        root / "rules" / "AGENTS.md"
        if (root / "rules" / "AGENTS.md").is_file()
        else root / ".agents" / "rules" / "AGENTS.md"
    )
    rules_dst_dir = plugin_dir / "rules"
    rules_dst_dir.mkdir(parents=True, exist_ok=True)
    if rules_src.is_file():
        shutil.copy2(rules_src, rules_dst_dir / "AGENTS.md")

    # 4. Sync scripts/ and scripts/hooks/
    scripts_src = root / "scripts"
    scripts_dst = plugin_dir / "scripts"
    scripts_dst.mkdir(parents=True, exist_ok=True)
    (scripts_dst / "hooks").mkdir(parents=True, exist_ok=True)

    copied_scripts: list[str] = []
    for py_file in scripts_src.glob("*.py"):
        dst_file = scripts_dst / py_file.name
        shutil.copy2(py_file, dst_file)
        dst_file.chmod(0o750)
        copied_scripts.append(py_file.name)

    hooks_src = scripts_src / "hooks"
    if hooks_src.is_dir():
        for hook_file in hooks_src.glob("*.py"):
            dst_hook = scripts_dst / "hooks" / hook_file.name
            shutil.copy2(hook_file, dst_hook)
            dst_hook.chmod(0o750)
            copied_scripts.append(f"hooks/{hook_file.name}")

    # Maintain backward-compatible script shims in scripts/ root
    if (scripts_dst / "hooks" / "auto_sync_vault.py").is_file():
        shutil.copy2(
            scripts_dst / "hooks" / "auto_sync_vault.py",
            scripts_dst / "on_stop_suggest_compounding.py",
        )
    if (scripts_dst / "hooks" / "log_tool_failure.py").is_file():
        shutil.copy2(
            scripts_dst / "hooks" / "log_tool_failure.py",
            scripts_dst / "on_error_capture_wikiskill.py",
        )

    # 4b. Keep embedded skill scripts in .agents/skills/ byte-for-byte synced with scripts/
    embedded_pairs = [
        ("extract_source.py", ".agents/skills/ingest/scripts/extract_source.py"),
        ("analyze_trace.py", ".agents/skills/wikiskill/scripts/analyze_trace.py"),
    ]
    for src_name, rel_dst in embedded_pairs:
        src_p = scripts_src / src_name
        dst_p = root / rel_dst
        if src_p.is_file() and dst_p.parent.is_dir():
            shutil.copy2(src_p, dst_p)

    # 5. Sync skills/
    skills_src = (
        root / ".agents" / "skills"
        if (root / ".agents" / "skills").is_dir()
        else root / "skills"
    )
    skills_dst = plugin_dir / "skills"
    skills_dst.mkdir(parents=True, exist_ok=True)
    copied_skills: list[str] = []

    if skills_src.is_dir():
        for skill_folder in sorted(skills_src.iterdir()):
            if not skill_folder.is_dir() or not (skill_folder / "SKILL.md").is_file():
                continue
            # Skip internal duplicate wrapper if 'ingest' is already present
            if (
                skill_folder.name == "knowledge-compiler"
                and (skills_src / "ingest").is_dir()
            ):
                continue
            target_skill = skills_dst / skill_folder.name
            if target_skill.exists():
                shutil.rmtree(target_skill)
            shutil.copytree(skill_folder, target_skill)
            copied_skills.append(skill_folder.name)

    # 5b. Sync bundled clean-room starter vault (examples/starter-vault/) for read-only graph preview
    starter_src = root / "examples" / "starter-vault"
    if starter_src.is_dir() and not starter_src.is_symlink():
        starter_dst = plugin_dir / "examples" / "starter-vault"
        if starter_dst.exists():
            shutil.rmtree(starter_dst)
        starter_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(starter_src, starter_dst)

    # 6. Install WebGL Graph UI Sidecar for AuxPane
    sidecar_manifest = {
        "command": "python3",
        "args": ["-B", "-u", "server.py"],
        "restart_policy": "always",
        "display_name": "Knowledge Graph",
        "description": "Interactive 2D/3D graph of your Open Knowledge Format wiki with a 21-note sample preview, search, and Markdown reader (v1.2.0).",
        "has_web_ui": True,
        "ui_config": {
            "display_name": "Vault WebGL Graph",
            "views": [
                {
                    "path": "/",
                    "entrypoint": "SIDECAR_UI_ENTRYPOINT_AUX_PANE",
                    "title": "Vault WebGL Graph",
                }
            ],
        },
    }
    sidecar_server_code = (
        "#!/usr/bin/env python3\n"
        '"""UI Sidecar entrypoint for the Knowledge Compiler WebGL Graph Visualizer."""\n'
        "from __future__ import annotations\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        "_plugin_scripts = Path(os.path.abspath(__file__)).parents[2] / 'scripts'\n"
        "if _plugin_scripts.is_dir() and str(_plugin_scripts) not in sys.path:\n"
        "    sys.path.insert(0, str(_plugin_scripts))\n\n"
        "import vault_graph\n\n"
        "if __name__ == '__main__':\n"
        "    port = int(os.environ.get('ANTIGRAVITY_SIDECAR_WEB_PORT', '8765'))\n"
        "    vault = vault_graph.resolve_default_vault(None)\n"
        "    vault_graph.serve_vault_graph(vault, port=port, sidecar_mode=True)\n"
    )

    sidecar_dir = plugin_dir / "sidecars" / "vault_graph"
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    (sidecar_dir / "sidecar.json").write_text(
        json.dumps(sidecar_manifest, indent=2) + "\n", encoding="utf-8"
    )
    srv_file = sidecar_dir / "server.py"
    srv_file.write_text(sidecar_server_code, encoding="utf-8")
    srv_file.chmod(0o750)

    # Remove legacy standalone global sidecar copy so the host does not list duplicate
    # "Vault WebGL Graph" extensions (`knowledge-compiler/vault_graph` + `vault_graph`).
    home_resolved = (home_dir or Path.home()).expanduser().resolve()
    legacy_sidecar_dir = home_resolved / ".gemini" / "config" / "sidecars" / "vault_graph"
    if legacy_sidecar_dir.exists() and legacy_sidecar_dir.resolve() != sidecar_dir.resolve():
        shutil.rmtree(legacy_sidecar_dir)

    # 7. Apply optional --enable-hooks / --disable-hooks toggle via vault_hooks
    hooks_result: dict | None = None
    _scripts_parent = str(Path(__file__).resolve().parent)
    if _scripts_parent not in sys.path:
        sys.path.insert(0, _scripts_parent)
    try:
        import vault_hooks  # type: ignore[import-not-found]
    except ImportError:
        from scripts import vault_hooks  # type: ignore[no-redef]

    if enable_hooks:
        grp = enable_hooks if isinstance(enable_hooks, str) else "all"
        hooks_result = vault_hooks.set_hooks_state(
            "enable",
            hooks_group=grp,
            scope="auto",
            plugin_dir=plugin_dir,
            home_dir=home_resolved,
        )
    elif disable_hooks:
        grp = disable_hooks if isinstance(disable_hooks, str) else "all"
        hooks_result = vault_hooks.set_hooks_state(
            "disable",
            hooks_group=grp,
            scope="auto",
            plugin_dir=plugin_dir,
            home_dir=home_resolved,
        )
    else:
        hooks_result = vault_hooks.get_hooks_status(
            plugin_dir=plugin_dir,
            home_dir=home_resolved,
        )

    return {
        "success": True,
        "plugin_dir": str(plugin_dir),
        "detection": detection,
        "copied_scripts": sorted(copied_scripts),
        "copied_skills": copied_skills,
        "hooks_status": hooks_result,
    }


def sync_repo_marketplace_bundle(repo_root: Path | None = None) -> dict:
    """Populate root-level Marketplace plugin layout (`plugin.json`, `hooks.json`, `assets/`, `sidecars/`, `skills/`)."""
    root = (repo_root or Path(__file__).resolve().parent.parent).resolve()

    # 1. Root plugin.json & .agents/hooks.json + root hooks.json
    (root / "plugin.json").write_text(
        json.dumps(MARKETPLACE_PLUGIN_MANIFEST, indent=2) + "\n", encoding="utf-8"
    )
    (root / "hooks.json").write_text(
        json.dumps(REPO_HOOKS_CONFIG, indent=2) + "\n", encoding="utf-8"
    )
    if (root / ".agents").is_dir():
        (root / ".agents" / "hooks.json").write_text(
            json.dumps(REPO_HOOKS_CONFIG, indent=2) + "\n", encoding="utf-8"
        )

    # 2. Root assets/logo.svg (keep existing animated crystal SVG if present)
    assets_dir = root / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    if not (assets_dir / "logo.svg").is_file():
        (assets_dir / "logo.svg").write_text(LOGO_SVG, encoding="utf-8")

    # 3. Root sidecars/vault_graph/
    sidecar_manifest = {
        "command": "python3",
        "args": ["-B", "-u", "server.py"],
        "restart_policy": "always",
        "display_name": "Knowledge Graph",
        "description": "Interactive 2D/3D graph of your Open Knowledge Format wiki with a 21-note sample preview, search, and Markdown reader (v1.2.0).",
        "has_web_ui": True,
        "ui_config": {
            "display_name": "Vault WebGL Graph",
            "views": [
                {
                    "path": "/",
                    "entrypoint": "SIDECAR_UI_ENTRYPOINT_AUX_PANE",
                    "title": "Vault WebGL Graph",
                }
            ],
        },
    }
    sidecar_server_code = (
        "#!/usr/bin/env python3\n"
        '"""UI Sidecar entrypoint for the Knowledge Compiler WebGL Graph Visualizer."""\n'
        "from __future__ import annotations\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        "_plugin_scripts = Path(os.path.abspath(__file__)).parents[2] / 'scripts'\n"
        "if _plugin_scripts.is_dir() and str(_plugin_scripts) not in sys.path:\n"
        "    sys.path.insert(0, str(_plugin_scripts))\n\n"
        "import vault_graph\n\n"
        "if __name__ == '__main__':\n"
        "    port = int(os.environ.get('ANTIGRAVITY_SIDECAR_WEB_PORT', '8765'))\n"
        "    vault = vault_graph.resolve_default_vault(None)\n"
        "    vault_graph.serve_vault_graph(vault, port=port, sidecar_mode=True)\n"
    )
    sc_dir = root / "sidecars" / "vault_graph"
    sc_dir.mkdir(parents=True, exist_ok=True)
    (sc_dir / "sidecar.json").write_text(
        json.dumps(sidecar_manifest, indent=2) + "\n", encoding="utf-8"
    )
    sc_srv = sc_dir / "server.py"
    sc_srv.write_text(sidecar_server_code, encoding="utf-8")
    sc_srv.chmod(0o750)

    # 4. Root skills/ synced from .agents/skills/
    skills_src = root / ".agents" / "skills"
    skills_dst = root / "skills"
    skills_dst.mkdir(parents=True, exist_ok=True)
    synced_skills: list[str] = []
    if skills_src.is_dir():
        for skill_folder in sorted(skills_src.iterdir()):
            if not skill_folder.is_dir() or not (skill_folder / "SKILL.md").is_file():
                continue
            if (
                skill_folder.name == "knowledge-compiler"
                and (skills_src / "ingest").is_dir()
            ):
                continue
            target_skill = skills_dst / skill_folder.name
            if target_skill.exists():
                shutil.rmtree(target_skill)
            shutil.copytree(skill_folder, target_skill)
            synced_skills.append(skill_folder.name)

    return {"root": str(root), "synced_skills": synced_skills}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install Knowledge Compiler global plugin for Antigravity CLI."
    )
    parser.add_argument(
        "--target-dir",
        type=str,
        default=None,
        help="Optional override directory for plugin installation.",
    )
    parser.add_argument(
        "--sync-repo-bundle",
        action="store_true",
        help="Also populate root-level Marketplace bundle files (plugin.json, hooks.json, assets/, sidecars/, skills/).",
    )
    hook_toggle = parser.add_mutually_exclusive_group()
    hook_toggle.add_argument(
        "--enable-hooks",
        nargs="?",
        const="all",
        default=None,
        choices=("all", "sync", "wikiskill"),
        help="Enable lifecycle hooks after installing (all, sync, or wikiskill).",
    )
    hook_toggle.add_argument(
        "--disable-hooks",
        nargs="?",
        const="all",
        default=None,
        choices=("all", "sync", "wikiskill"),
        help="Disable lifecycle hooks after installing (all, sync, or wikiskill).",
    )
    args = parser.parse_args()

    target = Path(args.target_dir) if args.target_dir else None
    result = install_global_plugin(
        target_plugin_dir=target,
        enable_hooks=args.enable_hooks,
        disable_hooks=args.disable_hooks,
    )
    if args.sync_repo_bundle:
        sync_repo_marketplace_bundle()
    det = result["detection"]

    harnesses = []
    if det.get(_LEGACY_HARNESS_KEY):
        harnesses.append("Host CLI")
    if det["antigravity"]:
        harnesses.append("Antigravity")
    if not harnesses:
        harnesses.append("Default (~/.gemini/config)")

    print("============================================================")
    print(" Knowledge Compiler — Global Plugin Installer (v1.2.0)")
    print("============================================================")
    print(f" Detected Harnesses : {', '.join(harnesses)}")
    print(f" Plugin Directory   : {result['plugin_dir']}")
    print(f" Installed Skills   : {', '.join(result['copied_skills'])}")
    print(f" Installed Scripts  : {', '.join(result['copied_scripts'])}")
    print("============================================================")


if __name__ == "__main__":
    main()
