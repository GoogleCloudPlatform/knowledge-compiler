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
"""Manage Knowledge Compiler lifecycle hooks across plugin, user, and workspace scopes."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any

HOOK_DEFS: dict[str, dict[str, Any]] = {
    "vault-session-start": {
        "script": "session_sync.py",
        "events": ("SessionStart", "PreInvocation"),
        "timeout": 15,
        "user_key": "kc-user-session-start",
        "group": "sync",
    },
    "vault-stop-hook": {
        "script": "auto_sync_vault.py",
        "events": ("Stop",),
        "timeout": 15,
        "user_key": "kc-user-stop-hook",
        "group": "sync",
    },
    "wikiskill-error-recorder": {
        "script": "log_tool_failure.py",
        "events": ("PostToolUse",),
        "timeout": 10,
        "user_key": "kc-user-wikiskill-recorder",
        "group": "wikiskill",
    },
}

HOOK_GROUPS: dict[str, tuple[str, ...]] = {
    "all": ("vault-session-start", "vault-stop-hook", "wikiskill-error-recorder"),
    "sync": ("vault-session-start", "vault-stop-hook"),
    "wikiskill": ("wikiskill-error-recorder",),
}


def resolve_plugin_dir(plugin_dir: str | Path | None = None) -> Path:
    """Resolve the active Knowledge Compiler plugin directory."""
    if plugin_dir is not None:
        return Path(plugin_dir).expanduser().resolve()
    env_dir = (os.environ.get("KC_PLUGIN_DIR") or "").strip()
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    return Path(__file__).resolve().parent.parent


def resolve_user_config_dir(
    config_dir: str | Path | None = None,
    home_dir: str | Path | None = None,
) -> Path:
    """Resolve the host CLI user configuration directory holding user hooks.json."""
    if config_dir is not None:
        return Path(config_dir).expanduser().resolve()
    env_cfg = (os.environ.get("KC_HOOKS_CONFIG_DIR") or "").strip()
    if env_cfg:
        return Path(env_cfg).expanduser().resolve()
    home = (
        Path(home_dir).expanduser().resolve()
        if home_dir is not None
        else Path.home().expanduser().resolve()
    )
    gemini_cfg = home / ".gemini" / "config"
    if gemini_cfg.is_dir() and not gemini_cfg.is_symlink():
        return gemini_cfg
    return home / ".agents"


_SHARED_CLOUD_PREFIXES: tuple[str, ...] = (
    "/mnt/shared/cloud/",
    "/Volumes/shared/cloud/",
)


def _is_writable_hooks_target(hooks_path: Path) -> bool:
    """Return True if hooks_path and its parent directory accept atomic writes (not EROFS/0555)."""
    parent = hooks_path.parent
    try:
        resolved_parent = parent.resolve().as_posix()
    except OSError:
        resolved_parent = str(parent)
    if any(resolved_parent.startswith(pfx) for pfx in _SHARED_CLOUD_PREFIXES):
        return False
    if not parent.is_dir() or parent.is_symlink() or hooks_path.is_symlink():
        return False
    if hooks_path.exists() and not os.access(hooks_path, os.W_OK):
        return False
    probe = parent / f".kc_hook_probe_{os.getpid()}_{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(probe, flags, 0o600)
        os.close(fd)
        probe.unlink(missing_ok=True)
    except OSError:
        return False
    return True


def _load_json_dict(path: Path) -> dict[str, Any]:
    """Load a JSON object from path, returning empty dict if absent."""
    if path.is_symlink():
        raise OSError(f"Refusing symlinked hooks file: {path}")
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


def _atomic_write_json(target: Path, data: dict[str, Any]) -> None:
    """Atomically write JSON dict to target with symlink guard and fsync."""
    if target.is_symlink() or target.parent.is_symlink():
        raise OSError(f"Refusing symlink target for hooks file: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.is_symlink():
        raise OSError(f"Refusing symlink parent directory: {target.parent}")
    tmp_path = target.parent / f".{target.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp_path, flags, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, target)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _build_hook_entry(
    hook_id: str,
    *,
    enabled: bool,
    plugin_dir: Path | None = None,
    workspace_relative: bool = False,
) -> dict[str, Any]:
    """Build a standard hook entry dictionary for plugin, user, or workspace hooks.json."""
    spec = HOOK_DEFS[hook_id]
    script_name = spec["script"]
    if workspace_relative:
        cmd = f"python3 -B scripts/hooks/{script_name} || exit 0"
    else:
        assert plugin_dir is not None
        script_abs = (plugin_dir / "scripts" / "hooks" / script_name).resolve().as_posix()
        cmd = f'python3 -B "{script_abs}" || exit 0'

    entry: dict[str, Any] = {"enabled": bool(enabled)}
    timeout = int(spec["timeout"])
    events: tuple[str, ...] = spec["events"]
    if events == ("PostToolUse",):
        entry["PostToolUse"] = [
            {
                "matcher": ".*",
                "hooks": [
                    {
                        "type": "command",
                        "command": cmd,
                        "timeout": timeout,
                    }
                ],
            }
        ]
    else:
        for ev_name in events:
            entry[ev_name] = [
                {
                    "type": "command",
                    "command": cmd,
                    "timeout": timeout,
                }
            ]
    return entry


def get_hooks_status(
    *,
    plugin_dir: str | Path | None = None,
    config_dir: str | Path | None = None,
    home_dir: str | Path | None = None,
    vault_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Return effective status of all Knowledge Compiler lifecycle hooks."""
    p_dir = resolve_plugin_dir(plugin_dir)
    u_dir = resolve_user_config_dir(config_dir=config_dir, home_dir=home_dir)
    plugin_hooks_file = p_dir / "hooks.json"
    user_hooks_file = u_dir / "hooks.json"

    plugin_data: dict[str, Any] = {}
    user_data: dict[str, Any] = {}
    if plugin_hooks_file.is_file() and not plugin_hooks_file.is_symlink():
        try:
            plugin_data = _load_json_dict(plugin_hooks_file)
        except Exception:
            plugin_data = {}
    if user_hooks_file.is_file() and not user_hooks_file.is_symlink():
        try:
            user_data = _load_json_dict(user_hooks_file)
        except Exception:
            user_data = {}

    workspace_hooks_file: Path | None = None
    workspace_data: dict[str, Any] = {}
    if vault_dir is not None:
        v_dir = Path(vault_dir).expanduser().resolve()
        workspace_hooks_file = v_dir / ".agents" / "hooks.json"
        if workspace_hooks_file.is_file() and not workspace_hooks_file.is_symlink():
            try:
                workspace_data = _load_json_dict(workspace_hooks_file)
            except Exception:
                workspace_data = {}

    is_readonly = not _is_writable_hooks_target(plugin_hooks_file)

    hooks_report: dict[str, dict[str, Any]] = {}
    for hook_id, spec in HOOK_DEFS.items():
        u_key = spec["user_key"]
        p_entry = plugin_data.get(hook_id)
        u_entry = user_data.get(u_key)
        w_entry = workspace_data.get(hook_id)

        p_enabled = bool(p_entry.get("enabled", False)) if isinstance(p_entry, dict) else False
        u_enabled = bool(u_entry.get("enabled", False)) if isinstance(u_entry, dict) else False
        w_enabled = bool(w_entry.get("enabled", False)) if isinstance(w_entry, dict) else False

        effective_enabled = p_enabled or u_enabled or w_enabled
        if u_enabled:
            active_scope = "user"
        elif p_enabled:
            active_scope = "plugin"
        elif w_enabled:
            active_scope = "workspace"
        else:
            active_scope = "disabled"

        hooks_report[hook_id] = {
            "group": spec["group"],
            "user_mirror_key": u_key,
            "effective_enabled": effective_enabled,
            "plugin_enabled": p_enabled,
            "user_mirror_enabled": u_enabled,
            "workspace_enabled": w_enabled,
            "active_scope": active_scope,
        }

    return {
        "success": True,
        "plugin_dir": str(p_dir),
        "plugin_hooks_file": str(plugin_hooks_file),
        "is_readonly_plugin": is_readonly,
        "user_hooks_file": str(user_hooks_file),
        "workspace_hooks_file": str(workspace_hooks_file) if workspace_hooks_file else None,
        "hooks": hooks_report,
    }


def set_hooks_state(
    action: str,
    *,
    hooks_group: str = "all",
    scope: str = "auto",
    plugin_dir: str | Path | None = None,
    config_dir: str | Path | None = None,
    home_dir: str | Path | None = None,
    vault_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Enable or disable selected Knowledge Compiler hooks cleanly."""
    if action not in ("enable", "disable"):
        return {"success": False, "error": f"Unsupported action: {action}"}
    if hooks_group not in HOOK_GROUPS:
        return {"success": False, "error": f"Unknown hook group: {hooks_group}"}
    if scope not in ("auto", "plugin", "user", "workspace"):
        return {"success": False, "error": f"Unknown scope: {scope}"}

    enable_flag = action == "enable"
    selected_ids = HOOK_GROUPS[hooks_group]
    p_dir = resolve_plugin_dir(plugin_dir)
    u_dir = resolve_user_config_dir(config_dir=config_dir, home_dir=home_dir)
    plugin_hooks_file = p_dir / "hooks.json"
    user_hooks_file = u_dir / "hooks.json"

    is_writable_plugin = _is_writable_hooks_target(plugin_hooks_file)

    if scope == "plugin" and not is_writable_plugin:
        return {
            "success": False,
            "error": (
                f"Plugin hooks.json is read-only ({plugin_hooks_file}). "
                "Re-run with --scope auto or --scope user to manage hooks in user config."
            ),
            "plugin_hooks_file": str(plugin_hooks_file),
            "is_readonly_plugin": True,
        }

    if scope == "workspace":
        if vault_dir is None:
            return {
                "success": False,
                "error": "--vault is required when using --scope workspace.",
            }
        v_dir = Path(vault_dir).expanduser().resolve()
        if not v_dir.is_dir() or v_dir.is_symlink():
            return {"success": False, "error": f"Invalid vault directory: {v_dir}"}
        ws_hooks_file = v_dir / ".agents" / "hooks.json"
        if ws_hooks_file.is_symlink():
            return {"success": False, "error": f"Refusing symlinked hooks file: {ws_hooks_file}"}
        try:
            ws_data = _load_json_dict(ws_hooks_file)
            for hook_id in selected_ids:
                existing = ws_data.get(hook_id)
                if isinstance(existing, dict):
                    updated = copy.deepcopy(existing)
                    updated["enabled"] = enable_flag
                else:
                    updated = _build_hook_entry(
                        hook_id, enabled=enable_flag, workspace_relative=True
                    )
                ws_data[hook_id] = updated
            _atomic_write_json(ws_hooks_file, ws_data)
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc)}
        status_rep = get_hooks_status(
            plugin_dir=p_dir, config_dir=u_dir, home_dir=home_dir, vault_dir=v_dir
        )
        status_rep["applied_scope"] = "workspace"
        status_rep["action"] = action
        status_rep["selected_hooks"] = list(selected_ids)
        return status_rep

    effective_scope = scope
    if scope == "auto":
        effective_scope = "plugin" if is_writable_plugin else "user"

    if effective_scope == "plugin":
        try:
            p_data = _load_json_dict(plugin_hooks_file)
            for hook_id in selected_ids:
                existing = p_data.get(hook_id)
                if isinstance(existing, dict):
                    updated = copy.deepcopy(existing)
                    updated["enabled"] = enable_flag
                else:
                    updated = _build_hook_entry(
                        hook_id, enabled=enable_flag, plugin_dir=p_dir
                    )
                p_data[hook_id] = updated
            _atomic_write_json(plugin_hooks_file, p_data)

            # Remove any duplicate kc-user-* mirror keys when writable plugin hooks.json succeeds
            if user_hooks_file.exists() and not user_hooks_file.is_symlink():
                u_data = _load_json_dict(user_hooks_file)
                removed = False
                for hook_id in selected_ids:
                    u_key = HOOK_DEFS[hook_id]["user_key"]
                    if u_key in u_data:
                        u_data.pop(u_key, None)
                        removed = True
                if removed:
                    _atomic_write_json(user_hooks_file, u_data)
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc)}
    else:
        # User scope: write/remove distinct kc-user-* entries without touching unrelated hooks
        try:
            u_data = _load_json_dict(user_hooks_file)
            changed = False
            if enable_flag:
                for hook_id in selected_ids:
                    u_key = HOOK_DEFS[hook_id]["user_key"]
                    u_data[u_key] = _build_hook_entry(
                        hook_id, enabled=True, plugin_dir=p_dir
                    )
                    changed = True
            else:
                for hook_id in selected_ids:
                    u_key = HOOK_DEFS[hook_id]["user_key"]
                    if u_key in u_data:
                        u_data.pop(u_key, None)
                        changed = True
            if changed or not user_hooks_file.exists():
                _atomic_write_json(user_hooks_file, u_data)
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc)}

    status_rep = get_hooks_status(
        plugin_dir=p_dir, config_dir=u_dir, home_dir=home_dir, vault_dir=vault_dir
    )
    status_rep["applied_scope"] = effective_scope
    status_rep["action"] = action
    status_rep["selected_hooks"] = list(selected_ids)
    return status_rep


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect, enable, or disable Knowledge Compiler lifecycle hooks."
    )
    parser.add_argument(
        "action",
        choices=("status", "enable", "disable"),
        help="Action to perform.",
    )
    parser.add_argument(
        "--hooks",
        choices=tuple(HOOK_GROUPS.keys()),
        default="all",
        help="Hook group to target (default: all).",
    )
    parser.add_argument(
        "--scope",
        choices=("auto", "plugin", "user", "workspace"),
        default="auto",
        help="Where hook settings should be written (default: auto).",
    )
    parser.add_argument(
        "--plugin-dir",
        default=None,
        help="Override Knowledge Compiler plugin directory.",
    )
    parser.add_argument(
        "--config-dir",
        default=None,
        help="Override user config directory holding hooks.json.",
    )
    parser.add_argument(
        "--vault",
        default=None,
        help="Vault root directory (used with --scope workspace).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON.",
    )
    args = parser.parse_args(argv)

    if args.action == "status":
        res = get_hooks_status(
            plugin_dir=args.plugin_dir,
            config_dir=args.config_dir,
            vault_dir=args.vault,
        )
    else:
        res = set_hooks_state(
            args.action,
            hooks_group=args.hooks,
            scope=args.scope,
            plugin_dir=args.plugin_dir,
            config_dir=args.config_dir,
            vault_dir=args.vault,
        )

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        if not res.get("success", False):
            print(f"Error: {res.get('error', 'Hook operation failed')}", file=sys.stderr)
        else:
            print(f"Plugin hooks.json : {res['plugin_hooks_file']} ({'read-only' if res['is_readonly_plugin'] else 'writable'})")
            print(f"User hooks.json   : {res['user_hooks_file']}")
            if res.get("workspace_hooks_file"):
                print(f"Workspace hooks   : {res['workspace_hooks_file']}")
            for h_id, h_info in res["hooks"].items():
                state_lbl = "ENABLED" if h_info["effective_enabled"] else "disabled"
                print(f"  - {h_id}: {state_lbl} (scope={h_info['active_scope']})")

    return 0 if res.get("success", False) else 2


if __name__ == "__main__":
    sys.exit(main())
