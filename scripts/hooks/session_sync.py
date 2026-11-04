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
"""session_sync.py - Generic Dual-Harness Startup & Continue Sync Hook.

Executes before Turn 1 across both brand-new sessions (`SessionStart`: `agy`, `/new`)
and resumed/continued sessions (`PreInvocation` with `invocationNum == 0`: `agy -c`,
`--continue`, `/resume`).
  1. `$KC_VAULT_PATH` or `$OBSIDIAN_VAULT_PATH` (default `~/knowledge-vault` or `~/ObsidianVault`):
     - If backed by a Git `origin` remote (`main` or `master`), fetches and fast-forwards
       (or executes an OKF-aware union rebase across `log.md`, `index.md`, and YAML
       frontmatter `updated:` dates) BEFORE the agent reads or edits any vault files.
     - If local-only (no `origin` remote) or offline, skips cleanly in <50ms.
     - Never leaves `<<<<<<<` conflict markers on disk: if a genuine same-line prose
       collision exists, aborts the rebase cleanly and injects a concise `systemMessage`
       notifying the agent on Turn 1.
  2. Optional Shared Patterns Repository (`$OKF_PATTERNS_PATH`):
     - If cloned, clean on `main`/`master`, and reachable, fast-forwards to `origin/<branch>`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

# Allow direct CLI execution as well as package import
HOOKS_DIR = Path(os.path.abspath(__file__)).parent
SCRIPTS_DIR = HOOKS_DIR.parent
for _p in (str(HOOKS_DIR), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from auto_sync_vault import (  # noqa: E402
    _check_and_mark_debounce,
    _run_vault_lint_fix,
    detect_harness,
    get_active_branch,
    get_default_vault_path,
    has_origin_remote,
    is_rebase_in_progress,
    merge_index_markdown,
    merge_log_markdown,
    rebase_onto_origin,
    run_cmd,
)
from init_vault import init_vault  # noqa: E402


def get_default_ce_patterns_path() -> Path:
    env_path = os.environ.get("OKF_PATTERNS_PATH") or os.environ.get("OKF_PATTERNS_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return Path("~/shared-okf-patterns").expanduser().resolve()


def get_default_compiler_repo_path() -> Path:
    env_path = os.environ.get("KC_COMPILER_REPO_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return Path("~/knowledge-compiler").expanduser().resolve()


def _resolve_stash_pop_unmerged(vault_path: Path) -> bool:
    """Resolve `log.md` and `index.md` unmerged entries after `git stash pop` if possible."""
    unmerged_proc = run_cmd(
        ["git", "diff", "--name-only", "--diff-filter=U"], cwd=vault_path, timeout=5
    )
    files = [ln.strip() for ln in unmerged_proc.stdout.splitlines() if ln.strip()]
    for rel_path in files:
        norm = rel_path.replace("\\", "/")
        if norm not in ("log.md", "index.md"):
            return False
        # During `git stash pop`, :2: (Updated upstream) is remote/HEAD and :3: (Stashed changes) is local
        s2 = run_cmd(["git", "show", f":2:{rel_path}"], cwd=vault_path, timeout=5)
        s3 = run_cmd(["git", "show", f":3:{rel_path}"], cwd=vault_path, timeout=5)
        if s2.returncode != 0 or s3.returncode != 0:
            return False
        merged = (
            merge_log_markdown(s2.stdout, s3.stdout)
            if norm == "log.md"
            else merge_index_markdown(s2.stdout, s3.stdout)
        )
        if "<<<<<<<" in merged:
            return False
        (vault_path / rel_path).write_text(merged, encoding="utf-8")
        if run_cmd(["git", "add", "--", rel_path], cwd=vault_path, timeout=5).returncode != 0:
            return False
    return True


def _sync_vault_on_session_start(vault_path: Path) -> tuple[dict, list[str]]:
    notices: list[str] = []
    if not vault_path.exists():
        if os.environ.get("KC_AUTO_INIT_VAULT") == "1":
            init_res = init_vault(vault_path, quiet=True, init_git=False)
            if init_res.get("success"):
                return {"status": "initialized_local_only", "path": str(vault_path)}, notices
        return {"status": "not_git_repo", "path": str(vault_path)}, notices
    if not (vault_path / ".git").exists():
        return {"status": "not_git_repo", "path": str(vault_path)}, notices

    if is_rebase_in_progress(vault_path):
        run_cmd(["git", "rebase", "--abort"], cwd=vault_path, timeout=8)

    if not has_origin_remote(vault_path):
        return {"status": "local_only", "path": str(vault_path)}, notices

    branch = get_active_branch(vault_path)
    fetch_proc = run_cmd(
        ["git", "fetch", "origin", branch], cwd=vault_path, timeout=6
    )
    if fetch_proc.returncode != 0:
        return {"status": "offline", "path": str(vault_path)}, notices

    head_proc = run_cmd(["git", "rev-parse", "HEAD"], cwd=vault_path, timeout=5)
    remote_proc = run_cmd(
        ["git", "rev-parse", f"origin/{branch}"], cwd=vault_path, timeout=5
    )
    if head_proc.returncode != 0 or remote_proc.returncode != 0:
        return {"status": "no_remote_branch", "path": str(vault_path)}, notices

    local_sha = head_proc.stdout.strip()
    remote_sha = remote_proc.stdout.strip()
    if local_sha == remote_sha:
        return {"status": "up_to_date", "sha": local_sha[:7]}, notices

    # Check if local is strictly ahead of origin/<branch> (unpushed commits from offline work, remote didn't move)
    remote_is_ancestor = (
        run_cmd(
            ["git", "merge-base", "--is-ancestor", f"origin/{branch}", "HEAD"],
            cwd=vault_path,
            timeout=5,
        ).returncode
        == 0
    )
    if remote_is_ancestor:
        push_proc = run_cmd(
            ["git", "push", "origin", branch], cwd=vault_path, timeout=8
        )
        return {
            "status": "pushed_pending",
            "pushed": push_proc.returncode == 0,
        }, notices

    # Remote has new commits -> stash any uncommitted working tree edits first
    dirty = bool(
        run_cmd(["git", "status", "--porcelain"], cwd=vault_path, timeout=5).stdout.strip()
    )
    stashed = False
    if dirty:
        stash_proc = run_cmd(
            ["git", "stash", "push", "-u", "-m", "kc-session-start-autostash"],
            cwd=vault_path,
            timeout=8,
        )
        stashed = (
            stash_proc.returncode == 0
            and "No local changes to save" not in stash_proc.stdout
        )

    local_is_ancestor = (
        run_cmd(
            ["git", "merge-base", "--is-ancestor", "HEAD", f"origin/{branch}"],
            cwd=vault_path,
            timeout=5,
        ).returncode
        == 0
    )

    sync_mode = "fast_forward"
    if local_is_ancestor:
        ff_proc = run_cmd(
            ["git", "merge", "--ff-only", f"origin/{branch}"],
            cwd=vault_path,
            timeout=8,
        )
        if ff_proc.returncode != 0:
            if stashed:
                run_cmd(["git", "stash", "pop"], cwd=vault_path, timeout=8)
            return {"status": "ff_failed"}, notices
    else:
        sync_mode = "rebased"
        rb_res = rebase_onto_origin(vault_path, branch=branch)
        if not rb_res.get("ok"):
            raw_conflicted = str(rb_res.get("conflicted_file", "a vault note"))
            conflicted = re.sub(r"[^a-zA-Z0-9._/ -]", "_", raw_conflicted)[:120]
            if stashed:
                run_cmd(["git", "stash", "pop"], cwd=vault_path, timeout=8)
            notices.append(
                f"[Knowledge Compiler] Vault sync paused on `{conflicted}` because local "
                f"and `origin/{branch}` edited the same prose lines (`git rebase --abort` ran "
                f"cleanly so 0 conflict markers are on disk). Rebase and reconcile `{conflicted}` "
                f"before editing vault notes."
            )
            return {
                "status": "conflict_aborted",
                "conflicted_file": conflicted,
            }, notices

    # Restore stash if created
    if stashed:
        pop_proc = run_cmd(["git", "stash", "pop"], cwd=vault_path, timeout=8)
        if pop_proc.returncode != 0:
            if _resolve_stash_pop_unmerged(vault_path):
                run_cmd(["git", "stash", "drop", "-q"], cwd=vault_path, timeout=5)
                run_cmd(["git", "reset", "HEAD"], cwd=vault_path, timeout=5)
            else:
                # Reset working tree cleanly; Git preserves stash@{0} when pop conflicts!
                run_cmd(["git", "reset", "--hard", "HEAD"], cwd=vault_path, timeout=5)
                notices.append(
                    f"[Knowledge Compiler] Fast-forwarded `{vault_path.name}` to `origin/{branch}` "
                    f"and preserved overlapping uncommitted local edits safely in `stash@{{0}}` "
                    f"(0 conflict markers on disk). Inspect `git stash show -p` to merge them."
                )

    _run_vault_lint_fix(vault_path)

    # If we rebased local commits onto origin/<branch>, push the rebased history back up
    if sync_mode == "rebased" and not dirty:
        post_lint_dirty = bool(
            run_cmd(["git", "status", "--porcelain"], cwd=vault_path, timeout=5).stdout.strip()
        )
        if post_lint_dirty:
            run_cmd(["git", "add", "-A"], cwd=vault_path, timeout=5)
            run_cmd(
                ["git", "commit", "--amend", "--no-edit"], cwd=vault_path, timeout=5
            )
        run_cmd(["git", "push", "origin", branch], cwd=vault_path, timeout=8)

    return {"status": sync_mode, "path": str(vault_path)}, notices


def _fast_forward_clean_shared_repo(repo_path: Path) -> dict:
    """Fast-forward a clean shared repository (`main` or `master`) from `origin`."""
    if not repo_path.exists() or not (repo_path / ".git").exists():
        return {"status": "missing"}
    if not has_origin_remote(repo_path):
        return {"status": "no_origin"}

    branch = get_active_branch(repo_path)
    if branch not in ("main", "master"):
        return {"status": "feature_branch", "branch": branch}

    dirty = bool(
        run_cmd(["git", "status", "--porcelain"], cwd=repo_path, timeout=5).stdout.strip()
    )
    if dirty:
        return {"status": "dirty_skipped"}

    before_sha = run_cmd(
        ["git", "rev-parse", "HEAD"], cwd=repo_path, timeout=5
    ).stdout.strip()
    if run_cmd(["git", "fetch", "origin", branch], cwd=repo_path, timeout=5).returncode != 0:
        return {"status": "offline"}

    remote_sha = run_cmd(
        ["git", "rev-parse", f"origin/{branch}"], cwd=repo_path, timeout=5
    ).stdout.strip()
    if not remote_sha or before_sha == remote_sha:
        return {"status": "up_to_date", "updated": False, "sha": before_sha[:7]}

    is_anc = (
        run_cmd(
            ["git", "merge-base", "--is-ancestor", "HEAD", f"origin/{branch}"],
            cwd=repo_path,
            timeout=5,
        ).returncode
        == 0
    )
    if not is_anc:
        return {"status": "ahead_or_diverged", "updated": False}

    ff = run_cmd(
        ["git", "merge", "--ff-only", f"origin/{branch}"], cwd=repo_path, timeout=6
    )
    if ff.returncode != 0:
        return {"status": "ff_failed", "updated": False}

    return {"status": "fast_forwarded", "updated": True, "sha": remote_sha[:7]}


def _ensure_global_scripts_link() -> None:
    """Optionally create a legacy scripts symlink only when explicitly requested via KC_ENABLE_GLOBAL_SYMLINK=1."""
    if os.environ.get("KC_ENABLE_GLOBAL_SYMLINK") != "1":
        return
    try:
        active_scripts_dir = Path(os.path.abspath(__file__)).parent.parent
        legacy_scripts_dir = (
            Path.home() / ".local" / "share" / "knowledge-compiler" / "scripts"
        )
        if not legacy_scripts_dir.exists() and active_scripts_dir.is_dir():
            legacy_scripts_dir.parent.mkdir(parents=True, exist_ok=True)
            legacy_scripts_dir.symlink_to(active_scripts_dir, target_is_directory=True)
    except Exception:
        pass


def sync_session_start(
    vault_path: Path | None = None,
    ce_patterns_path: Path | None = None,
    compiler_repo_path: Path | None = None,
    debounce_seconds: float = 0.0,
    auto_reinstall_plugin: bool = False,
) -> dict:
    _ensure_global_scripts_link()
    v_path = (vault_path or get_default_vault_path()).expanduser().resolve()
    p_path = (ce_patterns_path or get_default_ce_patterns_path()).expanduser().resolve()
    c_path = (
        compiler_repo_path or get_default_compiler_repo_path()
    ).expanduser().resolve()

    if _check_and_mark_debounce("session_start", v_path, debounce_seconds):
        return {"status": "debounced", "notices": []}

    vault_res, notices = _sync_vault_on_session_start(v_path)
    patterns_res = _fast_forward_clean_shared_repo(p_path)
    compiler_res = _fast_forward_clean_shared_repo(c_path)

    plugin_reinstalled = False
    if (
        compiler_res.get("updated")
        and auto_reinstall_plugin
        and os.environ.get("KC_AUTO_REINSTALL_PLUGIN") == "1"
    ):
        installer = c_path / "scripts" / "install_plugin.py"
        if installer.is_file():
            proc = run_cmd([sys.executable, str(installer)], cwd=c_path, timeout=8)
            plugin_reinstalled = proc.returncode == 0

    return {
        "status": "ok",
        "vault": vault_res,
        "shared_patterns": patterns_res,
        "compiler_repo": compiler_res,
        "plugin_reinstalled": plugin_reinstalled,
        "notices": notices,
    }


def format_session_start_output(result: dict) -> dict:
    notices = result.get("notices") or []
    if not notices:
        return {}
    return {
        "injectSteps": [
            {
                "systemMessage": {
                    "systemMessage": "\n".join(notices),
                }
            }
        ]
    }


DEFAULT_PREINVOCATION_COOLDOWN_SECONDS = 180.0


def _get_cooldown_seconds() -> float:
    raw = os.environ.get("KC_SYNC_COOLDOWN_SECONDS", "").strip()
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return DEFAULT_PREINVOCATION_COOLDOWN_SECONDS


def check_startup_sync_gate(
    payload: dict | None,
    target_path: Path,
    session_dedup_seconds: float = 5.0,
    preinvocation_cooldown_seconds: float | None = None,
    stamp_dir: Path | None = None,
) -> tuple[bool, str]:
    """Gate startup sync across both `SessionStart` (`agy`) and `PreInvocation` (`agy -c`).

    - When invoked from `PreInvocation` (`"invocationNum"` present in payload):
      1. Skips intra-turn tool-call loopbacks (`invocationNum > 0`) in <0.5ms.
      2. Runs immediately when switching/resuming a different `conversationId` (`agy -c`),
         or when the local cooldown stamp (`default 180s`) has expired.
      3. Skips duplicate fetches within `preinvocation_cooldown_seconds` for rapid
         back-to-back prompts (or immediately after `SessionStart` on Turn 1).
    - When invoked from `SessionStart` (`"invocationNum"` absent):
      Deduplicates back-to-back registrations (`session_dedup_seconds=5.0`) and stamps
      the active `conversationId` so Turn 1's subsequent `PreInvocation` skips cleanly.
    """
    payload = payload or {}
    is_pre_invocation = "invocationNum" in payload
    if is_pre_invocation:
        try:
            inv_num = int(payload.get("invocationNum", 0) or 0)
        except (TypeError, ValueError):
            inv_num = 0
        if inv_num > 0:
            return False, "intra_turn_loopback"

    cooldown = (
        _get_cooldown_seconds()
        if preinvocation_cooldown_seconds is None
        else preinvocation_cooldown_seconds
    )
    curr_conv = str(payload.get("conversationId", "") or "").strip()
    digest = hashlib.sha256(
        f"startup_sync:{target_path}".encode("utf-8")
    ).hexdigest()[:12]
    base_dir = stamp_dir if stamp_dir is not None else Path(tempfile.gettempdir())
    stamp_file = base_dir / f"kc_startup_sync_{digest}.json"
    now = time.time()

    try:
        if stamp_file.is_file():
            prev_data = json.loads(stamp_file.read_text(encoding="utf-8"))
            prev_ts = float(prev_data.get("ts", 0.0))
            prev_conv = str(prev_data.get("conversationId", "") or "").strip()

            switched_conversation = bool(
                curr_conv and prev_conv and curr_conv != prev_conv
            )
            if not switched_conversation:
                window = cooldown if is_pre_invocation else session_dedup_seconds
                if window > 0 and -0.05 <= (now - prev_ts) < window:
                    return False, "cooldown"

        stamp_file.write_text(
            json.dumps({"ts": now, "conversationId": curr_conv}),
            encoding="utf-8",
        )
    except Exception:
        pass

    return True, "ready"


def main() -> None:
    try:
        raw_input = sys.stdin.read().strip()
        payload = json.loads(raw_input) if raw_input else {}
    except Exception:
        payload = {}

    _ = detect_harness(payload)
    out_obj: dict = {}
    try:
        v_path = get_default_vault_path().expanduser().resolve()
        should_run, _ = check_startup_sync_gate(payload, v_path)
        if should_run:
            res = sync_session_start(vault_path=v_path, debounce_seconds=0.0)
            out_obj = format_session_start_output(res)
    except Exception:
        out_obj = {}

    print(json.dumps(out_obj), end="")


if __name__ == "__main__":
    main()
