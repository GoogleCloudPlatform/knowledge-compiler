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
"""auto_sync_vault.py - Stop Hook for Knowledge Compiler Vault Sync.

Executes when the agent execution loop finishes (Stop event).
Inspects the configured knowledge vault ($KC_VAULT_PATH or $OBSIDIAN_VAULT_PATH).
Works seamlessly across both:
  - Local-only vaults (no `origin` Git remote configured -> commits locally, skips push)
  - Multi-machine vaults backed by a Git remote (`origin/main` or `origin/master`):
      1. Runs vault_lint --fix to ensure graph and table link integrity.
      2. Commits OKF changes with session & harness provenance.
      3. Pushes to `origin <branch>`, automatically executing an OKF-aware union rebase
         (`log.md` chronological block union, `index.md` bullet union, `max(updated)` in
         YAML frontmatter, and clean `git rebase --abort` on same-line prose collisions so
         zero `<<<<<<<` conflict markers ever enter the vault) when another machine pushed first.
Always outputs a valid empty JSON object `{}` to stdout per the Stop contract.
"""

from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

FRONTMATTER_RE = re.compile(r"\A(---\r?\n.*?\r?\n---\r?\n?)(.*)\Z", re.DOTALL)
UPDATED_LINE_RE = re.compile(
    r"^(updated:\s*['\"]?)(\d{4}-\d{2}-\d{2})(['\"]?\s*)$", re.MULTILINE
)
LOG_HEADING_SPLIT_RE = re.compile(
    r"(?=^## (?:\[\d{4}-\d{2}-\d{2}\]|\d{4}-\d{2}-\d{2}(?=\s|$)))", re.MULTILINE
)
LOG_DATE_RE = re.compile(r"^## (?:\[(\d{4}-\d{2}-\d{2})\]|(\d{4}-\d{2}-\d{2})(?=\s|$))")
_PLAIN_V03_LOG_HEADING_RE = re.compile(r"^## (\d{4}-\d{2}-\d{2})\s*$")
SECTION_SPLIT_RE = re.compile(r"(?=^## )", re.MULTILINE)
WIKILINK_TARGET_RE = re.compile(r"\[\[([^\]|#]+)")


def get_plugin_data_dir() -> Path:
    """Return the per-user writable runtime data directory (outside immutable plugin source)."""
    for env_key in ("PLUGIN_DATA", "ANTIGRAVITY_EXECUTABLE_DATA_DIR", "KC_DATA_DIR"):
        val = (os.environ.get(env_key) or "").strip()
        if val:
            return Path(val).expanduser().resolve()
    xdg_state = (os.environ.get("XDG_STATE_HOME") or "").strip()
    if xdg_state:
        return (Path(xdg_state).expanduser() / "knowledge-compiler").resolve()
    return Path("~/.local/share/knowledge-compiler").expanduser().resolve()


@contextmanager
def acquire_vault_lock(vault_path: Path) -> Iterator[bool]:
    """Acquire a non-blocking exclusive fcntl.flock for `vault_path`.

    Yields True if the lock was acquired, or False if another hook process
    currently holds the lock.
    """
    if fcntl is None:
        yield True
        return

    resolved = vault_path.expanduser().resolve()
    sha16 = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:16]
    lock_dirs = [
        get_plugin_data_dir() / "locks",
        Path(tempfile.gettempdir()) / f"kc-locks-{os.getuid()}",
    ]

    fd: int | None = None
    for lock_dir in lock_dirs:
        try:
            lock_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(lock_dir, 0o700)
            except OSError:
                pass
            lock_path = lock_dir / f"vault-{sha16}.lock"
            if lock_path.is_symlink():
                yield False
                return
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            break
        except OSError:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                fd = None
            continue

    if fd is None:
        yield True
        return

    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                yield False
                return
            yield True
            return

        try:
            yield True
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def get_default_vault_path() -> Path:
    env_path = os.environ.get("KC_VAULT_PATH") or os.environ.get("OBSIDIAN_VAULT_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()
    for cand in (Path("~/knowledge-vault").expanduser(), Path("~/ObsidianVault").expanduser()):
        if cand.exists():
            return cand.resolve()
    return Path("~/ObsidianVault").expanduser().resolve()


_HARNESS_1P_TAG = "Antigravity"
_HARNESS_1P_ALT = "ANTIGRAVITY"
_SHARED_MOUNT_PREFIX = "/mnt/shared/cloud/"


def detect_harness(payload: dict | None = None) -> str:
    """Detect the active agent harness name."""
    payload = payload or {}
    transcript_path = str(payload.get("transcriptPath", ""))
    if (
        f"/.gemini/{_HARNESS_1P_TAG.lower()}/" in transcript_path
        or "/.gemini/llmext_bridge/" in transcript_path
    ):
        return _HARNESS_1P_TAG
    if "/.gemini/antigravity/" in transcript_path:
        return "Antigravity"

    for key in os.environ:
        upper = key.upper()
        if upper.startswith(_HARNESS_1P_TAG.upper()) or upper.startswith(_HARNESS_1P_ALT):
            return _HARNESS_1P_TAG
        if upper.startswith("ANTIGRAVITY"):
            return "Antigravity"

    try:
        cwd_str = str(Path.cwd().resolve())
        if cwd_str.startswith(_SHARED_MOUNT_PREFIX):
            return _HARNESS_1P_TAG
    except Exception:
        pass

    return "Antigravity"


def find_lint_script() -> Path | None:
    """Locate vault_lint.py across plugin, repo, and relative paths."""
    candidates = [
        Path(os.path.abspath(__file__)).parent.parent / "vault_lint.py",
        Path(__file__).resolve().parent.parent / "vault_lint.py",
        Path(__file__).resolve().parent / "vault_lint.py",
        Path("~/.local/share/knowledge-compiler/scripts/vault_lint.py").expanduser(),
        Path("~/knowledge-compiler/scripts/vault_lint.py").expanduser(),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def run_cmd(
    args: list[str],
    cwd: Path,
    timeout: int = 15,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )


def has_origin_remote(repo_dir: Path) -> bool:
    """Return True if the Git repository has an `origin` remote configured."""
    proc = run_cmd(["git", "remote", "get-url", "origin"], cwd=repo_dir, timeout=5)
    return proc.returncode == 0 and bool(proc.stdout.strip())


def get_active_branch(repo_dir: Path) -> str:
    """Return the active symbolic branch name (defaults to `main` if detached)."""
    proc = run_cmd(["git", "symbolic-ref", "--short", "HEAD"], cwd=repo_dir, timeout=5)
    branch = proc.stdout.strip()
    return branch if proc.returncode == 0 and branch else "main"


def _resolve_git_dir(repo_dir: Path) -> Path | None:
    git_dir_proc = run_cmd(
        ["git", "rev-parse", "--git-dir"], cwd=repo_dir, timeout=5
    )
    if git_dir_proc.returncode != 0:
        return None
    git_dir = Path(git_dir_proc.stdout.strip())
    if not git_dir.is_absolute():
        git_dir = (repo_dir / git_dir).resolve()
    return git_dir


def is_rebase_in_progress(repo_dir: Path) -> bool:
    git_dir = _resolve_git_dir(repo_dir)
    if git_dir is None:
        return False
    return (git_dir / "rebase-merge").exists() or (git_dir / "rebase-apply").exists()


def has_in_progress_git_operation(repo_dir: Path) -> str | None:
    """Return active Git conflict/operation state if sync must skip without mutating."""
    git_dir = _resolve_git_dir(repo_dir)
    if git_dir is None:
        return None
    if (git_dir / "rebase-merge").exists() or (git_dir / "rebase-apply").exists():
        return "rebase"

    def _has_ref_or_file(ref_name: str) -> bool:
        if (git_dir / ref_name).exists():
            return True
        proc = run_cmd(
            ["git", "rev-parse", "-q", "--verify", ref_name],
            cwd=repo_dir,
            timeout=5,
        )
        return proc.returncode == 0 and bool(proc.stdout.strip())

    if _has_ref_or_file("MERGE_HEAD"):
        return "merge"
    if _has_ref_or_file("CHERRY_PICK_HEAD"):
        return "cherry_pick"
    if _has_ref_or_file("REVERT_HEAD"):
        return "revert"
    if (git_dir / "sequencer").exists():
        return "sequencer"
    if (git_dir / "BISECT_LOG").exists():
        return "bisect"
    unmerged_proc = run_cmd(
        ["git", "diff", "--name-only", "--diff-filter=U"],
        cwd=repo_dir,
        timeout=5,
    )
    if unmerged_proc.returncode == 0 and unmerged_proc.stdout.strip():
        return "unmerged_conflicts"
    return None


def _extract_updated_date(text: str) -> str:
    fm_match = FRONTMATTER_RE.match(text)
    if not fm_match:
        return ""
    m = UPDATED_LINE_RE.search(fm_match.group(1))
    return m.group(2) if m else ""


def _normalize_updated_frontmatter(text: str, target_date: str) -> str:
    if not target_date:
        return text
    fm_match = FRONTMATTER_RE.match(text)
    if not fm_match:
        return text
    fm, body = fm_match.group(1), fm_match.group(2)
    new_fm = UPDATED_LINE_RE.sub(rf"\g<1>{target_date}\g<3>", fm, count=1)
    return new_fm + body


def merge_log_markdown(remote_text: str, local_text: str) -> str:
    """Union-merge two versions of OKF `log.md` cleanly without conflict markers.

    Supports both OKF v0.3 (`## YYYY-MM-DD` with no frontmatter) and legacy OKF v0.2
    (`## [YYYY-MM-DD] ...` with optional YAML frontmatter). Preserves all unique entries
    sorted newest-date first, merging distinct bullets under identical `## YYYY-MM-DD`
    date headings (local bullets ahead of remote bullets).
    """
    max_date = max(_extract_updated_date(remote_text), _extract_updated_date(local_text))
    base_doc = _normalize_updated_frontmatter(remote_text, max_date)

    fm_match = FRONTMATTER_RE.match(base_doc)
    frontmatter = fm_match.group(1) if fm_match else ""
    remote_body = fm_match.group(2) if fm_match else base_doc

    local_fm_match = FRONTMATTER_RE.match(local_text)
    local_body = local_fm_match.group(2) if local_fm_match else local_text

    remote_parts = LOG_HEADING_SPLIT_RE.split(remote_body)
    local_parts = LOG_HEADING_SPLIT_RE.split(local_body)

    preamble = remote_parts[0] if remote_parts else local_parts[0]
    if not preamble.strip() and local_parts:
        preamble = local_parts[0]

    entries: list[tuple[str, int, str]] = []
    seen_signatures: set[str] = set()
    v03_date_blocks: dict[str, list[str]] = {}
    v03_date_seen_lines: dict[str, set[str]] = {}

    # Order: local entries first (priority 1 on same-day ties), then remote entries (priority 0)
    for source_priority, blocks in ((1, local_parts[1:]), (0, remote_parts[1:])):
        for raw_block in blocks:
            cleaned = raw_block.strip()
            if not cleaned:
                continue
            lines = cleaned.splitlines()
            heading = lines[0].strip()
            plain_m = _PLAIN_V03_LOG_HEADING_RE.match(heading)
            if plain_m:
                date_key = plain_m.group(1)
                if date_key not in v03_date_blocks:
                    v03_date_blocks[date_key] = [f"## {date_key}"]
                    v03_date_seen_lines[date_key] = set()
                for body_line in lines[1:]:
                    norm_line = body_line.strip()
                    if not norm_line:
                        continue
                    if norm_line not in v03_date_seen_lines[date_key]:
                        v03_date_seen_lines[date_key].add(norm_line)
                        v03_date_blocks[date_key].append(body_line.rstrip())
                continue
            sig_body = "\n".join(line.strip() for line in lines[:3])
            if sig_body in seen_signatures:
                continue
            seen_signatures.add(sig_body)
            date_m = LOG_DATE_RE.match(heading)
            date_key = (date_m.group(1) or date_m.group(2)) if date_m else "0000-00-00"
            entries.append((date_key, source_priority, cleaned))

    for date_key, block_lines in v03_date_blocks.items():
        entries.append((date_key, 1, "\n".join(block_lines)))

    # Stable sort: newest date first; on same date, local (1) before remote (0), preserving internal order
    entries.sort(key=lambda item: (item[0], item[1]), reverse=True)

    assembled_body = preamble.rstrip()
    if entries:
        assembled_body += "\n\n" + "\n\n".join(item[2] for item in entries) + "\n"
    else:
        assembled_body += "\n"
    return frontmatter + assembled_body.lstrip("\r\n") if frontmatter else assembled_body


def _bullet_identity(line: str) -> str:
    stripped = line.strip()
    wl = WIKILINK_TARGET_RE.search(stripped)
    if wl:
        target = wl.group(1).strip().lower()
        if target.endswith(".md"):
            target = target[:-3]
        return f"wl:{target.split('/')[-1]}"
    return f"raw:{stripped.lower()}"


def merge_index_markdown(remote_text: str, local_text: str) -> str:
    """Union-merge two versions of OKF `index.md` by combining unique note bullets per section."""
    max_date = max(_extract_updated_date(remote_text), _extract_updated_date(local_text))
    remote_norm = _normalize_updated_frontmatter(remote_text, max_date)

    r_fm_match = FRONTMATTER_RE.match(remote_norm)
    frontmatter = r_fm_match.group(1) if r_fm_match else ""
    r_body = r_fm_match.group(2) if r_fm_match else remote_norm

    l_fm_match = FRONTMATTER_RE.match(local_text)
    l_body = l_fm_match.group(2) if l_fm_match else local_text

    r_sections = SECTION_SPLIT_RE.split(r_body)
    l_sections = SECTION_SPLIT_RE.split(l_body)

    preamble = r_sections[0] if r_sections else (l_sections[0] if l_sections else "")

    global_seen: set[str] = set()
    for line in r_body.splitlines():
        if line.lstrip().startswith("- "):
            global_seen.add(_bullet_identity(line))

    local_by_header: dict[str, list[str]] = {}
    local_section_order: list[tuple[str, str]] = []
    for sec in l_sections[1:]:
        sec_lines = sec.splitlines()
        if not sec_lines:
            continue
        hdr = sec_lines[0].strip()
        local_section_order.append((hdr, sec))
        bullets = [ln for ln in sec_lines[1:] if ln.lstrip().startswith("- ")]
        local_by_header.setdefault(hdr, []).extend(bullets)

    merged_sections: list[str] = []
    seen_headers: set[str] = set()

    for sec in r_sections[1:]:
        sec_lines = sec.splitlines()
        if not sec_lines:
            continue
        hdr = sec_lines[0].strip()
        seen_headers.add(hdr)
        extra_bullets: list[str] = []
        for candidate in local_by_header.get(hdr, []):
            ident = _bullet_identity(candidate)
            if ident not in global_seen:
                global_seen.add(ident)
                extra_bullets.append(candidate)

        if not extra_bullets:
            merged_sections.append(sec.rstrip())
        else:
            # Insert extra bullets right before trailing `---` divider if present
            trimmed = sec.rstrip().splitlines()
            insert_idx = len(trimmed)
            while insert_idx > 1 and trimmed[insert_idx - 1].strip() in ("", "---"):
                insert_idx -= 1
            rebuilt = (
                trimmed[:insert_idx]
                + extra_bullets
                + trimmed[insert_idx:]
            )
            merged_sections.append("\n".join(rebuilt).rstrip())

    for hdr, raw_sec in local_section_order:
        if hdr not in seen_headers:
            seen_headers.add(hdr)
            merged_sections.append(raw_sec.rstrip())

    out_body = preamble.rstrip()
    if merged_sections:
        out_body += "\n\n" + "\n\n".join(merged_sections) + "\n"
    else:
        out_body += "\n"
    return frontmatter + out_body.lstrip("\r\n") if frontmatter else out_body


def merge_living_note_three_way(
    base_text: str, remote_text: str, local_text: str, repo_dir: Path
) -> str | None:
    """Attempt a clean 3-way merge of an OKF Markdown note after normalizing `updated:`.

    Returns merged Markdown if non-overlapping hunks merge cleanly, or `None` if both
    sides edited the exact same prose lines (signaling the caller to abort the rebase
    cleanly with zero `<<<<<<<` conflict markers).
    """
    max_date = max(
        _extract_updated_date(base_text),
        _extract_updated_date(remote_text),
        _extract_updated_date(local_text),
    )
    b_norm = _normalize_updated_frontmatter(base_text, max_date)
    r_norm = _normalize_updated_frontmatter(remote_text, max_date)
    l_norm = _normalize_updated_frontmatter(local_text, max_date)

    with tempfile.TemporaryDirectory(prefix="kc_merge_") as tmpdir:
        tmp = Path(tmpdir)
        f_local = tmp / "local.md"
        f_base = tmp / "base.md"
        f_remote = tmp / "remote.md"
        f_local.write_text(l_norm, encoding="utf-8")
        f_base.write_text(b_norm, encoding="utf-8")
        f_remote.write_text(r_norm, encoding="utf-8")

        proc = run_cmd(
            ["git", "merge-file", "-p", str(f_local), str(f_base), str(f_remote)],
            cwd=repo_dir,
            timeout=5,
        )
        if proc.returncode == 0 and "<<<<<<<" not in proc.stdout:
            return proc.stdout
    return None


def resolve_unmerged_index_files(vault_path: Path) -> tuple[bool, str]:
    """Resolve currently unmerged index entries (`:1:`, `:2:`, `:3:`) in `vault_path`.

    Returns `(True, "")` if all unmerged files were cleanly resolved without conflict markers,
    or `(False, first_conflicted_rel_path)` if a genuine same-line prose conflict requires aborting.
    """
    unmerged_proc = run_cmd(
        ["git", "diff", "--name-only", "--diff-filter=U"], cwd=vault_path, timeout=5
    )
    unmerged_files = [
        line.strip() for line in unmerged_proc.stdout.splitlines() if line.strip()
    ]
    for rel_path in unmerged_files:
        if not rel_path.endswith(".md"):
            return False, rel_path

        s1 = run_cmd(["git", "show", f":1:{rel_path}"], cwd=vault_path, timeout=5)
        s2 = run_cmd(["git", "show", f":2:{rel_path}"], cwd=vault_path, timeout=5)
        s3 = run_cmd(["git", "show", f":3:{rel_path}"], cwd=vault_path, timeout=5)

        if s2.returncode != 0 or s3.returncode != 0:
            return False, rel_path

        base_txt = s1.stdout if s1.returncode == 0 else ""
        # During `git rebase origin/<branch>`, :2: (ours/HEAD) is remote and :3: (theirs) is local.
        remote_txt = s2.stdout
        local_txt = s3.stdout

        norm_rel = rel_path.replace("\\", "/")
        if norm_rel == "log.md":
            merged = merge_log_markdown(remote_txt, local_txt)
        elif norm_rel == "index.md":
            merged = merge_index_markdown(remote_txt, local_txt)
        else:
            merged = merge_living_note_three_way(
                base_txt, remote_txt, local_txt, repo_dir=vault_path
            )

        if merged is None or "<<<<<<<" in merged:
            return False, rel_path

        (vault_path / rel_path).write_text(merged, encoding="utf-8")
        add_proc = run_cmd(["git", "add", "--", rel_path], cwd=vault_path, timeout=5)
        if add_proc.returncode != 0:
            return False, rel_path

    return True, ""


def rebase_onto_origin(vault_path: Path, branch: str = "main") -> dict:
    """Rebase local vault commits onto `origin/<branch>` with OKF-aware union resolution.

    Guarantees zero `<<<<<<<` conflict markers on disk: if a genuine same-sentence prose
    collision cannot be auto-merged, runs `git rebase --abort` immediately.
    """
    rebase_proc = run_cmd(
        ["git", "rebase", f"origin/{branch}"],
        cwd=vault_path,
        timeout=15,
        extra_env={"GIT_EDITOR": "true"},
    )
    if rebase_proc.returncode == 0 and not is_rebase_in_progress(vault_path):
        return {"ok": True, "status": "rebased"}

    if not is_rebase_in_progress(vault_path):
        return {
            "ok": False,
            "status": "rebase_failed",
            "conflicted_file": "",
        }

    for _ in range(25):
        if not is_rebase_in_progress(vault_path):
            break
        resolved, failed_file = resolve_unmerged_index_files(vault_path)
        if not resolved:
            run_cmd(["git", "rebase", "--abort"], cwd=vault_path, timeout=10)
            return {
                "ok": False,
                "status": "conflict_aborted",
                "conflicted_file": failed_file,
            }

        cont_proc = run_cmd(
            ["git", "rebase", "--continue"],
            cwd=vault_path,
            timeout=15,
            extra_env={"GIT_EDITOR": "true"},
        )
        if cont_proc.returncode == 0 and not is_rebase_in_progress(vault_path):
            return {"ok": True, "status": "rebased_with_okf_merge"}

    if is_rebase_in_progress(vault_path):
        run_cmd(["git", "rebase", "--abort"], cwd=vault_path, timeout=10)
        return {"ok": False, "status": "conflict_aborted", "conflicted_file": "unknown"}

    return {"ok": False, "status": "rebase_failed", "conflicted_file": ""}


def _check_and_mark_debounce(tag: str, target_path: Path, debounce_seconds: float) -> bool:
    """Return True if an identical hook ran within `debounce_seconds` (skip duplicate run)."""
    if debounce_seconds <= 0:
        return False
    digest = hashlib.sha256(f"{tag}:{target_path}".encode("utf-8")).hexdigest()[:12]
    stamp_dir = get_plugin_data_dir() / "stamps"
    try:
        stamp_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(stamp_dir, 0o700)
    except OSError:
        stamp_dir = Path(tempfile.gettempdir())
    stamp_file = stamp_dir / f"kc_hook_{tag}_{digest}.stamp"
    now = time.time()
    try:
        if stamp_file.is_file():
            last = float(stamp_file.read_text(encoding="utf-8").strip())
            if 0 <= (now - last) < debounce_seconds:
                return True
        stamp_file.write_text(f"{now:.3f}", encoding="utf-8")
    except Exception:
        pass
    return False


def _run_vault_lint_fix(vault_path: Path) -> None:
    lint_script = find_lint_script()
    if lint_script is not None:
        try:
            run_cmd(
                [sys.executable, str(lint_script), str(vault_path), "--fix"],
                cwd=vault_path,
                timeout=10,
            )
        except Exception:
            pass


_OKF_STAGE_PATHS: tuple[str, ...] = (
    "wiki",
    "bases",
    "tables",
    "index.md",
    "log.md",
    "purpose.md",
    "GEMINI.md",
    ".gitallowed",
)


def _stage_vault_files(vault_path: Path) -> None:
    """Stage tracked modifications and known OKF paths without staging untracked root secrets."""
    run_cmd(["git", "add", "-u"], cwd=vault_path)
    existing = [rel for rel in _OKF_STAGE_PATHS if (vault_path / rel).exists()]
    if existing:
        run_cmd(["git", "add", "--", *existing], cwd=vault_path)


def sync_vault(
    vault_path: Path,
    conversation_id: str = "",
    harness: str = "Antigravity",
    debounce_seconds: float = 0.0,
) -> dict:
    if not vault_path.exists() or not (vault_path / ".git").exists():
        return {"status": "skipped", "reason": f"Not a git repository: {vault_path}"}

    if _check_and_mark_debounce("stop", vault_path, debounce_seconds):
        return {"status": "debounced", "vault_path": str(vault_path), "harness": harness}

    with acquire_vault_lock(vault_path) as lock_acquired:
        if not lock_acquired:
            return {
                "status": "locked_skipped",
                "vault_path": str(vault_path),
                "harness": harness,
                "committed": False,
                "pushed": False,
            }

        return _sync_vault_locked(
            vault_path=vault_path,
            conversation_id=conversation_id,
            harness=harness,
        )


def _sync_vault_locked(
    vault_path: Path,
    conversation_id: str = "",
    harness: str = "Antigravity",
) -> dict:
    # Safety guard: never commit/abort during an active rebase, merge, cherry-pick, revert, or unmerged conflict
    active_op = has_in_progress_git_operation(vault_path)
    if active_op:
        status = (
            "skipped_rebase_in_progress"
            if active_op == "rebase"
            else f"skipped_{active_op}_in_progress"
        )
        return {
            "status": status,
            "vault_path": str(vault_path),
            "harness": harness,
            "committed": False,
            "pushed": False,
        }

    branch = get_active_branch(vault_path)
    remote_configured = has_origin_remote(vault_path)

    # 1. Check for uncommitted working tree changes
    status_proc = run_cmd(["git", "status", "--porcelain"], cwd=vault_path)
    is_dirty = bool(status_proc.stdout.strip())

    # 2. Check for unpushed commits (only meaningful if upstream/origin exists)
    has_unpushed = False
    if remote_configured:
        cherry_proc = run_cmd(["git", "cherry", "-v"], cwd=vault_path)
        if cherry_proc.returncode == 0:
            has_unpushed = bool(cherry_proc.stdout.strip())
        else:
            # Branch may not have upstream tracking set yet; check origin/<branch>
            rev_proc = run_cmd(
                ["git", "rev-list", "--count", f"origin/{branch}..HEAD"],
                cwd=vault_path,
            )
            has_unpushed = (
                rev_proc.returncode == 0
                and int(rev_proc.stdout.strip() or "0") > 0
            )

    if not is_dirty and not has_unpushed:
        return {"status": "clean", "vault_path": str(vault_path), "harness": harness}

    # 3. If dirty, run vault_lint --fix and commit OKF files locally
    committed = False
    if is_dirty:
        _run_vault_lint_fix(vault_path)
        _stage_vault_files(vault_path)

        diff_proc = run_cmd(["git", "diff", "--cached", "--quiet"], cwd=vault_path)
        if diff_proc.returncode != 0:
            short_id = conversation_id[:8] if conversation_id else "session"
            commit_msg = (
                f"docs(auto-sync): compile updates from {harness} session "
                f"[{short_id}] [skip ci]"
            )
            commit_proc = run_cmd(["git", "commit", "-m", commit_msg], cwd=vault_path)
            committed = commit_proc.returncode == 0

    # 4. Local-only vaults without an `origin` remote finish cleanly here
    if not remote_configured or os.environ.get("KC_AUTO_PUSH", "1") == "0":
        return {
            "status": "synced",
            "local_only": not remote_configured,
            "vault_path": str(vault_path),
            "harness": harness,
            "committed": committed,
            "pushed": False,
        }

    # 5. Push to remote; if rejected (another harness/machine pushed first), fetch + OKF union-rebase + push
    pushed = False
    rebased = False
    conflict_aborted = False
    try:
        push_proc = run_cmd(
            ["git", "push", "origin", branch], cwd=vault_path, timeout=10
        )
        pushed = push_proc.returncode == 0

        if not pushed:
            fetch_proc = run_cmd(
                ["git", "fetch", "origin", branch], cwd=vault_path, timeout=8
            )
            if fetch_proc.returncode == 0:
                rb_res = rebase_onto_origin(vault_path, branch=branch)
                if rb_res.get("ok"):
                    rebased = True
                    _run_vault_lint_fix(vault_path)
                    post_status = run_cmd(
                        ["git", "status", "--porcelain"], cwd=vault_path
                    )
                    if post_status.stdout.strip():
                        _stage_vault_files(vault_path)
                        if (
                            run_cmd(
                                ["git", "diff", "--cached", "--quiet"], cwd=vault_path
                            ).returncode
                            != 0
                        ):
                            run_cmd(
                                ["git", "commit", "--amend", "--no-edit"],
                                cwd=vault_path,
                            )
                    retry_push = run_cmd(
                        ["git", "push", "origin", branch],
                        cwd=vault_path,
                        timeout=10,
                    )
                    pushed = retry_push.returncode == 0
                else:
                    conflict_aborted = True
    except Exception:
        pushed = False

    return {
        "status": "synced",
        "vault_path": str(vault_path),
        "harness": harness,
        "committed": committed,
        "pushed": pushed,
        "rebased": rebased,
        "conflict_aborted": conflict_aborted,
    }


def main() -> None:
    try:
        raw_input = sys.stdin.read().strip()
        payload = json.loads(raw_input) if raw_input else {}
    except Exception:
        payload = {}

    vault_path = get_default_vault_path()
    conv_id = payload.get("conversationId", "")
    harness = detect_harness(payload)
    try:
        sync_vault(
            vault_path,
            conversation_id=conv_id,
            harness=harness,
            debounce_seconds=3.0,
        )
    except Exception:
        pass

    # Stop hook contract expects a JSON object on stdout (e.g. {} or {"decision": "continue"})
    print("{}", end="")


if __name__ == "__main__":
    main()
