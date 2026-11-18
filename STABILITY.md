# Knowledge Compiler `1.x` Stability & Compatibility Policy (`v1.3.0`)

This document defines the Semantic Versioning (`SemVer 2.0.0`) and backward-compatibility guarantees for **Knowledge Compiler** across the `1.x` release series, starting with `v1.0.0` (updated for `v1.3.0` with full `OKF v0.3` interoperability: portable relative Markdown links, unambiguous `.` bundle root + `wiki/**/index.md` progressive disclosure, and `x-kc-*` namespaced epistemic extensions, while keeping full `OKF v0.2` backward compatibility).

Throughout `1.x`, patch releases (`1.0.z`) contain only bug fixes and security hardening, and minor releases (`1.y.0`) introduce backward-compatible features without breaking the frozen contracts documented below.

---

## 1. OKF v0.3 / v0.2 Bundle Root & Vault Workspace Profile (`1.x` Frozen)

- **OKF v0.3 Bundle Root (`.`) & Compiled Concepts Directory (`wiki/`)**:
  - The vault root (`.`) is the canonical Open Knowledge Format (`OKF v0.3`) bundle root holding `index.md` (`okf_version: "0.3"`), frontmatter-free `log.md`, and optional `purpose.md`, with compiled concepts organized in `wiki/` (`wiki/index.md`, `wiki/concepts/`, `wiki/entities/`, `wiki/patterns/`, `wiki/sources/`, and `wiki/synthesis/`).
  - All compiled notes inside `wiki/` conform to the OKF frontmatter schema (`title`, `type`, `status`, `created`, `updated`, `tags`, `sources`, optional `superseded_by`, `generated`, `verified`, `stale_after`) and optional 5-way typed epistemic extensions (`x-kc-corroborates`, `x-kc-complements`, `x-kc-extends`, `x-kc-contradicts`, `x-kc-supersedes`; legacy unprefixed keys remain 100% readable).
  - Both standard OKF v0.3 relative Markdown links (`[Label](../dir/Note%20Name.md)`) and Obsidian `[[wikilinks]]` are first-class across `vault-lint`, `vault-query`, and `vault-graph` (`vault-lint --fix --portable-links` deterministically rewrites resolved `[[wikilinks]]` to RFC 3986 relative Markdown links).
- **Vault Workspace Profile (Vault Root)**:
  - Vault-root files (`GEMINI.md`, `index.md` declaring `okf_version: "0.3"`, frontmatter-free `log.md`, `purpose.md`, and `.obsidian/`) compose the Workspace Profile alongside `wiki/index.md` and `wiki/<subdir>/index.md` (§8 progressive disclosure). Legacy `OKF v0.2` vaults remain 100% readable and can be upgraded in one command via `vault-lint --fix --migrate-v03` (plus optional `--portable-links`).
  - Raw source artifacts and extracted media reside under `raw/` and `raw/assets/` with SHA-256 idempotency metadata in `.ingest_cache.json` at the vault root.
- **Dual-Format `sources` Compatibility**:
  - Both legacy string `sources` entries (e.g., `sources: ["[[wiki/sources/deck]]"]`) and OKF v0.2 structured `{id, resource, title}` mapping entries remain readable across all `1.x` tools (`vault-lint`, `vault-query`, `vault-correct`, `vault-graph`, `vault-sync-patterns`); passing `--strict` to `vault-lint` requires migrated structured `sources` (`vault-lint --migrate-sources`).
- **Zero In-Vault Database or Search Index Pollution**:
  - Zero `.sqlite` databases, persistent BM25 search indexes, or telemetry counters are ever created or written inside `$VAULT/` (aside from the lightweight JSON extraction manifest `.ingest_cache.json` written by `vault-extract`). The vault directory remains pure human-readable Markdown, YAML, and original `raw/` assets.

---

## 2. Stable `vault-*` CLI Surface & Exit Code Contract (`1.x` Frozen)

### Frozen Console Entrypoints

The following primary console scripts and their documented CLI flags are frozen for the `1.x` series:

<!-- mdformat off -->
| Console Entrypoint | Backing Module | Frozen Role |
| :--- | :--- | :--- |
| `vault-init` | `scripts.init_vault:main` | Scaffold an OKF v0.2 knowledge vault (`raw/`, `wiki/`, `index.md`, `log.md`, `.obsidian/`) |
| `vault-extract` | `scripts.extract_source:main` | Extract `.pptx`, `.pdf`, `.docx`, `.xlsx`/`.xls`, `.csv`, and `http(s)` URLs into `raw/` with SHA-256 caching (plain-text/Markdown files are recognized as direct-read no-ops) |
| `vault-lint` | `scripts.vault_lint:main` | Validate OKF v0.2 bundle conformance, wikilinks, table pipes, synthesis drift, unlinked mentions, dedup manifests, and freshness (`--fix`, `--strict`, `--strict-drift`, `--mentions`, `--dedup-manifest`, `--apply-manifest`, `--json`) |
| `vault-correct` | `scripts.vault_correct:main` | Execute Tri-State fact correction sweeps (`AUTHORITATIVE`, `RESTATEMENT`, `HISTORICAL`) with Plan-by-default preview |
| `vault-query` | `scripts.vault_query:main` | Zero-dependency in-memory BM25 search, duplicate check (`--check-duplicate`), and raw fence retrieval (`--include-raw`) |
| `vault-graph` | `scripts.vault_graph:main` | Serve or export the 2D/3D WebGL Knowledge Graph and local Search Hub (`127.0.0.1:8765`, `--export`, `--json`, `/api/note`) |
| `vault-sync-patterns` | `scripts.sync_patterns:main` | Audit, de-identify, share (including isolated `--open-pr` worktree PRs), and pull reusable patterns with a shared Git patterns repository (`audit`, `sanitize`, `share`, `pull`, `init-repo`) |
| `vault-sanitize-check` | `scripts.sanitize_check:main` | Enforce fail-closed DLP, secret, workstation path, and private entity link checks (`--strict`, `--fix`) |
| `vault-analyze-trace` | `scripts.analyze_trace:main` | Analyze conversation transcripts and telemetry into redacted out-of-vault candidate guardrail diffs (`--propose`) |
| `vault-wikiskill-eval` | `scripts.wikiskill_eval:main` | Execute deterministic offline Asymmetric Rollback Evaluation for candidate `SKILL.md` patches (`--apply-impact`) |
| `vault-hooks` | `scripts.vault_hooks:main` | Inspect, enable, or disable lifecycle hooks across writable plugins, read-only (`EROFS`) Marketplace mounts, and workspace scopes |
| `kc-install-plugin` | `scripts.install_plugin:main` | Install or synchronize the plugin manifest, hooks (`--enable-hooks`, `--disable-hooks`, upgrade-safe), rules, skills, and graph sidecar |
<!-- mdformat on -->

### Deterministic Exit Code Contract (`0` / `1` / `2`)

Across `vault-lint`, `vault-query`, and `vault-correct`, process exit codes are frozen as follows:

- **`0` (Success / Conformant)**: Operation succeeded with zero validation errors (and zero warnings when `--strict` is active).
- **`1` (Validation / Conformance / Lint Failure)**: Vault notes failed OKF v0.2 schema validation, broken wikilinks or unescaped table pipes were detected, or `--strict` promoted warnings to failure.
- **`2` (Usage / Environment / CAS / IO Error)**: Invalid CLI arguments, missing or non-existent vault path, unreadable files or directories during `vault-lint`, or atomic Compare-And-Swap (`CAS`) concurrent modification conflict during `--apply`.

### Safe-by-Default Mutation Contract (`vault-correct` & `vault-lint --fix`)

- **Plan / Diff Preview by Default**: Invoking `vault-correct` without `--apply` runs strictly in read-only Plan/Diff preview mode (`dry_run: true`, `applied: false`), computing the Tri-State classification and unified diff without modifying any file on disk.
- **Protected Instruction & Provenance Files**:
  - `vault-correct` (even with `--apply`) never mutates agent instruction, manifest, or navigation catalog files (`GEMINI.md`, `AGENTS.md`, `CLAUDE.md`, `purpose.md`, any `SKILL.md` anywhere in the vault, `hooks.json`, `plugin.json`, `index.md`, `skills/**`, `rules/**`, and all dot-directories such as `.agents/**`, `.gemini/**`, `.claude/**`, `.github/**`) and never alters historical provenance files (`raw/`, `archive/`, `wiki/sources/`, `wiki/skill-impact.md`) byte-for-byte. Because `SKILL.md` (case-insensitive) is reserved by filename across the vault, any note named `Skill.md` cannot be targeted by `vault-correct --target` and is excluded from `--apply` and `--fix` rewrites.
  - For `log.md`, `vault-correct --apply` preserves all prior dated historical entries and prepends only the new `## [YYYY-MM-DD] correct | ...` audit heading when notes are updated.
  - `vault-lint --fix` leaves instruction, config, and historical provenance files untouched (`GEMINI.md`, `AGENTS.md`, `CLAUDE.md`, `purpose.md`, any `SKILL.md`, `hooks.json`, `plugin.json`, `skills/**`, `rules/**`, dot-directories, `raw/**`, `archive/**`, `wiki/sources/**`, `wiki/skill-impact.md`, and `log.md`) and does not flag escaped table pipes inside those protected files, while allowing table-pipe auto-fixing on `index.md` and living `wiki/` notes. When the explicit `--migrate-sources` flag is also passed (`vault-lint --fix --migrate-sources`), legacy string `sources:` in YAML frontmatter across `wiki/` (including `wiki/sources/**`, while still excluding `SKILL.md`, `purpose.md`, and `wiki/skill-impact.md`) are migrated to structured `{id, resource}` mappings with the Markdown body preserved byte-for-byte so the bundle passes `vault-lint --strict`.
- **Atomic CAS Writes**: When `--apply` is passed, every file write verifies the pre-read SHA-256 digest before atomic temp-file replacement (`os.replace`) and aborts with exit code `2` on concurrent modification.

---

## 3. JSON Output Contracts (`1.x` Additive-Only)

Machine-readable `--json` outputs follow an **additive-only** evolution policy throughout `1.x` minor releases. Existing documented top-level keys (`vault_lint --json`, `vault-query --json`, `vault-correct --json`, `vault-graph --json`) will not be removed or incompatibly retyped in `1.x`:

- **`vault-lint --json` (`vault_lint --json`)**:
  - Preserves top-level keys: `success`, `vault_path`, `bundle_root`, `concepts_dir`, `supported_okf_version`, `bundle_okf_version`, `total_markdown_files`, `total_wiki_notes`, `broken_links`, `wanted_pages`, `table_invariant_violations`, `fixed_files`, `migrated_sources_files`, `migrated_v03_files`, `portable_links_files`, `orphan_notes`, `missing_from_index`, `missing_frontmatter`, `conformance_errors`, `legacy_sources_notes`, `dangling_footnotes`, `stale_notes`, `stale_verification_notes`, `stale_syntheses`, `workspace_profile_warnings`, `trust_tier_counts`, `epistemic_edge_counts`, `is_healthy`, `strict`, `strict_passed`, `strict_drift`, `strict_drift_passed` (plus `unlinked_mentions` when `--mentions` is passed).
- **`vault-query --json`**:
  - Preserves top-level keys: `query`, `tokens`, `vault`, `include_raw`, `total_results`, `results` (or `query`, `create_safety`, `matches` when `--check-duplicate` is passed).
- **`vault-correct --json`**:
  - Preserves top-level keys: `vault_path`, `fact`, `stale_claim`, `replacement`, `dry_run`, `applied`, `cas_conflict`, `cas_conflicts`, `authoritative_updated`, `restatements_refactored`, `historical_preserved`, `diffs`, `warnings`, `errors`.
- **`vault-graph --json`**:
  - Preserves top-level keys: `vaultPath`, `vaultName`, `categories`, `epistemicTypes`, `stats`, `tags`, `nodes`, `edges`. Interactive HTTP mode serves slim initial HTML (`GET /`, with `lazyMarkdown: true`) and loads full per-node markdown on demand via `GET /api/note?id=...`, while `--export` and `--json` embed full markdown for offline portability.
- **`vault-analyze-trace --json`**:
  - Preserves top-level keys: `transcript_file`, `error_log_file`, `total_steps`, `tool_error_count`, `transcript_error_count`, `error_trace_count`, `user_correction_count`, `errors`, `error_traces`, `corrections`, `proposals`, `proposal_file`.

---

## 4. Privacy, Air-Gap & Hook Opt-In Guarantees (`1.x` Frozen)

- **100% Offline Plane 1 Default**:
  - All local vault compilation, linting (`vault-lint`), BM25 retrieval (`vault-query`), fact correction (`vault-correct`), and graph rendering (`vault-graph`) execute locally with zero background network calls.
  - Outbound HTTP requests occur only on explicit user action: passing an `http://` or `https://` URL to `vault-extract`, or passing `--check-okf-upstream` to `vault-lint`.
- **Disabled-by-Default Lifecycle Hooks (`hooks.json`)**:
  - All lifecycle hooks (`vault-session-start`, `vault-stop-hook`, `wikiskill-error-recorder`) ship disabled (`"enabled": false`) by default and require explicit user opt-in.
  - All mutable hook and server runtime state (redacted error traces, sync cooldown stamps, and owner bearer tokens) is written strictly outside the repository and outside `$VAULT/` under `$XDG_STATE_HOME/knowledge-compiler/`, `$XDG_CACHE_HOME/knowledge-compiler/`, or `$PLUGIN_DATA` (with owner bearer tokens and error trace logs enforced at `0600`).
- **Fail-Closed Pattern Sharing Egress Gate**:
  - `vault-sync-patterns share` and `vault-sanitize-check` enforce a mandatory in-code fail-closed DLP, secret, workstation path, and private entity (`wiki/entities/`, `raw/`) sanitization gate before any note is written to a shared patterns repository.

---

## 5. Graduated Surfaces (`1.x` Frozen in `v1.1.0`)

- **`/wikiskill`, `vault-analyze-trace` (`scripts/analyze_trace.py`), & `vault-wikiskill-eval` (`scripts/wikiskill_eval.py`) — Stable**:
  - Previously designated **Experimental** in `v1.0.0`, `/wikiskill`, `vault-analyze-trace`, and `vault-wikiskill-eval` graduated to **`Stable` (`1.x` Frozen)** in `v1.1.0`.
  - Candidate guardrail proposals from `vault-analyze-trace --propose` are written strictly outside `$VAULT/` (`0700`/`0600` directories/files with secret redaction), and `vault-wikiskill-eval` enforces deterministic offline Asymmetric Rollback Gating with `wiki/skill-impact.md` SHA-256 CAS updates (`--apply-impact`).
  - **Safety Invariant**: Zero code paths in `vault-analyze-trace`, `vault-wikiskill-eval`, or any lifecycle hook automatically rewrite `SKILL.md`, `AGENTS.md`, or `GEMINI.md` files unattended without explicit human review.
