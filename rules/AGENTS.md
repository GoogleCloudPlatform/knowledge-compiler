# Knowledge Compiler & Graph Engineering Rules

When the `knowledge-compiler` plugin is active:

1. **Vault Location & Progressive Disclosure**:
   - The primary Knowledge Compiler vault resides at the path specified by `$KC_VAULT_PATH` or `$OBSIDIAN_VAULT_PATH` (defaults to `./vault` or `~/ObsidianVault`).
   - When researching architecture patterns or cloud best practices, consult `index.md` in your local vault and your shared patterns repository (`$OKF_PATTERNS_PATH`).

2. **Privacy Boundaries & Export Isolation**:
   - **Shared Patterns Repository**: Reusable architectural patterns (`wiki/concepts/`, `wiki/patterns/`) are sanitized via `scripts/sync_patterns.py` and `scripts/sanitize_check.py`.
   - **Private Vault Notes**: Personal notes and entity dossiers (`wiki/entities/`, `raw/`) remain strictly local inside the private vault.

3. **Core Operational Commands**:
   - `/ingest <target>`: Distill raw documents, slide decks, PDFs, or transcripts into structured markdown following OKF v0.2.
   - `/distill-session`: Retrospectively scan the active session transcript and compile newly established concepts and decisions into the vault.
   - `/vault-correct "<fact>"`: Authoritatively update a canonical concept/entity note and refactor living restatements into wikilinks (`[[Target]]`).
   - `/vault-query <query>`: Traverse the knowledge graph to synthesize answers across accumulated notes.
   - `/vault-share`: Audit, sanitize, and share reusable architecture concepts to the shared patterns repository.
   - `/vault-pull`: Synchronize curated patterns from the shared patterns repository into the local vault.
   - `/vault-graph`: Launch or export the 2D/3D WebGL Orbit Graph & Search Hub (`127.0.0.1:8765`).
   - `/wikiskill`: Refine and evolve procedural agent skills (`SKILL.md`) using empirical validation loops.
   - `/vault-lint`: Audit graph connectivity, frontmatter compliance, and auto-heal links.
