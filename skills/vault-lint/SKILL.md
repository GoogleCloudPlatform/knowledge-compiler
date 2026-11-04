---
name: vault-lint
description: >-
  Audits graph health, validates Open Knowledge Format (OKF v0.2) frontmatter compliance, detects broken links, finds orphaned notes, repairs escaped table pipes, and verifies freshness across the central Obsidian Vault ($OBSIDIAN_VAULT_PATH or ~/ObsidianVault). Use when the user invokes /vault-lint or /lint, asks to lint the vault, check vault health, audit the vault, repair vault links, or after major batch ingestions and refactors. Don't use for ingesting new raw documents (use ingest) or launching the interactive 3D WebGL graph server (use vault-graph).
---

# 🧹 Vault Lint & Health-Check Skill (`/vault-lint`)

This skill performs automated graph validation, OKF v0.2 frontmatter schema verification, orphan detection, and link health checks across the central **Knowledge Compiler** Obsidian Vault (`$OBSIDIAN_VAULT_PATH`, defaults to `~/ObsidianVault`).

---

## 🚀 Triggers & Commands

- `/vault-lint` or `/lint`
- Natural language triggers:
  - *"Check vault health"*
  - *"Lint the Obsidian vault"*
  - *"Find broken links or orphan notes in the vault"*
  - *"Verify OKF schema compliance"*

---

## ⚡ Execution Workflow

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       VAULT LINT EXECUTION PIPELINE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [Step 1: Automated Graph & Schema Scan]                                    │
│  Run vault_lint.py across $OBSIDIAN_VAULT_PATH or ~/ObsidianVault           │
│                                │                                            │
│                                ▼                                            │
│  [Step 2: Diagnostic Evaluation]                                            │
│  Analyze broken links, orphan notes, schema defects & stale_after dates     │
│                                │                                            │
│                                ▼                                            │
│  [Step 3: Automated Remediation]                                            │
│  Auto-repair broken link aliases, index missing notes, fix escaped pipes   │
│                                │                                            │
│                                ▼                                            │
│  [Step 4: Audit Trail Logging]                                              │
│  Append audit summary to ObsidianVault/log.md                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. Run Automated Linter (and Optional Upstream OKF Spec Version Check)
Execute the OKF vault linter script via `run_command`:
```bash
python3 <plugin_dir>/scripts/vault_lint.py "${OBSIDIAN_VAULT_PATH:-$HOME/ObsidianVault}" --check-okf-upstream
```
- Pass `--check-okf-upstream` whenever checking whether a newer version of the official Open Knowledge Format specification has been published at [`github.com/GoogleCloudPlatform/open-knowledge-format`](https://github.com/GoogleCloudPlatform/open-knowledge-format) (`SPEC.md`, currently `v0.2`).

### 2. Inspect Audit Heuristics & Graph Intelligence
The linter verifies critical health metrics and computes graph structural insights:
1. **Broken Links (`🔗`)**: Unresolved `[[Target]]` wikilinks where the destination markdown file does not exist.
2. **Table Pipe Invariants (`⚠️`)**: Verifies no escaped pipe characters exist inside tables (`[[Target|Alias]]` required).
3. **Orphan Notes (`🏝️`)**: Notes with 0 inbound wikilinks from other notes or `index.md`.
4. **Dead-End Notes (`🛑`)**: Notes with 0 outbound links.
5. **Freshness & Stale Claims (`⏳`)**: Flags any notes where `current_time >= stale_after`.
6. **Unindexed Wiki Notes (`📑`)**: Markdown notes in `wiki/` that are omitted from `index.md`.
7. **OKF Schema Compliance (`📐`)**: Validates YAML frontmatter keys (`title`, `type`, `created`, `updated`, `tags`, `status`, `generated`, `verified`).
8. **4-Signal Graph Relevance Engine (`🧠`)**:
   - **Bridge Hubs**: High-degree nodes bridging $\ge 2$ distinct knowledge domains.
   - **Cluster Cohesion**: Calculates subgraph density $\frac{2E}{V(V-1)}$ across directories to spot sparse conceptual clusters.
   - **Cross-Synthesis Recommendations**: Uses composite multi-signal scoring ($W = 3.0 \cdot \text{Direct} + 4.0 \cdot \text{SourceOverlap} + 1.5 \cdot \text{Adamic-Adar} + 1.0 \cdot \text{TypeAffinity}$) to recommend missing cross-domain syntheses.

### 3. Automated Remediation
- **Missing Index Entries**: Automatically add missing notes into the appropriate section in `index.md`.
- **Table Pipe Invariant Violations**: Fix any escaped pipe characters inside markdown table links (replace `[[Target\|Alias]]` with `[[Target|Alias]]`).
- **Orphan Resolution**: Add reciprocal connections in corresponding concept or source summaries.
- **Cross-Synthesis Creation**: When recommended by the 4-signal engine, suggest or create `wiki/synthesis/` notes bridging high-affinity topics.

### 4. Append Audit Entry to `log.md`
Prepend a lint audit entry to `${OBSIDIAN_VAULT_PATH:-$HOME/ObsidianVault}/log.md`:
```markdown
## [YYYY-MM-DD] lint | Vault Health & 4-Signal Graph Audit
- Scanned N notes across wiki/, raw/, and index.md.
- Graph connections: N resolved links, 0 broken links.
- OKF compliance: 100%.
- Bridge Hubs identified: <list of key hubs>.
- Remediations: <list of auto-repaired links or index entries>.
```

---

## 🛡️ Critical Invariants
- **Table Wikilink Invariant**: Inside markdown tables, **never escape the pipe character** (always use `[[Target|Alias]]`, never `[[Target\|Alias]]`).
