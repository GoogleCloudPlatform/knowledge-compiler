---
name: vault-correct
description: >-
  Sweeps a corrected fact through the OKF v0.2 knowledge vault by updating the single authoritative note, refactoring stale restatements into wikilinks, and preserving historical records byte-for-byte. Use when the user invokes /vault-correct, asks to correct a vault fact or update an obsolete claim, or when superseded claims are detected during /distill-session or /ingest. Don't use for creating new notes from raw files (use ingest) or read-only vault searches (use vault-query).
---

# ⚖️ Vault Correct & Write-Correctness Sweep (`/vault-correct`)

This skill sweeps a corrected fact through the central **Knowledge Compiler** Obsidian Vault (`$OBSIDIAN_VAULT_PATH` or `~/ObsidianVault`). It implements the **Write-Correctness Laws** to eradicate knowledge staleness and contradiction drift while strictly guarding historical decision ledgers.

---

## 🚀 Triggers & Invocations

### 1. Explicit User Command
```bash
/vault-correct "<the corrected fact, stated as it is now true>" [--stale "<old claim>"] [--target "<authoritative note>"]
```
*Examples:*
- `/vault-correct "AcmeCorp MySQL spend is $25,000/mo across 20 Aurora clusters, not $30k/mo" --stale "$30k+/mo" --target "AcmeCorp"`
- `/vault-correct "Cloud Run A2A agents natively persist session memory via Vertex AI Memory Bank"`

### 2. Autonomous Trigger (Zero-Toil Mode)
Triggered automatically by the agent during:
- **`/ingest`**: When a newly ingested document or proposal carries a newer timestamp and directly contradicts an older claim in an entity or concept note.
- **`/distill-session` or Antigravity `Stop` Hook**: When an active session empirically disproves a previous assumption (e.g., verifying database sizing via BigQuery CUR queries or API diagnostic probes).

---

## 📐 Execution Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       VAULT CORRECT EXECUTION PIPELINE                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [Step 1: Dual-Arm Discovery Sweep]                                         │
│  Scan vault files using exact strings (ripgrep) and semantic overlap       │
│                                │                                            │
│                                ▼                                            │
│  [Step 2: Tri-State Classification]                                         │
│  Classify every matching note into:                                         │
│    1. AUTHORITATIVE: Single source of truth (wiki/entities/ or wiki/concepts)│
│    2. RESTATEMENT:   Living notes asserting the fact                        │
│    3. HISTORICAL:    Past records (raw/, wiki/sources/, dated, log.md)      │
│                                │                                            │
│                                ▼                                            │
│  [Step 3: Corrective Transformation]                                        │
│  • AUTHORITATIVE: Update text & bump updated: YYYY-MM-DD                   │
│  • RESTATEMENT:   Refactor assertion into [[Authoritative Note]] link      │
│  • HISTORICAL:    ✋ PRESERVE byte-for-byte (Do NOT edit past records)      │
│                                │                                            │
│                                ▼                                            │
│  [Step 4: Audit Ledger & Indexing]                                          │
│  Append structured entry to log.md (updated, refactored, preserved)        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ The Hard Rails (Safety Invariants)

1. **Historical Notes are Untouchable**:
   - Notes under `raw/`, `archive/`, `meetings/`, `1-1/`, `journal/`, `incidents/` are **never edited**.
   - Source summaries under `wiki/sources/` represent immutable extraction snapshots from a specific date and are **never edited**.
   - Any note whose filename or title carries explicit date provenance (e.g. `YYYY-MM-DD` or `(YYYY-MM)`) is **never edited**.
   - Any note whose frontmatter `status` is `superseded`, `archived`, `completed`, or `deprecated` is **never edited**.
   - The central operations ledger `log.md` is append-only and past entries are **never edited**.
   - *Rationale*: A missed restatement is a minor stale claim. But rewriting historical records destroys the empirical ledger of what was believed on that date.

2. **No Authoritative Note, No Edits**:
   - If the single source of truth cannot be determined with certainty, the sweep reports findings and halts rather than guessing.

3. **Never Delete Notes**:
   - Restatements are refactored into reciprocal `[[Authoritative Note]]` links, preserving page context and enhancing graph density.

4. **Table Pipe Invariant**:
   - In Markdown tables, never escape the pipe character within a wikilink alias (always `[[Target|Alias]]`, never `[[Target\|Alias]]`).

---

## ⚡ Step-by-Step Procedure

### Step 1: Run Candidate Discovery
Run the vault correction utility:
```bash
python3 <plugin_dir>/scripts/vault_correct.py "<corrected fact>" --stale "<old claim>" --target "<authoritative note>"
```
To preview changes before applying:
```bash
python3 <plugin_dir>/scripts/vault_correct.py "<corrected fact>" --stale "<old claim>" --target "<authoritative note>" --dry-run
```

### Step 2: Autonomous Engine Hook
When invoking programmatically from Python or subagents:
```python
from scripts.vault_correct import execute_vault_correction

results = execute_vault_correction(
    vault_root=vault_path,
    fact="Cloud Run A2A agents natively persist session memory via Vertex AI Memory Bank",
    stale_claim="in-memory Cloud Run storage",
    target_authoritative="Agent Memory & Vertex AI Memory Bank",
    dry_run=False,
    auto=True,
)
```

### Step 3: Verify & Audit
1. Inspect the terminal output for:
   - `AUTHORITATIVE`: Target note confirmed and updated.
   - `RESTATEMENTS`: Redundant claims replaced with wikilinks.
   - `HISTORICAL RECORDS`: Preserved notes clearly listed with reason.
2. Run `python3 <plugin_dir>/scripts/vault_lint.py "${OBSIDIAN_VAULT_PATH:-$HOME/ObsidianVault}"` to confirm that all newly inserted wikilinks resolve cleanly with zero pipe violations.

