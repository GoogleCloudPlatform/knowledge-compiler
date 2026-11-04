---
name: wikiskill
description: >-
  Executes autonomous closed-loop agent skill evolution, trace diagnosis, refinement, and optimization using Google Research's WikiSkill framework (arXiv:2608.27454). Use when the user invokes /wikiskill or /evolve-skill, asks to evolve, optimize, improve, debug, or refine a skill, or after observing tool failures, user corrections, or sub-optimal agent trajectories. Don't use for ingesting domain documents into the Obsidian Vault (use ingest) or checking markdown frontmatter links (use vault-lint).
---

# 🧬 WikiSkill: Autonomous Agent Skill Evolution (`/wikiskill`)

This skill implements the Google Research **WikiSkill** framework (Tang et al., 2026) to discover, compile, and evolve modular procedural skills (`SKILL.md`) using a **three-layer architecture**, **on-demand ReAct proposing**, and **asymmetric rollback gating**.

---

## 🚀 Triggers & Commands

- `/wikiskill <target_skill_or_tool>` or `/evolve-skill <target_skill>`
- Natural language triggers:
  - *"Evolve our ingest skill based on recent PDF runs"*
  - *"Optimize the google-antigravity-sdk skill to handle local models better"*
  - *"Refine our chrome-extensions skill after recent WebExtension errors"*
  - *"Improve skill based on the latest conversation trace"*

---

## 🏛 The 4-Agent Evolutionary Loop

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WIKISKILL 4-AGENT EVOLUTIONARY LOOP                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. Trace Ingestion (Layer 1: Raw Traces)                                   │
│     Parse transcript.jsonl using analyze_trace.py to extract tool errors.   │
│                                │                                            │
│                                ▼                                            │
│  2. Wiki Compilation (Layer 2: Persistent Knowledge)                        │
│     Diagnose root causes & compile into ObsidianVault/wiki/patterns/*.md    │
│                                │                                            │
│                                ▼                                            │
│  3. ReAct Skill Proposer (Layer 3: Candidate Directives)                    │
│     Read wiki/index.md, impact ledger & fetch patterns on demand.           │
│     Draft minimal, atomic patch P_k for target SKILL.md.                   │
│                                │                                            │
│                                ▼                                            │
│  4. Validation Gating & Asymmetric Rollback                                 │
│     Run test tasks (Inference agent isolated from wiki).                   │
│     ├── IF PASS: Retain SKILL.md and log "Accepted" in skill-impact.md      │
│     └── IF FAIL: Roll back SKILL.md, but log "Rejected" in skill-impact.md  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Execution Workflow

### Step 1: Trace Ingestion (`analyze_trace.py`)
1. Locate recent conversation transcripts in `<appDataDir>/brain/<conversation-id>/.system_generated/logs/transcript.jsonl`.
2. Run the trace analyzer to extract tool errors and user corrections:
   ```bash
   python3 <plugin_dir>/skills/wikiskill/scripts/analyze_trace.py <path_to_transcript.jsonl>
   ```
3. Identify recurring error signatures, parameter schema violations, or procedural ambiguities.

### Step 2: Compile Pattern Dossier (`wiki/patterns/`)
1. Create or update a persistent pattern dossier at:
   `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/wiki/patterns/<error_pattern_name>.md`
2. Include OKF v0.2 frontmatter:
   ```yaml
   ---
   title: "Pattern: Error or Strategy Name"
   type: concept
   tags:
     - skill-evolution/pattern
   status: stable
   sources:
     - "[[wiki/sources/...]]"
   aliases: []
   ---
   ```
3. Document:
   - **Observed Failure Trace**: Tool call arguments, error messages, and incorrect assumptions.
   - **Root Cause**: Why the model failed (missing flag, incorrect schema, context truncation).
   - **Corrective Strategy**: The verified, minimal procedural directive to prevent recurrence.

### Step 3: On-Demand Skill Proposing
1. Read the target skill (e.g. `~/.gemini/config/plugins/<plugin>/skills/<skill>/SKILL.md` or `.agents/skills/<skill>/SKILL.md`).
2. Read `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/wiki/skill-impact.md` to review prior accepted and rejected proposals (avoiding previously failed approaches).
3. Draft a clean, atomic patch $P_k$ to the target `SKILL.md`.

### Step 4: Validation Gating & Asymmetric Rollback
1. Execute validation test rollouts against sample tasks.
2. **Failure Mode Isolation**: Ensure the test agent executes purely against the candidate `SKILL.md` (no background wiki cheating).
3. Evaluate outcome:
   - **If Validation Passes**: Keep the updated `SKILL.md`. Append an `Accepted` entry to `wiki/skill-impact.md`.
   - **If Validation Fails/Regresses**: Immediately revert `SKILL.md` to previous checkpoint $S_{k-1}$. Append a `Rejected` entry to `wiki/skill-impact.md` with the diff and failure explanation. **The wiki record is never rolled back**.

### Step 5: Update Master Index & Vault Log
1. Add new pattern notes to `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/index.md`.
2. Append entry to `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/log.md`:
   `## [YYYY-MM-DD] evolve | <Target Skill Name>`

---

## 📚 Reference Assets
- **Asymmetric Rollback Protocol**: [references/rollback_protocol.md](references/rollback_protocol.md)
- **Trace Analyzer**: [scripts/analyze_trace.py](scripts/analyze_trace.py)
