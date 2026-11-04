---
name: vault-query
description: >-
  Searches, traverses, and synthesizes answers from the local OKF v0.2 knowledge vault and optional shared pattern repositories, writing durable cross-cutting analyses to wiki/synthesis/. Use when the user invokes /vault-query or /query, asks what the vault says about a topic, or wants to synthesize across compiled wiki notes. Don't use for ingesting new raw files into the vault (use ingest) or correcting stale claims across notes (use vault-correct).
---

# 🔍 Vault Query & Compounding Synthesis Skill (`/vault-query`)

This skill enables agents across any working directory to systematically explore, traverse, and synthesize accumulated intelligence from the central **Knowledge Compiler** Obsidian Vault (`$OBSIDIAN_VAULT_PATH`, defaults to `~/ObsidianVault`) and compound novel insights back into the persistent wiki following the **Open Knowledge Format (OKF v0.2)**.

---

## 🚀 Triggers & Commands

- `/vault-query <topic_or_question>` or `/query <topic_or_question>`
- Natural language requests:
  - *"What does our vault say about AcmeCorp's ERP modernization?"*
  - *"Search vault for FedRAMP high voice synthesis architectures"*
  - *"Consult vault for Google ADK vs LangGraph tradeoffs"*
  - *"Synthesize our accumulated patterns on agent governance and identity"*

---

## ⚡ Execution Workflow

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       VAULT QUERY EXECUTION PIPELINE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [Step 1: Anchor Discovery]                                                 │
│  Read ObsidianVault/index.md or grep_search in wiki/ to find entry nodes    │
│                                │                                            │
│                                ▼                                            │
│  [Step 2: Associative Graph Traversal]                                      │
│  Follow [[wikilinks]] across wiki/entities/, wiki/concepts/, wiki/sources/  │
│                                │                                            │
│                                ▼                                            │
│  [Step 3: Grounded Answer Synthesis]                                        │
│  Generate cited response with wikilinks & terminal ASCII diagrams          │
│                                │                                            │
│                                ▼                                            │
│  [Step 4: Compounding Knowledge Writeback]                                  │
│  If analysis is non-trivial, compile durable note to wiki/synthesis/<Topic> │
│  Update index.md and log.md                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

Follow these 4 mandatory steps:

### 1. Anchor Discovery & Federated Retrieval
1. Consult `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/purpose.md` to align the query context with active projects, architectural pillars, and open investigative theses.
2. Open the master catalog at `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/index.md` and, if present, `${OKF_PATTERNS_PATH:-~/shared-okf-patterns}/index.md`.
3. Locate primary entry points across:
   - `wiki/entities/`: Organization profiles, platforms, tools, people.
   - `wiki/concepts/`: Architecture blueprints, security patterns, algorithms, frameworks.
   - `wiki/sources/`: Distilled meeting notes, whitepapers, lecture decks.
4. If targeted keyword matching is required, search across `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/wiki`.

### 2. Associative Graph Traversal (Progressive Disclosure)
1. Read the anchor note(s) using `view_file`.
2. Follow outgoing `[[wikilinks]]` to related concepts, entities, and sources.
3. Check reciprocal links to ensure comprehensive bidirectional context.
4. Extract key facts, metrics, decision rationales, and customer constraints.

### 3. Grounded Answer Synthesis
1. Structure the response with clear headings, bullet points, and comparison tables.
2. **Clickable Links**: Link all referenced entities and concepts using `[[Target|Alias]]` or `[Target](file:///path/to/ObsidianVault/wiki/...)`.
3. **CLI Visual Invariant**: When rendering architectures or process flows, output clean **ASCII/Unicode text box diagrams** directly in the terminal chat.

### 4. Compounding Synthesis Writeback (Karpathy Compiler Invariant)
If the query produces non-trivial cross-cutting analysis, customer comparisons, or novel architectural synthesis:
1. Create a permanent synthesis note at:
   `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/wiki/synthesis/<Topic_Name>.md`
2. Include standard OKF v0.2 frontmatter:
   ```yaml
   ---
   title: "Synthesis Title"
   type: synthesis
   created: YYYY-MM-DD
   updated: YYYY-MM-DD
   tags:
     - domain/topic
   status: stable
   sources:
     - "[[wiki/sources/...]]"
   generated:
     by: antigravity/gemini-pro
     at: YYYY-MM-DDTHH:MM:SSZ
   verified:
     - by: human:<username>
       at: YYYY-MM-DDTHH:MM:SSZ
   aliases: []
   ---
   ```
3. Add the new synthesis note into `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/index.md` under `## 📑 Synthesis & Research Analyses`.
4. Append an entry to `${OBSIDIAN_VAULT_PATH:-~/ObsidianVault}/log.md`:
   `## [YYYY-MM-DD] query | <Topic Name>`

---

## 🛡️ Critical Invariants

- **Table Invariant**: Inside markdown tables, **never escape pipe characters** in wikilinks (always use `[[Target|Alias]]`, never `[[Target\|Alias]]`).
- **Reciprocal Integrity**: If writing a new synthesis note that references note A and note B, add reciprocal backlinks to note A and note B.
