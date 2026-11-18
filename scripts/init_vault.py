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
"""
Initialize an Open Knowledge Format (OKF v0.3) compliant Knowledge Compiler Obsidian Vault.
Scaffolds directory hierarchy, starter templates, and configuration.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

DEFAULT_GEMINI_MD = """# Vault Schema & Knowledge Compiler Protocol (GEMINI.md)

Welcome to the **Knowledge Compiler** vault. This repository is maintained collaboratively where **Obsidian is the IDE, the LLM is the maintenance programmer, and the markdown wiki is the persistent codebase**.

This vault follows the open standard defined by the **Open Knowledge Format (OKF v0.3)** and Andrej Karpathy's compiled LLM-wiki paradigm.

---

## 🏛 Architecture & Layering

1. **`raw/` (Raw Sources)**:
   - Immutable source materials (clipped web articles, papers, transcripts, PDFs, raw notes).
   - The LLM reads from these files as the source of truth, but **never modifies them**.
   - `raw/assets/`: Downloaded local images, diagrams, and attachments.

2. **`wiki/` (Persistent Knowledge Base)**:
   - Structured, interlinked markdown pages completely maintained by the LLM.
   - `wiki/sources/`: Distilled summaries of ingested sources with key takeaways, quotes, and metadata.
   - `wiki/entities/`: Entity dossiers (people, organizations, platforms, products, tools).
   - `wiki/concepts/`: Topic/concept deep-dives, theories, architectural patterns.
   - `wiki/synthesis/`: Cross-cutting analyses, comparisons, thesis documents, and durable query answers.

3. **Navigation & Audit**:
   - `index.md`: Content-oriented master index declaring `okf_version: "0.3"` and categorizing all wiki pages with one-line summaries (supporting progressive disclosure).
   - `log.md`: Chronological audit log (no frontmatter, `## YYYY-MM-DD` date headings newest-first per OKF v0.3 §9) tracking all vault operations (`ingest`, `query`, `lint`, `refactor`).

---

## 📐 Note Formatting & OKF v0.3 Metadata Standard

Every note created in `wiki/` must include YAML frontmatter compliant with **OKF v0.3**:

```yaml
---
title: "Note Title"
type: entity | concept | source-summary | synthesis
description: "One-sentence summary of this concept."
created: "YYYY-MM-DD"
updated: "YYYY-MM-DD"
tags:
  - domain/topic
status: stable # draft | stable | deprecated (add superseded_by: "/wiki/..." when deprecated)
sources:
  - id: source-slug
    resource: "/raw/source.md"
generated: { by: knowledge-compiler/gemini-pro, at: YYYY-MM-DDTHH:MM:SSZ }
aliases: []
---
```

> **Trust-Tier Integrity (OKF v0.3 §5.3)**: Omit `verified:` on agent-authored notes until explicit human review (`vault-lint --approve-human <note>`). Only verification events with `verified[].at >= generated.at` confer `human-reviewed` or `machine-confirmed` trust.

### Linking Rules
- Prefer standard **OKF v0.3 relative Markdown links** (`[Label](../concepts/Target%20Name.md)`) for cross-tool portability across generic OKF consumers, GitHub, and Obsidian. Obsidian `[[wikilinks]]` remain fully supported and can be converted deterministically via `vault-lint --fix --portable-links`.
- For typed epistemic relationships in frontmatter, use OKF v0.3 §4.1 `x-kc-*` extension keys (`x-kc-corroborates`, `x-kc-complements`, `x-kc-extends`, `x-kc-contradicts`, `x-kc-supersedes`) with bundle-root paths (`"/wiki/concepts/Target.md"`).
- For OKF path fields (`resource`, `sources[].resource`, `superseded_by`, `computation`, `executor.resource`, `attester.resource`), start bundle-root paths with `/` (e.g. `"/raw/deck.pptx"`).
- Ensure reciprocal connections: when note A links to note B as a key dependency/relation, verify note B reflects the relationship.
- **Table Formatting Invariant**: Inside Markdown tables, NEVER escape the pipe character within a wikilink alias (always use `[[Target|Alias]]`, never `[[Target\\|Alias]]`). Escaped pipes break Obsidian link graph resolution and vault linters.
"""

DEFAULT_WIKI_INDEX_MD = """# Wiki Index

Compiled knowledge directory for this OKF v0.3 bundle (see [Master Index](../index.md)).

## Sections

- `wiki/sources/`: Distilled summaries of ingested sources.
- `wiki/entities/`: Entity dossiers (organizations, platforms, products, tools).
- `wiki/concepts/`: Topic and concept deep-dives.
- `wiki/patterns/`: Reusable architectural patterns and engineering invariants.
- `wiki/synthesis/`: Cross-cutting analyses and decision matrices.

## Ledgers

- [Skill Impact & Evolution Ledger](skill-impact.md): Tracks WikiSkill evolution proposals and validation outcomes.
"""

DEFAULT_INDEX_MD = """---
okf_version: "0.3"
title: "Knowledge Vault Index"
description: "Master vault index covering compiled sources, entities, concepts, and synthesis notes."
---

# 🗂️ Master Index

Welcome to the **Knowledge Compiler** index. This document provides a high-level navigational directory of all accumulated sources, entity dossiers, concept deep-dives, and synthesis analyses.

---

## 📥 Ingested Sources (`wiki/sources/`)

| Source | Type | Summary |
| :--- | :--- | :--- |

---

## 🏢 Entity Dossiers (`wiki/entities/`)

| Entity | Domain / Category | Key Description |
| :--- | :--- | :--- |

---

## 💡 Core Concepts & Architectures (`wiki/concepts/`)

| Concept | Domain | Key Architecture / Thesis |
| :--- | :--- | :--- |

---

## 🔬 Compound Synthesis & Cross-Cutting Analyses (`wiki/synthesis/`)

| Synthesis Document | Focus Areas | Key Findings |
| :--- | :--- | :--- |

---

## 🛠️ Evolution & Operations Ledgers (`wiki/`)

| Ledger | Category | Purpose |
| :--- | :--- | :--- |
| [Vault Teleology & Strategic Anchors](purpose.md) | `meta/teleology` | Active engagements, architectural pillars, and open theses. |
| [Wiki Directory Index](wiki/index.md) | `meta/index` | Frontmatter-free OKF v0.3 §8 progressive-disclosure index for `wiki/`. |
| [Skill Impact & Evolution Ledger](wiki/skill-impact.md) | `skill-evolution/ledger` | Tracks WikiSkill evolution proposals and validation outcomes. |
| [Vault Schema & Compiler Protocol](GEMINI.md) | `meta/schema` | OKF v0.3 frontmatter rules, linking invariants, and directory architecture. |
| [Vault Activity Log](log.md) | `meta/audit` | Chronological log of ingest, query, correction, and lint runs. |
"""

DEFAULT_LOG_MD = """# 📜 Vault Activity Log

Chronological audit log tracking all vault operations (`ingest`, `query`, `lint`, `refactor`).

## {today}
- **init** | Vault Initialized: Scaffolding generated for OKF v0.3 Knowledge Compiler Obsidian Vault (`raw/`, `raw/assets/`, `wiki/sources/`, `wiki/entities/`, `wiki/concepts/`, `wiki/synthesis/`, `index.md`, `log.md`, `GEMINI.md`).
"""

DEFAULT_PURPOSE_MD = """---
title: "Vault Teleology & Strategic Anchors"
type: meta
created: {today}
updated: {today}
tags:
  - meta/teleology
  - strategy/architecture
status: stable
---

# 🎯 Vault Teleology & Strategic Anchors

This file serves as the **Layer 0 Strategic Anchor** for autonomous agent reasoning during `/ingest`, `/vault-query`, and `/wikiskill`.

## 🏢 Active Projects & Engagements
| Project / Organization | Primary Owner | Strategic Focus | Target Architecture |
| :--- | :--- | :--- | :--- |
| **Project Alpha** | @arch-lead | Cloud Migration & DB Modernization | Spanner, GKE Enterprise |

## 🏛 Core Architectural Pillars
1. **Enterprise Data Modernization**: Migrating legacy databases to Cloud Spanner and Cloud SQL.
2. **AI & Agentic Systems**: Autonomous multi-agent orchestration via Vertex AI Agent Engine and Antigravity SDK.

## 🔬 Open Investigative Theses
- **Thesis A**: Evaluating cross-region read latency trade-offs between Multi-Region Spanner vs Dual-Region Cloud SQL.
"""

DEFAULT_SKILL_IMPACT_MD = """---
title: "Skill Impact & Evolution Ledger"
type: meta
created: {today}
updated: {today}
tags:
  - skill-evolution/ledger
status: stable
---

# 📈 Skill Impact & Negative-Knowledge Ledger

This ledger tracks all autonomous and manual skill evolution proposals, benchmark validation outcomes, and rejected candidate diffs under the **WikiSkill Protocol** (Tang et al., 2026, [arXiv:2608.27454](https://arxiv.org/html/2608.27454v1)).

> [!IMPORTANT]
> **Asymmetric Invariant**: When a candidate skill proposal fails or regresses during validation, the active skill file (`SKILL.md`) is rolled back, but **this ledger entry is never rolled back**. It permanently documents rejected diffs and failure rationales to prevent optimization loops.

## 📜 Evolutionary History
| Iteration | Target Skill | Patch Summary | Validation Delta | Status | Failure / Success Rationale |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **001** | `knowledge-compiler` | Initial OKF v0.3 scaffolding and extraction pipeline | High | ✅ Accepted | Baseline skill initialization and multi-format extraction verified. |
"""

DEFAULT_ARCHITECTURE_BASE = """filters:
  and:
    - file.ext == "md"
    - or:
        - file.inFolder("wiki/concepts")
        - file.inFolder("wiki/patterns")
formulas:
  days_untouched: (now() - file.mtime).days.round(0)
properties:
  file.name:
    displayName: Architecture / Pattern
  status:
    displayName: Status
  type:
    displayName: Type
  tags:
    displayName: Tags
  updated:
    displayName: Updated
  formula.days_untouched:
    displayName: Days Untouched
views:
  - type: table
    name: All Patterns & Concepts
    order:
      - file.name
      - status
      - tags
      - updated
      - formula.days_untouched
  - type: table
    name: 🤖 Multi-Agent & Orchestration
    filters:
      or:
        - file.hasTag("multi-agent")
        - file.hasTag("architecture/multi-agent")
        - file.hasTag("a2a-protocol")
        - file.hasTag("model-context-protocol")
    order:
      - file.name
      - status
      - tags
      - updated
  - type: table
    name: 🧠 Context & Knowledge Compiler
    filters:
      or:
        - file.hasTag("context-engineering")
        - file.hasTag("knowledge-compiler")
        - file.hasTag("architecture/llm-wiki")
        - file.hasTag("llm-wiki")
        - file.hasTag("spec-driven-development")
    order:
      - file.name
      - status
      - tags
      - updated
  - type: table
    name: 🔒 Security & Governance
    filters:
      or:
        - file.hasTag("security")
        - file.hasTag("security/zero-trust")
        - file.hasTag("identity")
        - file.hasTag("agent-governance")
        - file.hasTag("threat-defense")
    order:
      - file.name
      - status
      - tags
      - updated
  - type: table
    name: ☁️ Cloud Modernization & Data
    filters:
      or:
        - file.hasTag("cloud-migration")
        - file.hasTag("modernization")
        - file.hasTag("data-architecture")
        - file.hasTag("finops")
        - file.hasTag("google-cloud")
    order:
      - file.name
      - status
      - tags
      - updated
  - type: table
    name: 🛠️ Invariants & Standards
    filters:
      or:
        - file.inFolder("wiki/patterns")
        - file.hasTag("skill-evolution/pattern")
        - file.hasTag("markdown/syntax")
        - file.hasTag("google-slides")
    order:
      - file.name
      - status
      - tags
      - updated
"""

DEFAULT_CUSTOMER_BASE = """filters:
  and:
    - file.ext == "md"
    - file.inFolder("wiki/entities")
formulas:
  days_untouched: (now() - file.mtime).days.round(0)
properties:
  file.name:
    displayName: Entity
  status:
    displayName: Status
  tags:
    displayName: Tags
  updated:
    displayName: Last Updated
  formula.days_untouched:
    displayName: Days Untouched
views:
  - type: table
    name: 🏢 Organizations & Projects
    filters:
      or:
        - file.hasTag("customer")
        - file.hasTag("entity/customer")
    order:
      - file.name
      - status
      - tags
      - updated
      - formula.days_untouched
  - type: table
    name: ☁️ Platforms, Products & Tools
    filters:
      or:
        - file.hasTag("google-cloud")
        - file.hasTag("agent-platform")
        - file.hasTag("database")
        - file.hasTag("tooling/compiler")
        - file.hasTag("developer-tools")
    order:
      - file.name
      - status
      - tags
      - updated
  - type: table
    name: 🤝 Partners & Ecosystem
    filters:
      or:
        - file.hasTag("partner")
        - file.hasTag("gsi")
    order:
      - file.name
      - status
      - tags
      - updated
  - type: table
    name: 👤 People & Researchers
    filters:
      or:
        - file.hasTag("person")
        - file.hasTag("entity/person")
    order:
      - file.name
      - tags
      - updated
  - type: table
    name: All Entities
    order:
      - file.name
      - status
      - tags
      - updated
      - formula.days_untouched
"""

DEFAULT_RECENT_BASE = """filters:
  and:
    - 'file.ext == "md"'
    - 'file.inFolder("wiki")'
formulas:
  days_untouched: '(now() - file.mtime).days.round(0)'
properties:
  file.name:
    displayName: "Note"
  type:
    displayName: "Type"
  status:
    displayName: "Status"
  tags:
    displayName: "Tags"
  updated:
    displayName: "Updated"
  formula.days_untouched:
    displayName: "Days Ago"
views:
  - type: table
    name: "⚡ Touched Last 7 Days"
    filters:
      - 'formula.days_untouched <= 7'
    order:
      - file.name
      - type
      - status
      - updated
      - formula.days_untouched
  - type: table
    name: "📅 Touched Last 30 Days"
    filters:
      - 'formula.days_untouched <= 30'
    order:
      - file.name
      - type
      - status
      - updated
      - formula.days_untouched
  - type: table
    name: "🗂️ All Compiled Notes"
    order:
      - file.name
      - type
      - status
      - tags
      - updated
      - formula.days_untouched
"""

DEFAULT_SOURCES_BASE = """filters:
  and:
    - 'file.ext == "md"'
    - or:
        - 'file.inFolder("wiki/sources")'
        - 'file.inFolder("wiki/synthesis")'
formulas:
  days_untouched: '(now() - file.mtime).days.round(0)'
properties:
  file.name:
    displayName: "Deliverable / Source"
  type:
    displayName: "Type"
  status:
    displayName: "Status"
  tags:
    displayName: "Tags"
  updated:
    displayName: "Updated"
  formula.days_untouched:
    displayName: "Days Untouched"
views:
  - type: table
    name: "🔬 Synthesis & Proposals"
    filters:
      - 'file.inFolder("wiki/synthesis")'
    order:
      - file.name
      - status
      - tags
      - updated
      - formula.days_untouched
  - type: table
    name: "📥 Distilled Sources"
    filters:
      - 'file.inFolder("wiki/sources")'
    order:
      - file.name
      - status
      - tags
      - updated
      - formula.days_untouched
  - type: table
    name: "All Sources & Synthesis"
    order:
      - file.name
      - type
      - status
      - tags
      - updated
"""

DEFAULT_GITIGNORE = """.obsidian/workspace*
.obsidian/cache/
.knowledge-compiler/
.trash/
*.tmp
__pycache__/
.DS_Store
"""


def init_vault(
    target_path: Path | str,
    force: bool = False,
    as_json: bool = False,
    quiet: bool = False,
    init_git: bool = False,
) -> dict:
    target_path = Path(target_path).resolve()
    results = {
        "target_path": str(target_path),
        "directories_created": [],
        "files_created": [],
        "errors": [],
        "success": False,
    }

    try:
        # Create directories
        directories = [
            target_path / "raw" / "assets",
            target_path / "wiki" / "sources",
            target_path / "wiki" / "entities",
            target_path / "wiki" / "concepts",
            target_path / "wiki" / "patterns",
            target_path / "wiki" / "synthesis",
            target_path / "bases",
            target_path / ".obsidian",
        ]

        for d in directories:
            if not d.exists():
                d.mkdir(parents=True, exist_ok=True)
                results["directories_created"].append(str(d.relative_to(target_path)))

        today_str = datetime.date.today().isoformat()

        # Create starter files
        file_templates = [
            (target_path / "purpose.md", DEFAULT_PURPOSE_MD.format(today=today_str)),
            (target_path / "GEMINI.md", DEFAULT_GEMINI_MD),
            (target_path / "index.md", DEFAULT_INDEX_MD.format(today=today_str)),
            (target_path / "log.md", DEFAULT_LOG_MD.format(today=today_str)),
            (target_path / "wiki" / "index.md", DEFAULT_WIKI_INDEX_MD),
            (
                target_path / "wiki" / "skill-impact.md",
                DEFAULT_SKILL_IMPACT_MD.format(today=today_str),
            ),
            (target_path / ".gitignore", DEFAULT_GITIGNORE),
            (
                target_path / "bases" / "Architecture Catalog.base",
                DEFAULT_ARCHITECTURE_BASE,
            ),
            (
                target_path / "bases" / "Customer & Entity Directory.base",
                DEFAULT_CUSTOMER_BASE,
            ),
            (
                target_path / "bases" / "Recently Touched.base",
                DEFAULT_RECENT_BASE,
            ),
            (
                target_path / "bases" / "Sources & Synthesis.base",
                DEFAULT_SOURCES_BASE,
            ),
        ]

        for file_path, content in file_templates:
            if not file_path.exists() or force:
                file_path.write_text(content, encoding="utf-8")
                results["files_created"].append(str(file_path.relative_to(target_path)))

        if init_git and not (target_path / ".git").exists():
            import subprocess

            subprocess.run(
                ["git", "init", "-b", "main"],
                cwd=str(target_path),
                capture_output=True,
                timeout=8,
                check=False,
            )

        results["success"] = True

    except Exception as e:
        results["errors"].append(str(e))
        results["success"] = False

    if quiet:
        return results

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        if results["success"]:
            print(f"🚀 OKF v0.3 Knowledge Compiler Vault initialized at: {target_path}")
            print("\n📁 Created Directory Hierarchy:")
            print("  ├── raw/               (Immutable sources)")
            print("  │   └── assets/        (Extracted diagrams & raster media)")
            print("  ├── wiki/              (Structured knowledge graph)")
            print("  │   ├── sources/       (Distilled source summaries)")
            print("  │   ├── entities/      (Account, tool, product dossiers)")
            print("  │   ├── concepts/      (Architectural deep-dives)")
            print("  │   └── synthesis/     (Cross-cutting analyses)")
            print("  ├── bases/             (Native Obsidian .base dynamic views)")
            print("  ├── GEMINI.md          (Vault schema & compiler protocol)")
            print("  ├── index.md           (Master catalog index)")
            print("  └── log.md             (Chronological audit log)")
        else:
            print(
                f"❌ Error initializing vault: {', '.join(results['errors'])}",
                file=sys.stderr,
            )

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Initialize an OKF v0.3 Knowledge Compiler Obsidian Vault."
    )
    parser.add_argument(
        "--target",
        "-t",
        default=".",
        help="Target directory to initialize as a Knowledge Compiler vault (default: current directory).",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite existing template files if present.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format.",
    )
    args = parser.parse_args()

    res = init_vault(Path(args.target), force=args.force, as_json=args.json)
    if not res["success"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
