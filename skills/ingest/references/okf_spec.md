# Open Knowledge Format (OKF v0.3) Specification Quick Reference

The **Open Knowledge Format (OKF v0.3)** (`https://github.com/open-knowledge-format/open-knowledge-format`) is the open standard for machine-maintained knowledge bases and compiled LLM wikis (full backward compatibility with OKF v0.2 bundles).

---

## 🏛 YAML Frontmatter Standard (OKF v0.3 §4–§10)

Every concept note created in `wiki/` (`wiki/sources/`, `wiki/entities/`, `wiki/concepts/`, `wiki/synthesis/`) MUST include valid YAML 1.2 frontmatter with unique keys:

```yaml
---
title: "Canonical Note Title"
type: entity | concept | source-summary | synthesis | BigQuery Table | Metric | Attested Computation
description: "One-sentence summary of this concept."
created: "YYYY-MM-DD"
updated: "YYYY-MM-DD"
tags:
  - domain/topic
  - subtopic
status: stable # draft | stable | deprecated (missing means stable; unknown means not current)
superseded_by: "/wiki/concepts/Replacement.md" # Optional, only with status: deprecated (§5.4)
stale_after: "YYYY-MM-DDTHH:MM:SSZ" # Optional RFC 3339 timestamp or YYYY-MM-DD (00:00Z)
sources:
  - id: source-slug
    resource: "/raw/DocumentName.md" # Leading / resolves from bundle root (§6.2)
    title: "Source Title"
    author: "team:cloud-architecture" # Optional OKF §7 actor (<tool>/<ver>, human:, team:, process:)
generated: { by: "knowledge-compiler/gemini-pro", at: "YYYY-MM-DDTHH:MM:SSZ" }
aliases:
  - "Common Alias"
  - "Acronym"
---
```

> **Trust-Tier Integrity (OKF v0.3 §5.3)**: Omit `verified:` on agent-authored notes until explicit human review (`vault-lint --approve-human <note>`). Every `verified` entry requires both `by` and `at`, and only **current** events (`verified[].at >= generated.at`) confer `human-reviewed` (`human:`) or `machine-confirmed` (`process:` / `team:` / `<tool>/<ver>`) trust.

---

## 📑 Reserved Bundle Files (OKF v0.3 §8–§9)

1. **Root `index.md` (§8.1)**:
   - Declares `okf_version: "0.3"` (quoted string), `title`, one-sentence `description`, and optional `license`.
   - Subdirectory `index.md` files MUST NOT include YAML frontmatter.
2. **`log.md` (§9)**:
   - MUST NOT include YAML frontmatter.
   - Uses strictly `## YYYY-MM-DD` date headings (newest date first) with operation bullets underneath (`- **ingest** | ...`).

---

## 🔗 Paths, Wikilinks & Markdown Formatting Invariants

1. **Path Fields (§6.2 & §12.1)**:
   - In OKF v0.3, path fields (`resource`, `sources[].resource`, `superseded_by`, `computation`, `executor.resource`, `attester.resource`) **starting with `/`** resolve from the bundle root; bare paths without `/` resolve from the file's own directory (v0.2 fallback applies only when `okf_version <= "0.2"` or absent).
2. **Obsidian [[Wikilinks]]**:
   - Use `[[Target]]` or `[[Target|Alias]]` for entity, concept, and source cross-references.
   - Maintain reciprocal connections between closely related notes.
3. **Markdown Table Invariant**:
   - **NEVER** escape the pipe character inside a wikilink in Markdown tables.
   - ✅ Correct: `| [[Target|Alias]] | Column B |`
   - ❌ Incorrect: `| [[Target\|Alias]] | Column B |` (Breaks graph resolution and vault linters).
4. **Footnotes & External Citations (§5.1)**:
   - Use `[^source-id]` matching `sources[].id` when referencing discrete claims.
5. **Mermaid Diagrams**:
   - Quote node labels containing parentheses, colons, or special characters: `id["Node Label (Detail)"]`.
