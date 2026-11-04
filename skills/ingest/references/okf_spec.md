# Open Knowledge Format (OKF v0.2) Specification Quick Reference

The **Open Knowledge Format (OKF v0.2)** is the open standard for machine-maintained personal knowledge management (PKM) and compiled LLM wikis.

---

## 🏛 YAML Frontmatter Standard

Every markdown note created in `wiki/` (`wiki/sources/`, `wiki/entities/`, `wiki/concepts/`, `wiki/synthesis/`) MUST include valid YAML frontmatter:

```yaml
---
title: "Canonical Note Title"
type: entity | concept | source-summary | synthesis | BigQuery Table | Metric | Attested Computation
created: YYYY-MM-DD
updated: YYYY-MM-DD
tags:
  - domain/topic
  - subtopic
status: stable # draft | stable | deprecated
stale_after: YYYY-MM-DDTHH:MM:SSZ # Optional ISO timestamp
sources:
  - "[[Source Note Link|Source Note Link]]"
  - "/optional/filesystem/path"
generated:
  by: antigravity/gemini-pro
  at: YYYY-MM-DDTHH:MM:SSZ
verified:
  - by: human:author
    at: YYYY-MM-DDTHH:MM:SSZ
aliases:
  - "Common Alias"
  - "Acronym"
---
```

---

## 🔗 Wikilink & Markdown Formatting Invariants

1. **Obsidian [[Wikilinks]]**:
   - Use `[[Target]]` or `[[Target|Alias]]` for all entity, concept, and source references.
   - Maintain reciprocal connections (if Note A depends on Note B, Note B should link back to Note A).
2. **Markdown Table Invariant**:
   - **NEVER** escape the pipe character inside a wikilink in Markdown tables.
   - ✅ Correct: `| [[Target|Alias]] | Column B |`
   - ❌ Incorrect: `| [[Target\|Alias]] | Column B |` (Breaks graph resolution and vault linters).
3. **Footnotes & External Citations**:
   - Use `[^source-id]` when referencing discrete external source claims or pages.
4. **Mermaid Diagrams**:
   - Quote node labels containing parentheses, colons, or special characters: `id["Node Label (Detail)"]`.
