# Knowledge Compiler (`knowledge-compiler`)

[![Version](https://img.shields.io/badge/version-0.9.0-1A73E8?style=flat-square)](https://github.com/GoogleCloudPlatform/knowledge-compiler)
[![OKF Standard](https://img.shields.io/badge/Open_Knowledge_Format-OKF_v0.2-34A853?style=flat-square)](https://github.com/GoogleCloudPlatform/open-knowledge-format)
[![License](https://img.shields.io/badge/license-Apache_2.0-FBBC04?style=flat-square)](LICENSE)

> **Obsidian is the IDE. The Agent is the Maintenance Programmer. The Markdown Wiki is the Persistent Codebase.**

**Knowledge Compiler** is an open-source knowledge engineering plugin and CLI suite implementing the [Open Knowledge Format (`OKF v0.2`)](https://github.com/GoogleCloudPlatform/open-knowledge-format) and Andrej Karpathy's compiled LLM-Wiki architecture. It compiles unstructured documents (`.pptx`, `.pdf`, `.docx`, `.xlsx`, `.html`, `.mhtml`, transcripts, and codebases) into a schema-validated Markdown wiki (`raw/` → `wiki/` → `index.md` & `log.md`) with an interactive **2D/3D WebGL Knowledge Graph**, so coding agents start every project with curated, reviewable context.

![Vault Architecture](assets/vault-layer-topology.svg)

---

## Core Capabilities

<!-- mdformat off -->
| Capability | Command / Skill | Underlying Script |
| :--- | :--- | :--- |
| **Multimodal Source Ingestion** | `/ingest <target>` | `scripts/extract_source.py` |
| **Retrospective Session Distillation** | `/distill-session` | Native skill workflow |
| **Tri-State Fact Correction Sweep** | `/vault-correct "<fact>"` | `scripts/vault_correct.py` |
| **Graph & Schema Auto-Linter** | `/vault-lint` | `scripts/vault_lint.py` |
| **2D/3D WebGL Knowledge Graph** | `/vault-graph` | `scripts/vault_graph.py` |
| **Sanitized Pattern Sharing** | `/vault-share` & `/vault-pull` | `scripts/sync_patterns.py` |
| **Strict DLP & Link Sanitizer** | `vault-sanitize-check` | `scripts/sanitize_check.py` |
| **Closed-Loop Skill Evolution** | `/wikiskill` | `scripts/analyze_trace.py` |
<!-- mdformat on -->

---

## What This Plugin Installs

- **10 Agent Skills (`skills/*/SKILL.md`)**: `knowledge-compiler`, `ingest`, `distill-session`, `vault-correct`, `vault-query`, `vault-lint`, `vault-graph`, `vault-share`, `vault-pull`, and `wikiskill`.
- **1 Workspace Rule (`rules/AGENTS.md`)**: Progressive disclosure and OKF v0.2 formatting guidelines.
- **3 Lifecycle Hooks (`hooks.json`)**:
  - `wikiskill-error-recorder` (`PostToolUse`, **enabled by default**): Captures redacted local tool failure diagnostics to `.agents/error_traces.jsonl` (or `~/.local/share/knowledge-compiler/logs/`) to power `/wikiskill`.
  - `vault-session-start` & `vault-stop-hook` (**disabled by default**): Optional Git pull/push synchronization hooks for users who explicitly opt in to backing their vault with a Git `origin` remote.
- **1 Interactive Sidecar (`sidecars/vault_graph`)**: Local loopback 2D/3D WebGL Knowledge Graph server (`127.0.0.1:8765`).

---

## Quick Start

**Prerequisites**: Python `>= 3.10` (`>= 3.11` recommended) and Git.

```bash
git clone https://github.com/GoogleCloudPlatform/knowledge-compiler.git
cd knowledge-compiler
python3 -m pip install -e ".[extract]"

# Initialize an OKF v0.2 Knowledge Vault
python3 scripts/init_vault.py --target ~/ObsidianVault

# Optional: manual install for Gemini CLI / non-Marketplace setups (Marketplace users skip this)
python3 scripts/install_plugin.py
```

---

## Hooks & Local Data Privacy

- **100% Local Default Operation**: All compiled Markdown notes (`wiki/`, `index.md`, `log.md`), SHA-256 ingestion caches (`raw/.ingest_cache.json`), and redacted error traces remain on your local filesystem.
- **User-Initiated Network Calls Only**: Outbound HTTP requests occur only when you explicitly pass a web URL to `scripts/extract_source.py`, pass `--check-okf-upstream` to `scripts/vault_lint.py`, or manually enable the opt-in Git `origin` sync hooks in `hooks.json`.

---

## Troubleshooting, Feedback & Security

- **Troubleshooting**: Run `python3 scripts/vault_lint.py --fix` to repair broken `[[wikilinks]]` or frontmatter formatting. If port `8765` is in use, pass `--port <PORT>` to `scripts/vault_graph.py`.
- **Feedback & Issues**: Report bugs or feature requests at [https://github.com/GoogleCloudPlatform/knowledge-compiler/issues](https://github.com/GoogleCloudPlatform/knowledge-compiler/issues).
- **Security**: See [SECURITY.md](SECURITY.md) for vulnerability reporting instructions (`https://g.co/vulnz`).

---

## Release History

### **v0.9.0** (`Latest`)
- **Pluggable Federation Architecture**: `FederationProvider` interface (`scripts/federation_provider.py`) supporting `LocalGitPatternProvider` for a Git-backed shared patterns repository.
- **Marketplace Native Packaging**: Top-level `plugin.json`, `hooks.json`, `skills/`, `rules/`, and `sidecars/vault_graph` ready for one-click installation.
- **Zero-Dependency OOXML Extraction**: Pure-Python stdlib XML/ZIP fallback extractors for `.pptx`, `.docx`, and `.xlsx` alongside `pypdf` and `python-pptx`.

---

## Disclaimer

This is not an officially supported Google product. Eligibility for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security) is determined by the Google OSS VRP Rules.
