# WikiSkill Asymmetric Rollback & Negative-Knowledge Protocol

This document defines the mathematical and procedural protocol for gating candidate skill modifications and managing the persistent negative-knowledge ledger.

---

## 1. The Core Asymmetric Invariant

When an agent evolves a skill $S_k = S_{k-1} \oplus P_k$ (where $P_k$ is the proposed patch), it evaluates the candidate skill set $S_k$ on validation tasks $\mathcal{T}_{\text{val},k}$ to compute reward $\mathcal{R}(S_k)$.

$$\text{Decision} = \begin{cases} 
\text{Accept}: S_k \text{ retained, update } \mathcal{R}_{\text{best}} \leftarrow \mathcal{R}(S_k) & \text{if } \mathcal{R}(S_k) > \mathcal{R}_{\text{best}} \\
\text{Reject}: S_k \leftarrow S_{k-1} \text{ (Rollback)}, \text{ Record in Wiki} & \text{if } \mathcal{R}(S_k) \le \mathcal{R}_{\text{best}}
\end{cases}$$

### The Invariant:
* **Executable Skills Roll Back**: The active `SKILL.md` file is immediately reverted to the known good checkpoint $S_{k-1}$.
* **The Wiki Never Rolls Back**: The proposed patch $P_k$, the score regression delta $\Delta \mathcal{R}$, and the failure explanation are permanently committed to `wiki/skill-impact.md` and `log.md`.

---

## 2. `skill-impact.md` Schema

The ledger is located at `$OBSIDIAN_VAULT_PATH/wiki/skill-impact.md` (defaults to `~/ObsidianVault/wiki/skill-impact.md`) and formatted as:

```markdown
# 📈 Skill Impact & Evolution Ledger

<!-- mdformat off -->
| Iteration | Target Skill | Patch Summary | Validation Delta | Status | Failure / Success Rationale |
| :--- | :--- | :--- | :---: | :---: | :--- |
| 001 | `ingest` | Add PPTX raster image extraction | +14.2% | ✅ Accepted | Extracted all embedded architecture diagrams cleanly. |
| 002 | `ingest` | Add write_to_file ArtifactMetadata | -22.0% | ❌ Rejected | write_to_file rejected ArtifactMetadata on project files outside brain/. |
<!-- mdformat on -->
```

---

## 3. Failure Mode Isolation Invariant

During validation rollouts:
1. The **Inference Agent** must only execute against the active skill set $S_k$ and the designated environment tools.
2. The Inference Agent must **never** be given direct access to `wiki/patterns/` or diagnostic notes during validation rollouts. Direct wiki access allows the agent to bypass flawed skill instructions, masking real procedural defects and degrading final skill quality.
