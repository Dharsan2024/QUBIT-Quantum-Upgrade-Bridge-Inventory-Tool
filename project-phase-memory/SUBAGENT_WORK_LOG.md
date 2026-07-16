# QUBIT — Sub-Agent Work Log

> **Who writes here:** every NON-Claude agent (OpenAI Codex, GitHub Copilot, Google Gemini, Google
> Antigravity). Claude keeps its authoritative log in `PROJECT_PHASE_MEMORY.md §5`; you log here.
> **Claude (orchestrator) reads this file** when the human returns, verifies your work, and records a
> KEEP / UPDATE / REMOVE verdict on each entry.
>
> **HOW TO LOG (do this CONTINUOUSLY, not just at the end):**
> - The moment you START a task, add an entry (newest at top) with a timestamp.
> - After EACH meaningful step, update it. Assume you could be cut off at any moment — never have more
>   than one unlogged step. If you sense you're low on credits/context, immediately write your partial
>   progress + the exact next step, commit, THEN stop.
> - Get a real timestamp from the shell: `date "+%Y-%m-%d %H:%M:%S %Z"`.
> - Say which branch you're on and which files you touched. Run the quality gate and record the result.
>
> **Entry template (copy):**
> ```
> ### <YYYY-MM-DD HH:MM %Z> — <agent> — <task title>  [status: in-progress | done | cut-off]
> - Branch: <branch>   Lane: <your assigned area from AGENT_WORK_SPLIT.md>
> - Did: <what you changed>
> - Files: <paths>
> - Gate: ruff <ok/fail> | mypy <ok/fail> | pytest <N passed>
> - Next step (if in-progress/cut-off): <exact next action so the next agent resumes seamlessly>
> - Orchestrator verdict (Claude fills this): <pending>
> ```

---

## Log (newest first)

### 2026-07-17 ~03:30 IST — OpenAI Codex — bulk scanner detection rules  [status: done]
- Branch: `codex/scanner-rules`   Lane: qubit-scanner catalog/rules only.
- Did: added detection rule packs following the `qubit-rule/v1` format proven by Claude's engine.
- Files: `catalog/rules/python/{cryptography.yaml (expanded), hashlib.yaml (expanded), jwt.yaml,
  pycryptodome.yaml}`, `catalog/rules/java/{jca.yaml, bouncycastle-pqc.yaml}`, `catalog/rules/go/crypto.yaml`.
- Result: 33 rules total (python 18, java 8, go 7); every rule ships positive+negative examples.
- Gate: ruff ok | pytest 85 passed.
- **Orchestrator verdict (Claude, 2026-07-17 04:00 IST): KEEP.** Verified: stayed in lane (no engine /
  core / docs edits), gate green, rules resolve to real algorithms. One follow-up owned by Claude (NOT a
  Codex defect): bare `"RSA"` literals (Cipher.getInstance("RSA"), JWT RS256) need a family-level registry
  entry in qubit-core so they keep their Shor-vulnerable verdict instead of degrading to UNKNOWN(RSA).
  Fix applied by Claude in the same session; Codex's rules kept as-is.
