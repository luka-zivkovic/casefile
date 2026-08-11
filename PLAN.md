# casefile — plan



## Vision

Agents gain capabilities by installing skills and plugins the way apps gain
capabilities by installing packages. There is no `npm audit` for that supply
chain. casefile is that missing tool: **verify and maintain agent
capabilities.**

Two complementary tools, one lifecycle:

- **SkillOpt optimizes** — makes a capability better (authoring, evals, tuning).
- **casefile verifies** — makes a capability trustworthy (audit, gating,
  provenance).

casefile answers "should I trust this skill/plugin, and did it change?" It is
deliberately mechanical and reproducible: same bytes in, same report out.

## Milestones

### M0 — static scanner (this milestone)

A TypeScript CLI that statically scans a skill dir, plugin dir, or marketplace
root and emits a versioned trust/audit report. No code is executed.

- Tolerant frontmatter parser (ported from overclock `validate_skill.py`).
- Five check categories: structural, resource integrity, capability audit,
  supply-chain hygiene, prompt-injection heuristics.
- Versioned JSON report + human rendering; content hash for change detection.
- Local SQLite history; `history` command.
- Exit codes for CI gating.

Static analysis cannot prove behavioral safety — it raises signal for human
review and blocks the obvious. That limit is stated in every report.

### M1 — behavioral probes

Run a skill and observe what it actually does (network egress, filesystem
writes, secret access) against canary endpoints.

> **HARD PREREQUISITE: a real sandbox.** M1 requires container/VM isolation, or
> `sandbox-exec` with a network-deny profile plus canary endpoints. Running
> untrusted skills under `claude -p` with permissive tools is **unsafe** and is
> not an acceptable M1 implementation — a malicious skill would execute for
> real. No behavioral testing ships until the sandbox exists.

### M2 — diff / gate / lockfile

`casefile.lock` pinning approved content hashes; `casefile diff` between two
versions; a CI gate that fails on new criticals or on any capability the lock
did not approve. Builds directly on the M0 content hash and report schema.

### M3 — local report viewer + signed reports

A local viewer for reports and history, and signed reports so a report's
provenance (which scanner version, over which bytes) is verifiable.

## Demand gates

**M1+ is gated on external users actually using M0** — same bar as any new
platform bet. We do not build the sandbox, the viewer, or signing on
speculation. If M0 does not earn real usage, the later milestones do not start.

## Non-goals

- Hosted registry or SaaS backend.
- Dynamic MCP server testing.
- A skill-authoring editor.
- Capability optimization (that is SkillOpt's job).
