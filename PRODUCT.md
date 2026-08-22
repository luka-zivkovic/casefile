# Casefile product charter

Status: **active target-state charter**

Last reviewed: 2026-08-22

This document is the source of truth for what Casefile is becoming. The
README, PLAN, launch material, and code may describe current behavior, but
they do not override this charter. Accepted ADRs in `docs/decisions/` may
refine it. Proposed ADRs record an open decision and are not yet binding.

## User and job

Casefile serves the platform or security owner responsible for deciding
whether static evidence about an agent capability artifact satisfies the
operator's admission policy and whether the artifact has changed since that
approval.

The job is:

> Inspect an untrusted capability artifact without executing it, produce
> reproducible trust evidence, and let an operator lock and later verify the
> exact approved state.

## Product loop

```text
untrusted capability bytes + trusted operator policy
→ deterministic no-execution analysis
→ reproducible findings and artifact identity
→ operator review / CI policy
→ lock and later verify
```

## Casefile owns

- Static structural, resource, capability, supply-chain, and injection
  analysis of supported agent artifact formats.
- Deterministic artifact enumeration and content identity.
- Explicit incomplete-analysis evidence and strict fail-closed behavior.
- Operator-controlled policy, findings, report identity, SARIF, lock, verify,
  and drift classification.
- An authored regression corpus for preventing known detector regressions.
- An eventual blind comparative trust benchmark with preregistered claims.

## Decisions Casefile makes

- What static findings are present and their scanner-defined severity.
- Whether a scan is complete enough for a lock.
- Whether current bytes, policy, findings, and report identity match a trusted
  lock.
- Whether configured CI policy passes or fails over Casefile evidence.

## Decisions Casefile does not make

- Whether an LLM output is high quality.
- Whether a prompt, model, or AI application change should ship.
- Whether untrusted code is behaviorally safe after execution.
- Runtime traffic interception, MCP proxying, or serving-path guardrails.
- Skill authoring, optimization, or automatic remediation.
- A claim that the absence of static findings proves safety.

Dynamic execution of untrusted artifacts is a separate product and trust
boundary. It must not be added to Casefile as a roadmap milestone merely
because it is adjacent.

## Inputs and outputs

Inputs include artifact bytes, format manifests, symlinks, and an explicitly
trusted operator policy.

Outputs include deterministic findings, completeness evidence, content and
report digests, SARIF, lockfiles, and drift classifications. Findings are
signals for review and policy; they are not accusations of malicious intent or
proof that an admitted artifact is behaviorally safe.

## Relationship to the other products

- **Coeval** validates behavioral evaluators against human truth. Casefile may
  statically inspect a packaged evaluator or skill, but it does not certify
  the evaluator's judgment quality.
- **Dailies** makes release decisions. It may consume Casefile evidence as one
  deterministic policy input, but Casefile does not own the release decision.

The products share explicit evidence contracts, not product ownership.

## Current state versus target state

Current Casefile supports static scanning of Claude Code skills, plugins, and
marketplaces, reproducible reports, SARIF, lock/verify, and an authored
31-artifact regression corpus. Additional artifact ecosystems and a blind
comparative benchmark are target work. Runtime behavioral probing is outside
the target product boundary.

## Product principles

1. Never execute the artifact being assessed.
2. Same readable bytes, trusted policy, and coverage evidence produce the same
   identity regardless of path or time.
3. Missing coverage is explicit and cannot be suppressed in strict mode.
4. The artifact cannot weaken the operator's policy.
5. Regression tests and comparative benchmarks are different artifacts with
   different claims.
6. Public findings describe observable static evidence, not author intent.
7. Semantic clustering is explicitly deferred and outside the current plan.

## Success signals

- An operator can scan third-party capabilities without executing them.
- A reviewed lock detects later byte, policy, finding, or tool-version drift.
- CI and SARIF consumers receive deterministic, path-independent evidence.
- Comparative performance claims come only from a sealed, independently
  labeled corpus rather than the authored regression suite.

## Open decisions

The supported ecosystem order and operational choices for the future blind
benchmark—sampling frame, label ontology, corpus size, and comparator
versions—remain open within ADR-0001's accepted procedure. They do not change
the no-execution boundary.
