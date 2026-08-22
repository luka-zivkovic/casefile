# AI contributor context

Before planning, auditing, or changing Casefile, read:

1. `PRODUCT.md` — authoritative target product scope;
2. `docs/glossary.md` — shared terminology;
3. `docs/decisions/README.md` and the relevant ADRs;
4. `docs/implementation-batches.md` — independently audited work sequencing;
   Batch 0 is authorized, while each later batch waits for its named decision
   gates;
5. `README.md` and `PLAN.md` — current implementation and local sequencing;
6. code and tests — current behavior.

For competitor or market claims, also read `docs/positioning.md` and refresh
its dated sources. It is context, never product authority.

## Authority and evidence labels

- Accepted ADRs and `PRODUCT.md` define intended direction.
- Proposed ADRs are unresolved. Do not implement behavior that depends on one
  without explicit approval.
- README, plans, launch copy, comments, and code can describe **CURRENT**
  behavior but cannot establish **TARGET** product intent when they conflict
  with the charter.
- In audits and plans, label material claims as `TARGET`, `CURRENT`, or
  `ASSUMPTION`.

## Product boundary

Casefile performs deterministic, no-execution trust intake for agent
capability artifacts. It owns static findings, reproducible artifact identity,
operator policy, SARIF, lock/verify, and honest benchmark evidence. It does not
execute untrusted artifacts, proxy runtime traffic, evaluate LLM output, or
make release decisions. Coeval owns governed evaluator evidence. Dailies owns
release decisions.

The authored corpus is regression-only; competitor claims require a separate
blind benchmark. Semantic clustering is deferred.

## Working tree

The repository may contain uncommitted work from coordinated batches. Preserve
unrelated changes, inspect diffs before editing, and never treat an uncommitted
document as accepted merely because it exists.
