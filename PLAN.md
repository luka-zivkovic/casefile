# casefile — plan

Status: **documentation-first target plan**

Last reviewed: 2026-08-22

`PRODUCT.md` defines the product. This plan sequences work; it does not expand
scope beyond deterministic, no-execution trust intake.
The concrete cross-product order and batch exit gates are vendored in
[`docs/implementation-batches.md`](docs/implementation-batches.md).

## Vision

Agents gain capabilities by installing skills and plugins the way apps gain
capabilities by installing packages. Security tools for this ecosystem now
exist, including Snyk Agent Scan, but their trust boundaries differ. Casefile
targets a narrower lifecycle: deterministic, offline, no-execution admission
evidence plus lock and later verification.

Two complementary tools, one lifecycle:

- **SkillOpt optimizes** — makes a capability better (authoring, evals, tuning).
- **casefile verifies** — makes a capability trustworthy (audit, gating,
  provenance).

casefile answers "does this artifact's static evidence satisfy my admission
policy, and did it change?" It is deliberately mechanical and reproducible:
same readable bytes and coverage gaps in, same canonical report identity out.

## Milestones

### Foundation — delivered in the current working tree

- Static skill/plugin/marketplace discovery without artifact execution.
- Structural, resource, capability, supply-chain, injection, and scan-hygiene
  findings.
- Versioned deterministic reports, canonical artifact identity, and SARIF.
- Operator-owned suppression policy and strict incomplete-analysis handling.
- Digest-first lock/verify with drift classification.
- Authored manifest-driven regression corpus with narrow claims.
- Public trust-benchmark protocol v1, an in-process no-execution Casefile
  adapter, and a synthetic qualification-only corpus. The separately owned
  `agent-artifact-trust-bench` repository owns comparator execution and raw
  benchmark results (ADR-0002).

Static analysis cannot prove behavioral safety. That limit remains visible in
reports, docs, and public claims.

### M1 — strengthen the static intake surface

- Prioritize additional agent artifact ecosystems from observed user demand.
- Define format adapters without weakening the shared artifact-identity and
  no-execution invariants.
- Improve evidence explanations, remediation context, and policy ergonomics
  while keeping findings deterministic.
- Add standalone diff/gate workflows on top of verified lock evidence.

### M2 — evidence portability

- Evaluate signing or attestations so report provenance can be verified across
  machines and organizations.
- Define a stable integration contract for CI and potential Dailies policy
  consumption without moving release decisions into Casefile.
- Add a local report viewer only if real users need it; the viewer must render
  existing evidence rather than create a second analysis engine.

### M3 — blind comparative trust benchmark

Design a sealed, independently labeled benchmark following
`docs/decisions/0001-benchmark-claims-and-corpus-separation.md`. Preregister
the sampling frame, review/adjudication protocol, sample size and stopping
rule, metrics and uncertainty, unsupported-format handling, frozen tool
versions, execution conditions, and publication rules before running Casefile
or competitors on the hidden set.

The public adapter boundary is delivered, but it deliberately freezes no blind
sampling frame, corpus size, budget, stopping rule, comparator version, or
independent corpus owner. Those remain Gate 5 decisions in the neutral
`agent-artifact-trust-bench` repository.

## Demand gates

Additional ecosystems, signing, a viewer, and broad comparative work require
evidence of real use. Improve the current admission-and-lock workflow before
adding adjacent surfaces.

## Non-goals

- Hosted registry or SaaS backend.
- Dynamic or sandboxed execution of untrusted artifacts.
- MCP traffic proxying or runtime guardrails.
- A skill-authoring editor.
- Capability optimization (that is SkillOpt's job).
- LLM-output evaluation or release-policy decisions.
- Semantic clustering in the current plan.
