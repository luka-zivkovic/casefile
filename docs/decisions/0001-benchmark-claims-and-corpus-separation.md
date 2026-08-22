# ADR-0001: Benchmark claims and corpus separation

Status: **Accepted**

Date: 2026-08-22

Amended: 2026-08-22 after founder review

## Context

Casefile has a visible corpus written alongside its scanner. It is valuable
for deterministic regression testing but cannot estimate ecosystem-wide
detection performance or support an unbiased competitor comparison.

## Decision

Maintain two separate benchmark artifacts:

1. **Authored regression corpus** — checked into the repository, optimized for
   known rules, mutations, near misses, determinism, and CI regression gates.
2. **Blind comparative trust benchmark** — a future sealed corpus with
   independent labeling and adjudication, preregistered metrics and stopping
   rules, and held-out cases that tool authors cannot tune against before
   evaluation.

Results from the authored corpus must always be labeled regression results.
They must not be marketed as broad recall, real-world precision, superiority
over another tool, or proof of safety.

A comparative benchmark must define before unsealing:

- artifact ecosystems and sampling frame;
- unit of analysis, label ontology, and at least two independent reviews for
  benchmark claims, followed by recorded disagreement adjudication;
- severity mapping and rule-equivalence adjudication;
- recall, precision, false-positive, coverage, runtime, and determinism
  metrics;
- sample-size rationale, stopping rule, confidence intervals, and handling of
  rare rule families;
- treatment of unsupported formats and incomplete analysis;
- frozen version and configuration for every tool before the blind run;
- execution, network, credential, and sandbox conditions for every tool; and
- leakage controls and publication rules.

Competitors run under equivalent constraints. If a comparator requires cloud
analysis, credentials, or execution, those conditions are reported rather
than normalized away.

The hidden corpus stays inaccessible to detector authors until versions and
procedures are frozen. No detector tuning, label-rule negotiation, or case
removal is allowed after unsealing except through a documented invalid-case
procedure applied symmetrically. Exploratory reruns may be published, but they
are labeled post-hoc and cannot replace the preregistered result.

## Consequences

- The 31-artifact suite remains a strong internal gate with deliberately
  narrow claims.
- A blind benchmark can later compare Casefile with tools such as Agent Scan
  without contaminating the development corpus.
- No public performance claim is made until the blind procedure and labels
  have independent review.
- Comparative results report uncertainty and operational trust boundaries,
  not only a ranking.
