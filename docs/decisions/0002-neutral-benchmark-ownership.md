# ADR-0002: Neutral benchmark ownership and Casefile adapter boundary

Status: **Accepted**

Date: 2026-08-22

## Context

Casefile needs a public tool-adapter contract before a later blind comparison,
but hosting comparator execution, hidden labels, or benchmark raw results in the
product repository would turn external assessment into Casefile product
behavior and weaken independence. Decision gate 8 in the implementation plan
therefore required an explicit owner and isolation boundary.

## Decision

A separate portfolio-level repository named `agent-artifact-trust-bench` owns:

- the neutral harness and comparator adapters;
- comparator execution and sandbox enforcement;
- frozen tool, configuration, and environment manifests;
- exact stdout/stderr/process receipts and normalized cross-tool results;
- any sealed comparative corpus, independent labels, adjudication, metric
  computation, intervals, and publication artifacts.

Casefile owns only:

- a public, versioned adapter protocol;
- the Casefile adapter, which invokes the static scanner in-process without
  executing assessed artifacts; and
- a synthetic public qualification corpus for protocol and isolation
  conformance, explicitly prohibited from supporting performance claims.

Casefile CI may validate its schemas, adapter, and public synthetic
qualification fixtures. It must never run a comparator, access a sealed corpus,
or execute assessed artifact code. The neutral harness consumes a released,
digest-pinned copy of Casefile's protocol; it must not import an unfrozen
Casefile working tree.

For the future common static-skill track, a positive case ending
`unsupported`, `incomplete`, `error`, or harness-owned `timeout` is a miss. A
negative case with any non-completed outcome is an explicit coverage failure,
not a true negative, and cannot improve specificity or negative-clearance.

Only the public qualification ontology v1 and transport semantics are frozen by
this decision. Blind sampling frame, corpus size, budget, stopping rule,
comparator roster/versions, independent corpus owner, label ontology, severity
mapping, and rule-equivalence adjudication remain decision gate 5 and must be
accepted before any blind run.

## Consequences

- A separate directory alone is insufficient isolation: the neutral repository
  needs separate ownership, protected CI/secrets, and corpus access controls.
- Casefile releases can improve the adapter, but a benchmark run pins an exact
  released protocol/adapter/tool/environment digest before unsealing.
- The current 31-artifact authored corpus remains a Casefile regression gate and
  is never relabeled as neutral qualification or comparative evidence.
- Cloud, credential, network, execution, and sandbox conditions are declared
  and retained by the neutral harness rather than normalized away.
