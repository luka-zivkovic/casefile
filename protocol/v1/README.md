# Casefile trust-benchmark protocol v1

Status: **public adapter/qualification contract**

This directory is the Casefile-owned side of the neutral trust benchmark. It
contains only a versioned transport contract and a synthetic public
qualification corpus. It does not contain a comparator harness, comparator
adapter, blind corpus, raw benchmark result, sampling plan, or performance
claim. Those belong to the separately owned `agent-artifact-trust-bench`
repository under accepted ADR-0002.

## Wire contract

The executable `casefile-benchmark-adapter` handles exactly one case per
process. It reads one UTF-8 JSON object conforming to
`schemas/adapter-request.schema.json` from standard input and writes exactly one
JSON object conforming to `schemas/tool-result.schema.json` to standard output.
Diagnostics go to standard error. Invalid UTF-8, invalid JSON, an unsupported
protocol version, or any unknown request field is a protocol error: exit 2 and
no standard-output value. A valid request always produces a result and exits 0,
including `unsupported`, `incomplete`, and `error` results.

The adapter invokes Casefile's scanner in-process with strict analysis and no
operator or artifact-owned suppression policy. It never invokes an artifact,
spawns a child process, stores scan history, accesses credentials or cloud
services, or initiates network traffic. `timeoutMs` is a declared harness
deadline; the adapter validates it but does not implement an internal timer.
The neutral harness owns process timeout and records `timeout` outside the tool
result because a killed process cannot authenticate its own terminal result.

`artifactRoot` is process-local input and is excluded from output. Finding and
coverage-gap paths are portable, artifact-relative POSIX paths. The result has
no wall clock, duration, raw-output reference, absolute artifact root, policy,
or benchmark label. Its SHA-256 `resultIdentity` covers the canonical result
object excluding only `resultIdentity` itself. Objects use fixed field order;
findings and coverage gaps use deterministic sort order.

`toolIdentityDigest` is a lowercase SHA-256 challenge supplied by the neutral
harness and echoed exactly as `tool.identityDigest`. It identifies the harness-
frozen distribution/config/environment statement; Casefile does not derive or
trust that external lock. The harness independently verifies the pinned bytes
and rejects a missing or changed echo.

## Status and disposition

- `completed`: all content required by Casefile's strict contract was analyzed.
  It is the only status that carries `disposition`, which is `flag` when at
  least one active `critical` or `warning` finding exists and `clean` otherwise.
- `incomplete`: scanning produced one or more named coverage gaps. Findings are
  retained, but no clean/flag disposition is asserted.
- `unsupported`: the artifact does not match a Casefile-supported artifact
  shape, or a non-skill is submitted to `common-static-skill`.
- `error`: the artifact should have been processable but scanning or evidence
  validation failed.

Casefile result statuses deliberately omit `timeout`. The neutral harness
synthesizes that terminal state from its pinned process deadline and retains the
exact stdout/stderr/process receipt outside this protocol object.

## Qualification-only ontology and common-track truth table

Qualification ontology v1 has two labels: `positive` means a synthetic fixture
contains a predeclared admission-relevant sentinel; `negative` means it does
not. `status` fixtures are unlabeled and exercise transport only. These labels
are intentionally insufficient for a blind benchmark. The blind corpus
ontology, sampling frame, independent review/adjudication, sample size, budget,
stopping rule, and comparator freezes remain a later Gate 5 decision.

The future neutral harness must apply this frozen common-track truth table. It
must not turn non-completion into an apparently good negative result:

| Ground truth | Terminal outcome | Common-track accounting |
|---|---|---|
| positive | completed + flag | detected positive |
| positive | completed + clean | miss |
| positive | unsupported / incomplete / error / harness timeout | miss |
| negative | completed + clean | correctly cleared negative |
| negative | completed + flag | false positive |
| negative | unsupported / incomplete / error / harness timeout | coverage failure; excluded from conditional specificity/FPR but retained in the negative-clearance denominator |

Common-track specificity and false-positive rate are conditional on completed
negative classifications: specificity is `TN / (TN + FP)` and false-positive
rate is `FP / (TN + FP)`. Negative clearance is a separate coverage-sensitive
metric, `TN / all negative cases`, so negative non-completion cannot improve it.
A zero-denominator metric is undefined, never 1. An all-unsupported adapter has
undefined conditional specificity/FPR, zero common coverage, zero positive
recall, and zero negative clearance. An all-positive adapter has false-positive
rate 1 on completed negative cases. Qualification output may assert only schema,
transport, isolation, and expected-fixture conformance; it may not emit recall,
precision, ranking, superiority, or any other performance claim.

## Canonical evidence and raw retention boundary

The result carries Casefile's native report/artifact identities and every
active or suppressed native finding. The adapter validates the report identity
before emitting it. It never maps Casefile rules into a blind label ontology.
Rule equivalence, label adjudication, normalization across tools, exact raw
stdout/stderr retention, process receipts, frozen tool/config/environment
manifests, sandbox/network/credential declarations, intervals, and metrics all
belong to `agent-artifact-trust-bench`.

The harness must vendor a released `protocol-manifest.json` and verify each
listed raw-file digest before parsing. Protocol JSON is fatal UTF-8, closed
against unknown fields, and version-rejecting. A harness may normalize field
order and process-local paths, but must retain exact raw bytes separately and
must not use hidden labels as normalization input.

## Synthetic qualification corpus

`qualification/manifest.json` is public, authored, deterministic, and marked
`performanceClaimsAllowed: false`. It contains a clean negative sentinel, an
obvious positive sentinel, an artifact self-policy sentinel, and status-only
incomplete and unsupported cases. Its generated-file form avoids checking a
multi-megabyte fixture into source control. It is separate from both the
existing Casefile-authored detector regression corpus in `benchmark/` and any
future sealed comparative corpus.
