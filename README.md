# casefile

> Deterministic trust intake for agent capabilities.

casefile statically scans Claude Code **skills**, **plugins**, and
**marketplaces** and produces a reproducible trust/audit report. It never
executes the code it scans.

Static analysis raises signal for human review and blocks the obvious; it
cannot prove behavioral safety. Runtime behavioral probing is intentionally
outside Casefile's product boundary.

[`PRODUCT.md`](PRODUCT.md) is authoritative for intended product scope. This
README describes the current scanner. See the shared
[glossary](docs/glossary.md), [architecture decisions](docs/decisions/README.md),
and [PLAN.md](PLAN.md) for the documentation-first roadmap. The time-sensitive
[positioning note](docs/positioning.md) records the intended wedge without
turning competitor behavior into product authority.

## Quickstart

```bash
npm install
npm run build            # tsc -> dist/

# Scan a skill dir, a plugin dir, or a marketplace root.
node dist/cli.js scan ./path/to/skill-or-plugin

# Machine-readable output, written to a file, failing CI on any warning.
# Suppressions come from an operator-owned policy outside the artifact:
node dist/cli.js scan ./plugin --json --out report.json --fail-on warning \
  --config ./casefile-policy.json

# SARIF 2.1.0 for GitHub code scanning and other standard security tooling.
node dist/cli.js scan ./plugin --sarif --out report.sarif --no-store

# Accept the current evidence as a path-independent lock, then verify it later.
# Keep the lock outside the artifact because every readable artifact byte is hashed.
node dist/cli.js lock ./plugin --out ../plugin.casefile-lock.json \
  --config ./casefile-policy.json --strict
node dist/cli.js verify ./plugin --lock ../plugin.casefile-lock.json \
  --config ./casefile-policy.json --strict

# List prior scans recorded for an artifact.
node dist/cli.js history ./plugin
```

After `npm link` (or install), the `casefile` binary is on your PATH:

```bash
casefile scan ./path/to/plugin
```

### What is an "artifact"?

`scan <path>` classifies the path automatically:

| Path contains | Treated as |
|---|---|
| `SKILL.md` | a **skill** |
| `.claude-plugin/plugin.json` | a **plugin** (all its skills are scanned) |
| `.claude-plugin/marketplace.json` or `plugins/*/` | a **marketplace** (every plugin scanned) |

## Checks

Every check emits findings of the form
`{ ruleId, severity: critical | warning | info, message, file, line? }`.

| Category | Rule ids | What it catches |
|---|---|---|
| **Structural** | `structural/*` | SKILL.md presence, frontmatter parse, name/description constraints, plugin.json validity, version presence, missing forked agents, routing metadata |
| **Resource integrity** | `resources/*` | Referenced `references/ templates/ scripts/ assets/` files that don't exist or escape the skill/artifact through traversal or symlinks; progressive-disclosure body-size limits |
| **Quality heuristics** | `quality/*` | Oversized SKILL.md body without a `references/` escape hatch (progressive disclosure); no failure-modes/guardrails guidance; bundled resources never referenced from SKILL.md; trigger-only routing descriptions with no anti-trigger. Ported from skill-mastery's `audit_skills.py`, recalibrated so a typical well-made skill yields **zero** quality findings (one `warning` rule, the rest `info`) |
| **Capability audit** | `capability/*` | Declared `allowed-tools`; hooks that run shell commands; scripts that make network calls, `curl \| sh`, read secret env vars (API_KEY/TOKEN/SECRET), write outside the artifact, `rm -rf`, or eval/exec downloaded content |
| **Supply-chain hygiene** | `supplychain/*` | Symlinks resolving outside the artifact; large base64/encoded blobs; unauditable binary files |
| **Injection heuristics** | `injection/*` | "ignore previous instructions", "do not tell the user", model-addressed hidden instructions in reference files, imperatives in HTML comments, zero-width / bidi / invisible-tag unicode |
| **Scan hygiene** | `scan/*` | Findings about the scan itself: lines longer than 2000 chars truncated, unreadable files or directories, invalid UTF-8, incomplete identity hashing, files over 5 MB skipped for content checks, and invalid suppression policy. `--strict` adds an unsuppressible critical `scan/incomplete-analysis` for each coverage gap. |

### What gets scanned

Everything under the artifact root **except `.git`** (directory, worktree file,
or symlink) is enumerated and identity-hashed when readable — including
vendored/generated dirs like `node_modules`, `dist`, `build`, and `venv`.
Eligible text is content-analyzed subject to the documented 5 MB memory cap.
Core `SKILL.md`, hook JSON, and plugin manifests use the same cap; oversized or
unreadable input produces explicit incomplete-analysis evidence rather than an
unbounded read. Symlink entries are never followed for content analysis; their
target text remains identity-bearing and a skipped core symlink is reported as
incomplete analysis. Only skill *discovery* (and therefore structural/resource/
quality rules) prunes vendored dirs, so third-party code does not generate
style noise.

Untrusted content quoted in finding messages is sanitized (newlines/tabs
collapsed, ANSI escapes and control characters stripped) so a scanned artifact
cannot forge report lines or emit terminal escape sequences.

The frontmatter parser and the structural/resource checks are ported faithfully
from the overclock repo's `validate_skill.py` and `audit_skills.py`, preserving
their real-spec tolerance (optional `name`, block scalars, plugin namespacing).

## Report

Reports are versioned (`reportVersion: 2`):

```jsonc
{
  "reportVersion": 2,
  "tool": { "name": "casefile", "version": "0.1.0" },
  "scannedAt": "2026-07-12T22:13:40.276Z",
  "artifact": {
    "type": "plugin",
    "path": "/abs/path",
    "contentHash": "<sha256 over canonical typed path/digest tuples>"
  },
  "policy": { "source": "none", "strict": false },
  "findings": [ /* sorted critical-first */ ],
  "suppressed": [ /* findings ignored via trusted operator policy */ ],
  "summary": { "critical": 8, "warning": 12, "info": 1, "total": 21, "suppressed": 0, "filesScanned": 7 },
  "identity": { "algorithm": "sha256", "digest": "<canonical report digest>" }
}
```

`contentHash` is a stable fingerprint of the artifact's bytes covering
everything except `.git`. Its preimage is canonical JSON containing sorted
`[relativePath, entryKind, sha256]` tuples, so delimiter characters in
filenames cannot change record boundaries. Symlinks contribute their target,
not their contents. Readable regular files are streamed and fully hashed even
when they exceed the 5 MB content-analysis limit, so same-size byte changes are
detected — including changes inside `node_modules` and other vendored dirs.
Traversal and hash failures are named as incomplete evidence; strict scans fail
closed, and lock creation refuses to certify an incomplete artifact identity.

`identity.digest` covers canonical report content: tool/report version,
artifact type and content hash, policy mode/hash, relative-path findings, and
the summary. It deliberately excludes `scannedAt` and the absolute artifact
root, so the same bytes and policy produce the same identity across runs and
locations.

### SARIF 2.1.0

`scan --sarif` emits deterministic SARIF 2.1.0. Casefile rule ids remain SARIF
rule ids, severities map `critical → error`, `warning → warning`, and
`info → note`, and all locations are explicitly artifact-relative URIs. Each
result has a stable SHA-256 partial fingerprint over rule, relative location,
line, and message, so distinct same-rule evidence at one location does not
collide. Suppression disposition is not fingerprint-bearing. The SARIF run records artifact, policy,
report-version, and report-identity evidence without embedding the absolute
artifact root or scan timestamp.

Suppressed findings remain SARIF results with an `external` suppression and a
`properties.disposition` of `suppressed`; consumers can distinguish reviewed
suppression from absence. `--sarif` and `--json` are mutually exclusive, and
SARIF rendering does not change the underlying report or lock identity.

## Lock and verify lifecycle

`casefile lock` turns a scan into a versioned, canonical evidence lock. Lock
version 1 pins:

- artifact type and full content hash;
- casefile tool and report-schema versions;
- report identity;
- trusted policy source, exact policy-byte hash, and strict-mode setting;
- deterministic snapshots of active and suppressed findings, including every
  `capability/*` finding available from the current scanner.

The lock contains no artifact path or timestamp. Its own SHA-256 digest covers
all canonical lock content except the digest field itself, so repeated scans
and copies of the same artifact at another location create identical locks.
Write the lock outside the scanned artifact to avoid a self-referential content
hash. Lock creation always refuses incomplete artifact identity, and a strict
lock also refuses incomplete content analysis. A non-strict lock may preserve a
snapshot with explicit incomplete-analysis findings; it certifies those exact
artifact bytes and findings, not uninspected behavior. The CLI resolves the
existing real output parent, rejects containment through symlink aliases and a
symlink destination file, and writes the lock atomically.

```jsonc
{
  "lockVersion": 1,
  "tool": { "name": "casefile", "version": "0.1.0" },
  "reportVersion": 2,
  "artifact": { "type": "plugin", "contentHash": "<sha256>" },
  "policy": { "source": "explicit", "strict": true, "contentHash": "<sha256>" },
  "reportIdentity": { "algorithm": "sha256", "digest": "<sha256>" },
  "snapshot": {
    "activeFindings": [ /* canonical relative-path findings */ ],
    "suppressedFindings": [ /* canonical relative-path findings */ ]
  },
  "digest": { "algorithm": "sha256", "digest": "<lock sha256>" }
}
```

`casefile verify` validates the lock structure and digest **before** scanning.
It then scans with only the current `--config` and `--strict` options. It never
loads policy from the artifact or copies policy settings out of the lock. If a
lock was created with a policy, pass the currently approved policy again; a
missing or byte-changed policy is reported as valid drift.

Verification distinguishes artifact-byte, policy, tool/report-version, and
report-identity drift, plus added, removed, and changed findings. A finding
moving between active and suppressed is a changed finding. `--json` exposes
the complete classification without absolute paths or scan timestamps.

The lock digest is an integrity checksum, not a signature: store locks in a
reviewed/trusted location if authenticity matters.

Library consumers can use the exported `createArtifactLock`, `createLock`,
`parseLock`, `validateLock`, `verifyArtifact`, and `canonicalLockContent`
functions, plus the `CasefileLock`, `LockVerification`, and drift/evidence
types. `verifyArtifact` applies the same digest-first and operator-policy-only
rules as the CLI.

## Reproducible authored benchmark

[`benchmark/manifest.json`](./benchmark/manifest.json) is a checked-in,
data-driven regression corpus. The runner materializes every case in a fresh
per-variant sandbox, rejects symlink targets that leave that sandbox and any
destination nested below a symlink destination, scans without trusting
artifact policy, and emits only deterministic machine-readable evidence—no
temporary paths or wall clock.

```bash
# Build, run the corpus, print JSON metrics, and fail if reviewed thresholds regress.
npm run benchmark --silent
```

The corpus currently contains 31 artifacts: 24 malicious base/mutation
variants across 9 rule families and 7 benign near-misses. Thirteen malicious
mutations cover case, whitespace, wrapping, tool variants, encoding, Unicode,
and policy-filename changes. Families include shell/download/eval, injection,
secret access plus exfiltration, out-of-tree writes, automatic hooks, encoded
payloads, Unicode obfuscation, symlink escape, and self-suppression. Benign
cases cover commented documentation, quoted regex/URLs, visible emoji and
Unicode, scanner source text, short encoded values, internal symlinks, and
vendored skill metadata.

The JSON metrics include:

- artifact blocking recall at the explicitly declared `warning` threshold;
- per-family and minimum family recall;
- warning-or-critical benign artifact false-positive rate;
- expected-rule precision and exact expected-rule-set match rate;
- mutation retention.

The reviewed authored-corpus gate is currently 100% blocking recall, family
recall, expected-rule precision, exact rule-set match, and mutation retention,
with 0% warning/critical benign false-positive artifacts. These numbers are
**regression-corpus results only**. The cases were written alongside the
scanner and are neither a representative ecosystem sample nor evidence of
broad detection accuracy. The manifest digest and exact thresholds are tested
so corpus/claim changes require an explicit review. Manifest validation also
requires malicious and benign cases, a malicious family and mutation, empty
benign expectations, and assessed-prefix malicious expectations; missing
metric denominators fail rather than receiving a favorable default.

The separation between this visible regression suite and any future blind
competitor benchmark is an accepted product rule; see
[ADR-0001](docs/decisions/0001-benchmark-claims-and-corpus-separation.md).

## Public neutral-benchmark adapter protocol

Casefile ships its half of the future neutral benchmark integration under
[`protocol/v1`](protocol/v1/README.md): closed JSON Schemas, a digest manifest,
an in-process no-execution adapter, and a synthetic public qualification
corpus. The separately owned `agent-artifact-trust-bench` repository owns the
harness, comparator execution, sandbox enforcement, exact raw results,
normalization, and any later sealed corpus or comparative claim. See accepted
[ADR-0002](docs/decisions/0002-neutral-benchmark-ownership.md).

The adapter handles exactly one request per process:

```bash
printf '%s\n' '{
  "protocolVersion": 1,
  "caseId": "qualification-negative",
  "artifactRoot": "/absolute/path/to/skill",
  "track": "common-static-skill",
  "runIndex": 0,
  "timeoutMs": 30000,
  "environmentId": "node20-linux-x64@sha256:example",
  "toolIdentityDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}' | casefile-benchmark-adapter
```

It reads one strict request object from stdin and writes one compact
`tool-result` v1 object to stdout. Unknown fields, invalid UTF-8/JSON, invalid
digests, and unsupported protocol versions exit 2 without a stdout value.
Valid requests exit 0 with `completed`, `incomplete`, `unsupported`, or `error`;
process timeout is owned and recorded by the neutral harness. Only `completed`
results have `disposition: flag | clean`. Findings retain Casefile-native rule
ids/severities and artifact-relative safe paths. Results exclude artifact root,
wall clock, duration, labels, and raw-output references and include a canonical
SHA-256 identity. The harness-owned `toolIdentityDigest` challenge is echoed as
`tool.identityDigest`; the harness independently verifies the frozen tool,
configuration, and environment behind it.

The adapter always calls `scanArtifact` in-process with strict analysis, no
suppression config, no history store, and no artifact execution. Casefile CI
validates only this adapter and the public synthetic fixtures; it never runs a
comparator or accesses a sealed corpus.

[`protocol/v1/qualification/manifest.json`](protocol/v1/qualification/manifest.json)
is marked `public-qualification` and `performanceClaimsAllowed: false`. Its
positive/negative labels are transport sentinels, not a blind-benchmark
ontology, and its results cannot support recall, precision, rank, or superiority
claims. It is separate from the 31-artifact authored detector regression corpus
above. Blind sampling, size, budget, stopping rules, comparator freezes, and
independent corpus ownership remain Gate 5 work.

## Suppressing findings (CI)

To accept a known finding without failing CI, keep the policy under operator
control and pass it explicitly with `--config <file>`:

```json
{
  "ignore": [
    { "ruleId": "capability/network-call", "path": "scripts/" },
    { "ruleId": "supplychain/binary-file" }
  ]
}
```

- `ruleId` is required; `path` is an optional **prefix** match against the
  finding's file path (relative to the artifact root). No globs.
- Ignored findings are excluded from the summary counts and from `--fail-on`
  exit-code evaluation, but stay listed in the report under `suppressed` so
  they remain visible in review.
- An artifact's own `casefile.config.json` or legacy
  `skillguard.config.json` is hashed and reported as `scan/untrusted-config`,
  but cannot weaken its own default scan.
- `--trust-artifact-config` explicitly restores the pre-0.2 behavior for
  trusted legacy workflows. Do not use it for third-party artifacts.
- Trusted policy and benchmark-manifest digests cover exact raw bytes; JSON is
  decoded as fatal UTF-8, so malformed bytes cannot normalize into trusted text.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan gate passed, lock written, or verification is an exact match |
| `1` | Scan gate failed, or a structurally valid lock has evidence drift |
| `2` | Invalid/tampered lock, bad path, unclassifiable artifact, or I/O error |

`--fail-on` accepts `critical` (default), `warning`, or `none`.

## Options

```
casefile scan <path>
  --json                 emit the JSON report instead of text
  --sarif                emit deterministic SARIF 2.1.0 (exclusive with JSON)
  --out <file>           also write the report to a file
  --db <path>            sqlite history store (default ~/.casefile/casefile.db)
  --config <file>        operator-owned suppression policy
  --trust-artifact-config
                         explicitly use legacy artifact-local suppressions
  --strict               critical finding when content analysis is incomplete
  --fail-on <level>      critical | warning | none   (default critical)
  --no-store             do not record this scan in history

casefile lock <path>
  --out <file>           required path outside the scanned artifact
  --config <file>        current operator-owned suppression policy
  --strict               lock a strict complete-analysis scan

casefile verify <path>
  --lock <file>          required lock to validate before scanning
  --config <file>        current operator-owned policy (never read from lock)
  --strict               use strict mode for the current scan
  --json                 machine-readable drift classification

casefile history <path>
  --db <path>            sqlite history store
  --json                 emit JSON rows
```

For `scan --out`, `scan --db`, and `lock --out`, the destination parent must
already exist and resolve outside the artifact. Symlink destination files are
rejected. Report and lock files use same-directory temporary files, `fsync`,
and atomic rename; history persistence remains best-effort after destination
safety validation.

## Development

```bash
npm run build   # tsc, must pass
npm test        # vitest (builds first), must pass
npm run benchmark --silent
```

GitHub Actions runs all three gates on Node 20 and Node 22.

Test fixtures live under `test/fixtures/` — a benign skill and a malicious
plugin that exercises the injection, exfiltration, and symlink-escape rules.

## License

MIT — see [LICENSE](./LICENSE).
