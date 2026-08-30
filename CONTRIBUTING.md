# Contributing to Casefile

Casefile is a deterministic, no-execution trust scanner for agent capability
artifacts. Contributions must preserve that boundary: tests, benchmarks, and
the CLI must never execute the artifact being assessed.

## Before opening a change

1. Read `PRODUCT.md`, `docs/glossary.md`, the accepted decisions under
   `docs/decisions/`, and `docs/implementation-batches.md`.
2. Keep operator policy outside the artifact. An artifact must not be able to
   suppress its own findings.
3. Preserve deterministic, path-independent identities and explicit
   incomplete-analysis evidence.
4. Treat the authored benchmark as a regression corpus, never as evidence of
   ecosystem-wide accuracy or superiority.

## Local checks

Requires Node.js 20 or newer.

```bash
npm ci
npm run build
npm test
npm run benchmark --silent
```

All four commands must pass. Add positive, negative, and near-miss fixtures for
new detection behavior, and verify that failure output does not expose private
artifact content unnecessarily.

## Pull requests

Keep changes narrowly scoped, describe the trust boundary affected, and call
out any report-schema, lock, protocol, or benchmark-contract change explicitly.
Do not include credentials, private customer artifacts, hidden benchmark data,
or generated scans of third-party repositories.

Report security problems through `SECURITY.md`, not a public pull request.

When publishing a Casefile release, update the exact version in the README's
reviewed-internal-artifact example so the worked pin matches the intended
release.
