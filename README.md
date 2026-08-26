<div align="center">

# Casefile

### Deterministic trust intake for agent capabilities

Statically inspect Claude Code skills, plugins, and marketplaces **without executing them**.

<p>
  <a href="https://www.npmjs.com/package/casefile"><img alt="npm version" src="https://img.shields.io/npm/v/casefile?style=flat-square&color=4f46e5"></a>
  <a href="https://github.com/luka-zivkovic/casefile/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/luka-zivkovic/casefile/ci.yml?branch=main&style=flat-square&label=CI"></a>
  <a href="https://github.com/luka-zivkovic/casefile/blob/main/LICENSE"><img alt="MIT license" src="https://img.shields.io/npm/l/casefile?style=flat-square"></a>
  <img alt="Node 20 or newer" src="https://img.shields.io/node/v/casefile?style=flat-square">
</p>

[Quick start](#quick-start) · [How it works](#how-it-works) · [CI](#use-it-in-ci) · [CLI reference](#cli-reference) · [Security](#security-model) · [Documentation](#documentation)

</div>

---

Casefile gives operators a reviewable record of what an agent capability contains, what it appears able to do, and whether it has changed since approval.

> [!IMPORTANT]
> Casefile never executes the artifact it scans. It uses static analysis to raise useful review signals and block obvious risks. It cannot prove that an artifact is behaviorally safe.

## At a glance

| | |
|---|---|
| **Scans** | Skills, plugins, and marketplace roots |
| **Finds** | Suspicious hooks, secret access, network calls, injection patterns, unsafe filesystem behavior, supply-chain issues, and structural problems |
| **Produces** | Human-readable reports, deterministic JSON, and SARIF 2.1.0 |
| **Tracks** | Artifact bytes, findings, policy, tool version, and evidence drift |
| **Executes scanned code** | **Never** |
| **Runtime** | Node.js 20 or newer |

## Quick start

Run the latest release directly from npm:

```bash
npx casefile@latest scan ./path/to/skill-or-plugin
```

Or install the CLI globally:

```bash
npm install --global casefile
casefile scan ./path/to/skill-or-plugin
```

Casefile classifies the artifact automatically and prints findings in severity order:

```text
# casefile report — /path/to/plugin

- Artifact type: plugin
- Content hash: sha256:…
- Report identity: sha256:…
- Files scanned: 14

**3 finding(s): 1 critical, 1 warning, 1 info**

- [CRITICAL] capability/eval-download — downloaded content is executed
- [WARNING] capability/network-call — script appears to make a network call
- [INFO] capability/allowed-tools — skill declares allowed tools
```

The default gate exits with code `1` when a critical finding is present. Tighten it for CI with `--fail-on warning`.

## How it works

### 1. Scan before installation

```bash
casefile scan ./plugin --strict --fail-on warning
```

`--strict` fails closed when Casefile cannot completely analyze a file—for example, because it is unreadable, invalid UTF-8, oversized for content analysis, or otherwise skipped.

### 2. Review machine-readable evidence

```bash
casefile scan ./plugin \
  --json \
  --out ./evidence/report.json \
  --no-store
```

For GitHub code scanning and other security tooling, emit SARIF instead:

```bash
casefile scan ./plugin \
  --sarif \
  --out ./evidence/report.sarif \
  --no-store
```

### 3. Lock an approved state

```bash
casefile lock ./plugin \
  --out ../plugin.casefile-lock.json \
  --strict
```

Keep the lock outside the scanned artifact. Every readable artifact byte except `.git` contributes to the artifact identity, so placing the lock inside would make it self-referential.

### 4. Detect drift later

```bash
casefile verify ./plugin \
  --lock ../plugin.casefile-lock.json \
  --strict
```

Verification distinguishes changes to artifact bytes, policy, tool/report versions, report identity, and individual findings. Locks are path-independent, so the same reviewed bytes produce the same evidence at another location.

## Supported artifacts

Pass a directory to `casefile scan <path>`. Casefile determines its type from the files it contains:

| Path contains | Classified as | Scan scope |
|---|---|---|
| `SKILL.md` | Skill | The skill and its bundled resources |
| `.claude-plugin/plugin.json` | Plugin | The plugin and all discovered skills |
| `.claude-plugin/marketplace.json` or `plugins/*/` | Marketplace | Every discovered plugin |

Everything below the artifact root except `.git` contributes to identity when readable, including generated and vendored directories. Eligible text files are also content-analyzed. Symlinks are recorded but never followed for content analysis.

## What Casefile checks

Every finding contains a rule ID, severity, message, relative file, and optional line number.

| Rule family | Examples |
|---|---|
| `structural/*` | Invalid frontmatter, manifests, versions, names, or routing metadata |
| `resources/*` | Missing references, path traversal, escaping symlinks, oversized skill bodies |
| `quality/*` | Missing guardrails, unused bundled resources, weak routing descriptions |
| `capability/*` | Shell hooks, network calls, secret reads, out-of-tree writes, destructive commands, download-and-execute behavior |
| `supplychain/*` | Escaping symlinks, encoded payloads, unauditable binary files |
| `injection/*` | Prompt-injection phrases, hidden imperatives, zero-width characters, bidi controls, Unicode tag characters |
| `scan/*` | Incomplete hashing or analysis, invalid policy, unreadable input, truncated lines |

Untrusted text is sanitized before it appears in terminal output, so a scanned artifact cannot forge report lines or emit terminal escape sequences.

## Use it in CI

This GitHub Actions job fails on warnings, uploads SARIF, and avoids writing to the local scan-history database:

```yaml
name: Casefile

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 20
      - run: npx casefile@latest scan ./plugin --strict --fail-on warning --sarif --out casefile.sarif --no-store
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: casefile.sarif
```

If you do not use GitHub code scanning, remove the upload step and use `--json` or the default text report.

## Operator-owned policy

Suppressions must come from a policy controlled by the operator, not from the artifact being assessed:

```json
{
  "ignore": [
    { "ruleId": "capability/network-call", "path": "scripts/" },
    { "ruleId": "supplychain/binary-file" }
  ]
}
```

```bash
casefile scan ./plugin \
  --config ./casefile-policy.json \
  --strict \
  --fail-on warning
```

`ruleId` is required. `path` is an optional relative-path prefix, not a glob. Suppressed findings remain in the report as reviewed evidence but do not count toward the exit-code gate.

Artifact-local `casefile.config.json` and legacy `skillguard.config.json` files are untrusted by default: they are hashed and reported, but they cannot weaken their own scan. `--trust-artifact-config` exists only for explicitly trusted legacy workflows.

## CLI reference

```text
casefile scan <path>
  --json                    emit deterministic JSON
  --sarif                   emit deterministic SARIF 2.1.0
  --out <file>              also write the report to a file
  --db <path>               SQLite history store
  --config <file>           operator-owned suppression policy
  --trust-artifact-config   trust legacy artifact-local policy
  --strict                  fail closed on incomplete analysis
  --fail-on <level>         critical | warning | none
  --no-store                do not record this scan in history

casefile lock <path>
  --out <file>              required; must be outside the artifact
  --config <file>           operator-owned suppression policy
  --strict                  require complete analysis

casefile verify <path>
  --lock <file>             required evidence lock
  --config <file>           current operator-owned policy
  --strict                  require complete analysis
  --json                    emit machine-readable drift

casefile history <path>
  --db <path>               SQLite history store
  --json                    emit JSON rows
```

Run `casefile <command> --help` for the complete command help.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Gate passed, lock written, or verification matched |
| `1` | Finding gate failed or a valid lock has evidence drift |
| `2` | Invalid input, tampered lock, unsafe output path, or I/O failure |

## Evidence and reproducibility

Casefile reports use a deterministic identity derived from:

- tool and report versions;
- artifact type and full content hash;
- strict mode and exact operator-policy bytes;
- active and suppressed findings;
- summary counts.

Absolute paths and scan timestamps are deliberately excluded. Identical bytes and policy therefore produce identical evidence across runs and locations.

Report and lock destinations must resolve outside the artifact. Symlink destinations are rejected, and files are written with same-directory temporary files, `fsync`, and atomic rename.

### Reproducible regression corpus

The checked-in [`benchmark/manifest.json`](./benchmark/manifest.json) contains 31 authored regression artifacts across nine rule families: 24 malicious base/mutation variants and seven benign near-misses.

```bash
npm run benchmark --silent
```

The current gate requires complete recall for the authored malicious cases, exact expected-rule matching, complete mutation retention, and no warning/critical findings on the authored benign cases.

> [!NOTE]
> These are regression-corpus results, not a representative ecosystem benchmark or a claim of broad detection accuracy. The cases were developed alongside the scanner.

The boundary between this corpus and any future independently owned comparison is documented in [ADR-0001](docs/decisions/0001-benchmark-claims-and-corpus-separation.md) and [ADR-0002](docs/decisions/0002-neutral-benchmark-ownership.md).

## Security model

Casefile is designed to support a deliberate trust decision—not replace one.

- Static analysis can miss dynamic or deliberately concealed behavior.
- Casefile does not run hooks, scripts, imports, installers, or commands from scanned artifacts.
- A lock digest is an integrity checksum, not a signature. Store approved locks in a reviewed location if authenticity matters.
- Runtime behavioral probing and sandbox execution are intentionally outside the product boundary.
- Incomplete coverage is explicit; use `--strict` when incomplete analysis must fail closed.

Please report vulnerabilities through GitHub's private vulnerability reporting flow. See [SECURITY.md](./SECURITY.md) for supported versions and disclosure guidance.

## Documentation

| Document | Purpose |
|---|---|
| [PRODUCT.md](./PRODUCT.md) | Authoritative product boundary and trust model |
| [Glossary](./docs/glossary.md) | Shared product and evidence terminology |
| [Architecture decisions](./docs/decisions/README.md) | Accepted design and claim-boundary decisions |
| [Protocol v1](./protocol/v1/README.md) | Public neutral-benchmark adapter protocol |
| [CHANGELOG.md](./CHANGELOG.md) | Release history |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Development and contribution workflow |
| [SECURITY.md](./SECURITY.md) | Private vulnerability reporting |

## Development

```bash
git clone https://github.com/luka-zivkovic/casefile.git
cd casefile
npm ci
npm run build
npm test
npm run benchmark --silent
```

CI runs the build, 172-test suite, and authored benchmark on Node.js 20 and 22. See [CONTRIBUTING.md](./CONTRIBUTING.md) before proposing a change.

## License

[MIT](./LICENSE) © Luka Živković
