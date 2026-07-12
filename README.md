# skillguard

> `npm audit` for agent capabilities. Working name — not final.

skillguard statically scans Claude Code **skills**, **plugins**, and
**marketplaces** and produces a reproducible trust/audit report. It never
executes the code it scans.

This is **M0**: static analysis only. Static analysis raises signal for human
review and blocks the obvious; it cannot prove behavioral safety. Behavioral
verification is M1 and requires a real sandbox — see [PLAN.md](./PLAN.md).

## Quickstart

```bash
npm install
npm run build            # tsc -> dist/

# Scan a skill dir, a plugin dir, or a marketplace root.
node dist/cli.js scan ./path/to/skill-or-plugin

# Machine-readable output, written to a file, failing CI on any warning:
node dist/cli.js scan ./plugin --json --out report.json --fail-on warning

# List prior scans recorded for an artifact.
node dist/cli.js history ./plugin
```

After `npm link` (or install), the `skillguard` binary is on your PATH:

```bash
skillguard scan ./path/to/plugin
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
| **Resource integrity** | `resources/*` | Referenced `references/ templates/ scripts/ assets/` files that don't exist; progressive-disclosure body-size limits |
| **Capability audit** | `capability/*` | Declared `allowed-tools`; hooks that run shell commands; scripts that make network calls, `curl \| sh`, read secret env vars (API_KEY/TOKEN/SECRET), write outside the artifact, `rm -rf`, or eval/exec downloaded content |
| **Supply-chain hygiene** | `supplychain/*` | Symlinks resolving outside the artifact; large base64/encoded blobs; unauditable binary files |
| **Injection heuristics** | `injection/*` | "ignore previous instructions", "do not tell the user", model-addressed hidden instructions in reference files, imperatives in HTML comments, zero-width / bidi / invisible-tag unicode |
| **Scan hygiene** | `scan/*` | Info findings about the scan itself: lines longer than 2000 chars truncated for line-based checks (`scan/line-truncated`), unreadable files skipped (`scan/unreadable-file`), files over 5 MB skipped for content checks (`scan/file-too-large`), invalid suppression config (`scan/config-invalid`) |

### What gets scanned

Everything under the artifact root **except `.git`** is content-scanned and
hashed — including vendored/generated dirs like `node_modules`, `dist`,
`build`, `venv`: those are exactly where a payload would hide. The capability,
supply-chain, and injection rules apply there at full severity. Only skill
*discovery* (and therefore the structural/resource quality rules) prunes
vendored dirs, so third-party code does not generate style noise.

Untrusted content quoted in finding messages is sanitized (newlines/tabs
collapsed, ANSI escapes and control characters stripped) so a scanned artifact
cannot forge report lines or emit terminal escape sequences.

The frontmatter parser and the structural/resource checks are ported faithfully
from the overclock repo's `validate_skill.py` and `audit_skills.py`, preserving
their real-spec tolerance (optional `name`, block scalars, plugin namespacing).

## Report

Reports are versioned (`reportVersion: 1`):

```jsonc
{
  "reportVersion": 1,
  "tool": { "name": "skillguard", "version": "0.1.0" },
  "scannedAt": "2026-07-12T22:13:40.276Z",
  "artifact": {
    "type": "plugin",
    "path": "/abs/path",
    "contentHash": "<sha256 over the sorted per-file sha256 hashes>"
  },
  "findings": [ /* sorted critical-first */ ],
  "suppressed": [ /* findings ignored via skillguard.config.json */ ],
  "summary": { "critical": 8, "warning": 12, "info": 1, "total": 21, "suppressed": 0, "filesScanned": 7 }
}
```

`contentHash` is a stable fingerprint of the artifact's bytes covering
everything except `.git` (symlinks contribute their target, not their
contents; files over 5 MB are fingerprinted by size+name), so a re-scan
detects any change — including changes inside `node_modules` and other
vendored dirs.

## Suppressing findings (CI)

To accept a known finding without failing CI, put a `skillguard.config.json`
in the scanned artifact's root or in the directory you run skillguard from
(the artifact's own config wins):

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
- An artifact can ship its own config: review `suppressed` (and the config
  file itself) when auditing third-party artifacts.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no findings at or above `--fail-on` |
| `1` | Scan completed; findings at or above `--fail-on` |
| `2` | Scan error (bad path, unclassifiable artifact, I/O failure) |

`--fail-on` accepts `critical` (default), `warning`, or `none`.

## Options

```
skillguard scan <path>
  --json                 emit the JSON report instead of text
  --out <file>           also write the report to a file
  --db <path>            sqlite history store (default ~/.skillguard/skillguard.db)
  --fail-on <level>      critical | warning | none   (default critical)
  --no-store             do not record this scan in history

skillguard history <path>
  --db <path>            sqlite history store
  --json                 emit JSON rows
```

## Development

```bash
npm run build   # tsc, must pass
npm test        # vitest (builds first), must pass
```

Test fixtures live under `test/fixtures/` — a benign skill and a malicious
plugin that exercises the injection, exfiltration, and symlink-escape rules.

## License

MIT — see [LICENSE](./LICENSE).
