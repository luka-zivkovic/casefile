# Changelog

All notable changes to Casefile are recorded here.

## Unreleased

- Renamed the sibling evaluator-evidence product Coeval to Rubrist in
  `PRODUCT.md`, `AGENTS.md`, and the vendored glossary and implementation
  batches (owner decision, 2026-09-22). Casefile's name, CLI, and outputs are
  unchanged; `launch/` drafts stay as historical material.
- The GitHub Action now defaults `fail-on` to `critical`, matching the CLI, so
  warnings such as a bundled script's network call stay visible in the report
  and job summary without failing the job; set `fail-on: warning` to gate on
  them.
- Repositioned the README to lead with reviewed admission plus lock and
  verify: no execution, reproducible identity and findings, explicit coverage
  gaps, operator-owned policy, drift verification, and SARIF for CI. Added a
  "Casefile is not" boundary list drawn from `PRODUCT.md`. Detection rules
  remain documented below the lifecycle story.
- Added `casefile init [dir]`, which writes a documented starter
  `casefile.config.json` operator policy with an empty `ignore` list. It
  refuses to overwrite an existing file and never creates a lock.
- Added a composite GitHub Action (`uses: luka-zivkovic/casefile@main`) with
  `scripts/action-run.sh`. It runs the published CLI through `npx --yes
  casefile@<version>`, writes JSON and SARIF outside the artifact, optionally
  verifies a reviewed lock and fails on drift, exposes `exit-code`,
  `report-json`, and `sarif` outputs, and appends severity counts plus top
  findings with `file:line` to the job summary. SARIF upload is opt-in and
  requires the caller to grant `security-events: write`.
- The `inspect-skill` plugin skill now points operators at `casefile init`
  for a starter policy while still refusing to write policy for the artifact.
- Added a Claude Code plugin marketplace layout (`.claude-plugin/marketplace.json`
  and `plugins/casefile`) with an `inspect-skill` skill, so a coding agent can
  install Casefile in one line and scan an artifact before installing it. The
  README documents the install commands, a paste-a-prompt alternative for other
  agents, and Overclock's CI use of Casefile as a gate.
- Added public contribution and security-reporting guidance.
- Documented a lock-first CI workflow for reviewed internal capabilities, with
  exact tool pinning and separate severity and evidence-drift checks.
- Removed legacy exploratory third-party scan reports from the product
  repository; comparative evidence belongs to the separately governed neutral
  benchmark workflow.
- Documented npm-first installation in the README.
- Corrected stale documentation: the README no longer hardcodes a test count,
  and the launch kit no longer repeats the resolved naming step or links to the
  removed exploratory scan reports; comparative evidence is pointed at the
  neutral benchmark workflow instead.

## 0.2.1 — 2026-08-24

- Corrected the published package version identity so the CLI, package and Git
  tag report the same version.

## 0.2.0 — 2026-08-24

- Added deterministic lock and verify workflows with typed drift evidence.
- Added operator-owned suppression policy and strict incomplete-analysis
  handling.
- Added deterministic SARIF output and the public neutral-benchmark adapter
  protocol.
- Expanded the authored regression corpus while retaining narrow internal
  correctness claims.

## 0.1.0 — 2026-08-11

- Initial npm release of the static skill, plugin and marketplace scanner.
