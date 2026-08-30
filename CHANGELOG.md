# Changelog

All notable changes to Casefile are recorded here.

## Unreleased

- Added public contribution and security-reporting guidance.
- Documented a lock-first CI workflow for reviewed internal capabilities, with
  exact tool pinning and separate severity and evidence-drift checks.
- Removed legacy exploratory third-party scan reports from the product
  repository; comparative evidence belongs to the separately governed neutral
  benchmark workflow.
- Documented npm-first installation in the README.

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
