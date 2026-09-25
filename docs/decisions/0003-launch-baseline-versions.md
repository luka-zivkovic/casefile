# ADR-0003: Restart Casefile's formats at a v1 launch baseline

Status: **Accepted**

Date: 2026-09-25

Decision owner: Luka Živković (founder).

## Context

On 2026-09-25 the founder decided, for Rubrist, Dailies, and Casefile, that
none keeps version history or backward compatibility before launch: "when we
[are] done, i will expect for everything to basically be v1. These projects
don't have users, so everything we do doesn't need exact history, nor
backward compatibility." Rubrist records it as ADR-0014 decision 7 and plans
it as slice 8G of Rubrist's Batch 8, which Casefile vendors.

CURRENT: Casefile has two identifiers above v1:

- `REPORT_VERSION = 2` in `src/report.ts`;
- the `casefile-artifact-content/v2` basis of the artifact content hash in
  `src/hash.ts`, which is part of every artifact digest and lock file.

## Decision

In Rubrist's Batch 8G, every versioned identifier in Casefile restarts at v1:

- the report version becomes 1;
- the content-hash basis becomes `casefile-artifact-content/v1`, so every
  artifact digest, lock file, and fixture that derives from it is
  regenerated;
- documents, fixtures, and code that only described the superseded versions
  are deleted.

Casefile's runtime behaviour doesn't otherwise change in Batch 8.

## Consequences

- Locks and digests produced before the baseline stop matching. This is
  acceptable only because no external user or lock file exists before
  launch.
- After launch, a format change needs a new version again; this is a
  one-time pre-launch reset.
