# Batch 0 foundation inventory

Status: **active checkpoint record**

Captured: 2026-08-22 before Batch 0 commits

## Repository state

- Batch branch: `codex/batch0-foundation`
- Preserved base: `37781253b1cd15b0cb3c82885f88e2b96d829c97`
- Observed `origin/main`: `1f7f99c3d42418fdbefe691af6a38a17eb7050cf`
- Relationship at capture: the preserved base was one commit behind
  `origin/main`, with no file-content difference.
- Dirty state at capture: 23 tracked files plus 19 untracked files before this
  inventory was added.
- No stash was present.

The uncommitted foundation covers deterministic reporting, strict completeness,
SARIF, lock/verify, bounded and path-safe static analysis, authored benchmark
hardening, CI, adversarial tests, and the authoritative documentation stack.

## Checkpoint order

1. Commit authoritative documentation only.
2. Commit the preserved runtime/test foundation in reviewable units.
3. Integrate current `origin/main` and confirm the tree remains equivalent.
4. Run full tests, build, authored benchmark, package dry-run, and
   relocation/permission-sensitive checks.
5. Obtain an independent read-only audit before merge.
