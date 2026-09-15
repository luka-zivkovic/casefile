# Launch kit

> **Status: historical draft material.** Product scope and permitted benchmark
> claims are governed by [`../PRODUCT.md`](../PRODUCT.md) and
> [ADR-0001](../docs/decisions/0001-benchmark-claims-and-corpus-separation.md).
> If this material conflicts with either document, update it before use.

Materials for casefile's first public moment: a scan of 16 popular Claude Code
plugin/skill collections, published alongside `casefile scan` as the call to action.

These are **drafts for Luka to review, edit, and send**. The package and repository are
already public; the post and disclosure notes themselves remain unsent drafts as far as
this kit records.

## What's here

- `disclosure/` — heads-up notes to the maintainers of the three repos we name with
  notable findings. Send these **before** publishing anything public.
- `launch-post.md` — the public write-up. It was originally built from an exploratory
  scan of third-party collections whose per-repo reports have since been removed from
  this repository (see `CHANGELOG.md`, Unreleased). Comparative evidence belongs to the
  separately governed neutral benchmark workflow described in
  [ADR-0002](../docs/decisions/0002-neutral-benchmark-ownership.md).
- `naming-shortlist.md` — the naming exploration that led to "casefile" (resolved
  2026-08-12).

## Suggested order (why disclosure comes first)

1. **Send the disclosure notes** to the three maintainers. Give them a window (5–7 business
   days is customary) before the public post goes up.
2. **Publish the launch post.** It links to the public repo. It must not link to per-repo
   scan reports, which no longer live here; any comparative evidence has to come from the
   neutral benchmark workflow in ADR-0002.

Sending maintainers a heads-up before publishing findings about their code is the whole
credibility play for a *trust* product: "we told them before we told you." It costs a week and
buys the moral authority the product is selling. It also catches our own false positives before
they're public — see the anthropics note, where most of the flagged items are illustrative
doc-example paths, not real bugs.

## The one rule for all of this

Every public claim is a **static-analysis signal for human review, not a verdict of malice.**
The post and every disclosure note repeat it. A pipe-to-shell in an installer is a fact worth
surfacing, not an accusation. Keep that framing everywhere.
