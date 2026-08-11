# Launch kit

Materials for casefile's first public moment: a scan of 16 popular Claude Code
plugin/skill collections, published alongside `casefile scan` as the call to action.

These are **drafts for Luka to review, edit, and send** — nothing here has been sent or
published.

## What's here

- `disclosure/` — heads-up notes to the maintainers of the three repos we name with
  notable findings. Send these **before** publishing anything public.
- `launch-post.md` — the public write-up, built from `reports/2026-07-13/SUMMARY.md`.
- `naming-shortlist.md` — the naming exploration that led to "casefile" (resolved).

## Suggested order (why disclosure comes first)

1. **Pick a name** and make the repo public (license is already MIT).
2. **Send the disclosure notes** to the three maintainers. Give them a window (5–7 business
   days is customary) before the public post goes up.
3. **Publish the launch post.** It links to the public repo and the full `reports/` directory.

Sending maintainers a heads-up before publishing findings about their code is the whole
credibility play for a *trust* product: "we told them before we told you." It costs a week and
buys the moral authority the product is selling. It also catches our own false positives before
they're public — see the anthropics note, where most of the flagged items are illustrative
doc-example paths, not real bugs.

## The one rule for all of this

Every public claim is a **static-analysis signal for human review, not a verdict of malice.**
The SUMMARY leads with this; the post and every disclosure note repeat it. A pipe-to-shell in an
installer is a fact worth surfacing, not an accusation. Keep that framing everywhere.
