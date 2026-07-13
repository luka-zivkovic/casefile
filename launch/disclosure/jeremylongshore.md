# Disclosure — jeremylongshore/claude-code-plugins-plus-skills

**To:** maintainer of https://github.com/jeremylongshore/claude-code-plugins-plus-skills
**Channel:** GitHub issue or direct message.
**Send before:** the public launch post.

---

## Draft message

Hi — we scanned 16 popular Claude Code plugin/skill collections with a static tool and are about
to publish the results; your 425-plugin marketplace is one of them. It's the largest repo in the
set (16k+ files) and it scanned cleanly overall — the reason I'm reaching out is one plugin worth
a second look, plus a heads-up on the general pattern.

The one that stands out is `plugins/business-tools/promptbook`:

- `plugins/business-tools/promptbook/scripts/submit.js:427` — evaluates/executes downloaded
  content
- Four hooks in `promptbook/hooks/hooks.json` run shell commands automatically on session start,
  prompt submit, tool use, and session end

A marketplace bundles third-party plugins, so this is really about what `promptbook` does rather
than your repo — but because it ships inside your collection, anyone installing from you inherits
it. The auto-running hooks plus remote-content execution are the combination a reviewer would
want flagged before install. Might be worth confirming `promptbook` is a plugin you want to vouch
for, or noting its capabilities in your listing.

Two of the other pipe-to-shell criticals we found are in `scripts/scan-synced-content.mjs` and
its test file — those look like your own sync tooling; just flagging for completeness.

Everything we publish is a static-analysis signal for human review, not a judgment. Planning to
post around [DATE]; happy to share the full report early or adjust timing.

— [name], skill-guard

---

## Internal notes (do not send)

- The interesting angle here is **marketplace supply chain**: the maintainer curates 425 plugins
  and inherits the capabilities of every one. `promptbook` (a third-party plugin inside the
  collection) has eval-download + 4 auto-running hooks. This is the cleanest illustration in the
  corpus of *why* a pre-install scanner matters — you're not just trusting the marketplace author,
  you're trusting everyone they bundled.
- The earlier review flagged a `bash <(curl -sL promptbook.gg/setup.sh)` remote-exec-by-
  instruction; in the committed report the promptbook criticals are the eval-download at
  submit.js:427 and the hook commands. Use the file:line findings that are actually in the
  report — don't cite the setup.sh line unless you re-verify it's in the published output.
- This is the launch post's best "supply chain" example. Keep it factual.
