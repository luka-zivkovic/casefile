# Disclosure — thedotmack/claude-mem

**To:** maintainer of https://github.com/thedotmack/claude-mem
**Channel:** GitHub issue or direct message to the maintainer.
**Send before:** the public launch post.

---

## Draft message

Hi — we scanned 16 popular Claude Code plugin/skill collections with a static tool and are about
to publish the results. claude-mem is one of them. Nothing here is an accusation — it's an
installer-heavy memory tool and most of what we flagged is inherent to that — but I want to show
you what a reviewer sees before it's public, in case any of it is worth tightening.

Our scanner flagged claude-mem as the most capability-dense repo in the set: 10 critical, 117
warning across 850 files. The criticals are downloads piped straight into an interpreter and one
eval-of-downloaded-content:

- `openclaw/install.sh:419` and `:1491` — pipe-to-shell and eval-download
- `openclaw/test-install.sh:1572` — pipe-to-shell
- `src/npx-cli/commands/install.ts:542`, `src/npx-cli/install/setup-runtime.ts:26`,
  `src/npx-cli/install/error-taxonomy.ts:52` — pipe-to-shell
- `src/services/integrations/WindsurfHooksInstaller.ts:177`, `src/shared/dependency-health.ts:23`

The pattern is the usual `curl https://… | bash` bootstrap (e.g. installing `bun`). That's a
legitimate and common install step — the reason we surface it is that it's exactly the line a
careful user wants to read before running your installer, and right now they'd have to find it
themselves across 850 files.

If any of these can fetch-then-verify (checksum/signature) instead of pipe-straight-to-shell,
that's the one change that would drop your critical count and give installers a safer default.
Entirely your call.

We frame every finding as a signal for human review, not a verdict. Planning to post around
[DATE] — happy to send the full report ahead of time or adjust timing.

— [name], casefile

---

## Internal notes (do not send)

- All 8 pipe-to-shell / eval-download criticals are real matches, factual and quoted with
  file:line. Verifiable in the report.
- The framing must stay non-accusatory: `curl | bash` for installing bun is normal. We are the
  "read this first" tool, not the "this is malware" tool. If the note reads as an accusation we
  lose the maintainer and the credibility.
- 87k stars — this is the highest-visibility repo in the corpus. Getting the tone right here
  matters most. If the maintainer engages positively, that's a launch-day quote.
- Also present (not in the note, lower priority): one SKILL.md with no frontmatter,
  `capability/rm-rf` and `secret-env-read` warnings in `openclaw/install.sh`.
