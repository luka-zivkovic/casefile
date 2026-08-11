# Disclosure — anthropics/claude-plugins-official

**To:** maintainers of https://github.com/anthropics/claude-plugins-official
**Channel:** a GitHub issue on the repo (public is fine — these are quality, not security, findings), or a note to the plugins team.
**Send before:** the public launch post.

---

## Draft message

Hi — we ran a static scanner over 16 popular Claude Code plugin/skill collections and are
about to publish the results. Yours is one of them, and before we do I want to share what we
found and, honestly, flag that most of it is our tool being over-eager, not your repo being
broken. Two things:

**1. One skill looks genuinely incomplete: `plugins/cwc-makers/skills/m5-onboard`.**
Its `SKILL.md` references ten resources that aren't in the repo — the scripts it's built around
(`scripts/detect.py`, `scripts/flash.py`, `scripts/fetch_firmware.py`, `scripts/onboard.py`,
`scripts/smoke_test.py`, and others) plus `references/hardware_signatures.md` and
`references/uiflow2_nvs.md`. As written the skill can't run; it reads like the script bundle was
left out of the commit. Worth a look.

**2. The rest of our "missing resource" criticals on your repo are false positives — flagging
them so you don't waste time.** `plugins/plugin-dev/skills/skill-development` is a skill that
*teaches the skill format*, so it mentions paths like `references/api-reference.md`,
`assets/logo.png`, and `references/examples/` illustratively. Our scanner can't yet tell "this
skill documents a path" from "this skill depends on a path," so it flagged them. That's a gap on
our side, noted in our roadmap — no action needed from you.

For context: `anthropics/skills` (your other repo) scanned clean of criticals — 0 critical, 12
warning, 60 info, the warnings being ordinary hook/network capability declarations.

Everything we publish is framed as a static-analysis signal for human review, not a judgment of
anything. Happy to share the full report for your repo ahead of time if useful. Planning to post
around [DATE]; glad to adjust or hold if you'd like.

— [name], casefile

---

## Internal notes (do not send)

- Confirmed-real finding: **m5-onboard** (`plugins/cwc-makers/skills/m5-onboard/SKILL.md`) — 10
  missing resources, all look load-bearing (real script names, not doc examples). High confidence.
- Likely-FP: **plugin-dev/skill-development** — ~20 of the 30 missing-resource criticals. These
  match the "doc-example resource paths" known-FP pattern in SUMMARY.md. Leading with this in the
  note (before they find it themselves) turns our own false positive into a credibility signal.
- This note is the single best proof that the scanner's output needs human triage — use the
  honesty here in the launch post too.
- Total on claude-plugins-official: 33 critical / 66 warning / 28 info across 407 files. Most
  criticals are the two skills above plus `injection/phrase` hits on security-education content.
