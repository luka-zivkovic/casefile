# We scanned 16 popular Claude Code plugin collections. Here's what installing them actually pulls in.

_Draft. Replace "skill-guard" with the final product name before publishing._

Claude Code plugins and skills are `git clone` plus a bit of trust. You add a marketplace, install
a plugin, and from then on it can register hooks that run on every session, ship scripts that make
network calls, and read files across your project. Almost all of that is fine. The problem is that
"almost" is doing a lot of work, and nobody reads 850 files before running an installer.

So we built a static scanner for exactly that artifact — skills, plugins, marketplaces — and
pointed it at 16 of the most-installed collections on GitHub, from Anthropic's own directory down
to community marketplaces with hundreds of plugins. About 33,000 files. Here's what came back.

## The headline: it's mostly fine, and the exceptions are worth reading

Most of these repos are clean or close to it. The scanner isn't a malware detector and didn't find
malware. What it found is the stuff a careful reviewer *would* want to see first and currently
can't, because it's buried:

- **An official-directory skill that can't run.** In `anthropics/claude-plugins-official`, the
  `m5-onboard` skill references ten scripts and reference files it doesn't ship — the whole script
  bundle it's built around is missing from the repo. Not dangerous, just broken, and easy to miss.

- **The most capability-dense repo we scanned: `thedotmack/claude-mem` (87k stars).** Eight places
  where its installer downloads content and pipes it straight into a shell or eval — the familiar
  `curl https://… | bash` bootstrap. Legitimate for an installer-heavy tool. Also exactly the line
  you'd want to read before running it, across 850 files you otherwise wouldn't.

- **A marketplace inheriting a plugin's capabilities.** In a 425-plugin collection, one bundled
  third-party plugin (`promptbook`) executes downloaded content and runs four hooks automatically —
  on session start, every prompt, every tool use, and session end. Install from the marketplace and
  you get all of it. This is the supply-chain shape that matters: you're not trusting one author,
  you're trusting everyone they bundled.

Full per-repo reports are in the repo. Every finding has a file and line number.

## What "clean" and "flagged" mean here

Two honesty notes, because a trust tool that oversells is worse than no tool.

First: **these are signals for human review, not verdicts of malice.** A pipe-to-shell in an
installer is a fact, not an accusation. The tool's job is to put the five lines worth reading in
front of you, not to decide what they mean.

Second: **it has false positives, and we'll show you ours.** A skill that teaches the skill format
mentions example paths that don't exist, and our scanner flagged them as missing dependencies. A
CSS parser using a template literal got flagged as reading a secret. We found these by running on
real code, fixed three of them before publishing, and left the judgment-call ones in the reports
labeled as such. Scanning security-education content that quotes "ignore previous instructions" will
always light up — a static tool can't tell quoting from injecting. That's what the human is for.

We told the maintainers of the three named repos what we found before writing this. That's the
deal for a tool like this: you get the heads-up before the internet does.

## Try it on your own plugins

```
npx skill-guard scan ./path-to-a-plugin
```

It runs locally, reads only what's on disk, needs no credentials, and prints a report with exit
codes you can wire into CI. Point it at a plugin before you install it, or at your own before you
publish it.

The scanning you just read about took under four seconds per repo. The reading you'd have had to
do by hand is why nobody does it.
