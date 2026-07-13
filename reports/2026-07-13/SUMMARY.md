# skillguard real-world corpus scan — 2026-07-13

16 public Claude Code skill/plugin repositories were shallow-cloned and scanned with
`skillguard scan <path> --no-store` (skillguard v0.1.0, 120s timeout per repo). Every scan
completed without a crash or hang; the slowest repo (16,256 files) finished in 3.8s.

**Findings are static-analysis signals intended for human review. They are not verdicts of
malice.** A `capability/*` warning means a bundled script *can* do something (call the network,
read a token, pipe a download into a shell) — installers and dev tools do these things
legitimately. A `critical` means the artifact contains a pattern that deserves a look before
you install it, nothing more.

## Results

| Repo | Stars | Artifact type | Files scanned | Critical | Warning | Info | Scan time | Notes |
|---|---:|---|---:|---:|---:|---:|---:|---|
| [anthropics/skills](https://github.com/anthropics/skills) | 160,784 | marketplace | 415 | 0 | 12 | 60 | 0.2s | No criticals. Warnings are office-conversion scripts making network calls, one `rm -rf` in a build script, and a bundled `shadcn-components.tar.gz` that can't be statically audited. |
| [obra/superpowers](https://github.com/obra/superpowers) | 253,580 | plugin | 172 | 0 | 32 | 16 | 0.1s | No criticals. Warnings dominated by `injection/html-comment-imperative` on the skill templates' own HTML comments and hook shell commands (by design for this plugin). |
| [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official) | 32,069 | marketplace | 407 | 33 | 66 | 28 | 0.2s | 30/33 criticals are `resources/missing-resource`: the `cwc-makers/m5-onboard` skill references ~10 `scripts/*.py` it does not ship, and `plugin-dev/skill-development` mentions example paths in prose (doc-example FPs, see below). 3 `injection/phrase` hits are agent docs quoting attack phrases. |
| [davila7/claude-code-templates](https://github.com/davila7/claude-code-templates) | 29,371 | marketplace | 6,681 | 2 | 271 | 256 | 1.9s | Scanned at `cli-tool/components` (the marketplace root inside the monorepo). Both criticals are `injection/phrase` in AI-safety-themed templates (quoted attack phrases). Large warning count is proportional to 878 skills; mostly network-call/hook warnings. |
| [wshobson/agents](https://github.com/wshobson/agents) | 37,861 | marketplace | 1,094 | 19 | 45 | 161 | 0.4s | All 19 criticals are `resources/missing-resource`: several skills (e.g. `github-actions-templates`, `secrets-management`) reference `assets/*.yml` / `references/*.md` files that are not in the repo. |
| [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | 77,784 | plugin | 128 | 16 | 10 | 24 | 0.1s | 15/16 criticals are `resources/missing-resource`: single-file skills reference `references/*-checklist.md` files that don't exist. One `injection/phrase` in a testing skill that quotes an injection example. |
| [nextlevelbuilder/ui-ux-pro-max-skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) | 105,017 | plugin | 484 | 18 | 13 | 77 | 0.3s | All 18 criticals are `resources/missing-resource`: `.claude/skills/*` reference `scripts/search.py`, design-token assets, and reference docs that are not shipped at those paths. |
| [JuliusBrussee/caveman](https://github.com/JuliusBrussee/caveman) | 88,900 | plugin | 167 | 2 | 10 | 16 | 0.1s | Both `capability/pipe-to-shell` criticals match `curl \| node`-style text inside string literals (an error message and a test); a string-literal FP pattern, not executed code paths. |
| [mvanhorn/last30days-skill](https://github.com/mvanhorn/last30days-skill) | 51,875 | plugin | 400 | 1 | 54 | 12 | 0.3s | The single critical is `injection/phrase` ("do not tell the user") inside the repo's own eval baseline notes. Warnings are the skill's genuinely broad surface: `Bash` + `WebSearch` allowed-tools, network calls, secret env reads (`X_BEARER_TOKEN` etc.). |
| [alirezarezvani/claude-skills](https://github.com/alirezarezvani/claude-skills) | 22,477 | marketplace | 4,606 | 3 | 67 | 2 | 1.2s | 3 criticals: a "skill-security-auditor" skill quoting injection phrases it teaches you to detect. Warnings mostly hooks and installer scripts. |
| [Jeffallan/claude-skills](https://github.com/Jeffallan/claude-skills) | 10,563 | plugin | 557 | 6 | 8 | 70 | 0.3s | 3 missing-resource criticals (skills referencing `templates/`/`scripts/` paths not shipped) and 3 `injection/phrase` in prompt-engineering reference docs that quote attack strings. |
| [jeremylongshore/claude-code-plugins-plus-skills](https://github.com/jeremylongshore/claude-code-plugins-plus-skills) | 2,514 | marketplace | 16,256 | 26 | 272 | 44 | 3.8s | Largest artifact in the corpus (425+ plugins). 21 `injection/phrase` criticals are overwhelmingly security-education content. Real signals: a plugin script whose update hint tells users to run `bash <(curl -sL promptbook.gg/setup.sh)`, and intentional unicode-tag-char test fixtures the scanner correctly catches. |
| [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) | 2,690 | skill | 1 | 0 | 1 | 1 | 0.1s | Repo root is a bare skill collection (`Skills/<category>/<name>/`) with no plugin/marketplace manifest, which skillguard does not classify; scanned the representative `offensive-osint` skill (58 skills total in repo). A "scan every skill in a plain collection repo" mode is a real gap surfaced by this corpus. |
| [jarrodwatts/claude-hud](https://github.com/jarrodwatts/claude-hud) | 26,376 | plugin | 345 | 0 | 5 | 32 | 0.1s | Clean. A pure plugin (no skills); warnings are its statusline hook command and network calls in its own TypeScript source. |
| [thedotmack/claude-mem](https://github.com/thedotmack/claude-mem) | 87,054 | plugin | 850 | 10 | 117 | 53 | 0.4s | Most capability-dense repo in the corpus: `openclaw/install.sh` genuinely pipes `curl https://bun.sh/install \| bash` (7 pipe-to-shell + 1 eval-download criticals), one `SKILL.md` with no frontmatter, high hook/network/secret-env warning counts. Consistent with an installer-heavy memory tool, but exactly the surface a reviewer should read first. |
| [SawyerHood/dev-browser](https://github.com/SawyerHood/dev-browser) | 6,436 | marketplace | 170 | 0 | 10 | 1 | 0.2s | Clean of criticals. Warnings are network/write capability in the bundled browser daemon (inherent to what the tool is). |

## Bugs found and fixed during this pass

Scanning the corpus surfaced three objectively-wrong behaviors, each fixed minimally in `src/`
with a regression test distilled from the failing input:

1. **`resources/missing-resource` flagged existing directories as missing.** A skill referencing
   `scripts/lib/` (which exists as a directory) was reported critical-missing because the check
   required a regular file. Found via mvanhorn/last30days-skill. Fix: an existing directory counts
   as present. (−2 false criticals corpus-wide.)
2. **`injection/zero-width-unicode` flagged emoji ZWJ sequences as hidden characters.** U+200D
   inside standard, visible emoji sequences (person+laptop, shrug+gender) was reported as
   "can hide instructions from human review". Found via anthropics/claude-plugins-official and
   others. Fix: a ZWJ joining two pictographic code points is not counted; bare ZWJ/ZWSP between
   ordinary text still is. (−5 false warnings; all genuine zero-width-space detections retained.)
3. **`capability/secret-env-read` matched ordinary JS template literals.** The case-insensitive
   shell-expansion pattern fired on code like `` `${tokens.join(", ")}` `` and
   `"${unsupportedToken.toSource()}"`, labeling a CSS parser a secret reader. Found via
   SawyerHood/dev-browser. Fix: shell expansions must be `UPPER_CASE` to match; explicit
   `process.env`/`os.environ`/`getenv` reads remain case-insensitive. (−37 false warnings
   corpus-wide; all true positives retained.)

No crashes, hangs, or frontmatter parser failures were found: the parser was additionally
stress-run against all 5,316 `SKILL.md` files in the corpus with zero exceptions and zero
misparses of valid frontmatter (35 files genuinely lack frontmatter).

## Known false-positive patterns (judgment calls, intentionally not tuned away)

- **Security-education content**: skills/docs that teach injection defense quote phrases like
  "ignore previous instructions" and are flagged `injection/phrase` (critical). This is the
  dominant source of criticals in security-themed repos. A static scanner cannot distinguish
  quoting from injecting; human review resolves these in seconds.
- **Doc-example resource paths**: SKILL.md files that *document* the skill format mention paths
  like `references/advanced.md` illustratively, and prose such as "scripts/references/examples
  needed" matches the resource-path regex, producing `resources/missing-resource` criticals.
- **Shell-looking text in string literals**: e.g. an error message mentioning "standalone
  curl|node mode" trips `capability/pipe-to-shell`.
- **Regex literals in JS/TS**: `/>>/g` matches the shell-redirection heuristic behind
  `capability/write-outside-artifact`.
- **Test files**: repo test suites are scanned as bundled scripts, so intentional fixtures
  (eval-of-fetch tests, unicode-hygiene fixtures) surface as findings. Arguably correct — the
  content does ship with the artifact.

## Gaps surfaced (not fixed; noted for roadmap)

- Bare skill-collection repos (skills in arbitrary subdirectories, no `SKILL.md` at root, no
  `.claude-plugin` manifest) are not classifiable as a single artifact and exit with a clear
  error. Two corpus repos needed a sub-path or representative-skill scan (SnailSploit/Claude-Red,
  davila7/claude-code-templates).
