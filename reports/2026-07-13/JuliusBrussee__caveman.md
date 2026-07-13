# skillguard report — /private/tmp/skillguard-corpus/JuliusBrussee__caveman

- Artifact type: plugin
- Content hash: sha256:358899203b4dd842a8eef21d392747c2c2265c131e54556ce6e10715e0a90a28
- Scanned at: 2026-07-13T14:05:33.301Z (skillguard v0.1.0, report v1)
- Files scanned: 167

**28 finding(s): 2 critical, 10 warning, 16 info**

- [CRITICAL] capability/pipe-to-shell — bundled script downloads content and pipes it directly into an interpreter (src/tools/caveman-init.js:126)
- [CRITICAL] capability/pipe-to-shell — bundled script downloads content and pipes it directly into an interpreter (tests/installer/slash-commands.test.mjs:120)
- [WARNING] structural/plugin-version-missing — plugin.json has no 'version'; versioning is required for auditable updates (.claude-plugin/plugin.json)
- [WARNING] capability/hook-shell-command — SessionStart hook executes a shell command automatically: echo 'CAVEMAN MODE ACTIVE. Rules: Drop articles/filler/pleasantries/hedging. Fragments OK. Short syn… (.codex/hooks.json)
- [WARNING] capability/network-call — bundled script makes a network call (bin/install.js:1099)
- [WARNING] injection/model-addressed — reference file addresses the model with concealment language: "Claude Code Zod silently" (CLAUDE.md:203)
- [WARNING] injection/model-addressed — reference file addresses the model with concealment language: "Claude Code's Zod schema silently" (CONTRIBUTING.md:178)
- [WARNING] supplychain/binary-file — bundled binary file cannot be statically audited (dist/caveman.skill)
- [WARNING] capability/network-call — bundled script makes a network call (src/hooks/install.sh:112)
- [WARNING] supplychain/binary-file — bundled binary file cannot be statically audited (src/mcp-servers/caveman-shrink/compress.js)
- [WARNING] capability/write-outside-artifact — bundled script writes to an absolute or home path outside the artifact directory (tests/installer/e2e.freshinstall.test.mjs:302)
- [WARNING] capability/rm-rf — bundled script uses rm -rf (recursive force delete) (tests/test_validate_inline.py:24)
- [INFO] supplychain/binary-file — bundled binary media file (.png) (docs/assets/caveman-logo-banner.png)
- [INFO] supplychain/binary-file — bundled binary media file (.png) (docs/assets/dancing-rock-32.png)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (docs/assets/dancing-rock.svg:6)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (plugins/caveman/skills/cavecrew/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (plugins/caveman/skills/caveman-compress/SKILL.md)
- [INFO] structural/routing-no-trigger — routing description lacks a concrete positive trigger (plugins/caveman/skills/caveman-compress/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (plugins/caveman/skills/caveman-stats/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (plugins/caveman/skills/caveman/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (skills/cavecrew/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (skills/caveman-commit/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (skills/caveman-compress/SKILL.md)
- [INFO] structural/routing-no-trigger — routing description lacks a concrete positive trigger (skills/caveman-compress/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (skills/caveman-help/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (skills/caveman-review/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (skills/caveman-stats/SKILL.md)
- [INFO] structural/routing-no-anti-trigger — routing description lacks an explicit anti-trigger (skills/caveman/SKILL.md)

_Static analysis only — behavioral verification (M1) requires sandboxed execution and is out of scope for this report._
