# skillguard report — /private/tmp/skillguard-corpus/jarrodwatts__claude-hud

- Artifact type: plugin
- Content hash: sha256:85ed873a11a31b4677644f6013c81f17d0b683d077197515ea89ab7eb1385f9d
- Scanned at: 2026-07-13T14:05:37.010Z (skillguard v0.1.0, report v1)
- Files scanned: 345

**37 finding(s): 0 critical, 5 warning, 32 info**

- [WARNING] structural/no-skills — artifact contains no skills (.)
- [WARNING] injection/model-addressed — reference file addresses the model with concealment language: "claude-hud") -ErrorAction Silently" (commands/setup.md:71)
- [WARNING] capability/network-call — bundled script makes a network call (dist/usage-api.js:792)
- [WARNING] capability/secret-env-read — bundled script reads a secret-looking environment variable (API key / token / secret) (tests/auth.test.js:85)
- [WARNING] capability/secret-env-read — bundled script reads a secret-looking environment variable (API key / token / secret) (tests/render.test.js:1765)
- [INFO] supplychain/binary-file — bundled binary media file (.png) (claude-hud-preview-16-9.png)
- [INFO] supplychain/binary-file — bundled binary media file (.png) (claude-hud-preview-5-2.png)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/auth.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/config-reader.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/config.d.ts.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/config.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/context-cache.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/cost.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/external-usage.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/extra-cmd.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/git.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/index.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/memory.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/agents-line.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/colors.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/index.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/lines/added-dirs.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/lines/advisor.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/lines/identity.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/lines/project.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/lines/prompt-cache.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/lines/session-time.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/lines/usage.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/session-line.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/render/tools-line.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/speed-tracker.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/stdin.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/transcript.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/types.d.ts.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/usage-api.d.ts.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/usage-api.js.map:1)
- [INFO] scan/line-truncated — 1 line(s) longer than 2000 chars were truncated for line-based checks (dist/version.js.map:1)

_Static analysis only — behavioral verification (M1) requires sandboxed execution and is out of scope for this report._
