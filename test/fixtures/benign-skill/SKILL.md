---
name: benign-skill
description: >-
  Format changelog entries from git history into a tidy release-notes section.
  Use when the user asks for release notes, a changelog, or "what changed since
  the last tag". Do not use for commit-message authoring or PR descriptions.
allowed-tools: Read, Grep, Bash(git log:*)
---

# Benign Skill

Turn recent git history into human-readable release notes.

## Steps

1. Read the template in templates/notes.md.
2. Collect commits since the last tag.
3. Group by type and render the template.

See references/style.md for tone guidance.
