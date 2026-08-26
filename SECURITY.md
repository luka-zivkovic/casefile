# Security policy

## Supported versions

Security fixes are applied to the latest published `0.2.x` release. Older
versions may not receive fixes.

## Reporting a vulnerability

Please do not open a public issue containing exploit details, private artifact
content, credentials, or other sensitive material.

Use GitHub's private vulnerability reporting flow from the repository's
**Security** tab. Include the affected version, a minimal reproduction, the
expected impact, and whether the issue can expose or execute scanned artifact
content.

If private vulnerability reporting is unavailable, open a public issue asking
for a private security contact without including vulnerability details.

## Product boundary

Casefile performs deterministic static analysis and does not execute the
artifact it scans. A clean scan is not proof of behavioral safety. Reports and
issues should distinguish a scanner defect from a limitation of static
analysis.
