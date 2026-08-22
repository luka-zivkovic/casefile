# Casefile positioning note

Status: **time-sensitive market context; not product authority**

Last verified against linked official documentation: 2026-08-22

Refresh this note before using it in external claims. `PRODUCT.md` and accepted
ADRs define Casefile even when competitors change.

## Closest current comparator

[Snyk Agent Scan](https://github.com/snyk/agent-scan) discovers and scans agent
components across several ecosystems, including MCP servers and skills. Its
documented checks include prompt injection, tool poisoning or shadowing,
malware payloads, credential handling, and hardcoded secrets. This makes it a
closer comparator than a general source-code scanner.

Agent Scan is broader than Casefile today in ecosystem discovery and MCP
analysis. Its documentation also states that scanning an MCP configuration may
start the configured stdio server after consent and recommends a sandbox for
untrusted configurations. That is a different execution boundary, not a flaw
to hide in comparisons.

## Intended wedge

Casefile focuses on deterministic, offline, no-execution admission and later
verification of capability artifacts:

- enumerate and hash the whole supported artifact reproducibly;
- make unreadable or unsupported coverage explicit and fail closed in strict
  mode;
- keep policy under operator control rather than trusting the artifact;
- emit stable findings and SARIF;
- lock exact artifact, policy, finding, and report identity; and
- classify later drift without executing the artifact.

Casefile should not claim that agent-skill security scanning, prompt-injection
detection, secret detection, or multi-agent discovery is unique. Its thesis is
the narrower trust boundary and lifecycle evidence.

## Comparative-test rule

The checked-in authored corpus is only a regression gate. A public comparison
with Agent Scan or another tool requires the blind procedure in
[ADR-0001](decisions/0001-benchmark-claims-and-corpus-separation.md), including
independent labels, adjudication, frozen versions, confidence intervals, and
honest reporting of cloud, credential, network, execution, and sandbox
requirements.

Until that benchmark exists, statements about stronger detection, lower false
positives, speed, or broader safety are untested hypotheses.
