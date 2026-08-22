import { createHash } from 'node:crypto';
import { DiscoveryError } from './discover.js';
import { canonicalizeFinding, canonicalReportContent, TOOL_NAME, TOOL_VERSION } from './report.js';
import { INCOMPLETE_ANALYSIS_RULES, scanArtifact } from './scan.js';
import type { Finding, Report } from './types.js';
import {
  attachTrustBenchmarkResultIdentity,
  CASEFILE_BENCHMARK_ADAPTER_VERSION,
  compareTrustBenchmarkCoverageGaps,
  compareTrustBenchmarkFindings,
  isSafeArtifactRelativePath,
  parseTrustBenchmarkAdapterRequest,
  TRUST_BENCHMARK_PROTOCOL_VERSION,
  TrustBenchmarkProtocolError,
  type TrustBenchmarkAdapterRequest,
  type TrustBenchmarkCoverageGap,
  type TrustBenchmarkFinding,
  type TrustBenchmarkToolResult,
  type TrustBenchmarkToolResultContent,
} from './trust-benchmark-protocol.js';

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function base(request: TrustBenchmarkAdapterRequest) {
  return {
    protocolVersion: TRUST_BENCHMARK_PROTOCOL_VERSION,
    resultType: 'tool-result' as const,
    caseId: request.caseId,
    track: request.track,
    runIndex: request.runIndex,
    environmentId: request.environmentId,
    adapter: { id: 'casefile' as const, version: CASEFILE_BENCHMARK_ADAPTER_VERSION },
    tool: {
      name: TOOL_NAME as 'casefile',
      version: TOOL_VERSION,
      identityDigest: request.toolIdentityDigest,
    },
  };
}

function reason(code: string, message: string) {
  return { code, message };
}

function unsupported(request: TrustBenchmarkAdapterRequest, code: string, message: string): TrustBenchmarkToolResult {
  return attachTrustBenchmarkResultIdentity({
    ...base(request),
    status: 'unsupported',
    statusReason: reason(code, message),
    findings: [],
    coverageGaps: [],
  });
}

function error(request: TrustBenchmarkAdapterRequest, code: string, message: string): TrustBenchmarkToolResult {
  return attachTrustBenchmarkResultIdentity({
    ...base(request),
    status: 'error',
    statusReason: reason(code, message),
    findings: [],
    coverageGaps: [],
  });
}

function findingToProtocol(
  report: Report,
  finding: Finding,
  disposition: 'active' | 'suppressed',
): TrustBenchmarkFinding {
  const canonical = canonicalizeFinding(finding, report.artifact.path);
  if (!isSafeArtifactRelativePath(canonical.file)) {
    throw new TrustBenchmarkProtocolError(
      `scanner emitted a finding path that is not a safe artifact-relative POSIX path: ${JSON.stringify(canonical.file)}`,
    );
  }
  return {
    ruleId: canonical.ruleId,
    severity: canonical.severity,
    message: canonical.message,
    path: canonical.file,
    ...(canonical.line === undefined ? {} : { line: canonical.line }),
    disposition,
  };
}

function coverageGapFromFinding(report: Report, finding: Finding): TrustBenchmarkCoverageGap {
  const canonical = canonicalizeFinding(finding, report.artifact.path);
  if (!isSafeArtifactRelativePath(canonical.file)) {
    throw new TrustBenchmarkProtocolError(
      `scanner emitted a coverage path that is not a safe artifact-relative POSIX path: ${JSON.stringify(canonical.file)}`,
    );
  }
  return {
    ruleId: canonical.ruleId,
    message: canonical.message,
    path: canonical.file,
    ...(canonical.line === undefined ? {} : { line: canonical.line }),
  };
}

function validateReportIdentity(report: Report): void {
  if (!/^[a-f0-9]{64}$/.test(report.artifact.contentHash)) {
    throw new TrustBenchmarkProtocolError('scanner artifact identity is not a lowercase SHA-256 digest');
  }
  if (report.identity.algorithm !== 'sha256' || !/^[a-f0-9]{64}$/.test(report.identity.digest)) {
    throw new TrustBenchmarkProtocolError('scanner report identity is not a lowercase SHA-256 digest');
  }
  const expected = sha256(canonicalReportContent(report));
  if (report.identity.digest !== expected) {
    throw new TrustBenchmarkProtocolError('scanner report identity mismatch');
  }
}

/**
 * Convert native Casefile evidence into the public tool-result contract.
 * Exported so consumers can independently exercise identity/path validation;
 * ordinary callers should use runCasefileBenchmarkAdapter.
 */
export function adaptCasefileReport(
  requestValue: TrustBenchmarkAdapterRequest,
  report: Report,
): TrustBenchmarkToolResult {
  const request = parseTrustBenchmarkAdapterRequest(requestValue);
  validateReportIdentity(report);
  if (request.track === 'common-static-skill' && report.artifact.type !== 'skill') {
    return unsupported(
      request,
      'common-track-artifact-unsupported',
      'common-static-skill accepts only a skill directory rooted at SKILL.md',
    );
  }

  const findings = [
    ...report.findings.map((finding) => findingToProtocol(report, finding, 'active')),
    ...report.suppressed.map((finding) => findingToProtocol(report, finding, 'suppressed')),
  ].sort(compareTrustBenchmarkFindings);
  const coverageGaps = [...report.findings, ...report.suppressed]
    .filter((finding) => INCOMPLETE_ANALYSIS_RULES.has(finding.ruleId))
    .map((finding) => coverageGapFromFinding(report, finding))
    .sort(compareTrustBenchmarkCoverageGaps);
  const evidence = {
    artifact: {
      type: report.artifact.type,
      contentIdentity: { algorithm: 'sha256' as const, digest: report.artifact.contentHash },
    },
    report: {
      version: report.reportVersion,
      identity: { algorithm: 'sha256' as const, digest: report.identity.digest },
    },
    findings,
    coverageGaps,
  };
  let content: TrustBenchmarkToolResultContent;
  if (coverageGaps.length > 0) {
    content = {
      ...base(request),
      status: 'incomplete',
      statusReason: reason(
        'coverage-incomplete',
        'strict Casefile analysis reported one or more named coverage gaps',
      ),
      ...evidence,
    };
  } else {
    const flagged = findings.some(
      (finding) =>
        finding.disposition === 'active' &&
        (finding.severity === 'critical' || finding.severity === 'warning'),
    );
    content = {
      ...base(request),
      status: 'completed',
      disposition: flagged ? 'flag' : 'clean',
      ...evidence,
    };
  }
  return attachTrustBenchmarkResultIdentity(content);
}

/**
 * Run one Casefile benchmark request in-process. The scanner receives strict
 * mode and no suppression config; no artifact-local policy is trusted.
 */
export function runCasefileBenchmarkAdapter(value: unknown): TrustBenchmarkToolResult {
  const request = parseTrustBenchmarkAdapterRequest(value);
  let report: Report;
  try {
    report = scanArtifact(request.artifactRoot, { strict: true });
  } catch (cause) {
    if (cause instanceof DiscoveryError && cause.message.startsWith('cannot classify ')) {
      return unsupported(
        request,
        'artifact-profile-unsupported',
        'artifact is not a supported Casefile skill, plugin, or marketplace',
      );
    }
    return error(request, 'scan-error', 'Casefile could not scan the requested artifact');
  }
  try {
    return adaptCasefileReport(request, report);
  } catch (cause) {
    if (cause instanceof TrustBenchmarkProtocolError) {
      return error(request, 'evidence-invalid', 'Casefile evidence violated the adapter contract');
    }
    return error(request, 'adapter-error', 'Casefile could not construct valid benchmark evidence');
  }
}
