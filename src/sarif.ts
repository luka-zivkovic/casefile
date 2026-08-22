import { createHash } from 'node:crypto';
import type { Finding, Report, Severity } from './types.js';

export const SARIF_VERSION = '2.1.0' as const;
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

export interface SarifLog {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  properties: {
    reportVersion: number;
    reportIdentity: string;
    artifactType: string;
    artifactContentHash: string;
    policySource: string;
    policyContentHash?: string;
    strict: boolean;
  };
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: { casefileSeverity: Severity };
}

export type SarifLevel = 'error' | 'warning' | 'note';

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  kind: 'fail' | 'informational';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
  partialFingerprints: { 'casefileFinding/v1': string };
  properties: { casefileSeverity: Severity; disposition: 'active' | 'suppressed' };
  suppressions?: Array<{ kind: 'external'; justification: string }>;
}

function compareText(a: string, b: string): number {
  return a === b ? 0 : a < b ? -1 : 1;
}

function levelFor(severity: Severity): SarifLevel {
  if (severity === 'critical') return 'error';
  if (severity === 'warning') return 'warning';
  return 'note';
}

function stableUri(relativePath: string): string {
  return relativePath
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

function findingFingerprint(finding: Finding): string {
  // Message distinguishes multiple findings from the same rule and location.
  // Suppression disposition remains deliberately outside the fingerprint.
  const canonical = JSON.stringify({
    ruleId: finding.ruleId,
    file: finding.file,
    ...(finding.line === undefined ? {} : { line: finding.line }),
    message: finding.message,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

function ruleSeverity(findings: Finding[]): Severity {
  if (findings.some((finding) => finding.severity === 'critical')) return 'critical';
  if (findings.some((finding) => finding.severity === 'warning')) return 'warning';
  return 'info';
}

/** Render deterministic SARIF without embedding scan time or absolute artifact paths. */
export function toSarif(report: Report): SarifLog {
  const all = [...report.findings, ...report.suppressed];
  const ruleIds = [...new Set(all.map((finding) => finding.ruleId))].sort(compareText);
  const rules = ruleIds.map((ruleId): SarifRule => {
    const severity = ruleSeverity(all.filter((finding) => finding.ruleId === ruleId));
    return {
      id: ruleId,
      name: ruleId,
      shortDescription: { text: `Casefile ${ruleId} finding` },
      defaultConfiguration: { level: levelFor(severity) },
      properties: { casefileSeverity: severity },
    };
  });
  const ruleIndex = new Map(rules.map((rule, index) => [rule.id, index]));

  const resultFor = (finding: Finding, disposition: 'active' | 'suppressed'): SarifResult => {
    const physicalLocation: SarifResult['locations'][number]['physicalLocation'] = {
      artifactLocation: { uri: stableUri(finding.file) },
    };
    if (finding.line !== undefined) physicalLocation.region = { startLine: finding.line };
    const result: SarifResult = {
      ruleId: finding.ruleId,
      ruleIndex: ruleIndex.get(finding.ruleId) as number,
      level: levelFor(finding.severity),
      kind: finding.severity === 'info' ? 'informational' : 'fail',
      message: { text: finding.message },
      locations: [{ physicalLocation }],
      partialFingerprints: { 'casefileFinding/v1': findingFingerprint(finding) },
      properties: { casefileSeverity: finding.severity, disposition },
    };
    if (disposition === 'suppressed') {
      result.suppressions = [{ kind: 'external', justification: 'Matched trusted Casefile operator policy' }];
    }
    return result;
  };

  const properties: SarifRun['properties'] = {
    reportVersion: report.reportVersion,
    reportIdentity: report.identity.digest,
    artifactType: report.artifact.type,
    artifactContentHash: report.artifact.contentHash,
    policySource: report.policy.source,
    strict: report.policy.strict,
  };
  if (report.policy.contentHash !== undefined) properties.policyContentHash = report.policy.contentHash;

  return {
    version: SARIF_VERSION,
    $schema: SARIF_SCHEMA,
    runs: [
      {
        tool: { driver: { name: report.tool.name, version: report.tool.version, rules } },
        results: [
          ...report.findings.map((finding) => resultFor(finding, 'active')),
          ...report.suppressed.map((finding) => resultFor(finding, 'suppressed')),
        ],
        properties,
      },
    ],
  };
}

export function renderSarif(report: Report): string {
  return JSON.stringify(toSarif(report), null, 2);
}
