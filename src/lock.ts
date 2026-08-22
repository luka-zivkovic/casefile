import { createHash } from 'node:crypto';
import * as path from 'node:path';
import { canonicalReportContent, canonicalizeFinding } from './report.js';
import { INCOMPLETE_ANALYSIS_RULES, scanArtifact } from './scan.js';
import type { ArtifactType, Finding, Report, ReportPolicy, Severity } from './types.js';

export const LOCK_VERSION = 1 as const;

export interface LockPolicy {
  /** Lock workflows only accept no policy or an explicit operator policy. */
  source: 'none' | 'explicit';
  strict: boolean;
  contentHash?: string;
}

export interface CasefileLock {
  lockVersion: 1;
  tool: { name: string; version: string };
  reportVersion: number;
  artifact: { type: ArtifactType; contentHash: string };
  policy: LockPolicy;
  reportIdentity: { algorithm: 'sha256'; digest: string };
  snapshot: {
    /** Includes capability/* evidence emitted by the current scanner. */
    activeFindings: Finding[];
    suppressedFindings: Finding[];
  };
  digest: { algorithm: 'sha256'; digest: string };
}

export interface LockScanOptions {
  /** Explicit operator-owned policy. Artifact-local policy is never trusted. */
  configPath?: string;
  /** Fail closed when content analysis is incomplete. */
  strict?: boolean;
}

export type FindingDisposition = 'active' | 'suppressed';

export interface FindingEvidence extends Finding {
  disposition: FindingDisposition;
}

export interface ChangedFinding {
  expected: FindingEvidence;
  actual: FindingEvidence;
}

export interface LockDrift {
  artifact: {
    changed: boolean;
    expected: { type: ArtifactType; contentHash: string };
    actual: { type: ArtifactType; contentHash: string };
  };
  policy: { changed: boolean; expected: LockPolicy; actual: ReportPolicy };
  tool: {
    changed: boolean;
    expected: { name: string; version: string };
    actual: { name: string; version: string };
  };
  reportVersion: { changed: boolean; expected: number; actual: number };
  reportIdentity: { changed: boolean; expected: string; actual: string };
  findings: {
    added: FindingEvidence[];
    removed: FindingEvidence[];
    changed: ChangedFinding[];
  };
}

export interface LockVerification {
  exact: boolean;
  lock: CasefileLock;
  report: Report;
  drift: LockDrift;
}

export class LockValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockValidationError';
  }
}

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function compareText(a: string, b: string): number {
  return a === b ? 0 : a < b ? -1 : 1;
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

function compareFindings(a: Finding, b: Finding): number {
  return (
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
    compareText(a.file, b.file) ||
    compareText(a.ruleId, b.ruleId) ||
    (a.line ?? 0) - (b.line ?? 0) ||
    compareText(a.message, b.message)
  );
}

function canonicalFinding(finding: Finding): Finding {
  const result: Finding = {
    ruleId: finding.ruleId,
    severity: finding.severity,
    message: finding.message,
    file: finding.file,
  };
  if (finding.line !== undefined) result.line = finding.line;
  return result;
}

function sortedFindings(findings: Finding[]): Finding[] {
  return findings.map(canonicalFinding).sort(compareFindings);
}

function canonicalPolicy(policy: LockPolicy): LockPolicy {
  return policy.contentHash === undefined
    ? { source: policy.source, strict: policy.strict }
    : { source: policy.source, strict: policy.strict, contentHash: policy.contentHash };
}

/** Canonical lock statement covered by `digest`; formatting and array order are not identity-bearing. */
export function canonicalLockContent(lock: Omit<CasefileLock, 'digest'> | CasefileLock): string {
  return JSON.stringify({
    lockVersion: lock.lockVersion,
    tool: { name: lock.tool.name, version: lock.tool.version },
    reportVersion: lock.reportVersion,
    artifact: { type: lock.artifact.type, contentHash: lock.artifact.contentHash },
    policy: canonicalPolicy(lock.policy),
    reportIdentity: { algorithm: lock.reportIdentity.algorithm, digest: lock.reportIdentity.digest },
    snapshot: {
      activeFindings: sortedFindings(lock.snapshot.activeFindings),
      suppressedFindings: sortedFindings(lock.snapshot.suppressedFindings),
    },
  });
}

function lockPolicyFromReport(policy: ReportPolicy): LockPolicy {
  if (policy.source === 'artifact-legacy') {
    throw new LockValidationError(
      'artifact-local suppression policy cannot be locked; use an explicit operator-owned policy',
    );
  }
  if (policy.source === 'explicit' && policy.contentHash === undefined) {
    throw new LockValidationError('explicit operator policy could not be hashed');
  }
  return policy.contentHash === undefined
    ? { source: policy.source, strict: policy.strict }
    : { source: policy.source, strict: policy.strict, contentHash: policy.contentHash };
}

/** Build a deterministic lock from a valid report. No time or absolute artifact path is retained. */
export function createLock(report: Report): CasefileLock {
  const reportDigest = sha256(canonicalReportContent(report));
  if (report.identity.algorithm !== 'sha256' || report.identity.digest !== reportDigest) {
    throw new LockValidationError('report identity is invalid');
  }
  const identityGap = [...report.findings, ...report.suppressed].find(
    (finding) => finding.ruleId === 'scan/unreadable-directory' || finding.ruleId === 'scan/identity-incomplete',
  );
  if (identityGap !== undefined) {
    throw new LockValidationError(
      `artifact identity is incomplete because ${identityGap.ruleId} occurred at ${identityGap.file}`,
    );
  }
  if (report.policy.strict) {
    const analysisGap = [...report.findings, ...report.suppressed].find(
      (finding) =>
        finding.ruleId === 'scan/incomplete-analysis' ||
        INCOMPLETE_ANALYSIS_RULES.has(finding.ruleId),
    );
    if (analysisGap !== undefined) {
      throw new LockValidationError(
        `strict lock requires complete content analysis; ${analysisGap.ruleId} occurred at ${analysisGap.file}`,
      );
    }
  }
  const withoutDigest: Omit<CasefileLock, 'digest'> = {
    lockVersion: LOCK_VERSION,
    tool: { name: report.tool.name, version: report.tool.version },
    reportVersion: report.reportVersion,
    artifact: { type: report.artifact.type, contentHash: report.artifact.contentHash },
    policy: lockPolicyFromReport(report.policy),
    snapshot: {
      activeFindings: sortedFindings(
        report.findings.map((finding) => canonicalizeFinding(finding, report.artifact.path)),
      ),
      suppressedFindings: sortedFindings(
        report.suppressed.map((finding) => canonicalizeFinding(finding, report.artifact.path)),
      ),
    },
    reportIdentity: { algorithm: 'sha256', digest: report.identity.digest },
  };
  return {
    ...withoutDigest,
    digest: { algorithm: 'sha256', digest: sha256(canonicalLockContent(withoutDigest)) },
  };
}

export function createArtifactLock(inputPath: string, options: LockScanOptions = {}): CasefileLock {
  return createLock(scanArtifact(inputPath, { configPath: options.configPath, strict: options.strict }));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new LockValidationError(`${label} must be an object`);
  return value;
}

function requireKeys(
  value: Record<string, unknown>,
  required: string[],
  optional: string[],
  label: string,
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!(key in value)) throw new LockValidationError(`${label}.${key} is required`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new LockValidationError(`${label}.${key} is not allowed`);
  }
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value === '') throw new LockValidationError(`${label} must be a non-empty string`);
  return value;
}

function requireHash(value: unknown, label: string): string {
  const hash = requireString(value, label);
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new LockValidationError(`${label} must be a lowercase SHA-256 digest`);
  return hash;
}

function parseFinding(value: unknown, label: string): Finding {
  const finding = requireRecord(value, label);
  requireKeys(finding, ['ruleId', 'severity', 'message', 'file'], ['line'], label);
  const severity = requireString(finding.severity, `${label}.severity`);
  if (severity !== 'critical' && severity !== 'warning' && severity !== 'info') {
    throw new LockValidationError(`${label}.severity is invalid`);
  }
  const file = requireString(finding.file, `${label}.file`);
  if (path.posix.isAbsolute(file) || path.win32.isAbsolute(file)) {
    throw new LockValidationError(`${label}.file must be relative to the artifact`);
  }
  const parsed: Finding = {
    ruleId: requireString(finding.ruleId, `${label}.ruleId`),
    severity,
    message: requireString(finding.message, `${label}.message`),
    file,
  };
  if (finding.line !== undefined) {
    if (!Number.isInteger(finding.line) || (finding.line as number) < 1) {
      throw new LockValidationError(`${label}.line must be a positive integer`);
    }
    parsed.line = finding.line as number;
  }
  return parsed;
}

function parseFindings(value: unknown, label: string): Finding[] {
  if (!Array.isArray(value)) throw new LockValidationError(`${label} must be an array`);
  return value.map((finding, index) => parseFinding(finding, `${label}[${index}]`));
}

/** Parse, structurally validate, and authenticate a lock before it is used for any scan. */
export function validateLock(value: unknown): CasefileLock {
  const lock = requireRecord(value, 'lock');
  requireKeys(
    lock,
    ['lockVersion', 'tool', 'reportVersion', 'artifact', 'policy', 'reportIdentity', 'snapshot', 'digest'],
    [],
    'lock',
  );
  if (lock.lockVersion !== LOCK_VERSION) throw new LockValidationError('lock.lockVersion is unsupported');

  const tool = requireRecord(lock.tool, 'lock.tool');
  requireKeys(tool, ['name', 'version'], [], 'lock.tool');

  if (!Number.isInteger(lock.reportVersion) || (lock.reportVersion as number) < 1) {
    throw new LockValidationError('lock.reportVersion must be a positive integer');
  }

  const artifact = requireRecord(lock.artifact, 'lock.artifact');
  requireKeys(artifact, ['type', 'contentHash'], [], 'lock.artifact');
  if (artifact.type !== 'skill' && artifact.type !== 'plugin' && artifact.type !== 'marketplace') {
    throw new LockValidationError('lock.artifact.type is invalid');
  }

  const policy = requireRecord(lock.policy, 'lock.policy');
  requireKeys(policy, ['source', 'strict'], ['contentHash'], 'lock.policy');
  if (policy.source !== 'none' && policy.source !== 'explicit') {
    throw new LockValidationError('lock.policy.source must be none or explicit');
  }
  if (typeof policy.strict !== 'boolean') throw new LockValidationError('lock.policy.strict must be boolean');
  if (policy.source === 'none' && policy.contentHash !== undefined) {
    throw new LockValidationError('lock.policy.contentHash is not allowed when source is none');
  }
  if (policy.source === 'explicit' && policy.contentHash === undefined) {
    throw new LockValidationError('lock.policy.contentHash is required when source is explicit');
  }

  const reportIdentity = requireRecord(lock.reportIdentity, 'lock.reportIdentity');
  requireKeys(reportIdentity, ['algorithm', 'digest'], [], 'lock.reportIdentity');
  if (reportIdentity.algorithm !== 'sha256') {
    throw new LockValidationError('lock.reportIdentity.algorithm must be sha256');
  }

  const snapshot = requireRecord(lock.snapshot, 'lock.snapshot');
  requireKeys(snapshot, ['activeFindings', 'suppressedFindings'], [], 'lock.snapshot');

  const digest = requireRecord(lock.digest, 'lock.digest');
  requireKeys(digest, ['algorithm', 'digest'], [], 'lock.digest');
  if (digest.algorithm !== 'sha256') throw new LockValidationError('lock.digest.algorithm must be sha256');

  const parsed: CasefileLock = {
    lockVersion: LOCK_VERSION,
    tool: {
      name: requireString(tool.name, 'lock.tool.name'),
      version: requireString(tool.version, 'lock.tool.version'),
    },
    reportVersion: lock.reportVersion as number,
    artifact: {
      type: artifact.type,
      contentHash: requireHash(artifact.contentHash, 'lock.artifact.contentHash'),
    },
    policy:
      policy.contentHash === undefined
        ? { source: policy.source, strict: policy.strict }
        : {
            source: policy.source,
            strict: policy.strict,
            contentHash: requireHash(policy.contentHash, 'lock.policy.contentHash'),
          },
    reportIdentity: {
      algorithm: 'sha256',
      digest: requireHash(reportIdentity.digest, 'lock.reportIdentity.digest'),
    },
    snapshot: {
      activeFindings: parseFindings(snapshot.activeFindings, 'lock.snapshot.activeFindings'),
      suppressedFindings: parseFindings(snapshot.suppressedFindings, 'lock.snapshot.suppressedFindings'),
    },
    digest: { algorithm: 'sha256', digest: requireHash(digest.digest, 'lock.digest.digest') },
  };
  const expected = sha256(canonicalLockContent(parsed));
  if (parsed.digest.digest !== expected) throw new LockValidationError('lock digest mismatch');
  return parsed;
}

export function parseLock(content: string): CasefileLock {
  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch (error) {
    throw new LockValidationError(`lock is not valid JSON: ${(error as Error).message}`);
  }
  return validateLock(value);
}

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function evidence(finding: Finding, disposition: FindingDisposition): FindingEvidence {
  return { ...canonicalFinding(finding), disposition };
}

function evidenceKey(finding: FindingEvidence): string {
  // Location/message/severity/disposition changes at the same rule + file are
  // reported as changed evidence instead of a less useful remove/add pair.
  return `${finding.ruleId}\0${finding.file}`;
}

function compareEvidence(a: FindingEvidence, b: FindingEvidence): number {
  return compareFindings(a, b) || compareText(a.disposition, b.disposition);
}

function classifyFindingDrift(
  expectedActive: Finding[],
  expectedSuppressed: Finding[],
  actualActive: Finding[],
  actualSuppressed: Finding[],
): LockDrift['findings'] {
  const expected = [
    ...expectedActive.map((finding) => evidence(finding, 'active')),
    ...expectedSuppressed.map((finding) => evidence(finding, 'suppressed')),
  ];
  const actual = [
    ...actualActive.map((finding) => evidence(finding, 'active')),
    ...actualSuppressed.map((finding) => evidence(finding, 'suppressed')),
  ];
  const keys = new Set([...expected.map(evidenceKey), ...actual.map(evidenceKey)]);
  const added: FindingEvidence[] = [];
  const removed: FindingEvidence[] = [];
  const changed: ChangedFinding[] = [];

  for (const key of [...keys].sort(compareText)) {
    let before = expected.filter((finding) => evidenceKey(finding) === key).sort(compareEvidence);
    let after = actual.filter((finding) => evidenceKey(finding) === key).sort(compareEvidence);
    const exactBefore: FindingEvidence[] = [];
    const remainingAfter = [...after];
    for (const candidate of before) {
      const index = remainingAfter.findIndex((current) => sameValue(candidate, current));
      if (index === -1) exactBefore.push(candidate);
      else remainingAfter.splice(index, 1);
    }
    before = exactBefore;
    after = remainingAfter;
    const paired = Math.min(before.length, after.length);
    for (let index = 0; index < paired; index++) {
      changed.push({ expected: before[index], actual: after[index] });
    }
    removed.push(...before.slice(paired));
    added.push(...after.slice(paired));
  }
  return {
    added: added.sort(compareEvidence),
    removed: removed.sort(compareEvidence),
    changed: changed.sort((a, b) => compareEvidence(a.expected, b.expected)),
  };
}

/** Validate the lock first, then scan with only the policy/strict options supplied by the caller. */
export function verifyArtifact(
  inputPath: string,
  lockValue: unknown,
  options: LockScanOptions = {},
): LockVerification {
  const lock = validateLock(lockValue);
  const report = scanArtifact(inputPath, { configPath: options.configPath, strict: options.strict });
  const actualSnapshot = {
    activeFindings: sortedFindings(
      report.findings.map((finding) => canonicalizeFinding(finding, report.artifact.path)),
    ),
    suppressedFindings: sortedFindings(
      report.suppressed.map((finding) => canonicalizeFinding(finding, report.artifact.path)),
    ),
  };
  const actualArtifact = { type: report.artifact.type, contentHash: report.artifact.contentHash };
  const drift: LockDrift = {
    artifact: { changed: !sameValue(lock.artifact, actualArtifact), expected: lock.artifact, actual: actualArtifact },
    policy: { changed: !sameValue(lock.policy, report.policy), expected: lock.policy, actual: report.policy },
    tool: { changed: !sameValue(lock.tool, report.tool), expected: lock.tool, actual: report.tool },
    reportVersion: {
      changed: lock.reportVersion !== report.reportVersion,
      expected: lock.reportVersion,
      actual: report.reportVersion,
    },
    reportIdentity: {
      changed: lock.reportIdentity.digest !== report.identity.digest,
      expected: lock.reportIdentity.digest,
      actual: report.identity.digest,
    },
    findings: classifyFindingDrift(
      lock.snapshot.activeFindings,
      lock.snapshot.suppressedFindings,
      actualSnapshot.activeFindings,
      actualSnapshot.suppressedFindings,
    ),
  };
  const exact =
    !drift.artifact.changed &&
    !drift.policy.changed &&
    !drift.tool.changed &&
    !drift.reportVersion.changed &&
    !drift.reportIdentity.changed &&
    drift.findings.added.length === 0 &&
    drift.findings.removed.length === 0 &&
    drift.findings.changed.length === 0;
  return { exact, lock, report, drift };
}
