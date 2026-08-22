import { createHash } from 'node:crypto';
import * as path from 'node:path';
import { decodeUtf8Fatal } from './io.js';
import type { ArtifactType, Severity } from './types.js';

export const TRUST_BENCHMARK_PROTOCOL_VERSION = 1 as const;
export const CASEFILE_BENCHMARK_ADAPTER_VERSION = 1 as const;

export type TrustBenchmarkTrack = 'common-static-skill' | 'breadth';
export type TrustBenchmarkResultStatus = 'completed' | 'unsupported' | 'incomplete' | 'error';
export type TrustBenchmarkDisposition = 'flag' | 'clean';

export interface TrustBenchmarkAdapterRequest {
  protocolVersion: 1;
  caseId: string;
  /** Process-local path. It must never enter a tool result or its identity. */
  artifactRoot: string;
  track: TrustBenchmarkTrack;
  runIndex: number;
  /** Enforced by the neutral harness, not by an in-process Casefile timer. */
  timeoutMs: number;
  environmentId: string;
  /** Harness-owned frozen tool/config/environment statement, echoed verbatim. */
  toolIdentityDigest: string;
}

export interface TrustBenchmarkFinding {
  ruleId: string;
  severity: Severity;
  message: string;
  path: string;
  line?: number;
  disposition: 'active' | 'suppressed';
}

export interface TrustBenchmarkCoverageGap {
  ruleId: string;
  message: string;
  path: string;
  line?: number;
}

export interface TrustBenchmarkStatusReason {
  code: string;
  message: string;
}

interface TrustBenchmarkToolResultBase {
  protocolVersion: 1;
  resultType: 'tool-result';
  caseId: string;
  track: TrustBenchmarkTrack;
  runIndex: number;
  environmentId: string;
  adapter: { id: 'casefile'; version: 1 };
  tool: { name: 'casefile'; version: string; identityDigest: string };
  status: TrustBenchmarkResultStatus;
  findings: TrustBenchmarkFinding[];
  coverageGaps: TrustBenchmarkCoverageGap[];
  resultIdentity: { algorithm: 'sha256'; digest: string };
}

export interface TrustBenchmarkCompletedResult extends TrustBenchmarkToolResultBase {
  status: 'completed';
  disposition: TrustBenchmarkDisposition;
  artifact: { type: ArtifactType; contentIdentity: { algorithm: 'sha256'; digest: string } };
  report: { version: number; identity: { algorithm: 'sha256'; digest: string } };
  statusReason?: never;
}

export interface TrustBenchmarkIncompleteResult extends TrustBenchmarkToolResultBase {
  status: 'incomplete';
  disposition?: never;
  artifact: { type: ArtifactType; contentIdentity: { algorithm: 'sha256'; digest: string } };
  report: { version: number; identity: { algorithm: 'sha256'; digest: string } };
  statusReason: TrustBenchmarkStatusReason;
}

export interface TrustBenchmarkUnsupportedResult extends TrustBenchmarkToolResultBase {
  status: 'unsupported';
  disposition?: never;
  artifact?: never;
  report?: never;
  statusReason: TrustBenchmarkStatusReason;
}

export interface TrustBenchmarkErrorResult extends TrustBenchmarkToolResultBase {
  status: 'error';
  disposition?: never;
  artifact?: never;
  report?: never;
  statusReason: TrustBenchmarkStatusReason;
}

export type TrustBenchmarkToolResult =
  | TrustBenchmarkCompletedResult
  | TrustBenchmarkIncompleteResult
  | TrustBenchmarkUnsupportedResult
  | TrustBenchmarkErrorResult;

export type TrustBenchmarkToolResultContent =
  | Omit<TrustBenchmarkCompletedResult, 'resultIdentity'>
  | Omit<TrustBenchmarkIncompleteResult, 'resultIdentity'>
  | Omit<TrustBenchmarkUnsupportedResult, 'resultIdentity'>
  | Omit<TrustBenchmarkErrorResult, 'resultIdentity'>;

export class TrustBenchmarkProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TrustBenchmarkProtocolError';
  }
}

const CASE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const ENVIRONMENT_ID = /^[a-z0-9][a-z0-9._:@/+\-]{0,255}$/;
const REASON_CODE = /^[a-z0-9][a-z0-9-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new TrustBenchmarkProtocolError(`${label} must be an object`);
  return value;
}

function keys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!(key in value)) throw new TrustBenchmarkProtocolError(`${label}.${key} is required`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new TrustBenchmarkProtocolError(`${label}.${key} is not allowed`);
  }
}

function string(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TrustBenchmarkProtocolError(`${label} must be a non-empty string`);
  }
  return value;
}

function integer(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TrustBenchmarkProtocolError(`${label} must be an integer from ${minimum} to ${maximum}`);
  }
  return value as number;
}

function parseTrack(value: unknown, label: string): TrustBenchmarkTrack {
  if (value !== 'common-static-skill' && value !== 'breadth') {
    throw new TrustBenchmarkProtocolError(`${label} is unsupported`);
  }
  return value;
}

function parseHash(value: unknown, label: string): { algorithm: 'sha256'; digest: string } {
  const digest = record(value, label);
  keys(digest, ['algorithm', 'digest'], [], label);
  if (digest.algorithm !== 'sha256') throw new TrustBenchmarkProtocolError(`${label}.algorithm must be sha256`);
  const text = string(digest.digest, `${label}.digest`);
  if (!SHA256.test(text)) throw new TrustBenchmarkProtocolError(`${label}.digest must be a lowercase SHA-256 digest`);
  return { algorithm: 'sha256', digest: text };
}

export function isSafeArtifactRelativePath(value: string): boolean {
  if (value === '.') return true;
  if (
    value.length === 0 ||
    value.length > 4096 ||
    CONTROL.test(value) ||
    value.includes('\\') ||
    path.posix.isAbsolute(value) ||
    path.win32.isAbsolute(value)
  ) {
    return false;
  }
  const parts = value.split('/');
  return parts.every((part) => part !== '' && part !== '.' && part !== '..');
}

export function parseTrustBenchmarkAdapterRequest(value: unknown): TrustBenchmarkAdapterRequest {
  const request = record(value, 'request');
  keys(
    request,
    [
      'protocolVersion',
      'caseId',
      'artifactRoot',
      'track',
      'runIndex',
      'timeoutMs',
      'environmentId',
      'toolIdentityDigest',
    ],
    [],
    'request',
  );
  if (request.protocolVersion !== TRUST_BENCHMARK_PROTOCOL_VERSION) {
    throw new TrustBenchmarkProtocolError('request.protocolVersion is unsupported');
  }
  const caseId = string(request.caseId, 'request.caseId');
  if (!CASE_ID.test(caseId)) throw new TrustBenchmarkProtocolError('request.caseId is invalid');
  const artifactRoot = string(request.artifactRoot, 'request.artifactRoot');
  if (artifactRoot.length > 4096 || CONTROL.test(artifactRoot)) {
    throw new TrustBenchmarkProtocolError('request.artifactRoot is invalid');
  }
  const environmentId = string(request.environmentId, 'request.environmentId');
  if (!ENVIRONMENT_ID.test(environmentId)) {
    throw new TrustBenchmarkProtocolError('request.environmentId is invalid');
  }
  return {
    protocolVersion: TRUST_BENCHMARK_PROTOCOL_VERSION,
    caseId,
    artifactRoot,
    track: parseTrack(request.track, 'request.track'),
    runIndex: integer(request.runIndex, 'request.runIndex', 0, 2_147_483_647),
    timeoutMs: integer(request.timeoutMs, 'request.timeoutMs', 1, 3_600_000),
    environmentId,
    toolIdentityDigest: (() => {
      const digest = string(request.toolIdentityDigest, 'request.toolIdentityDigest');
      if (!SHA256.test(digest)) {
        throw new TrustBenchmarkProtocolError(
          'request.toolIdentityDigest must be a lowercase SHA-256 digest',
        );
      }
      return digest;
    })(),
  };
}

export function decodeTrustBenchmarkAdapterRequest(raw: Buffer): TrustBenchmarkAdapterRequest {
  let text: string;
  try {
    text = decodeUtf8Fatal(raw, 'benchmark adapter request');
  } catch {
    throw new TrustBenchmarkProtocolError('request is not valid UTF-8');
  }
  const parsed = parseJsonRejectingDuplicateKeys(text, 'request');
  return parseTrustBenchmarkAdapterRequest(parsed);
}

/** Parse JSON while rejecting duplicate object keys, including escaped-key aliases. */
export function parseJsonRejectingDuplicateKeys(text: string, label: string): unknown {
  let index = 0;
  const fail = (): never => {
    throw new TrustBenchmarkProtocolError(`${label} is not valid JSON`);
  };
  const whitespace = (): void => {
    while (index < text.length && /\s/.test(text[index])) index++;
  };
  const jsonString = (): string => {
    if (text[index] !== '"') fail();
    const start = index++;
    while (index < text.length) {
      const char = text[index];
      if (char === '"') {
        index++;
        try {
          return JSON.parse(text.slice(start, index)) as string;
        } catch {
          return fail();
        }
      }
      if (char === '\\') {
        index++;
        if (index >= text.length) fail();
        if (text[index] === 'u') {
          if (!/^[a-fA-F0-9]{4}$/.test(text.slice(index + 1, index + 5))) fail();
          index += 5;
        } else {
          index++;
        }
      } else {
        index++;
      }
    }
    return fail();
  };
  const value = (): void => {
    whitespace();
    if (text[index] === '{') {
      object();
      return;
    }
    if (text[index] === '[') {
      array();
      return;
    }
    if (text[index] === '"') {
      jsonString();
      return;
    }
    const start = index;
    while (index < text.length && !/[\s,}\]]/.test(text[index])) index++;
    if (index === start) fail();
  };
  const object = (): void => {
    index++;
    whitespace();
    const seen = new Set<string>();
    if (text[index] === '}') {
      index++;
      return;
    }
    while (index < text.length) {
      const key = jsonString();
      if (seen.has(key)) throw new TrustBenchmarkProtocolError(`${label} contains duplicate object key ${key}`);
      seen.add(key);
      whitespace();
      if (text[index++] !== ':') fail();
      value();
      whitespace();
      if (text[index] === '}') {
        index++;
        return;
      }
      if (text[index++] !== ',') fail();
      whitespace();
    }
    fail();
  };
  const array = (): void => {
    index++;
    whitespace();
    if (text[index] === ']') {
      index++;
      return;
    }
    while (index < text.length) {
      value();
      whitespace();
      if (text[index] === ']') {
        index++;
        return;
      }
      if (text[index++] !== ',') fail();
      whitespace();
    }
    fail();
  };
  try {
    value();
    whitespace();
    if (index !== text.length) fail();
    return JSON.parse(text) as unknown;
  } catch (cause) {
    if (cause instanceof TrustBenchmarkProtocolError) throw cause;
    throw new TrustBenchmarkProtocolError(`${label} is not valid JSON: ${(cause as Error).message}`);
  }
}

export function decodeTrustBenchmarkToolResult(raw: Buffer): TrustBenchmarkToolResult {
  let text: string;
  try {
    text = decodeUtf8Fatal(raw, 'benchmark tool result');
  } catch {
    throw new TrustBenchmarkProtocolError('result is not valid UTF-8');
  }
  return validateTrustBenchmarkToolResult(parseJsonRejectingDuplicateKeys(text, 'result'));
}

function compareText(a: string, b: string): number {
  return a === b ? 0 : a < b ? -1 : 1;
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

export function compareTrustBenchmarkFindings(a: TrustBenchmarkFinding, b: TrustBenchmarkFinding): number {
  return (
    compareText(a.disposition, b.disposition) ||
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
    compareText(a.path, b.path) ||
    compareText(a.ruleId, b.ruleId) ||
    (a.line ?? 0) - (b.line ?? 0) ||
    compareText(a.message, b.message)
  );
}

export function compareTrustBenchmarkCoverageGaps(
  a: TrustBenchmarkCoverageGap,
  b: TrustBenchmarkCoverageGap,
): number {
  return (
    compareText(a.path, b.path) ||
    compareText(a.ruleId, b.ruleId) ||
    (a.line ?? 0) - (b.line ?? 0) ||
    compareText(a.message, b.message)
  );
}

function canonicalResultObject(result: Omit<TrustBenchmarkToolResult, 'resultIdentity'> | TrustBenchmarkToolResult) {
  return {
    protocolVersion: result.protocolVersion,
    resultType: result.resultType,
    caseId: result.caseId,
    track: result.track,
    runIndex: result.runIndex,
    environmentId: result.environmentId,
    adapter: { id: result.adapter.id, version: result.adapter.version },
    tool: {
      name: result.tool.name,
      version: result.tool.version,
      identityDigest: result.tool.identityDigest,
    },
    status: result.status,
    ...('disposition' in result && result.disposition !== undefined ? { disposition: result.disposition } : {}),
    ...('artifact' in result && result.artifact !== undefined
      ? {
          artifact: {
            type: result.artifact.type,
            contentIdentity: {
              algorithm: result.artifact.contentIdentity.algorithm,
              digest: result.artifact.contentIdentity.digest,
            },
          },
        }
      : {}),
    ...('report' in result && result.report !== undefined
      ? {
          report: {
            version: result.report.version,
            identity: { algorithm: result.report.identity.algorithm, digest: result.report.identity.digest },
          },
        }
      : {}),
    ...('statusReason' in result && result.statusReason !== undefined
      ? { statusReason: { code: result.statusReason.code, message: result.statusReason.message } }
      : {}),
    findings: result.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      message: finding.message,
      path: finding.path,
      ...(finding.line === undefined ? {} : { line: finding.line }),
      disposition: finding.disposition,
    })),
    coverageGaps: result.coverageGaps.map((gap) => ({
      ruleId: gap.ruleId,
      message: gap.message,
      path: gap.path,
      ...(gap.line === undefined ? {} : { line: gap.line }),
    })),
  };
}

export function canonicalTrustBenchmarkToolResultContent(
  result: Omit<TrustBenchmarkToolResult, 'resultIdentity'> | TrustBenchmarkToolResult,
): string {
  return JSON.stringify(canonicalResultObject(result));
}

export function attachTrustBenchmarkResultIdentity(
  result: TrustBenchmarkToolResultContent,
): TrustBenchmarkToolResult {
  const canonical = canonicalResultObject(result) as TrustBenchmarkToolResultContent;
  const digest = sha256(JSON.stringify(canonical));
  return {
    ...canonical,
    resultIdentity: { algorithm: 'sha256', digest },
  } as TrustBenchmarkToolResult;
}

function parseFinding(value: unknown, label: string): TrustBenchmarkFinding {
  const finding = record(value, label);
  keys(finding, ['ruleId', 'severity', 'message', 'path', 'disposition'], ['line'], label);
  const severity = string(finding.severity, `${label}.severity`);
  if (severity !== 'critical' && severity !== 'warning' && severity !== 'info') {
    throw new TrustBenchmarkProtocolError(`${label}.severity is invalid`);
  }
  const relativePath = string(finding.path, `${label}.path`);
  if (!isSafeArtifactRelativePath(relativePath)) {
    throw new TrustBenchmarkProtocolError(`${label}.path must be a safe artifact-relative POSIX path`);
  }
  if (finding.disposition !== 'active' && finding.disposition !== 'suppressed') {
    throw new TrustBenchmarkProtocolError(`${label}.disposition is invalid`);
  }
  return {
    ruleId: string(finding.ruleId, `${label}.ruleId`),
    severity,
    message: string(finding.message, `${label}.message`),
    path: relativePath,
    ...(finding.line === undefined ? {} : { line: integer(finding.line, `${label}.line`, 1, 2_147_483_647) }),
    disposition: finding.disposition,
  };
}

function parseCoverageGap(value: unknown, label: string): TrustBenchmarkCoverageGap {
  const gap = record(value, label);
  keys(gap, ['ruleId', 'message', 'path'], ['line'], label);
  const relativePath = string(gap.path, `${label}.path`);
  if (!isSafeArtifactRelativePath(relativePath)) {
    throw new TrustBenchmarkProtocolError(`${label}.path must be a safe artifact-relative POSIX path`);
  }
  return {
    ruleId: string(gap.ruleId, `${label}.ruleId`),
    message: string(gap.message, `${label}.message`),
    path: relativePath,
    ...(gap.line === undefined ? {} : { line: integer(gap.line, `${label}.line`, 1, 2_147_483_647) }),
  };
}

function parseStatusReason(value: unknown, label: string): TrustBenchmarkStatusReason {
  const reason = record(value, label);
  keys(reason, ['code', 'message'], [], label);
  const code = string(reason.code, `${label}.code`);
  if (!REASON_CODE.test(code)) throw new TrustBenchmarkProtocolError(`${label}.code is invalid`);
  return { code, message: string(reason.message, `${label}.message`) };
}

function assertCanonicalOrder<T>(actual: T[], sorted: T[], label: string): void {
  if (JSON.stringify(actual) !== JSON.stringify(sorted)) {
    throw new TrustBenchmarkProtocolError(`${label} is not in canonical order`);
  }
}

export function validateTrustBenchmarkToolResult(value: unknown): TrustBenchmarkToolResult {
  const result = record(value, 'result');
  keys(
    result,
    [
      'protocolVersion',
      'resultType',
      'caseId',
      'track',
      'runIndex',
      'environmentId',
      'adapter',
      'tool',
      'status',
      'findings',
      'coverageGaps',
      'resultIdentity',
    ],
    ['disposition', 'artifact', 'report', 'statusReason'],
    'result',
  );
  if (result.protocolVersion !== TRUST_BENCHMARK_PROTOCOL_VERSION || result.resultType !== 'tool-result') {
    throw new TrustBenchmarkProtocolError('result protocol/type is unsupported');
  }
  const caseId = string(result.caseId, 'result.caseId');
  if (!CASE_ID.test(caseId)) throw new TrustBenchmarkProtocolError('result.caseId is invalid');
  const environmentId = string(result.environmentId, 'result.environmentId');
  if (!ENVIRONMENT_ID.test(environmentId)) throw new TrustBenchmarkProtocolError('result.environmentId is invalid');

  const adapter = record(result.adapter, 'result.adapter');
  keys(adapter, ['id', 'version'], [], 'result.adapter');
  if (adapter.id !== 'casefile' || adapter.version !== CASEFILE_BENCHMARK_ADAPTER_VERSION) {
    throw new TrustBenchmarkProtocolError('result.adapter is unsupported');
  }
  const tool = record(result.tool, 'result.tool');
  keys(tool, ['name', 'version', 'identityDigest'], [], 'result.tool');
  if (tool.name !== 'casefile') throw new TrustBenchmarkProtocolError('result.tool.name must be casefile');

  if (!Array.isArray(result.findings)) throw new TrustBenchmarkProtocolError('result.findings must be an array');
  if (!Array.isArray(result.coverageGaps)) {
    throw new TrustBenchmarkProtocolError('result.coverageGaps must be an array');
  }
  const findings = result.findings.map((finding, index) => parseFinding(finding, `result.findings[${index}]`));
  const coverageGaps = result.coverageGaps.map((gap, index) =>
    parseCoverageGap(gap, `result.coverageGaps[${index}]`),
  );
  assertCanonicalOrder(findings, [...findings].sort(compareTrustBenchmarkFindings), 'result.findings');
  assertCanonicalOrder(
    coverageGaps,
    [...coverageGaps].sort(compareTrustBenchmarkCoverageGaps),
    'result.coverageGaps',
  );

  const base = {
    protocolVersion: TRUST_BENCHMARK_PROTOCOL_VERSION,
    resultType: 'tool-result' as const,
    caseId,
    track: parseTrack(result.track, 'result.track'),
    runIndex: integer(result.runIndex, 'result.runIndex', 0, 2_147_483_647),
    environmentId,
    adapter: { id: 'casefile' as const, version: CASEFILE_BENCHMARK_ADAPTER_VERSION },
    tool: {
      name: 'casefile' as const,
      version: string(tool.version, 'result.tool.version'),
      identityDigest: (() => {
        const digest = string(tool.identityDigest, 'result.tool.identityDigest');
        if (!SHA256.test(digest)) {
          throw new TrustBenchmarkProtocolError(
            'result.tool.identityDigest must be a lowercase SHA-256 digest',
          );
        }
        return digest;
      })(),
    },
    findings,
    coverageGaps,
  };
  const status = result.status;
  let content: TrustBenchmarkToolResultContent;
  if (status === 'completed' || status === 'incomplete') {
    const artifact = record(result.artifact, 'result.artifact');
    keys(artifact, ['type', 'contentIdentity'], [], 'result.artifact');
    if (artifact.type !== 'skill' && artifact.type !== 'plugin' && artifact.type !== 'marketplace') {
      throw new TrustBenchmarkProtocolError('result.artifact.type is invalid');
    }
    const artifactType: ArtifactType = artifact.type;
    const report = record(result.report, 'result.report');
    keys(report, ['version', 'identity'], [], 'result.report');
    const evidence = {
      artifact: {
        type: artifactType,
        contentIdentity: parseHash(artifact.contentIdentity, 'result.artifact.contentIdentity'),
      },
      report: {
        version: integer(report.version, 'result.report.version', 1, 2_147_483_647),
        identity: parseHash(report.identity, 'result.report.identity'),
      },
    };
    if (status === 'completed') {
      if (result.disposition !== 'flag' && result.disposition !== 'clean') {
        throw new TrustBenchmarkProtocolError('completed result.disposition is required');
      }
      if (result.statusReason !== undefined || coverageGaps.length !== 0) {
        throw new TrustBenchmarkProtocolError('completed result cannot contain a status reason or coverage gap');
      }
      content = { ...base, status, disposition: result.disposition, ...evidence };
    } else {
      if (result.disposition !== undefined) {
        throw new TrustBenchmarkProtocolError('incomplete result cannot contain disposition');
      }
      if (coverageGaps.length === 0) throw new TrustBenchmarkProtocolError('incomplete result requires coverage gaps');
      content = {
        ...base,
        status,
        ...evidence,
        statusReason: parseStatusReason(result.statusReason, 'result.statusReason'),
      };
    }
  } else if (status === 'unsupported' || status === 'error') {
    if (result.disposition !== undefined || result.artifact !== undefined || result.report !== undefined) {
      throw new TrustBenchmarkProtocolError(`${status} result contains completed evidence`);
    }
    if (findings.length !== 0 || coverageGaps.length !== 0) {
      throw new TrustBenchmarkProtocolError(`${status} result findings and coverage gaps must be empty`);
    }
    content = {
      ...base,
      status,
      statusReason: parseStatusReason(result.statusReason, 'result.statusReason'),
    };
  } else {
    throw new TrustBenchmarkProtocolError('result.status is invalid');
  }

  const identity = parseHash(result.resultIdentity, 'result.resultIdentity');
  const expected = sha256(canonicalTrustBenchmarkToolResultContent(content));
  if (identity.digest !== expected) throw new TrustBenchmarkProtocolError('result identity mismatch');
  return attachTrustBenchmarkResultIdentity(content);
}
