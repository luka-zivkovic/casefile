import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { decodeUtf8Fatal } from './io.js';
import {
  isSafeArtifactRelativePath,
  parseJsonRejectingDuplicateKeys,
  TRUST_BENCHMARK_PROTOCOL_VERSION,
  TrustBenchmarkProtocolError,
  type TrustBenchmarkDisposition,
  type TrustBenchmarkResultStatus,
  type TrustBenchmarkTrack,
} from './trust-benchmark-protocol.js';

export const QUALIFICATION_VERSION = 1 as const;

export interface QualificationExpected {
  status: TrustBenchmarkResultStatus;
  disposition?: TrustBenchmarkDisposition;
  requiredRuleIds: string[];
  requiredCoverageGapRuleIds: string[];
}

export interface QualificationGeneratedFile {
  path: string;
  byte: number;
  length: number;
}

interface QualificationCaseBase {
  caseId: string;
  track: TrustBenchmarkTrack;
  description: string;
  files: Record<string, string>;
  generatedFiles: QualificationGeneratedFile[];
  expected: QualificationExpected;
}

export interface QualificationClassificationCase extends QualificationCaseBase {
  purpose: 'classification';
  truth: 'positive' | 'negative';
}

export interface QualificationStatusCase extends QualificationCaseBase {
  purpose: 'status';
  truth?: never;
}

export type QualificationCase = QualificationClassificationCase | QualificationStatusCase;

export interface QualificationManifest {
  qualificationVersion: 1;
  protocolVersion: 1;
  name: 'casefile-public-adapter-qualification-v1';
  exposureRole: 'public-qualification';
  claimScope: string;
  performanceClaimsAllowed: false;
  ontology: { version: 1; positive: string; negative: string; statusOnly: string };
  cases: QualificationCase[];
}

export interface LoadedQualificationManifest {
  manifest: QualificationManifest;
  /** SHA-256 of exact raw manifest bytes, before UTF-8 decode or JSON parse. */
  digest: string;
}

function sha256(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex');
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

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) throw new TrustBenchmarkProtocolError(`${label} must be an array`);
  const result = value.map((entry, index) => string(entry, `${label}[${index}]`));
  if (new Set(result).size !== result.length) throw new TrustBenchmarkProtocolError(`${label} must be unique`);
  return result;
}

function track(value: unknown, label: string): TrustBenchmarkTrack {
  if (value !== 'common-static-skill' && value !== 'breadth') {
    throw new TrustBenchmarkProtocolError(`${label} is unsupported`);
  }
  return value;
}

function safePath(value: unknown, label: string): string {
  const relative = string(value, label);
  if (relative === '.' || !isSafeArtifactRelativePath(relative)) {
    throw new TrustBenchmarkProtocolError(`${label} must name a file below the artifact root`);
  }
  return relative;
}

function parseFiles(value: unknown, label: string): Record<string, string> {
  const input = record(value, label);
  const files: Record<string, string> = {};
  for (const [relative, content] of Object.entries(input)) {
    const checked = safePath(relative, `${label} path`);
    if (typeof content !== 'string') throw new TrustBenchmarkProtocolError(`${label}.${relative} must be a string`);
    files[checked] = content;
  }
  return files;
}

function parseExpected(value: unknown, label: string): QualificationExpected {
  const expected = record(value, label);
  keys(expected, ['status', 'requiredRuleIds', 'requiredCoverageGapRuleIds'], ['disposition'], label);
  const status = expected.status;
  if (status !== 'completed' && status !== 'unsupported' && status !== 'incomplete' && status !== 'error') {
    throw new TrustBenchmarkProtocolError(`${label}.status is invalid`);
  }
  if (status === 'completed') {
    if (expected.disposition !== 'flag' && expected.disposition !== 'clean') {
      throw new TrustBenchmarkProtocolError(`${label}.disposition is required for completed status`);
    }
  } else if (expected.disposition !== undefined) {
    throw new TrustBenchmarkProtocolError(`${label}.disposition is allowed only for completed status`);
  }
  return {
    status,
    ...(status === 'completed' ? { disposition: expected.disposition as TrustBenchmarkDisposition } : {}),
    requiredRuleIds: stringArray(expected.requiredRuleIds, `${label}.requiredRuleIds`),
    requiredCoverageGapRuleIds: stringArray(
      expected.requiredCoverageGapRuleIds,
      `${label}.requiredCoverageGapRuleIds`,
    ),
  };
}

function parseCase(value: unknown, index: number): QualificationCase {
  const label = `qualification.cases[${index}]`;
  const input = record(value, label);
  keys(
    input,
    ['caseId', 'purpose', 'track', 'description', 'files', 'generatedFiles', 'expected'],
    ['truth'],
    label,
  );
  const caseId = string(input.caseId, `${label}.caseId`);
  if (!/^[a-z0-9][a-z0-9-]{0,127}$/.test(caseId)) {
    throw new TrustBenchmarkProtocolError(`${label}.caseId is invalid`);
  }
  if (!Array.isArray(input.generatedFiles)) {
    throw new TrustBenchmarkProtocolError(`${label}.generatedFiles must be an array`);
  }
  const generatedFiles = input.generatedFiles.map((entry, generatedIndex) => {
    const generatedLabel = `${label}.generatedFiles[${generatedIndex}]`;
    const generated = record(entry, generatedLabel);
    keys(generated, ['path', 'byte', 'length'], [], generatedLabel);
    if (!Number.isInteger(generated.byte) || (generated.byte as number) < 1 || (generated.byte as number) > 255) {
      throw new TrustBenchmarkProtocolError(`${generatedLabel}.byte must be an integer from 1 to 255`);
    }
    if (
      !Number.isInteger(generated.length) ||
      (generated.length as number) < 1 ||
      (generated.length as number) > 6 * 1024 * 1024
    ) {
      throw new TrustBenchmarkProtocolError(`${generatedLabel}.length must be from 1 to 6291456`);
    }
    return {
      path: safePath(generated.path, `${generatedLabel}.path`),
      byte: generated.byte as number,
      length: generated.length as number,
    };
  });
  const base: QualificationCaseBase = {
    caseId,
    track: track(input.track, `${label}.track`),
    description: string(input.description, `${label}.description`),
    files: parseFiles(input.files, `${label}.files`),
    generatedFiles,
    expected: parseExpected(input.expected, `${label}.expected`),
  };
  const destinations = [...Object.keys(base.files), ...generatedFiles.map((generated) => generated.path)];
  if (new Set(destinations).size !== destinations.length) {
    throw new TrustBenchmarkProtocolError(`${label} has duplicate materialization paths`);
  }
  if (input.purpose === 'classification') {
    if (input.truth !== 'positive' && input.truth !== 'negative') {
      throw new TrustBenchmarkProtocolError(`${label}.truth is required for a classification fixture`);
    }
    if (base.expected.status !== 'completed') {
      throw new TrustBenchmarkProtocolError(`${label} classification fixtures must complete`);
    }
    if (input.truth === 'positive' && base.expected.disposition !== 'flag') {
      throw new TrustBenchmarkProtocolError(`${label} positive fixture must expect flag`);
    }
    if (input.truth === 'negative' && base.expected.disposition !== 'clean') {
      throw new TrustBenchmarkProtocolError(`${label} negative fixture must expect clean`);
    }
    return { ...base, purpose: 'classification', truth: input.truth };
  }
  if (input.purpose === 'status') {
    if (input.truth !== undefined) throw new TrustBenchmarkProtocolError(`${label}.truth is not allowed for status fixtures`);
    return { ...base, purpose: 'status' };
  }
  throw new TrustBenchmarkProtocolError(`${label}.purpose is invalid`);
}

export function validateQualificationManifest(value: unknown): QualificationManifest {
  const input = record(value, 'qualification');
  keys(
    input,
    [
      'qualificationVersion',
      'protocolVersion',
      'name',
      'exposureRole',
      'claimScope',
      'performanceClaimsAllowed',
      'ontology',
      'cases',
    ],
    [],
    'qualification',
  );
  if (input.qualificationVersion !== QUALIFICATION_VERSION) {
    throw new TrustBenchmarkProtocolError('qualification.qualificationVersion is unsupported');
  }
  if (input.protocolVersion !== TRUST_BENCHMARK_PROTOCOL_VERSION) {
    throw new TrustBenchmarkProtocolError('qualification.protocolVersion is unsupported');
  }
  if (input.name !== 'casefile-public-adapter-qualification-v1') {
    throw new TrustBenchmarkProtocolError('qualification.name is unsupported');
  }
  if (input.exposureRole !== 'public-qualification' || input.performanceClaimsAllowed !== false) {
    throw new TrustBenchmarkProtocolError('qualification must be public and forbid performance claims');
  }
  const ontology = record(input.ontology, 'qualification.ontology');
  keys(ontology, ['version', 'positive', 'negative', 'statusOnly'], [], 'qualification.ontology');
  if (ontology.version !== 1) throw new TrustBenchmarkProtocolError('qualification ontology version is unsupported');
  if (!Array.isArray(input.cases)) throw new TrustBenchmarkProtocolError('qualification.cases must be an array');
  const cases = input.cases.map(parseCase);
  const caseIds = cases.map((entry) => entry.caseId);
  if (new Set(caseIds).size !== caseIds.length) {
    throw new TrustBenchmarkProtocolError('qualification case ids must be unique');
  }
  if (!cases.some((entry) => entry.purpose === 'classification' && entry.truth === 'positive')) {
    throw new TrustBenchmarkProtocolError('qualification requires a positive classification fixture');
  }
  if (!cases.some((entry) => entry.purpose === 'classification' && entry.truth === 'negative')) {
    throw new TrustBenchmarkProtocolError('qualification requires a negative classification fixture');
  }
  if (!cases.some((entry) => entry.expected.status === 'incomplete')) {
    throw new TrustBenchmarkProtocolError('qualification requires an incomplete status fixture');
  }
  if (!cases.some((entry) => entry.expected.status === 'unsupported')) {
    throw new TrustBenchmarkProtocolError('qualification requires an unsupported status fixture');
  }
  return {
    qualificationVersion: QUALIFICATION_VERSION,
    protocolVersion: TRUST_BENCHMARK_PROTOCOL_VERSION,
    name: 'casefile-public-adapter-qualification-v1',
    exposureRole: 'public-qualification',
    claimScope: string(input.claimScope, 'qualification.claimScope'),
    performanceClaimsAllowed: false,
    ontology: {
      version: 1,
      positive: string(ontology.positive, 'qualification.ontology.positive'),
      negative: string(ontology.negative, 'qualification.ontology.negative'),
      statusOnly: string(ontology.statusOnly, 'qualification.ontology.statusOnly'),
    },
    cases,
  };
}

export function loadQualificationManifest(file: string): LoadedQualificationManifest {
  const raw = fs.readFileSync(path.resolve(file));
  let text: string;
  try {
    text = decodeUtf8Fatal(raw, 'qualification manifest');
  } catch {
    throw new TrustBenchmarkProtocolError('qualification manifest is not valid UTF-8');
  }
  const parsed = parseJsonRejectingDuplicateKeys(text, 'qualification manifest');
  return { manifest: validateQualificationManifest(parsed), digest: sha256(raw) };
}

/** Materialize one reviewed synthetic fixture below a caller-owned existing directory. */
export function materializeQualificationCase(fixture: QualificationCase, parent: string): string {
  const realParent = fs.realpathSync(parent);
  const root = path.join(realParent, fixture.caseId);
  if (fs.existsSync(root)) throw new TrustBenchmarkProtocolError(`qualification destination already exists: ${fixture.caseId}`);
  fs.mkdirSync(root);
  const write = (relative: string, content: string | Buffer): void => {
    if (!isSafeArtifactRelativePath(relative) || relative === '.') {
      throw new TrustBenchmarkProtocolError(`qualification path is unsafe: ${relative}`);
    }
    const destination = path.resolve(root, ...relative.split('/'));
    if (!destination.startsWith(`${root}${path.sep}`)) {
      throw new TrustBenchmarkProtocolError(`qualification path escapes fixture root: ${relative}`);
    }
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    let current = path.dirname(destination);
    while (current !== root) {
      if (fs.lstatSync(current).isSymbolicLink()) {
        throw new TrustBenchmarkProtocolError(`qualification destination has a symlink parent: ${relative}`);
      }
      current = path.dirname(current);
    }
    fs.writeFileSync(destination, content);
  };
  for (const relative of Object.keys(fixture.files).sort()) write(relative, fixture.files[relative]);
  for (const generated of [...fixture.generatedFiles].sort((a, b) => a.path.localeCompare(b.path))) {
    write(generated.path, Buffer.alloc(generated.length, generated.byte));
  }
  return root;
}
