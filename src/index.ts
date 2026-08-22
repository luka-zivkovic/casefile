export { scanArtifact } from './scan.js';
export type { ScanOptions } from './scan.js';
export { loadBenchmarkManifest, runBenchmark, BENCHMARK_VERSION } from './benchmark.js';
export type {
  BenchmarkArtifactResult,
  BenchmarkCase,
  BenchmarkManifest,
  BenchmarkMetrics,
  BenchmarkMutation,
  BenchmarkReport,
  BenchmarkThresholds,
  LoadedBenchmarkManifest,
} from './benchmark.js';
export {
  canonicalLockContent,
  createArtifactLock,
  createLock,
  LockValidationError,
  parseLock,
  validateLock,
  verifyArtifact,
  LOCK_VERSION,
} from './lock.js';
export type {
  CasefileLock,
  ChangedFinding,
  FindingDisposition,
  FindingEvidence,
  LockDrift,
  LockPolicy,
  LockScanOptions,
  LockVerification,
} from './lock.js';
export { discover, DiscoveryError } from './discover.js';
export { parseFrontmatter, FrontmatterError } from './frontmatter.js';
export { loadConfig, isIgnored, CONFIG_FILENAME } from './config.js';
export type { IgnoreRule, CasefileConfig, LoadConfigOptions } from './config.js';
export {
  buildReport,
  canonicalizeFinding,
  canonicalReportContent,
  renderMarkdown,
  sanitizeText,
  REPORT_VERSION,
  TOOL_VERSION,
} from './report.js';
export { ReportStore, defaultDbPath } from './store.js';
export { atomicWriteText, validateExternalDestination } from './output.js';
export type { SafeDestination } from './output.js';
export { renderSarif, toSarif, SARIF_SCHEMA, SARIF_VERSION } from './sarif.js';
export type { SarifLevel, SarifLog, SarifResult, SarifRule, SarifRun } from './sarif.js';
export type {
  Artifact,
  ArtifactType,
  Finding,
  Report,
  ReportIdentity,
  ReportPolicy,
  ReportSummary,
  Severity,
} from './types.js';
export {
  attachTrustBenchmarkResultIdentity,
  canonicalTrustBenchmarkToolResultContent,
  CASEFILE_BENCHMARK_ADAPTER_VERSION,
  decodeTrustBenchmarkAdapterRequest,
  decodeTrustBenchmarkToolResult,
  isSafeArtifactRelativePath,
  parseJsonRejectingDuplicateKeys,
  parseTrustBenchmarkAdapterRequest,
  TRUST_BENCHMARK_PROTOCOL_VERSION,
  TrustBenchmarkProtocolError,
  validateTrustBenchmarkToolResult,
} from './trust-benchmark-protocol.js';
export type {
  TrustBenchmarkAdapterRequest,
  TrustBenchmarkCompletedResult,
  TrustBenchmarkCoverageGap,
  TrustBenchmarkDisposition,
  TrustBenchmarkErrorResult,
  TrustBenchmarkFinding,
  TrustBenchmarkIncompleteResult,
  TrustBenchmarkResultStatus,
  TrustBenchmarkStatusReason,
  TrustBenchmarkToolResult,
  TrustBenchmarkToolResultContent,
  TrustBenchmarkTrack,
  TrustBenchmarkUnsupportedResult,
} from './trust-benchmark-protocol.js';
export { adaptCasefileReport, runCasefileBenchmarkAdapter } from './trust-benchmark-adapter.js';
export {
  loadQualificationManifest,
  materializeQualificationCase,
  QUALIFICATION_VERSION,
  validateQualificationManifest,
} from './trust-benchmark-qualification.js';
export type {
  LoadedQualificationManifest,
  QualificationCase,
  QualificationClassificationCase,
  QualificationExpected,
  QualificationGeneratedFile,
  QualificationManifest,
  QualificationStatusCase,
} from './trust-benchmark-qualification.js';
