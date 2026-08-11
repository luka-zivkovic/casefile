export { scanArtifact } from './scan.js';
export { discover, DiscoveryError } from './discover.js';
export { parseFrontmatter, FrontmatterError } from './frontmatter.js';
export { loadConfig, isIgnored, CONFIG_FILENAME } from './config.js';
export type { IgnoreRule, CasefileConfig } from './config.js';
export { buildReport, renderMarkdown, sanitizeText, REPORT_VERSION, TOOL_VERSION } from './report.js';
export { ReportStore, defaultDbPath } from './store.js';
export type { Artifact, ArtifactType, Finding, Report, ReportSummary, Severity } from './types.js';
