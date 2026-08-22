import { createHash } from 'node:crypto';
import type { Artifact, Finding, Report, ReportPolicy, Severity } from './types.js';

export const TOOL_NAME = 'casefile';
export const TOOL_VERSION = '0.1.0';
export const REPORT_VERSION = 2 as const;

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

/** ANSI/VT escape sequences (CSI like `ESC[31m` plus two-char `ESC X` forms). */
const ANSI_ESCAPES = /\u001B\[[0-9;?]*[ -\/]*[@-~]|\u001B[@-_]/g;
/** Remaining C0 control chars and DEL (after newlines/tabs were collapsed). */
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/g;

function compareText(a: string, b: string): number {
  return a === b ? 0 : a < b ? -1 : 1;
}

/**
 * Sanitize untrusted text (finding messages quote artifact content verbatim)
 * so it cannot forge report lines or emit terminal escape sequences:
 * newlines/tabs collapse to a single space, ANSI escapes and other control
 * characters are stripped.
 */
export function sanitizeText(text: string): string {
  return text.replace(ANSI_ESCAPES, '').replace(/[\r\n\t]+/g, ' ').replace(CONTROL_CHARS, '');
}

function sanitizeFinding(f: Finding): Finding {
  return { ...f, message: sanitizeText(f.message), file: sanitizeText(f.file) };
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      compareText(a.file, b.file) ||
      compareText(a.ruleId, b.ruleId) ||
      (a.line ?? 0) - (b.line ?? 0) ||
      compareText(a.message, b.message),
  );
}

/** Drop exact duplicates (several checks may emit the same hygiene finding). */
function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.ruleId}\0${f.severity}\0${f.file}\0${f.line ?? ''}\0${f.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function withoutAbsoluteRoot(text: string, root: string): string {
  const roots = new Set([root, root.split('\\').join('/'), root.split('/').join('\\')]);
  let canonical = text;
  for (const candidate of roots) {
    if (candidate !== '') canonical = canonical.split(candidate).join('<artifact-root>');
  }
  return canonical;
}

export function canonicalizeFinding(f: Finding, artifactRoot: string): Finding {
  const base: Finding = {
    ruleId: f.ruleId,
    severity: f.severity,
    message: withoutAbsoluteRoot(f.message, artifactRoot),
    file: withoutAbsoluteRoot(f.file, artifactRoot),
  };
  if (f.line !== undefined) base.line = f.line;
  return base;
}

/**
 * Stable report statement for future lockfiles and signatures. Presentation
 * metadata (`scannedAt`, absolute `artifact.path`) is deliberately excluded;
 * all paths that remain are finding paths relative to the artifact root.
 */
export function canonicalReportContent(report: Omit<Report, 'identity'> | Report): string {
  const canonical = {
    schema: 'casefile-report-identity/v1',
    reportVersion: report.reportVersion,
    tool: { name: report.tool.name, version: report.tool.version },
    artifact: { type: report.artifact.type, contentHash: report.artifact.contentHash },
    policy:
      report.policy.contentHash === undefined
        ? { source: report.policy.source, strict: report.policy.strict }
        : { source: report.policy.source, strict: report.policy.strict, contentHash: report.policy.contentHash },
    findings: report.findings.map((f) => canonicalizeFinding(f, report.artifact.path)),
    suppressed: report.suppressed.map((f) => canonicalizeFinding(f, report.artifact.path)),
    summary: {
      critical: report.summary.critical,
      warning: report.summary.warning,
      info: report.summary.info,
      total: report.summary.total,
      suppressed: report.summary.suppressed,
      filesScanned: report.summary.filesScanned,
    },
  };
  return JSON.stringify(canonical);
}

export function buildReport(
  artifact: Artifact,
  findings: Finding[],
  filesScanned: number,
  suppressed: Finding[] = [],
  policy: ReportPolicy = { source: 'none', strict: false },
): Report {
  const sorted = sortFindings(dedupe(findings.map(sanitizeFinding)));
  const sortedSuppressed = sortFindings(dedupe(suppressed.map(sanitizeFinding)));
  const count = (s: Severity) => sorted.filter((f) => f.severity === s).length;
  const reportWithoutIdentity: Omit<Report, 'identity'> = {
    reportVersion: REPORT_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scannedAt: new Date().toISOString(),
    artifact,
    policy,
    findings: sorted,
    suppressed: sortedSuppressed,
    summary: {
      critical: count('critical'),
      warning: count('warning'),
      info: count('info'),
      total: sorted.length,
      suppressed: sortedSuppressed.length,
      filesScanned,
    },
  };
  const digest = createHash('sha256').update(canonicalReportContent(reportWithoutIdentity)).digest('hex');
  return { ...reportWithoutIdentity, identity: { algorithm: 'sha256', digest } };
}

const BADGE: Record<Severity, string> = {
  critical: 'CRITICAL',
  warning: 'WARNING ',
  info: 'INFO    ',
};

function findingLine(f: Finding): string {
  const loc = f.line !== undefined ? `${f.file}:${f.line}` : f.file;
  return `- [${BADGE[f.severity].trim()}] ${f.ruleId} — ${sanitizeText(f.message)} (${loc})`;
}

/** Human-readable rendering (used for both terminal output and --out markdown). */
export function renderMarkdown(report: Report): string {
  const { artifact, summary } = report;
  const lines: string[] = [];
  lines.push(`# casefile report — ${artifact.path}`);
  lines.push('');
  lines.push(`- Artifact type: ${artifact.type}`);
  lines.push(`- Content hash: sha256:${artifact.contentHash}`);
  lines.push(`- Report identity: sha256:${report.identity.digest}`);
  lines.push(
    report.policy.contentHash === undefined
      ? `- Scan policy: ${report.policy.source}, strict=${report.policy.strict}`
      : `- Scan policy: ${report.policy.source}, strict=${report.policy.strict} (sha256:${report.policy.contentHash})`,
  );
  lines.push(`- Scanned at: ${report.scannedAt} (casefile v${report.tool.version}, report v${report.reportVersion})`);
  lines.push(`- Files scanned: ${summary.filesScanned}`);
  lines.push('');
  lines.push(
    `**${summary.total} finding(s): ${summary.critical} critical, ${summary.warning} warning, ${summary.info} info**`,
  );
  if (report.findings.length > 0) {
    lines.push('');
    for (const f of report.findings) lines.push(findingLine(f));
  } else {
    lines.push('');
    lines.push('No findings. This is a static scan only: it cannot prove behavioral safety.');
  }
  if (report.suppressed.length > 0) {
    lines.push('');
    lines.push(
      `**${report.suppressed.length} suppressed finding(s)** (matched by trusted policy; excluded from exit-code evaluation):`,
    );
    for (const f of report.suppressed) lines.push(`  ${findingLine(f)}`);
  }
  lines.push('');
  lines.push(
    '_Static analysis only: absence of findings is not proof of behavioral safety._',
  );
  return lines.join('\n');
}
