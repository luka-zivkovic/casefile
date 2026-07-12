import type { Artifact, Finding, Report, Severity } from './types.js';

export const TOOL_NAME = 'skillguard';
export const TOOL_VERSION = '0.1.0';
export const REPORT_VERSION = 1 as const;

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

export function buildReport(artifact: Artifact, findings: Finding[], filesScanned: number): Report {
  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.ruleId.localeCompare(b.ruleId) ||
      (a.line ?? 0) - (b.line ?? 0),
  );
  const count = (s: Severity) => sorted.filter((f) => f.severity === s).length;
  return {
    reportVersion: REPORT_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scannedAt: new Date().toISOString(),
    artifact,
    findings: sorted,
    summary: {
      critical: count('critical'),
      warning: count('warning'),
      info: count('info'),
      total: sorted.length,
      filesScanned,
    },
  };
}

const BADGE: Record<Severity, string> = {
  critical: 'CRITICAL',
  warning: 'WARNING ',
  info: 'INFO    ',
};

/** Human-readable rendering (used for both terminal output and --out markdown). */
export function renderMarkdown(report: Report): string {
  const { artifact, summary } = report;
  const lines: string[] = [];
  lines.push(`# skillguard report — ${artifact.path}`);
  lines.push('');
  lines.push(`- Artifact type: ${artifact.type}`);
  lines.push(`- Content hash: sha256:${artifact.contentHash}`);
  lines.push(`- Scanned at: ${report.scannedAt} (skillguard v${report.tool.version}, report v${report.reportVersion})`);
  lines.push(`- Files scanned: ${summary.filesScanned}`);
  lines.push('');
  lines.push(
    `**${summary.total} finding(s): ${summary.critical} critical, ${summary.warning} warning, ${summary.info} info**`,
  );
  if (report.findings.length > 0) {
    lines.push('');
    for (const f of report.findings) {
      const loc = f.line !== undefined ? `${f.file}:${f.line}` : f.file;
      lines.push(`- [${BADGE[f.severity].trim()}] ${f.ruleId} — ${f.message} (${loc})`);
    }
  } else {
    lines.push('');
    lines.push('No findings. This is a static scan only: it cannot prove behavioral safety.');
  }
  lines.push('');
  lines.push(
    '_Static analysis only — behavioral verification (M1) requires sandboxed execution and is out of scope for this report._',
  );
  return lines.join('\n');
}
