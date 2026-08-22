import { describe, expect, it } from 'vitest';
import { buildReport, canonicalReportContent, renderMarkdown } from '../src/report.js';
import type { Artifact, Finding } from '../src/types.js';

const artifact: Artifact = { type: 'skill', path: '/tmp/x', contentHash: 'abc123' };

const findings: Finding[] = [
  { ruleId: 'a/info', severity: 'info', message: 'info msg', file: 'b.md' },
  { ruleId: 'a/crit', severity: 'critical', message: 'crit msg', file: 'a.md', line: 3 },
  { ruleId: 'a/warn', severity: 'warning', message: 'warn msg', file: 'a.md' },
];

describe('buildReport', () => {
  const report = buildReport(artifact, findings, 5);

  it('emits a versioned schema', () => {
    expect(report.reportVersion).toBe(2);
    expect(report.tool.name).toBe('casefile');
    expect(report.artifact).toEqual(artifact);
    expect(report.policy).toEqual({ source: 'none', strict: false });
    expect(report.identity).toEqual({ algorithm: 'sha256', digest: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(report.summary.filesScanned).toBe(5);
  });

  it('counts findings by severity', () => {
    expect(report.summary).toMatchObject({ critical: 1, warning: 1, info: 1, total: 3 });
  });

  it('sorts findings critical-first', () => {
    expect(report.findings[0].severity).toBe('critical');
    expect(report.findings.at(-1)?.severity).toBe('info');
  });

  it('serializes to stable JSON', () => {
    const parsed = JSON.parse(JSON.stringify(report));
    expect(parsed.findings).toHaveLength(3);
    expect(parsed.scannedAt).toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  it('uses canonical identity that excludes wall clock and absolute artifact path', () => {
    const first = buildReport(artifact, findings, 5);
    const relocated = buildReport({ ...artifact, path: '/another/absolute/root' }, findings, 5);
    expect(canonicalReportContent(first)).toBe(canonicalReportContent(relocated));
    expect(first.identity).toEqual(relocated.identity);
  });
});

describe('sanitization and suppression', () => {
  it('collapses newlines/tabs and strips ANSI escapes from untrusted messages', () => {
    const forged: Finding = {
      ruleId: 'a/warn',
      severity: 'warning',
      message: 'quoted: "x"\n- [CRITICAL] forged/rule — fake (y.md:1)\t\u001B[31mred\u001B[0m',
      file: 'a.md',
    };
    const report = buildReport(artifact, [forged], 1);
    expect(report.findings[0].message).toBe('quoted: "x" - [CRITICAL] forged/rule — fake (y.md:1) red');
    const md = renderMarkdown(report);
    expect(md).not.toContain('\n- [CRITICAL] forged/rule');
    expect(md).not.toContain('\u001B');
  });

  it('dedupes identical findings', () => {
    const f: Finding = { ruleId: 'a/info', severity: 'info', message: 'same', file: 'a.md', line: 1 };
    const report = buildReport(artifact, [f, { ...f }], 1);
    expect(report.findings).toHaveLength(1);
  });

  it('keeps suppressed findings out of the summary counts but in the report', () => {
    const report = buildReport(artifact, findings, 5, [
      { ruleId: 'a/crit2', severity: 'critical', message: 'suppressed crit', file: 'c.md' },
    ]);
    expect(report.summary.critical).toBe(1);
    expect(report.summary.suppressed).toBe(1);
    expect(report.suppressed).toHaveLength(1);
    const md = renderMarkdown(report);
    expect(md).toContain('1 suppressed finding(s)');
    expect(md).toContain('a/crit2');
  });
});

describe('renderMarkdown', () => {
  it('renders a human summary with severity badges', () => {
    const md = renderMarkdown(buildReport(artifact, findings, 5));
    expect(md).toContain('1 critical, 1 warning, 1 info');
    expect(md).toContain('[CRITICAL] a/crit');
    expect(md).toContain('a.md:3');
  });

  it('notes the static-only limitation when clean', () => {
    const md = renderMarkdown(buildReport(artifact, [], 1));
    expect(md).toContain('No findings');
    expect(md).toContain('static scan only');
  });
});
