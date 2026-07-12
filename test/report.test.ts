import { describe, expect, it } from 'vitest';
import { buildReport, renderMarkdown } from '../src/report.js';
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
    expect(report.reportVersion).toBe(1);
    expect(report.tool.name).toBe('skillguard');
    expect(report.artifact).toEqual(artifact);
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
