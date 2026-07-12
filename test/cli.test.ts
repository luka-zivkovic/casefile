import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { fixture } from './helpers.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');
const tmpDb = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-cli-')), 'store.db');

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

function run(args: string[]): RunResult {
  try {
    const stdout = execFileSync('node', [CLI, ...args], { encoding: 'utf-8' });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as { status: number; stdout: string; stderr: string };
    return { status: e.status, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

afterAll(() => {
  fs.rmSync(path.dirname(tmpDb), { recursive: true, force: true });
});

describe('skillguard CLI', () => {
  it('scans a benign skill and exits 0 with JSON', () => {
    const res = run(['scan', fixture('benign-skill'), '--json', '--db', tmpDb]);
    expect(res.status).toBe(0);
    const report = JSON.parse(res.stdout);
    expect(report.reportVersion).toBe(1);
    expect(report.summary.critical).toBe(0);
  });

  it('exits 1 on the malicious plugin with default --fail-on critical', () => {
    const res = run(['scan', fixture('malicious-plugin'), '--db', tmpDb]);
    expect(res.status).toBe(1);
    expect(res.stdout).toContain('CRITICAL');
  });

  it('exits 0 on the malicious plugin with --fail-on none', () => {
    const res = run(['scan', fixture('malicious-plugin'), '--fail-on', 'none', '--db', tmpDb]);
    expect(res.status).toBe(0);
  });

  it('exits 2 on an unclassifiable path', () => {
    const res = run(['scan', os.tmpdir(), '--no-store']);
    expect(res.status).toBe(2);
    expect(res.stderr).toContain('cannot classify');
  });

  it('writes the report to --out', () => {
    const out = path.join(path.dirname(tmpDb), 'report.md');
    run(['scan', fixture('benign-skill'), '--out', out, '--db', tmpDb]);
    expect(fs.readFileSync(out, 'utf-8')).toContain('skillguard report');
  });

  it('excludes suppressed findings from exit-code evaluation but lists them', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-suppress-'));
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      '---\nname: sup\ndescription: a skill with a suppressed missing-resource critical finding\n---\n\nSee references/missing.md for details.\n',
    );
    // Without a config the missing resource is critical -> exit 1.
    expect(run(['scan', dir, '--db', tmpDb]).status).toBe(1);
    fs.writeFileSync(
      path.join(dir, 'skillguard.config.json'),
      JSON.stringify({ ignore: [{ ruleId: 'resources/missing-resource' }] }),
    );
    const res = run(['scan', dir, '--json', '--db', tmpDb]);
    expect(res.status).toBe(0);
    const report = JSON.parse(res.stdout);
    expect(report.summary.critical).toBe(0);
    expect(report.suppressed.some((f: { ruleId: string }) => f.ruleId === 'resources/missing-resource')).toBe(true);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('records and lists scan history', () => {
    run(['scan', fixture('benign-skill'), '--db', tmpDb]);
    const res = run(['history', fixture('benign-skill'), '--db', tmpDb, '--json']);
    expect(res.status).toBe(0);
    const rows = JSON.parse(res.stdout);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].artifactType).toBe('skill');
  });
});
