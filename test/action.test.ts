import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { fixture } from './helpers.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const SCRIPT = path.join(ROOT, 'scripts', 'action-run.sh');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-action-'));

interface ActionRun {
  status: number;
  stdout: string;
  stderr: string;
  outputs: Record<string, string>;
  summary: string;
}

function runAction(env: Record<string, string>): ActionRun {
  const scratch = fs.mkdtempSync(path.join(base, 'run-'));
  const githubOutput = path.join(scratch, 'output.txt');
  const stepSummary = path.join(scratch, 'summary.md');
  fs.writeFileSync(githubOutput, '');
  fs.writeFileSync(stepSummary, '');
  const fullEnv = {
    ...process.env,
    CASEFILE_COMMAND: `node ${CLI}`,
    CASEFILE_OUTPUT_DIR: path.join(scratch, 'reports'),
    GITHUB_OUTPUT: githubOutput,
    GITHUB_STEP_SUMMARY: stepSummary,
    ...env,
  };
  let status = 0;
  let stdout = '';
  let stderr = '';
  try {
    stdout = execFileSync('bash', [SCRIPT], { encoding: 'utf-8', env: fullEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    const e = err as { status: number; stdout: string; stderr: string };
    status = e.status;
    stdout = e.stdout ?? '';
    stderr = e.stderr ?? '';
  }
  const outputs: Record<string, string> = {};
  for (const line of fs.readFileSync(githubOutput, 'utf-8').split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) outputs[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return { status, stdout, stderr, outputs, summary: fs.readFileSync(stepSummary, 'utf-8') };
}

afterAll(() => {
  fs.rmSync(base, { recursive: true, force: true });
});

describe.skipIf(process.platform === 'win32')('composite action runner', () => {
  it('declares the documented inputs and outputs in action.yml', () => {
    const yml = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf-8')) as { version: string };
    for (const input of ['path:', 'config:', 'version:', 'fail-on:', 'strict:', 'sarif:', 'lock:', 'upload-sarif:']) {
      expect(yml).toContain(`  ${input}`);
    }
    for (const output of ['exit-code:', 'report-json:', 'sarif:']) expect(yml).toContain(`  ${output}`);
    expect(yml).toContain(`default: ${pkg.version}`);
    expect(yml).toContain('using: composite');
    expect(yml).toContain('scripts/action-run.sh');
  });

  it('passes a benign skill, exposes report and SARIF paths, and summarizes counts', () => {
    const res = runAction({ CASEFILE_PATH: fixture('benign-skill') });
    expect(res.status).toBe(0);
    expect(res.outputs['exit-code']).toBe('0');
    const report = JSON.parse(fs.readFileSync(res.outputs['report-json'], 'utf-8'));
    expect(report.reportVersion).toBe(2);
    expect(report.policy.strict).toBe(true);
    const sarif = JSON.parse(fs.readFileSync(res.outputs.sarif, 'utf-8'));
    expect(sarif.version).toBe('2.1.0');
    expect(res.summary).toContain('## Casefile');
    expect(res.summary).toContain('| critical | 0 |');
    expect(res.summary).toContain('| warning | 0 |');
    expect(res.summary).toContain('**passed**');
    expect(res.summary).toContain('not verdicts');
  });

  it('maps a failed warning gate to exit 1 and lists top findings with file:line', () => {
    const res = runAction({ CASEFILE_PATH: fixture('malicious-plugin') });
    expect(res.status).toBe(1);
    expect(res.outputs['exit-code']).toBe('1');
    expect(fs.existsSync(res.outputs['report-json'])).toBe(true);
    expect(fs.existsSync(res.outputs.sarif)).toBe(true);
    expect(res.summary).toContain('**failed**');
    expect(res.summary).toMatch(/\| critical \| [1-9]\d* \|/);
    expect(res.summary).toContain('### Top findings');
    expect(res.summary).toMatch(/`skills\/helper\/scripts\/setup\.sh:\d+`/);
    expect(res.summary).toContain('capability/pipe-to-shell');
  });

  it('honors fail-on none and sarif false', () => {
    const res = runAction({ CASEFILE_PATH: fixture('malicious-plugin'), CASEFILE_FAIL_ON: 'none', CASEFILE_SARIF: 'false' });
    expect(res.status).toBe(0);
    expect(res.outputs['exit-code']).toBe('0');
    expect(res.outputs.sarif).toBe('');
    expect(fs.existsSync(path.join(path.dirname(res.outputs['report-json']), 'casefile-report.sarif'))).toBe(false);
  });

  it('applies an operator policy through the config input', () => {
    const policy = path.join(base, 'policy.json');
    fs.writeFileSync(policy, JSON.stringify({ ignore: [{ ruleId: 'capability/network-call' }] }));
    const res = runAction({ CASEFILE_PATH: fixture('malicious-plugin'), CASEFILE_CONFIG: policy, CASEFILE_FAIL_ON: 'none' });
    expect(res.status).toBe(0);
    const report = JSON.parse(fs.readFileSync(res.outputs['report-json'], 'utf-8'));
    expect(report.policy.source).toBe('explicit');
    expect(report.summary.suppressed).toBeGreaterThan(0);
    expect(res.summary).toMatch(/\| suppressed \| [1-9]\d* \|/);
  });

  it('verifies a lock when given and fails on drift', () => {
    const artifact = path.join(base, 'locked-skill');
    fs.mkdirSync(artifact);
    fs.writeFileSync(
      path.join(artifact, 'SKILL.md'),
      '---\nname: locked-skill\ndescription: a skill used to test the composite action lock verification path\n---\n\nBody.\n',
    );
    const lock = path.join(base, 'locked-skill.casefile-lock.json');
    execFileSync('node', [CLI, 'lock', artifact, '--strict', '--out', lock], { encoding: 'utf-8' });

    const exact = runAction({ CASEFILE_PATH: artifact, CASEFILE_LOCK: lock, CASEFILE_FAIL_ON: 'critical' });
    expect(exact.status).toBe(0);
    expect(exact.outputs['exit-code']).toBe('0');
    expect(exact.summary).toContain('**exact match**');

    fs.appendFileSync(path.join(artifact, 'SKILL.md'), 'Revised after approval.\n');
    const drift = runAction({ CASEFILE_PATH: artifact, CASEFILE_LOCK: lock, CASEFILE_FAIL_ON: 'critical' });
    expect(drift.status).toBe(1);
    expect(drift.outputs['exit-code']).toBe('1');
    expect(drift.summary).toContain('**drift detected**');
    expect(drift.summary).toContain('artifact changed');
    // The report itself still passed the gate: drift is what failed the run.
    expect(drift.summary).toContain('**passed**');

    const tampered = JSON.parse(fs.readFileSync(lock, 'utf-8'));
    tampered.reportIdentity.digest = '0'.repeat(64);
    fs.writeFileSync(lock, JSON.stringify(tampered));
    const invalid = runAction({ CASEFILE_PATH: artifact, CASEFILE_LOCK: lock, CASEFILE_FAIL_ON: 'critical' });
    expect(invalid.status).toBe(2);
    expect(invalid.outputs['exit-code']).toBe('2');
    expect(invalid.stderr).toContain('invalid lock');
    expect(invalid.summary).toContain('**verification failed**');
  });

  it('maps operational errors and invalid inputs to exit 2', () => {
    const unclassifiable = runAction({ CASEFILE_PATH: base });
    expect(unclassifiable.status).toBe(2);
    expect(unclassifiable.outputs['exit-code']).toBe('2');
    expect(unclassifiable.outputs['report-json']).toBe('');
    expect(unclassifiable.outputs.sarif).toBe('');
    expect(unclassifiable.summary).toContain('could not produce a report');

    const badGate = runAction({ CASEFILE_PATH: fixture('benign-skill'), CASEFILE_FAIL_ON: 'severe' });
    expect(badGate.status).toBe(2);
    expect(badGate.outputs['exit-code']).toBe('2');
    expect(badGate.stderr).toContain('fail-on must be');

    const noVersion = runAction({ CASEFILE_PATH: fixture('benign-skill'), CASEFILE_COMMAND: '', CASEFILE_VERSION: '' });
    expect(noVersion.status).toBe(2);
    expect(noVersion.stderr).toContain('version input is required');
  });
});
