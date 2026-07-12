import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { scanArtifact } from '../src/scan.js';
import type { Finding, Report } from '../src/types.js';
import { fixture, rm, stageFixture } from './helpers.js';

function ids(findings: Finding[]): Set<string> {
  return new Set(findings.map((f) => f.ruleId));
}

describe('benign skill', () => {
  const report = scanArtifact(fixture('benign-skill'));

  it('classifies as a skill', () => {
    expect(report.artifact.type).toBe('skill');
  });

  it('produces no critical findings', () => {
    expect(report.summary.critical).toBe(0);
  });

  it('resolves its referenced resources', () => {
    expect(ids(report.findings).has('resources/missing-resource')).toBe(false);
  });
});

describe('malicious plugin', () => {
  let staged: string;
  let report: Report;

  // Stage a copy and add an escaping symlink that cannot be committed to git.
  staged = stageFixture('malicious-plugin');
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-outside-'));
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'top secret\n');
  fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(staged, 'skills', 'helper', 'link-to-secret'));
  report = scanArtifact(staged);
  const found = ids(report.findings);

  afterAll(() => {
    rm(staged);
    rm(outside);
  });

  it('classifies as a plugin', () => {
    expect(report.artifact.type).toBe('plugin');
  });

  it('flags prompt-injection phrases', () => {
    expect(found.has('injection/phrase')).toBe(true);
  });

  it('flags an HTML comment imperative', () => {
    expect(found.has('injection/html-comment-imperative')).toBe(true);
  });

  it('flags model-addressed concealment in a reference file', () => {
    expect(found.has('injection/model-addressed')).toBe(true);
  });

  it('flags zero-width and bidi unicode', () => {
    expect(found.has('injection/zero-width-unicode')).toBe(true);
    expect(found.has('injection/bidi-control')).toBe(true);
  });

  it('flags curl|sh pipe-to-shell as critical', () => {
    const pipe = report.findings.find((f) => f.ruleId === 'capability/pipe-to-shell');
    expect(pipe?.severity).toBe('critical');
  });

  it('flags eval of downloaded content', () => {
    expect(found.has('capability/eval-download')).toBe(true);
  });

  it('flags secret env-var reads', () => {
    expect(found.has('capability/secret-env-read')).toBe(true);
  });

  it('flags network calls', () => {
    expect(found.has('capability/network-call')).toBe(true);
  });

  it('flags rm -rf and destructive delete of root', () => {
    expect(found.has('capability/rm-rf') || found.has('capability/destructive-delete')).toBe(true);
    expect(found.has('capability/destructive-delete')).toBe(true);
  });

  it('flags writes outside the artifact directory', () => {
    expect(found.has('capability/write-outside-artifact')).toBe(true);
  });

  it('flags a hook that runs a shell command', () => {
    expect(found.has('capability/hook-shell-command')).toBe(true);
  });

  it('flags broad allowed-tools', () => {
    expect(found.has('capability/broad-tools')).toBe(true);
  });

  it('flags an encoded blob', () => {
    expect(found.has('supplychain/encoded-blob')).toBe(true);
  });

  it('flags a symlink escaping the artifact directory as critical', () => {
    const esc = report.findings.find((f) => f.ruleId === 'supplychain/symlink-escape');
    expect(esc?.severity).toBe('critical');
  });

  it('has multiple critical findings overall', () => {
    expect(report.summary.critical).toBeGreaterThan(2);
  });
});

describe('structural checks', () => {
  it('flags a missing SKILL.md', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-empty-'));
    fs.mkdirSync(path.join(dir, '.claude-plugin'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude-plugin', 'plugin.json'), '{"name":"x","version":"1.0.0"}');
    const report = scanArtifact(dir);
    expect(report.artifact.type).toBe('plugin');
    // no skills: warns rather than crashes
    expect(ids(report.findings).has('structural/no-skills')).toBe(true);
    rm(dir);
  });

  it('flags invalid plugin.json as critical', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-badjson-'));
    fs.mkdirSync(path.join(dir, '.claude-plugin'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude-plugin', 'plugin.json'), '{ not json');
    const report = scanArtifact(dir);
    const f = report.findings.find((x) => x.ruleId === 'structural/plugin-json-invalid');
    expect(f?.severity).toBe('critical');
    rm(dir);
  });

  it('flags a missing referenced resource as critical', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-res-'));
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      '---\nname: res\ndescription: a skill referencing a resource that does not exist for testing\n---\n\nSee references/missing.md for details.\n',
    );
    const report = scanArtifact(dir);
    const f = report.findings.find((x) => x.ruleId === 'resources/missing-resource');
    expect(f?.severity).toBe('critical');
    rm(dir);
  });
});
