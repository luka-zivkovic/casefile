import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  canonicalLockContent,
  createArtifactLock,
  createLock,
  LockValidationError,
  parseLock,
  validateLock,
  verifyArtifact,
} from '../src/lock.js';
import { scanArtifact } from '../src/scan.js';

const cleanups: string[] = [];

const SKILL_MD =
  '---\nname: locked\ndescription: a skill used to exercise deterministic casefile evidence locks\n---\n\n## Guardrails\n\nDo not guess.\n';

function makeSkill(files: Record<string, string | Buffer> = {}, skillMd: string = SKILL_MD): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-lock-'));
  cleanups.push(dir);
  fs.writeFileSync(path.join(dir, 'SKILL.md'), skillMd);
  for (const [relative, content] of Object.entries(files)) {
    const absolute = path.join(dir, relative);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, content);
  }
  return dir;
}

afterEach(() => {
  for (const target of cleanups.splice(0)) fs.rmSync(target, { recursive: true, force: true });
});

describe('canonical evidence locks', () => {
  it('is byte-for-byte deterministic across repeated scans and relocated artifacts', () => {
    const firstRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-lock-root-a-'));
    const secondRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-lock-root-b-'));
    cleanups.push(firstRoot, secondRoot);
    const first = path.join(firstRoot, 'locked');
    const second = path.join(secondRoot, 'locked');
    fs.mkdirSync(path.join(first, 'scripts'), { recursive: true });
    fs.writeFileSync(path.join(first, 'SKILL.md'), SKILL_MD);
    fs.writeFileSync(path.join(first, 'scripts', 'z.sh'), '#!/bin/sh\ncurl https://example.com/z\n');
    fs.writeFileSync(path.join(first, 'scripts', 'a.sh'), '#!/bin/sh\necho ok\n');
    fs.cpSync(first, second, { recursive: true });

    const lock = createArtifactLock(first);
    const repeated = createArtifactLock(first);
    const relocated = createArtifactLock(second);
    expect(repeated).toEqual(lock);
    expect(relocated).toEqual(lock);
    expect(JSON.stringify(relocated, null, 2)).toBe(JSON.stringify(lock, null, 2));
    expect(JSON.stringify(lock)).not.toContain(first);
    expect(JSON.stringify(lock)).not.toContain(second);
    expect(verifyArtifact(first, lock).exact).toBe(true);
    expect(verifyArtifact(second, lock).exact).toBe(true);

    const reordered = structuredClone(lock);
    reordered.snapshot.activeFindings.reverse();
    expect(canonicalLockContent(reordered)).toBe(canonicalLockContent(lock));
    expect(validateLock(reordered).digest).toEqual(lock.digest);
  });

  it('pins every byte of a >5 MB file and detects a same-size mutation', () => {
    const dir = makeSkill({ 'scripts/big.sh': Buffer.alloc(5 * 1024 * 1024 + 1, 0x61) });
    const lock = createArtifactLock(dir);
    const big = path.join(dir, 'scripts', 'big.sh');
    const fd = fs.openSync(big, 'r+');
    try {
      fs.writeSync(fd, Buffer.from([0x62]), 0, 1, 1024);
    } finally {
      fs.closeSync(fd);
    }

    const verification = verifyArtifact(dir, lock);
    expect(verification.exact).toBe(false);
    expect(verification.drift.artifact.changed).toBe(true);
    expect(verification.drift.artifact.actual.contentHash).not.toBe(lock.artifact.contentHash);
    expect(verification.drift.reportIdentity.changed).toBe(true);
  });

  it('classifies newly added scanner evidence', () => {
    const dir = makeSkill({ 'scripts/old.sh': '#!/bin/sh\ncurl https://example.com/old\n' });
    const lock = createArtifactLock(dir);
    fs.rmSync(path.join(dir, 'scripts', 'old.sh'));
    fs.writeFileSync(path.join(dir, 'scripts', 'net.sh'), '#!/bin/sh\ncurl https://example.com/data\n');

    const verification = verifyArtifact(dir, lock);
    expect(verification.exact).toBe(false);
    expect(verification.drift.findings.added.some((finding) => finding.ruleId === 'capability/network-call')).toBe(
      true,
    );
    expect(
      verification.drift.findings.removed.some(
        (finding) => finding.ruleId === 'capability/network-call' && finding.file === 'scripts/old.sh',
      ),
    ).toBe(true);
  });

  it('classifies current policy drift and active/suppressed disposition changes', () => {
    const dir = makeSkill(
      {},
      '---\nname: policy\ndescription: a skill used to prove that lock verification uses current operator policy\n---\n\nSee references/missing.md.\n',
    );
    const operatorDir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-lock-policy-'));
    cleanups.push(operatorDir);
    const policy = path.join(operatorDir, 'policy.json');
    fs.writeFileSync(policy, JSON.stringify({ ignore: [{ ruleId: 'resources/missing-resource' }] }));
    const lock = createArtifactLock(dir, { configPath: policy });

    expect(verifyArtifact(dir, lock, { configPath: policy }).exact).toBe(true);
    const withoutCurrentPolicy = verifyArtifact(dir, lock);
    expect(withoutCurrentPolicy.exact).toBe(false);
    expect(withoutCurrentPolicy.drift.artifact.changed).toBe(false);
    expect(withoutCurrentPolicy.drift.policy.changed).toBe(true);
    const dispositionChange = withoutCurrentPolicy.drift.findings.changed.find(
      (change) => change.expected.ruleId === 'resources/missing-resource',
    );
    expect(dispositionChange?.expected.disposition).toBe('suppressed');
    expect(dispositionChange?.actual.disposition).toBe('active');

    fs.appendFileSync(policy, '\n');
    const changedPolicyBytes = verifyArtifact(dir, lock, { configPath: policy });
    expect(changedPolicyBytes.drift.artifact.changed).toBe(false);
    expect(changedPolicyBytes.drift.policy.changed).toBe(true);
    expect(changedPolicyBytes.drift.reportIdentity.changed).toBe(true);
    expect(changedPolicyBytes.drift.findings).toEqual({ added: [], removed: [], changed: [] });
  });

  it('rejects a tampered lock before attempting to scan', () => {
    const lock = createArtifactLock(makeSkill());
    const tampered = structuredClone(lock);
    tampered.artifact.contentHash = `${tampered.artifact.contentHash[0] === 'a' ? 'b' : 'a'}${tampered.artifact.contentHash.slice(1)}`;
    expect(() => validateLock(tampered)).toThrowError(/lock digest mismatch/);
    expect(() => verifyArtifact('/path/that/does/not/exist', tampered)).toThrowError(LockValidationError);
  });

  it('never lets an artifact self-config suppress evidence during lock or verify', () => {
    const dir = makeSkill(
      { 'casefile.config.json': JSON.stringify({ ignore: [{ ruleId: 'resources/missing-resource' }] }) },
      '---\nname: self-policy\ndescription: a skill whose own config must never control lock verification\n---\n\nSee references/missing.md.\n',
    );
    const lock = createArtifactLock(dir);
    expect(lock.policy).toEqual({ source: 'none', strict: false });
    expect(lock.snapshot.activeFindings.some((finding) => finding.ruleId === 'resources/missing-resource')).toBe(true);
    expect(lock.snapshot.suppressedFindings).toEqual([]);

    const verification = verifyArtifact(dir, lock);
    expect(verification.exact).toBe(true);
    expect(verification.report.suppressed).toEqual([]);
    expect(verification.report.findings.some((finding) => finding.ruleId === 'resources/missing-resource')).toBe(true);
  });

  it('refuses to convert a legacy artifact-policy report into a trusted lock', () => {
    const dir = makeSkill({
      'casefile.config.json': JSON.stringify({ ignore: [{ ruleId: 'capability/network-call' }] }),
      'scripts/net.sh': '#!/bin/sh\ncurl https://example.com\n',
    });
    const report = scanArtifact(dir, { trustArtifactConfig: true });
    expect(() => createLock(report)).toThrowError(/artifact-local suppression policy cannot be locked/);
  });

  it.skipIf(process.getuid?.() === 0)('refuses locks when file or directory identity is incomplete', () => {
    const unreadableFile = makeSkill({ 'scripts/hidden.sh': '#!/bin/sh\necho hidden\n' });
    fs.chmodSync(path.join(unreadableFile, 'scripts', 'hidden.sh'), 0o000);
    expect(() => createArtifactLock(unreadableFile)).toThrowError(/artifact identity is incomplete/);

    const unreadableDir = makeSkill({ 'sealed/hidden.sh': '#!/bin/sh\necho hidden\n' });
    fs.chmodSync(path.join(unreadableDir, 'sealed'), 0o000);
    expect(() => createArtifactLock(unreadableDir)).toThrowError(/artifact identity is incomplete/);
    fs.chmodSync(path.join(unreadableFile, 'scripts', 'hidden.sh'), 0o644);
    fs.chmodSync(path.join(unreadableDir, 'sealed'), 0o755);
  });

  it('round-trips a generated lock through strict parsing', () => {
    const lock = createArtifactLock(makeSkill(), { strict: true });
    expect(parseLock(JSON.stringify(lock))).toEqual(lock);
    expect(lock.policy.strict).toBe(true);
  });
});
