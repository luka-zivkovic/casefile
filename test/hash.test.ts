import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { contentHash } from '../src/hash.js';

const cleanups: string[] = [];

function sha256(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

/** The ambiguous pre-v2 framing retained only to prove the regression. */
function legacyContentHash(root: string): string {
  const lines = fs
    .readdirSync(root)
    .map((name) => `${name}:${sha256(fs.readFileSync(path.join(root, name)))}`)
    .sort();
  return sha256(lines.join('\n'));
}

function tempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanups.push(dir);
  return dir;
}

afterEach(() => {
  for (const target of cleanups.splice(0)) fs.rmSync(target, { recursive: true, force: true });
});

describe('artifact content hash framing', () => {
  it.skipIf(process.platform === 'win32')(
    'separates adversarial newline/colon filenames that collided under legacy line framing',
    () => {
      const firstContent = 'first file bytes';
      const secondContent = 'second file bytes';
      const ordinary = tempDir('casefile-hash-ordinary-');
      fs.writeFileSync(path.join(ordinary, 'a'), firstContent);
      fs.writeFileSync(path.join(ordinary, 'b'), secondContent);

      const framed = tempDir('casefile-hash-framed-');
      const injectedName = `a:${sha256(firstContent)}\nb`;
      fs.writeFileSync(path.join(framed, injectedName), secondContent);

      // The old `${path}:${digest}` + newline construction synthesized the
      // exact same byte stream for these different directory contents.
      expect(legacyContentHash(ordinary)).toBe(legacyContentHash(framed));
      expect(contentHash(ordinary)).not.toBe(contentHash(framed));

      const relocatedOrdinary = tempDir('casefile-hash-ordinary-copy-');
      const relocatedFramed = tempDir('casefile-hash-framed-copy-');
      fs.cpSync(ordinary, relocatedOrdinary, { recursive: true });
      fs.cpSync(framed, relocatedFramed, { recursive: true });
      expect(contentHash(relocatedOrdinary)).toBe(contentHash(ordinary));
      expect(contentHash(relocatedFramed)).toBe(contentHash(framed));
    },
  );

  it.skipIf(process.platform === 'win32')('keeps symlink targets identity-bearing and relocation-stable', () => {
    const artifact = tempDir('casefile-hash-symlink-');
    fs.writeFileSync(path.join(artifact, 'target-a'), 'same target bytes');
    fs.writeFileSync(path.join(artifact, 'target-b'), 'same target bytes');
    fs.symlinkSync('target-a', path.join(artifact, 'link'));
    const before = contentHash(artifact);

    fs.unlinkSync(path.join(artifact, 'link'));
    fs.symlinkSync('target-b', path.join(artifact, 'link'));
    const retargeted = contentHash(artifact);
    expect(retargeted).not.toBe(before);

    const relocated = tempDir('casefile-hash-symlink-copy-');
    fs.cpSync(artifact, relocated, { recursive: true, verbatimSymlinks: true });
    expect(contentHash(relocated)).toBe(retargeted);
  });

  it('excludes worktree-style .git files from portable identity', () => {
    const first = tempDir('casefile-hash-git-a-');
    const second = tempDir('casefile-hash-git-b-');
    fs.writeFileSync(path.join(first, 'payload'), 'same\n');
    fs.writeFileSync(path.join(second, 'payload'), 'same\n');
    fs.writeFileSync(path.join(first, '.git'), 'gitdir: /absolute/one\n');
    fs.writeFileSync(path.join(second, '.git'), 'gitdir: /absolute/two\n');
    expect(contentHash(first)).toBe(contentHash(second));
  });

  it.skipIf(process.platform === 'win32')('excludes a .git symlink regardless of its target', () => {
    const first = tempDir('casefile-hash-git-link-a-');
    const second = tempDir('casefile-hash-git-link-b-');
    fs.writeFileSync(path.join(first, 'payload'), 'same\n');
    fs.writeFileSync(path.join(second, 'payload'), 'same\n');
    fs.symlinkSync('/different/worktree/one', path.join(first, '.git'));
    fs.symlinkSync('/different/worktree/two', path.join(second, '.git'));
    expect(contentHash(first)).toBe(contentHash(second));
  });
});
