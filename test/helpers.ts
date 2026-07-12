import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

export const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');

export function fixture(name: string): string {
  return path.join(FIXTURES, name);
}

/** Copy a fixture into a fresh temp dir so tests can add symlinks etc. */
export function stageFixture(name: string): string {
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-'));
  fs.cpSync(fixture(name), dest, { recursive: true });
  return dest;
}

export function rm(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}
