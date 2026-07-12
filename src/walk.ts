import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * The ONLY directory excluded from walking (and therefore from both content
 * checks and the content hash). Everything else — including node_modules,
 * dist, venv — is scanned and hashed: vendored dirs are exactly where a
 * payload would hide.
 */
export const SKIP_DIRS = new Set(['.git']);

/**
 * Vendored/generated dirs. Still walked, scanned by the capability /
 * supply-chain / injection rules, and included in the content hash — but
 * skill discovery prunes them, so the structural / resource quality rules
 * do not add noise for third-party code.
 */
export const VENDORED_DIRS = new Set([
  '.impeccable',
  '.venv',
  '_work',
  '__pycache__',
  'build',
  'dist',
  'node_modules',
  'venv',
]);

export interface WalkEntry {
  /** Absolute path. */
  abs: string;
  /** Path relative to the walk root (posix separators). */
  rel: string;
  isSymlink: boolean;
}

/**
 * Walk all files under `root` (skipping only `.git`), without following
 * directory symlinks. Symlinked files are reported but not read through by
 * callers unless they choose to.
 */
export function walkFiles(root: string): WalkEntry[] {
  const out: WalkEntry[] = [];
  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = path.join(dir, entry.name);
      const rel = path.relative(root, abs).split(path.sep).join('/');
      if (entry.isSymbolicLink()) {
        out.push({ abs, rel, isSymlink: true });
        continue; // never follow symlinks while walking
      }
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(abs);
      } else if (entry.isFile()) {
        out.push({ abs, rel, isSymlink: false });
      }
    }
  };
  walk(root);
  return out;
}

/** Heuristic: treat a file as binary if its first 8 KiB contain a NUL byte. */
export function isBinaryFile(abs: string): boolean {
  let fd: number;
  try {
    fd = fs.openSync(abs, 'r');
  } catch {
    return false;
  }
  try {
    const buf = Buffer.alloc(8192);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n).includes(0);
  } finally {
    fs.closeSync(fd);
  }
}

export function readText(abs: string): string {
  return fs.readFileSync(abs, 'utf-8');
}
