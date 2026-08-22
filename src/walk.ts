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

export interface WalkGap {
  /** Directory traversal or unsupported entry, relative to the walk root. */
  rel: string;
  kind: 'directory' | 'entry';
  /** Stable OS error code; absolute host paths are deliberately omitted. */
  code: string;
}

export interface WalkResult {
  files: WalkEntry[];
  gaps: WalkGap[];
}

/**
 * Walk all files under `root` (skipping only `.git`), without following
 * directory symlinks. Symlinked files are reported but not read through by
 * callers unless they choose to.
 */
export function walkArtifact(root: string): WalkResult {
  const out: WalkEntry[] = [];
  const gaps: WalkGap[] = [];
  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      const rel = path.relative(root, dir).split(path.sep).join('/') || '.';
      gaps.push({ rel, kind: 'directory', code: (error as NodeJS.ErrnoException).code ?? 'UNKNOWN' });
      return;
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      // Git metadata is excluded regardless of whether a worktree represents
      // it as a directory, a `gitdir:` file, or a symlink.
      if (SKIP_DIRS.has(entry.name)) continue;
      const abs = path.join(dir, entry.name);
      const rel = path.relative(root, abs).split(path.sep).join('/');
      if (entry.isSymbolicLink()) {
        out.push({ abs, rel, isSymlink: true });
        continue; // never follow symlinks while walking
      }
      if (entry.isDirectory()) {
        walk(abs);
      } else if (entry.isFile()) {
        out.push({ abs, rel, isSymlink: false });
      } else {
        gaps.push({ rel, kind: 'entry', code: 'UNSUPPORTED_ENTRY_TYPE' });
      }
    }
  };
  walk(root);
  return { files: out, gaps };
}

/** Compatibility wrapper for callers that only need the enumerated files. */
export function walkFiles(root: string): WalkEntry[] {
  return walkArtifact(root).files;
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
