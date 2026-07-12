import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { walkFiles } from './walk.js';

function sha256(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Files larger than this are hashed by size+name instead of content. */
export const MAX_HASH_FILE_BYTES = 5 * 1024 * 1024;

/**
 * Content hash of an artifact: sha256 over the sorted `relpath:sha256(bytes)`
 * lines of every regular file under the root (everything except `.git`,
 * including vendored dirs like node_modules). Symlinks contribute their link
 * target instead of following it, so a retargeted symlink changes the hash.
 * Unreadable files contribute a deterministic marker instead of aborting the
 * scan; oversized files are hashed by size+name.
 */
export function contentHash(root: string): string {
  const lines: string[] = [];
  for (const entry of walkFiles(root)) {
    let fileHash: string;
    if (entry.isSymlink) {
      try {
        fileHash = sha256(`symlink:${fs.readlinkSync(entry.abs)}`);
      } catch {
        fileHash = sha256(`symlink-unreadable:${entry.rel}`);
      }
    } else {
      try {
        const size = fs.statSync(entry.abs).size;
        fileHash =
          size > MAX_HASH_FILE_BYTES
            ? sha256(`large:${entry.rel}:${size}`)
            : sha256(fs.readFileSync(entry.abs));
      } catch {
        fileHash = sha256(`unreadable:${entry.rel}`);
      }
    }
    lines.push(`${entry.rel}:${fileHash}`);
  }
  lines.sort();
  return sha256(lines.join('\n'));
}
