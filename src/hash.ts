import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { walkFiles } from './walk.js';

function sha256(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Content hash of an artifact: sha256 over the sorted `relpath:sha256(bytes)`
 * lines of every regular file under the root. Symlinks contribute their link
 * target instead of following it, so a retargeted symlink changes the hash.
 */
export function contentHash(root: string): string {
  const lines: string[] = [];
  for (const entry of walkFiles(root)) {
    let fileHash: string;
    if (entry.isSymlink) {
      fileHash = sha256(`symlink:${fs.readlinkSync(entry.abs)}`);
    } else {
      fileHash = sha256(fs.readFileSync(entry.abs));
    }
    lines.push(`${entry.rel}:${fileHash}`);
  }
  lines.sort();
  return sha256(lines.join('\n'));
}
