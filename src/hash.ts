import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { walkArtifact, type WalkResult } from './walk.js';

function sha256(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Hash a file in bounded chunks. Artifact identity must cover every byte even
 * when the file is too large for the content analyzers to load into memory.
 */
function sha256File(file: string): string {
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1024);
  const fd = fs.openSync(file, 'r');
  try {
    let bytesRead: number;
    do {
      bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead > 0) hash.update(buffer.subarray(0, bytesRead));
    } while (bytesRead > 0);
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

/**
 * Content hash of an artifact: sha256 over a canonical JSON object containing
 * sorted `[relativePath, entryKind, sha256]` tuples. JSON string framing is
 * unambiguous even when a filename contains colons, newlines, or other record-
 * separator characters. Every regular file under the root is included except
 * `.git` (directory, worktree file, or symlink), including vendored dirs like node_modules. Symlinks contribute a
 * digest of their link target instead of following it, so a retargeted symlink
 * changes the hash. Unreadable entries contribute a typed deterministic marker
 * and a named gap instead of aborting the scan; locks refuse such incomplete
 * identity. Readable regular files are streamed in full, independently of
 * content-analysis size limits, so a same-size byte mutation always changes
 * the artifact hash.
 */
export interface IdentityGap {
  rel: string;
  kind: 'directory' | 'entry' | 'file' | 'symlink';
  code: string;
}

export interface ContentHashResult {
  digest: string;
  gaps: IdentityGap[];
}

/** Hash a captured walk so the scan and identity cover the same entry set. */
export function contentHashResult(root: string, walked: WalkResult = walkArtifact(root)): ContentHashResult {
  const entries: Array<[relativePath: string, kind: string, digest: string]> = [];
  const gaps: IdentityGap[] = walked.gaps.map((gap) => ({ rel: gap.rel, kind: gap.kind, code: gap.code }));
  for (const entry of walked.files) {
    let kind: string;
    let digest: string;
    if (entry.isSymlink) {
      try {
        kind = 'symlink';
        digest = sha256(fs.readlinkSync(entry.abs));
      } catch (error) {
        kind = 'symlink-unreadable';
        digest = sha256('unreadable');
        gaps.push({ rel: entry.rel, kind: 'symlink', code: (error as NodeJS.ErrnoException).code ?? 'UNKNOWN' });
      }
    } else {
      try {
        kind = 'file';
        digest = sha256File(entry.abs);
      } catch (error) {
        kind = 'file-unreadable';
        digest = sha256('unreadable');
        gaps.push({ rel: entry.rel, kind: 'file', code: (error as NodeJS.ErrnoException).code ?? 'UNKNOWN' });
      }
    }
    entries.push([entry.rel, kind, digest]);
  }
  entries.sort((a, b) => {
    if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
    if (a[1] !== b[1]) return a[1] < b[1] ? -1 : 1;
    return 0;
  });
  gaps.sort((a, b) => a.rel.localeCompare(b.rel) || a.kind.localeCompare(b.kind));
  return { digest: sha256(JSON.stringify({ schema: 'casefile-artifact-content/v2', entries })), gaps };
}

export function contentHash(root: string): string {
  return contentHashResult(root).digest;
}
