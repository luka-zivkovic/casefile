/**
 * Supply-chain hygiene: symlinks escaping the artifact, large encoded blobs,
 * and unauditable binary files.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Finding } from '../types.js';
import { isBinaryFile } from '../walk.js';
import { finding, type CheckContext } from './context.js';

const BASE64_RUN = /[A-Za-z0-9+/]{200,}={0,2}/;
/** Media/document formats that are expected to be binary; still reported, but as info. */
const EXPECTED_BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf',
  '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.mp4', '.wav',
]);

export function supplyChainCheck(ctx: CheckContext): Finding[] {
  const findings: Finding[] = [];
  const realRoot = fs.realpathSync(ctx.root);

  for (const entry of ctx.files) {
    if (entry.isSymlink) {
      let resolved: string;
      try {
        resolved = fs.realpathSync(entry.abs);
      } catch {
        findings.push(
          finding('supplychain/broken-symlink', 'warning', `symlink target does not exist: ${fs.readlinkSync(entry.abs)}`, entry.rel),
        );
        continue;
      }
      if (resolved !== realRoot && !resolved.startsWith(realRoot + path.sep)) {
        findings.push(
          finding(
            'supplychain/symlink-escape',
            'critical',
            `symlink resolves outside the artifact directory: ${resolved}`,
            entry.rel,
          ),
        );
      }
      continue;
    }

    if (isBinaryFile(entry.abs)) {
      const ext = path.extname(entry.abs).toLowerCase();
      const expected = EXPECTED_BINARY_EXT.has(ext);
      findings.push(
        finding(
          'supplychain/binary-file',
          expected ? 'info' : 'warning',
          expected
            ? `bundled binary media file (${ext})`
            : 'bundled binary file cannot be statically audited',
          entry.rel,
        ),
      );
      continue;
    }

    // Large base64-like runs in text files (possible encoded payloads).
    let text: string;
    try {
      text = fs.readFileSync(entry.abs, 'utf-8');
    } catch {
      continue;
    }
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const m = BASE64_RUN.exec(lines[i]);
      if (m) {
        findings.push(
          finding(
            'supplychain/encoded-blob',
            'warning',
            `large base64-like blob (${m[0].length}+ chars) — possible obfuscated payload`,
            entry.rel,
            i + 1,
          ),
        );
        break; // one per file is enough
      }
    }
  }
  return findings;
}
