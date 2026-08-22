import * as fs from 'node:fs';
import { TextDecoder } from 'node:util';

/** Maximum bytes loaded into memory by content analyzers. */
export const MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024;

/** Decode untrusted text without silently replacing malformed UTF-8 bytes. */
export function decodeUtf8Fatal(bytes: Uint8Array, label: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}

/** Bounded metadata/read helper for discovery paths that must not load large files. */
export function readSmallUtf8File(file: string, label: string): string {
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink()) {
    throw new Error(`${label} is a symlink; target content is outside the captured artifact entry`);
  }
  if (stat.size > MAX_SCAN_FILE_BYTES) {
    throw new Error(`${label} exceeds the ${MAX_SCAN_FILE_BYTES}-byte analysis limit`);
  }
  return decodeUtf8Fatal(fs.readFileSync(file), label);
}
