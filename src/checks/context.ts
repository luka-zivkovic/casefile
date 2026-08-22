import * as fs from 'node:fs';
import * as path from 'node:path';
import { decodeUtf8Fatal, MAX_SCAN_FILE_BYTES } from '../io.js';
import type { ArtifactType, Finding, PluginRef, Severity, SkillRef } from '../types.js';
import type { WalkEntry } from '../walk.js';

export interface CheckContext {
  /** Absolute artifact root. */
  root: string;
  type: ArtifactType;
  skills: SkillRef[];
  plugins: PluginRef[];
  /** All files under the artifact root (symlinks not followed). */
  files: WalkEntry[];
}

export type Check = (ctx: CheckContext) => Finding[];

export function relTo(root: string, abs: string): string {
  const rel = path.relative(root, abs);
  return rel === '' ? '.' : rel.split(path.sep).join('/');
}

export function finding(
  ruleId: string,
  severity: Severity,
  message: string,
  file: string,
  line?: number,
): Finding {
  const f: Finding = { ruleId, severity, message, file };
  if (line !== undefined) f.line = line;
  return f;
}

/**
 * Global per-line length cap for regex-based line checks. Lines longer than
 * this are truncated before any pattern runs against them, so no rule regex
 * can be weaponized into a ReDoS with a pathological long line.
 */
export const MAX_LINE_LENGTH = 2000;

export { MAX_SCAN_FILE_BYTES } from '../io.js';

export interface CappedLines {
  lines: string[];
  /** 1-indexed line numbers that were truncated to MAX_LINE_LENGTH. */
  truncatedLines: number[];
}

/** Split text into lines, truncating overlong lines for regex safety. */
export function splitLinesCapped(text: string): CappedLines {
  const lines = text.split(/\r?\n/);
  const truncatedLines: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > MAX_LINE_LENGTH) {
      lines[i] = lines[i].slice(0, MAX_LINE_LENGTH);
      truncatedLines.push(i + 1);
    }
  }
  return { lines, truncatedLines };
}

/**
 * Standard truncation finding. Message is deterministic so identical findings
 * emitted by multiple checks for the same file dedupe in the report.
 */
export function truncationFinding(rel: string, truncatedLines: number[]): Finding {
  return finding(
    'scan/line-truncated',
    'info',
    `${truncatedLines.length} line(s) longer than ${MAX_LINE_LENGTH} chars were truncated for line-based checks`,
    rel,
    truncatedLines[0],
  );
}

/**
 * Read a file for content checks, skipping (and reporting) unreadable or
 * oversized files instead of aborting the scan. Returns null when skipped.
 */
export function readTextChecked(entry: { abs: string; rel: string }, findings: Finding[]): string | null {
  let size: number;
  try {
    size = fs.statSync(entry.abs).size;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? 'UNKNOWN';
    findings.push(
      finding('scan/unreadable-file', 'info', `file could not be read and was skipped (${code})`, entry.rel),
    );
    return null;
  }
  if (size > MAX_SCAN_FILE_BYTES) {
    findings.push(
      finding(
        'scan/file-too-large',
        'info',
        `file is ${size} bytes (limit ${MAX_SCAN_FILE_BYTES}); content checks skipped; readable bytes remain covered by artifact identity`,
        entry.rel,
      ),
    );
    return null;
  }
  try {
    return decodeUtf8Fatal(fs.readFileSync(entry.abs), entry.rel);
  } catch (err) {
    if ((err as Error).message === `${entry.rel} is not valid UTF-8`) {
      findings.push(finding('scan/invalid-utf8', 'info', 'file is not valid UTF-8 and content checks were skipped', entry.rel));
      return null;
    }
    const code = (err as NodeJS.ErrnoException).code ?? 'UNKNOWN';
    findings.push(
      finding('scan/unreadable-file', 'info', `file could not be read and was skipped (${code})`, entry.rel),
    );
    return null;
  }
}
