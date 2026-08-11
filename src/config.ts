/**
 * Minimal CI suppression config. A `casefile.config.json` in the scanned
 * artifact's root (preferred) or the current working directory may list
 * findings to ignore:
 *
 *   { "ignore": [ { "ruleId": "capability/network-call", "path": "scripts/" } ] }
 *
 * `path` is an optional prefix match against the finding's file (relative to
 * the artifact root). Ignored findings are excluded from the summary counts
 * and exit-code evaluation but still listed in the report under `suppressed`.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Finding } from './types.js';

export const CONFIG_FILENAME = 'casefile.config.json';
/** Pre-rename filename, still honored so existing repos keep their suppressions. */
export const LEGACY_CONFIG_FILENAME = 'skillguard.config.json';

export interface IgnoreRule {
  ruleId: string;
  /** Optional file-path prefix (relative to the artifact root). */
  path?: string;
}

export interface CasefileConfig {
  ignore: IgnoreRule[];
  /** Set when a config file exists but could not be parsed. */
  error?: string;
}

export function loadConfig(artifactRoot: string, cwd: string = process.cwd()): CasefileConfig {
  for (const dir of [artifactRoot, cwd]) {
    // Within a directory the new filename wins; the legacy name still loads.
    let file: string | undefined;
    let raw: string | undefined;
    for (const name of [CONFIG_FILENAME, LEGACY_CONFIG_FILENAME]) {
      const candidate = path.join(dir, name);
      try {
        raw = fs.readFileSync(candidate, 'utf-8');
        file = candidate;
        break;
      } catch {
        // not here; try the next name
      }
    }
    if (raw === undefined || file === undefined) {
      continue; // no config in this dir; try the next location
    }
    try {
      const parsed = JSON.parse(raw) as { ignore?: unknown };
      const ignore: IgnoreRule[] = [];
      if (Array.isArray(parsed?.ignore)) {
        for (const entry of parsed.ignore) {
          const e = entry as { ruleId?: unknown; path?: unknown };
          if (typeof e?.ruleId !== 'string' || e.ruleId === '') continue;
          if (e.path !== undefined && typeof e.path !== 'string') continue;
          ignore.push(e.path === undefined ? { ruleId: e.ruleId } : { ruleId: e.ruleId, path: e.path });
        }
      }
      return { ignore };
    } catch (err) {
      return { ignore: [], error: `${file} is not valid JSON: ${(err as Error).message}` };
    }
  }
  return { ignore: [] };
}

export function isIgnored(finding: Finding, config: CasefileConfig): boolean {
  return config.ignore.some(
    (rule) => rule.ruleId === finding.ruleId && (rule.path === undefined || finding.file.startsWith(rule.path)),
  );
}
