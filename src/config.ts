/**
 * Minimal CI suppression config. A `skillguard.config.json` in the scanned
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

export const CONFIG_FILENAME = 'skillguard.config.json';

export interface IgnoreRule {
  ruleId: string;
  /** Optional file-path prefix (relative to the artifact root). */
  path?: string;
}

export interface SkillguardConfig {
  ignore: IgnoreRule[];
  /** Set when a config file exists but could not be parsed. */
  error?: string;
}

export function loadConfig(artifactRoot: string, cwd: string = process.cwd()): SkillguardConfig {
  for (const dir of [artifactRoot, cwd]) {
    const file = path.join(dir, CONFIG_FILENAME);
    let raw: string;
    try {
      raw = fs.readFileSync(file, 'utf-8');
    } catch {
      continue; // no config here; try the next location
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

export function isIgnored(finding: Finding, config: SkillguardConfig): boolean {
  return config.ignore.some(
    (rule) => rule.ruleId === finding.ruleId && (rule.path === undefined || finding.file.startsWith(rule.path)),
  );
}
