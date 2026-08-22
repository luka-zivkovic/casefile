/**
 * Minimal CI suppression policy. Suppressions affect the gate result, so the
 * default scan never trusts policy shipped inside the untrusted artifact.
 * Operators opt in with an explicit config path; the legacy artifact-local
 * behavior remains available only through `trustArtifactConfig`.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { decodeUtf8Fatal } from './io.js';
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
  source: 'none' | 'explicit' | 'artifact-legacy';
  /** Stable display name only; absolute policy paths do not enter reports. */
  file?: string;
  /** SHA-256 of the trusted policy bytes; included in report identity. */
  contentHash?: string;
  /** Set when a config file exists but could not be parsed. */
  error?: string;
  /** Artifact-local policy present but deliberately not trusted. */
  ignoredArtifactConfig?: string;
}

export interface LoadConfigOptions {
  /** Explicit operator-owned policy. Relative paths resolve from cwd. */
  configPath?: string;
  /** Explicit opt-in to the pre-0.2 artifact-local suppression behavior. */
  trustArtifactConfig?: boolean;
  cwd?: string;
}

function findArtifactConfig(artifactRoot: string): string | undefined {
  for (const name of [CONFIG_FILENAME, LEGACY_CONFIG_FILENAME]) {
    const candidate = path.join(artifactRoot, name);
    try {
      const stat = fs.lstatSync(candidate);
      if (stat.isFile() || stat.isSymbolicLink()) return candidate;
    } catch {
      // Not present/readable as a regular file; try the legacy name.
    }
  }
  return undefined;
}

function parseConfig(file: string, source: 'explicit' | 'artifact-legacy'): CasefileConfig {
  if (source === 'artifact-legacy') {
    try {
      if (fs.lstatSync(file).isSymbolicLink()) {
        return {
          ignore: [],
          source,
          file: path.basename(file),
          error: 'artifact-local suppression policy must not be a symlink',
        };
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? 'unknown-error';
      return {
        ignore: [],
        source,
        file: path.basename(file),
        error: `trusted suppression policy could not be inspected (${code})`,
      };
    }
  }
  let rawBytes: Buffer;
  try {
    rawBytes = fs.readFileSync(file);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? 'unknown-error';
    return {
      ignore: [],
      source,
      file: source === 'explicit' ? '<operator-config>' : path.basename(file),
      error: `trusted suppression policy could not be read (${code})`,
    };
  }

  const contentHash = createHash('sha256').update(rawBytes).digest('hex');
  let raw: string;
  try {
    raw = decodeUtf8Fatal(rawBytes, 'trusted suppression policy');
  } catch {
    return {
      ignore: [],
      source,
      file: source === 'explicit' ? '<operator-config>' : path.basename(file),
      contentHash,
      error: 'trusted suppression policy is not valid UTF-8',
    };
  }
  try {
    const parsed = JSON.parse(raw) as { ignore?: unknown };
    if (parsed === null || typeof parsed !== 'object' || (parsed.ignore !== undefined && !Array.isArray(parsed.ignore))) {
      return {
        ignore: [],
        source,
        file: source === 'explicit' ? '<operator-config>' : path.basename(file),
        contentHash,
        error: 'trusted suppression policy must contain an ignore array',
      };
    }

    const ignore: IgnoreRule[] = [];
    for (const [index, entry] of (parsed.ignore ?? []).entries()) {
      const e = entry as { ruleId?: unknown; path?: unknown };
      if (typeof e?.ruleId !== 'string' || e.ruleId === '') {
        return {
          ignore: [],
          source,
          file: source === 'explicit' ? '<operator-config>' : path.basename(file),
          contentHash,
          error: `trusted suppression policy ignore[${index}] has no ruleId`,
        };
      }
      if (e.path !== undefined && typeof e.path !== 'string') {
        return {
          ignore: [],
          source,
          file: source === 'explicit' ? '<operator-config>' : path.basename(file),
          contentHash,
          error: `trusted suppression policy ignore[${index}].path is not a string`,
        };
      }
      ignore.push(e.path === undefined ? { ruleId: e.ruleId } : { ruleId: e.ruleId, path: e.path });
    }
    return {
      ignore,
      source,
      file: source === 'explicit' ? '<operator-config>' : path.basename(file),
      contentHash,
    };
  } catch (err) {
    return {
      ignore: [],
      source,
      file: source === 'explicit' ? '<operator-config>' : path.basename(file),
      contentHash,
      error: `trusted suppression policy is not valid JSON: ${(err as Error).message}`,
    };
  }
}

export function loadConfig(artifactRoot: string, options: LoadConfigOptions = {}): CasefileConfig {
  const artifactConfig = findArtifactConfig(artifactRoot);
  if (options.configPath !== undefined) {
    const explicit = path.resolve(options.cwd ?? process.cwd(), options.configPath);
    const config = parseConfig(explicit, 'explicit');
    if (artifactConfig !== undefined && path.resolve(artifactConfig) !== explicit) {
      config.ignoredArtifactConfig = path.basename(artifactConfig);
    }
    return config;
  }
  if (options.trustArtifactConfig && artifactConfig !== undefined) {
    return parseConfig(artifactConfig, 'artifact-legacy');
  }
  return {
    ignore: [],
    source: 'none',
    ...(artifactConfig === undefined ? {} : { ignoredArtifactConfig: path.basename(artifactConfig) }),
  };
}

export function isIgnored(finding: Finding, config: CasefileConfig): boolean {
  return config.ignore.some(
    (rule) => rule.ruleId === finding.ruleId && (rule.path === undefined || finding.file.startsWith(rule.path)),
  );
}
