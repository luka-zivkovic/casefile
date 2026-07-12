import * as path from 'node:path';
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
