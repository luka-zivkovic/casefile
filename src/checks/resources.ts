/**
 * Resource-link integrity and progressive-disclosure size, ported from
 * overclock/tools/audit_skills.py.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseFrontmatter } from '../frontmatter.js';
import type { Finding } from '../types.js';
import { finding, readTextChecked, relTo, type CheckContext } from './context.js';

/** `references/...`, `templates/...`, `scripts/...`, `assets/...` mentions. */
const RESOURCE_RE = /(?<![\w/])((?:references|templates|scripts|assets)\/[A-Za-z0-9._/-]+)/g;
const MAX_BODY_TOKENS = 4000;

function estimateTokens(text: string): number {
  return Math.floor(text.length / 4);
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

/** Resolve symlink components lexically, including chains whose final target is missing. */
function resolveSymlinkComponents(candidate: string, depth = 0): string | undefined {
  if (depth > 40) return undefined;
  const absolute = path.resolve(candidate);
  const parsed = path.parse(absolute);
  const components = absolute.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  for (let index = 0; index < components.length; index++) {
    const next = path.join(current, components[index]);
    try {
      if (fs.lstatSync(next).isSymbolicLink()) {
        const linked = path.resolve(path.dirname(next), fs.readlinkSync(next));
        return resolveSymlinkComponents(path.join(linked, ...components.slice(index + 1)), depth + 1);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return path.join(next, ...components.slice(index + 1));
      }
      return undefined;
    }
    current = next;
  }
  return current;
}

/** Detect both direct symlink escapes and escapes through an existing parent. */
function existingResolutionEscapes(target: string, skillRoot: string, artifactRoot: string): boolean {
  const resolved = resolveSymlinkComponents(target);
  if (resolved === undefined) return false;
  return !isWithin(fs.realpathSync(skillRoot), resolved) || !isWithin(fs.realpathSync(artifactRoot), resolved);
}

export function resourceCheck(ctx: CheckContext): Finding[] {
  const findings: Finding[] = [];
  for (const skill of ctx.skills) {
    const skillFile = path.join(skill.dir, 'SKILL.md');
    if (!fs.existsSync(skillFile)) continue;
    const relSkill = relTo(ctx.root, skillFile);
    const text = readTextChecked({ abs: skillFile, rel: relSkill }, findings);
    if (text === null) continue;
    let body = text;
    try {
      ({ body } = parseFrontmatter(text));
    } catch {
      // Unparseable frontmatter is reported by the structural check; audit the raw text.
    }

    const tokens = estimateTokens(body);
    if (tokens > MAX_BODY_TOKENS) {
      findings.push(
        finding(
          'resources/body-tokens',
          'warning',
          `~${tokens} body tokens; split non-core detail into resources (soft limit ${MAX_BODY_TOKENS})`,
          relSkill,
        ),
      );
    }

    const referenced = new Set<string>();
    for (const m of body.matchAll(RESOURCE_RE)) {
      referenced.add(m[1].replace(/[.,);:`"]+$/, ''));
    }
    for (const rel of [...referenced].sort()) {
      const target = path.resolve(skill.dir, rel);
      const lexicalEscape =
        rel.split('/').includes('..') || !isWithin(skill.dir, target) || !isWithin(ctx.root, target);
      if (lexicalEscape || existingResolutionEscapes(target, skill.dir, ctx.root)) {
        findings.push(
          finding(
            'resources/resource-escape',
            'critical',
            `referenced resource escapes the skill or artifact boundary: ${rel}`,
            relSkill,
          ),
        );
        continue;
      }
      // A referenced resource may legitimately be a directory (`scripts/lib/`),
      // so an existing directory counts as present.
      let exists = false;
      try {
        const st = fs.statSync(target);
        exists = st.isFile() || st.isDirectory();
      } catch {
        exists = false;
      }
      if (!exists) {
        findings.push(
          finding('resources/missing-resource', 'critical', `referenced resource is missing: ${rel}`, relSkill),
        );
      }
    }
  }
  return findings;
}
