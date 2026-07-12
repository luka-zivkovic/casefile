/**
 * Resource-link integrity and progressive-disclosure size, ported from
 * overclock/tools/audit_skills.py.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseFrontmatter } from '../frontmatter.js';
import type { Finding } from '../types.js';
import { finding, relTo, type CheckContext } from './context.js';

/** `references/...`, `templates/...`, `scripts/...`, `assets/...` mentions. */
const RESOURCE_RE = /(?<![\w/])((?:references|templates|scripts|assets)\/[A-Za-z0-9._/-]+)/g;
const MAX_BODY_TOKENS = 4000;

function estimateTokens(text: string): number {
  return Math.floor(text.length / 4);
}

export function resourceCheck(ctx: CheckContext): Finding[] {
  const findings: Finding[] = [];
  for (const skill of ctx.skills) {
    const skillFile = path.join(skill.dir, 'SKILL.md');
    if (!fs.existsSync(skillFile)) continue;
    const relSkill = relTo(ctx.root, skillFile);
    const text = fs.readFileSync(skillFile, 'utf-8');
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
      const target = path.join(skill.dir, rel);
      let isFile = false;
      try {
        isFile = fs.statSync(target).isFile();
      } catch {
        isFile = false;
      }
      if (!isFile) {
        findings.push(
          finding('resources/missing-resource', 'critical', `referenced resource is missing: ${rel}`, relSkill),
        );
      }
    }
  }
  return findings;
}
