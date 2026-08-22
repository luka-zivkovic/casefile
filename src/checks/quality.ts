/**
 * Quality heuristics ported from skill-mastery's scripts/audit_skills.py,
 * recalibrated for signal: that audit graded every skill it saw as WARN,
 * which destroys the tier's value. These rules are tuned so a typical
 * well-made skill produces ZERO quality findings — only genuine
 * progressive-disclosure violations warn, everything else is advisory info.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseFrontmatter } from '../frontmatter.js';
import type { Finding } from '../types.js';
import { finding, readTextChecked, relTo, type CheckContext } from './context.js';
import { hasAntiTrigger, hasPositiveRoutingTrigger } from './routing.js';

/** Body budget (est. tokens, chars/4) when the skill ships no references/. */
const BODY_TOKEN_LIMIT = 1500;
/** Looser budget when a references/ dir exists (detail has somewhere to go). */
const BODY_TOKEN_LIMIT_WITH_REFERENCES = 2500;

/** Heading cues that count as a failure-modes/guardrails section. */
const FAILURE_HEADING_CUES = [
  'failure',
  'pitfall',
  'gotcha',
  'mistake',
  'anti-pattern',
  'antipattern',
  'guardrail',
  'caveat',
  'limitation',
];
/** Inline guidance that serves the same purpose without a dedicated heading. */
const DO_NOT_GUIDANCE_RE = /\b(do not|don't|never)\b/i;

/** Same resource-path shape the resources check matches. */
const RESOURCE_MENTION_RE = /(?<![\w/])((?:references|templates|scripts|assets)\/[A-Za-z0-9._/-]*)/g;
/** Resource dirs policed for orphans (scripts are often invoked indirectly). */
const ORPHAN_DIRS = ['references', 'templates', 'assets'];

function estimateTokens(text: string): number {
  return Math.floor(text.length / 4);
}

/** All files under `dir` as posix paths relative to the skill dir. */
function listFiles(skillDir: string, sub: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue; // symlinks are the supply-chain check's turf
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) walk(abs);
      else if (e.isFile()) out.push(path.relative(skillDir, abs).split(path.sep).join('/'));
    }
  };
  walk(path.join(skillDir, sub));
  return out.sort();
}

function checkSkill(ctx: CheckContext, skillDir: string): Finding[] {
  const findings: Finding[] = [];
  const skillFile = path.join(skillDir, 'SKILL.md');
  if (!fs.existsSync(skillFile)) return findings; // reported by the structural check
  const relSkill = relTo(ctx.root, skillFile);
  const text = readTextChecked({ abs: skillFile, rel: relSkill }, findings);
  if (text === null) return findings;
  let body = text;
  let desc = '';
  try {
    const parsed = parseFrontmatter(text);
    body = parsed.body;
    desc = parsed.frontmatter['description'] ?? '';
  } catch {
    // Unparseable frontmatter is reported by the structural check; audit the raw text.
  }

  // quality/oversized-body — progressive-disclosure violation. A references/
  // dir alongside SKILL.md earns a looser budget: the overflow has a home.
  let hasReferencesDir = false;
  try {
    hasReferencesDir = fs.statSync(path.join(skillDir, 'references')).isDirectory();
  } catch {
    hasReferencesDir = false;
  }
  const tokens = estimateTokens(body);
  const limit = hasReferencesDir ? BODY_TOKEN_LIMIT_WITH_REFERENCES : BODY_TOKEN_LIMIT;
  if (tokens > limit) {
    findings.push(
      finding(
        'quality/oversized-body',
        'warning',
        hasReferencesDir
          ? `~${tokens} est. body tokens (limit ${limit}); move detail into references/ (progressive disclosure)`
          : `~${tokens} est. body tokens with no references/ dir (limit ${limit}); split detail into references/ (progressive disclosure)`,
        relSkill,
      ),
    );
  }

  // quality/no-failure-modes — advisory only. A dedicated heading OR inline
  // "do not"-style guidance anywhere in the body both count.
  const headings = [...body.matchAll(/^#{1,6}\s*(.+?)\s*$/gm)].map((m) => m[1].toLowerCase());
  const headingBlob = headings.join(' ');
  const hasFailureGuidance =
    FAILURE_HEADING_CUES.some((cue) => headingBlob.includes(cue)) || DO_NOT_GUIDANCE_RE.test(body);
  if (!hasFailureGuidance) {
    findings.push(
      finding(
        'quality/no-failure-modes',
        'info',
        'no failure-modes/guardrails/anti-patterns guidance — state the mistakes the skill should prevent',
        relSkill,
      ),
    );
  }

  // quality/orphaned-resource — bundled files SKILL.md never points at.
  // Lenient by design: an explicit path, any ancestor-directory mention, or a
  // bare-filename mention all count as referenced.
  const mentions = new Set<string>();
  for (const m of body.matchAll(RESOURCE_MENTION_RE)) {
    mentions.add(m[1].replace(/[.,);:`"/]+$/, ''));
  }
  for (const sub of ORPHAN_DIRS) {
    for (const rel of listFiles(skillDir, sub)) {
      const referenced =
        body.includes(path.basename(rel)) ||
        [...mentions].some((m) => rel === m || rel.startsWith(m + '/'));
      if (!referenced) {
        findings.push(
          finding(
            'quality/orphaned-resource',
            'info',
            `bundled resource is never referenced from SKILL.md: ${rel}`,
            relSkill,
          ),
        );
      }
    }
  }

  // quality/missing-anti-trigger — only when a positive trigger exists; a
  // description with no trigger at all is the structural check's business.
  if (desc && hasPositiveRoutingTrigger(desc) && !hasAntiTrigger(desc)) {
    findings.push(
      finding(
        'quality/missing-anti-trigger',
        'info',
        "description has a trigger but no negative guidance — add what the skill is NOT for ('do not use for ...')",
        relSkill,
      ),
    );
  }

  return findings;
}

export function qualityCheck(ctx: CheckContext): Finding[] {
  return ctx.skills.flatMap((skill) => checkSkill(ctx, skill.dir));
}
