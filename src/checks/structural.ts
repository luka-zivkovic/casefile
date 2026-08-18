/**
 * Structural validation, ported from overclock/tools/validate_skill.py plus
 * plugin.json validity. Errors that break loading are critical; quality and
 * style issues are warnings; advisory routing hints are info.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { FrontmatterError, NAME_RE, parseFrontmatter } from '../frontmatter.js';
import type { Finding } from '../types.js';
import { finding, relTo, type CheckContext } from './context.js';
import { hasAntiTrigger, hasPositiveRoutingTrigger } from './routing.js';

const MAX_BODY_LINES = 500;
const MAX_CHARS = 30_000;
const BUILTIN_AGENTS = new Set(['Explore', 'Plan', 'general-purpose']);

function checkSkill(ctx: CheckContext, skillDir: string, plugin?: string): Finding[] {
  const findings: Finding[] = [];
  const skillFile = path.join(skillDir, 'SKILL.md');
  const relSkill = relTo(ctx.root, skillFile);
  if (!fs.existsSync(skillFile)) {
    return [finding('structural/skill-md-missing', 'critical', 'SKILL.md does not exist', relSkill)];
  }

  let text: string;
  try {
    text = fs.readFileSync(skillFile, 'utf-8');
  } catch (err) {
    return [
      finding('scan/unreadable-file', 'info', `SKILL.md could not be read and was skipped: ${(err as Error).message}`, relSkill),
    ];
  }
  let fm: Record<string, string>;
  let body: string;
  try {
    ({ frontmatter: fm, body } = parseFrontmatter(text));
  } catch (err) {
    if (err instanceof FrontmatterError) {
      return [finding('structural/frontmatter-invalid', 'critical', err.message, relSkill, 1)];
    }
    throw err;
  }

  // name is OPTIONAL (defaults to directory name); validate only when present.
  const name = fm['name'];
  if (name) {
    if (!NAME_RE.test(name)) {
      findings.push(
        finding(
          'structural/name-unusual',
          'warning',
          `name '${name}' is unusual; expected lowercase/digits/hyphens, optionally plugin-namespaced (plugin:skill)`,
          relSkill,
        ),
      );
    } else {
      const bare = name.split(':').pop() as string;
      const folder = path.basename(skillDir);
      if (![bare, 'codex-skill', 'claude-skill'].includes(folder)) {
        findings.push(
          finding(
            'structural/name-folder-mismatch',
            'warning',
            `folder name '${folder}' differs from skill name '${name}'`,
            relSkill,
          ),
        );
      }
    }
  }

  const desc = fm['description'] ?? '';
  if (!desc) {
    findings.push(
      finding(
        'structural/description-missing',
        'warning',
        'no description — recommended so Claude can route to the skill',
        relSkill,
      ),
    );
  } else if (desc.length < 40) {
    findings.push(
      finding(
        'structural/description-short',
        'warning',
        'description is short; make it specific enough to trigger the skill',
        relSkill,
      ),
    );
  }

  const bodyLines = body.trim() === '' ? [] : body.trim().split('\n');
  if (body.trim() === '' && !desc) {
    findings.push(
      finding('structural/empty-skill', 'critical', 'skill has neither a description nor body content', relSkill),
    );
  }
  if (bodyLines.length > MAX_BODY_LINES) {
    findings.push(
      finding(
        'structural/body-too-long',
        'warning',
        `body has ${bodyLines.length} lines; move detail into references/ (soft limit ${MAX_BODY_LINES})`,
        relSkill,
      ),
    );
  }
  if (text.length > MAX_CHARS) {
    findings.push(
      finding(
        'structural/skill-md-too-large',
        'warning',
        `SKILL.md has ${text.length} chars; move detail into references/ (soft limit ${MAX_CHARS})`,
        relSkill,
      ),
    );
  }

  const headings = bodyLines.filter((l) => l.startsWith('#')).map((l) => l.trim());
  const duplicates = [...new Set(headings.filter((h) => headings.filter((x) => x === h).length > 1))].sort();
  if (duplicates.length > 0) {
    findings.push(
      finding('structural/duplicate-headings', 'warning', `duplicate headings: ${duplicates.join(', ')}`, relSkill),
    );
  }

  // Routing metadata (from audit_skills.py) — advisory quality hints.
  if (desc) {
    const hasTrigger = hasPositiveRoutingTrigger(desc);
    if (!hasTrigger) {
      findings.push(
        finding('structural/routing-no-trigger', 'info', 'routing description lacks a concrete positive trigger', relSkill),
      );
      if (!hasAntiTrigger(desc)) {
        findings.push(
          finding('structural/routing-no-anti-trigger', 'info', 'routing description lacks an explicit anti-trigger', relSkill),
        );
      }
    }
  }

  // Forked skills must ship the agent they reference (from audit_skills.py),
  // generalized to check inside the owning plugin directory.
  if (fm['context'] === 'fork' && plugin) {
    const agent = fm['agent'] ?? 'general-purpose';
    if (!BUILTIN_AGENTS.has(agent)) {
      const pluginRoot = ctx.plugins.find((p) => skillDir.startsWith(p.dir + path.sep) || skillDir === p.dir)?.dir;
      if (pluginRoot) {
        let parts = agent.split(':');
        if (parts[0] === plugin) parts = parts.slice(1);
        const agentPath = path.join(pluginRoot, 'agents', ...parts) + '.md';
        if (!fs.existsSync(agentPath)) {
          findings.push(
            finding(
              'structural/fork-agent-missing',
              'critical',
              `forked skill agent is missing: ${relTo(ctx.root, agentPath)}`,
              relSkill,
            ),
          );
        }
      }
    }
  }

  return findings;
}

function checkPlugin(ctx: CheckContext, pluginDir: string): Finding[] {
  const findings: Finding[] = [];
  const manifest = path.join(pluginDir, '.claude-plugin', 'plugin.json');
  const relManifest = relTo(ctx.root, manifest);
  let raw: string;
  try {
    raw = fs.readFileSync(manifest, 'utf-8');
  } catch {
    return [finding('structural/plugin-json-missing', 'critical', '.claude-plugin/plugin.json is missing', relManifest)];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return [
      finding('structural/plugin-json-invalid', 'critical', `plugin.json is not valid JSON: ${(err as Error).message}`, relManifest),
    ];
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return [finding('structural/plugin-json-invalid', 'critical', 'plugin.json must be a JSON object', relManifest)];
  }
  const obj = parsed as Record<string, unknown>;
  if (typeof obj['name'] !== 'string' || obj['name'] === '') {
    findings.push(finding('structural/plugin-name-missing', 'critical', "plugin.json has no 'name'", relManifest));
  }
  if (typeof obj['version'] !== 'string' || obj['version'] === '') {
    findings.push(
      finding('structural/plugin-version-missing', 'warning', "plugin.json has no 'version'; versioning is required for auditable updates", relManifest),
    );
  }
  return findings;
}

export function structuralCheck(ctx: CheckContext): Finding[] {
  const findings: Finding[] = [];
  for (const plugin of ctx.plugins) findings.push(...checkPlugin(ctx, plugin.dir));
  for (const skill of ctx.skills) findings.push(...checkSkill(ctx, skill.dir, skill.plugin));
  if (ctx.type !== 'skill' && ctx.skills.length === 0) {
    findings.push(finding('structural/no-skills', 'warning', 'artifact contains no skills', '.'));
  }
  return findings;
}
