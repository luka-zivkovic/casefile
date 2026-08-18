import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanArtifact } from '../src/scan.js';
import type { Finding } from '../src/types.js';
import { rm } from './helpers.js';

/** Findings from the quality tier only. */
function quality(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.ruleId.startsWith('quality/'));
}

function ids(findings: Finding[]): Set<string> {
  return new Set(quality(findings).map((f) => f.ruleId));
}

/** Materialize a skill dir from a { relPath: content } map in a temp dir. */
function mkSkill(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-quality-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, ...rel.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return dir;
}

const GOOD_DESC =
  'description: >-\n' +
  '  Format changelog entries from git history into release notes. Use when the\n' +
  '  user asks for release notes or a changelog. Do not use for commit messages.\n';

function frontmatter(desc: string = GOOD_DESC): string {
  return `---\nname: quality-fixture\n${desc}---\n\n`;
}

/** ~`tokens` estimated tokens of filler prose (4 chars/token heuristic). */
function filler(tokens: number): string {
  return 'word '.repeat(Math.ceil((tokens * 4) / 5)) + '\n';
}

describe('quality tier grading curve', () => {
  it('produces ZERO quality findings for a typical well-made skill', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() +
        '# Release Notes\n\n' +
        'Turn recent git history into human-readable release notes.\n\n' +
        '## Steps\n\n' +
        '1. Read the template in references/notes.md.\n' +
        '2. Group commits by type and render the template.\n\n' +
        '## Failure modes\n\n' +
        '- Do not invent commits that are not in the log.\n',
      'references/notes.md': '# template\n',
    });
    expect(quality(scanArtifact(dir).findings)).toEqual([]);
    rm(dir);
  });
});

describe('quality/oversized-body', () => {
  it('fires as a warning above ~1500 est. tokens with no references/ dir', () => {
    const dir = mkSkill({
      'SKILL.md': frontmatter() + '# Big\n\n## Guardrails\n\nDo not skip steps.\n\n' + filler(1800),
    });
    const f = scanArtifact(dir).findings.find((x) => x.ruleId === 'quality/oversized-body');
    expect(f?.severity).toBe('warning');
    rm(dir);
  });

  it('stays silent at the same size when a references/ dir exists', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() +
        '# Big\n\n## Guardrails\n\nDo not skip steps. See references/extra.md.\n\n' +
        filler(1800),
      'references/extra.md': 'detail\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/oversized-body')).toBe(false);
    rm(dir);
  });

  it('fires above ~2500 est. tokens even with a references/ dir', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() +
        '# Huge\n\n## Guardrails\n\nDo not skip steps. See references/extra.md.\n\n' +
        filler(2800),
      'references/extra.md': 'detail\n',
    });
    const f = scanArtifact(dir).findings.find((x) => x.ruleId === 'quality/oversized-body');
    expect(f?.severity).toBe('warning');
    rm(dir);
  });

  it('stays silent for a normal-size body', () => {
    const dir = mkSkill({
      'SKILL.md': frontmatter() + '# Small\n\n## Guardrails\n\nDo not skip steps.\n\n' + filler(400),
    });
    expect(ids(scanArtifact(dir).findings).has('quality/oversized-body')).toBe(false);
    rm(dir);
  });
});

describe('quality/no-failure-modes', () => {
  it('fires as info when the body has no failure-modes/guardrail guidance', () => {
    const dir = mkSkill({
      'SKILL.md': frontmatter() + '# Plain\n\n## Steps\n\n1. Run the tool.\n2. Report the output.\n',
    });
    const f = scanArtifact(dir).findings.find((x) => x.ruleId === 'quality/no-failure-modes');
    expect(f?.severity).toBe('info');
    rm(dir);
  });

  it('stays silent when a guardrail-style heading exists', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() +
        '# Plain\n\n## Steps\n\n1. Run the tool.\n\n## Anti-patterns\n\n- Guessing output shapes.\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/no-failure-modes')).toBe(false);
    rm(dir);
  });

  it("stays silent when the body carries 'do not' guidance without a dedicated section", () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() +
        '# Plain\n\n## Steps\n\n1. Run the tool. Do not fabricate results if it fails.\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/no-failure-modes')).toBe(false);
    rm(dir);
  });
});

describe('quality/orphaned-resource', () => {
  it('fires as info for a bundled resource never referenced from SKILL.md', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() + '# Orphans\n\n## Guardrails\n\nDo not guess.\n\nSee references/used.md.\n',
      'references/used.md': 'used\n',
      'references/forgotten.md': 'never mentioned\n',
    });
    const f = scanArtifact(dir).findings.find((x) => x.ruleId === 'quality/orphaned-resource');
    expect(f?.severity).toBe('info');
    expect(f?.message).toContain('references/forgotten.md');
    rm(dir);
  });

  it('stays silent when every bundled resource is referenced', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() +
        '# Linked\n\n## Guardrails\n\nDo not guess.\n\nSee references/used.md and templates/out.md.\n',
      'references/used.md': 'used\n',
      'templates/out.md': 'template\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/orphaned-resource')).toBe(false);
    rm(dir);
  });

  it('counts files under a referenced directory as referenced', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() + '# Dir\n\n## Guardrails\n\nDo not guess.\n\nGuides live in references/guides/.\n',
      'references/guides/deep.md': 'guide\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/orphaned-resource')).toBe(false);
    rm(dir);
  });

  it('counts a top-level resource directory mention as referencing its contents', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() +
        '# Dir\n\n## Guardrails\n\nDo not guess.\n\nLoad the appropriate file from references/.\n',
      'references/one.md': 'one\n',
      'references/two.md': 'two\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/orphaned-resource')).toBe(false);
    rm(dir);
  });

  it('counts a parameterized resource path as referencing its directory', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() +
        '# Dynamic\n\n## Guardrails\n\nDo not guess.\n\nLoad `references/<topic>.md` for the requested topic.\n',
      'references/one.md': 'one\n',
      'references/two.md': 'two\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/orphaned-resource')).toBe(false);
    rm(dir);
  });

  it('counts a bare-filename mention as a reference', () => {
    const dir = mkSkill({
      'SKILL.md':
        frontmatter() + '# Name\n\n## Guardrails\n\nDo not guess.\n\nLoad the schema from schema.json.\n',
      'assets/schema.json': '{}\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/orphaned-resource')).toBe(false);
    rm(dir);
  });

  it('does not police scripts/ (executables are often invoked indirectly)', () => {
    const dir = mkSkill({
      'SKILL.md': frontmatter() + '# Scripts\n\n## Guardrails\n\nDo not guess.\n\nRun the bundled helper.\n',
      'scripts/helper.sh': 'echo hi\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/orphaned-resource')).toBe(false);
    rm(dir);
  });
});

describe('quality/missing-anti-trigger', () => {
  it('fires as info when the description has a trigger but no negative guidance', () => {
    const dir = mkSkill({
      'SKILL.md':
        '---\nname: quality-fixture\ndescription: >-\n' +
        '  Format changelog entries from git history. Use when the user asks for\n' +
        '  release notes or a changelog summary of recent commits.\n---\n\n' +
        '# Trigger\n\n## Guardrails\n\nDo not guess.\n',
    });
    const f = scanArtifact(dir).findings.find((x) => x.ruleId === 'quality/missing-anti-trigger');
    expect(f?.severity).toBe('info');
    rm(dir);
  });

  it('stays silent when the trigger is paired with negative guidance', () => {
    const dir = mkSkill({
      'SKILL.md': frontmatter() + '# Paired\n\n## Guardrails\n\nDo not guess.\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/missing-anti-trigger')).toBe(false);
    rm(dir);
  });

  it("recognizes the common 'use this skill when' trigger form", () => {
    const dir = mkSkill({
      'SKILL.md':
        '---\nname: quality-fixture\ndescription: >-\n' +
        '  Format changelog entries from git history. Use this skill when the user\n' +
        '  asks for release notes or a changelog summary of recent commits.\n---\n\n' +
        '# Trigger\n\n## Guardrails\n\nDo not guess.\n',
    });
    const report = scanArtifact(dir);
    expect(ids(report.findings).has('quality/missing-anti-trigger')).toBe(true);
    expect(report.findings.filter((f) => f.ruleId.includes('routing-no-anti-trigger'))).toEqual([]);
    rm(dir);
  });

  it("accepts 'out of scope' as negative routing guidance", () => {
    const dir = mkSkill({
      'SKILL.md':
        '---\nname: quality-fixture\ndescription: >-\n' +
        '  Format changelog entries from git history. Use when the user asks for\n' +
        '  release notes. Destructive repository changes are out of scope.\n---\n\n' +
        '# Paired\n\n## Guardrails\n\nDo not guess.\n',
    });
    expect(ids(scanArtifact(dir).findings).has('quality/missing-anti-trigger')).toBe(false);
    rm(dir);
  });

  it('does not duplicate the anti-trigger advisory under structural rules', () => {
    const dir = mkSkill({
      'SKILL.md':
        '---\nname: quality-fixture\ndescription: >-\n' +
        '  Format changelog entries from git history. Use when the user asks for\n' +
        '  release notes or a changelog summary of recent commits.\n---\n\n' +
        '# Trigger\n\n## Guardrails\n\nDo not guess.\n',
    });
    const antiTriggerFindings = scanArtifact(dir).findings.filter(
      (f) => f.ruleId === 'quality/missing-anti-trigger' || f.ruleId === 'structural/routing-no-anti-trigger',
    );
    expect(antiTriggerFindings.map((f) => f.ruleId)).toEqual(['quality/missing-anti-trigger']);
    rm(dir);
  });

  it('stays silent when the description states no trigger at all', () => {
    const dir = mkSkill({
      'SKILL.md':
        '---\nname: quality-fixture\ndescription: >-\n' +
        '  Formats changelog entries from git history into tidy grouped sections\n' +
        '  suitable to paste into published release documents.\n---\n\n' +
        '# NoTrigger\n\n## Guardrails\n\nDo not guess.\n',
    });
    const findings = scanArtifact(dir).findings;
    expect(ids(findings).has('quality/missing-anti-trigger')).toBe(false);
    expect(findings.some((f) => f.ruleId === 'structural/routing-no-anti-trigger')).toBe(true);
    rm(dir);
  });
});
