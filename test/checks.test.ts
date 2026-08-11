import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { scanArtifact } from '../src/scan.js';
import type { Finding, Report } from '../src/types.js';
import { fixture, rm, stageFixture } from './helpers.js';

function ids(findings: Finding[]): Set<string> {
  return new Set(findings.map((f) => f.ruleId));
}

describe('benign skill', () => {
  const report = scanArtifact(fixture('benign-skill'));

  it('classifies as a skill', () => {
    expect(report.artifact.type).toBe('skill');
  });

  it('produces no critical findings', () => {
    expect(report.summary.critical).toBe(0);
  });

  it('resolves its referenced resources', () => {
    expect(ids(report.findings).has('resources/missing-resource')).toBe(false);
  });
});

describe('malicious plugin', () => {
  let staged: string;
  let report: Report;

  // Stage a copy and add an escaping symlink that cannot be committed to git.
  staged = stageFixture('malicious-plugin');
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-outside-'));
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'top secret\n');
  fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(staged, 'skills', 'helper', 'link-to-secret'));
  report = scanArtifact(staged);
  const found = ids(report.findings);

  afterAll(() => {
    rm(staged);
    rm(outside);
  });

  it('classifies as a plugin', () => {
    expect(report.artifact.type).toBe('plugin');
  });

  it('flags prompt-injection phrases', () => {
    expect(found.has('injection/phrase')).toBe(true);
  });

  it('flags an HTML comment imperative', () => {
    expect(found.has('injection/html-comment-imperative')).toBe(true);
  });

  it('flags model-addressed concealment in a reference file', () => {
    expect(found.has('injection/model-addressed')).toBe(true);
  });

  it('flags zero-width and bidi unicode', () => {
    expect(found.has('injection/zero-width-unicode')).toBe(true);
    expect(found.has('injection/bidi-control')).toBe(true);
  });

  it('flags curl|sh pipe-to-shell as critical', () => {
    const pipe = report.findings.find((f) => f.ruleId === 'capability/pipe-to-shell');
    expect(pipe?.severity).toBe('critical');
  });

  it('flags eval of downloaded content', () => {
    expect(found.has('capability/eval-download')).toBe(true);
  });

  it('flags secret env-var reads', () => {
    expect(found.has('capability/secret-env-read')).toBe(true);
  });

  it('flags network calls', () => {
    expect(found.has('capability/network-call')).toBe(true);
  });

  it('flags rm -rf and destructive delete of root', () => {
    expect(found.has('capability/rm-rf') || found.has('capability/destructive-delete')).toBe(true);
    expect(found.has('capability/destructive-delete')).toBe(true);
  });

  it('flags writes outside the artifact directory', () => {
    expect(found.has('capability/write-outside-artifact')).toBe(true);
  });

  it('flags a hook that runs a shell command', () => {
    expect(found.has('capability/hook-shell-command')).toBe(true);
  });

  it('flags broad allowed-tools', () => {
    expect(found.has('capability/broad-tools')).toBe(true);
  });

  it('flags an encoded blob', () => {
    expect(found.has('supplychain/encoded-blob')).toBe(true);
  });

  it('flags a symlink escaping the artifact directory as critical', () => {
    const esc = report.findings.find((f) => f.ruleId === 'supplychain/symlink-escape');
    expect(esc?.severity).toBe('critical');
  });

  it('has multiple critical findings overall', () => {
    expect(report.summary.critical).toBeGreaterThan(2);
  });
});

describe('structural checks', () => {
  it('flags a missing SKILL.md', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-empty-'));
    fs.mkdirSync(path.join(dir, '.claude-plugin'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude-plugin', 'plugin.json'), '{"name":"x","version":"1.0.0"}');
    const report = scanArtifact(dir);
    expect(report.artifact.type).toBe('plugin');
    // no skills: warns rather than crashes
    expect(ids(report.findings).has('structural/no-skills')).toBe(true);
    rm(dir);
  });

  it('flags invalid plugin.json as critical', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-badjson-'));
    fs.mkdirSync(path.join(dir, '.claude-plugin'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude-plugin', 'plugin.json'), '{ not json');
    const report = scanArtifact(dir);
    const f = report.findings.find((x) => x.ruleId === 'structural/plugin-json-invalid');
    expect(f?.severity).toBe('critical');
    rm(dir);
  });

  it('flags a missing referenced resource as critical', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-res-'));
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      '---\nname: res\ndescription: a skill referencing a resource that does not exist for testing\n---\n\nSee references/missing.md for details.\n',
    );
    const report = scanArtifact(dir);
    const f = report.findings.find((x) => x.ruleId === 'resources/missing-resource');
    expect(f?.severity).toBe('critical');
    rm(dir);
  });
});

// Regressions distilled from scanning real public skill/plugin repos.
describe('real-world hardening regressions', () => {
  it('does not report a referenced resource directory that exists as missing', () => {
    // Real-world shape: SKILL.md says "helpers live in scripts/lib/" and ships
    // that directory (seen in mvanhorn/last30days-skill).
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-resdir-'));
    fs.mkdirSync(path.join(dir, 'scripts', 'lib'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      '---\nname: resdir\ndescription: references a bundled directory of helper scripts\n---\n\nShared helpers live in scripts/lib/ next to this file.\n',
    );
    const report = scanArtifact(dir);
    expect(ids(report.findings).has('resources/missing-resource')).toBe(false);
    rm(dir);
  });

  it('does not flag emoji ZWJ sequences as zero-width unicode, but still flags bare ZWJ/ZWSP', () => {
    // Real-world shape: READMEs full of emoji like "\u{1F9D1}‍\u{1F4BB}"
    // (seen in anthropics/claude-plugins-official telegram docs).
    const emojiDir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-zwj-'));
    fs.writeFileSync(
      path.join(emojiDir, 'SKILL.md'),
      '---\nname: zwj\ndescription: a skill whose docs contain emoji joiner sequences\n---\n\n## \u{1F468}‍\u{1F4BB} Maintainers \u{1F937}‍♂️\n',
    );
    expect(ids(scanArtifact(emojiDir).findings).has('injection/zero-width-unicode')).toBe(false);
    rm(emojiDir);

    const hiddenDir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-zwsp-'));
    fs.writeFileSync(
      path.join(hiddenDir, 'SKILL.md'),
      '---\nname: zwsp\ndescription: a skill hiding characters between letters\n---\n\nno‍tice the hid​den joiners here.\n',
    );
    expect(ids(scanArtifact(hiddenDir).findings).has('injection/zero-width-unicode')).toBe(true);
    rm(hiddenDir);
  });

  it('does not flag skin-tone-modified emoji ZWJ sequences, but still flags ZWJ between letters', () => {
    // Real-world shape: "\u{1F469}\u{1F3FD}‍\u{1F4BB}" — the ZWJ follows a
    // skin-tone modifier (U+1F3FB–FF), which is Emoji_Component rather than
    // Extended_Pictographic, so a naive pictographic check misses it.
    const toneDir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-zwj-tone-'));
    fs.writeFileSync(
      path.join(toneDir, 'SKILL.md'),
      '---\nname: zwjtone\ndescription: a skill whose docs contain skin-tone emoji joiner sequences\n---\n\n## \u{1F469}\u{1F3FD}‍\u{1F4BB} Maintainers\n',
    );
    expect(ids(scanArtifact(toneDir).findings).has('injection/zero-width-unicode')).toBe(false);
    rm(toneDir);

    const lettersDir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-zwj-letters-'));
    fs.writeFileSync(
      path.join(lettersDir, 'SKILL.md'),
      '---\nname: zwjletters\ndescription: a skill hiding a joiner between ordinary letters\n---\n\nhid‍den instructions here.\n',
    );
    expect(ids(scanArtifact(lettersDir).findings).has('injection/zero-width-unicode')).toBe(true);
    rm(lettersDir);
  });

  it('does not flag lowercase JS template interpolations as secret env reads', () => {
    // Real-world shape: `${tokens.join(", ")}` in a bundled TS/JS helper
    // (seen in SawyerHood/dev-browser stringUtils.ts).
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-envfp-'));
    fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      '---\nname: envfp\ndescription: ships a formatting helper script with template literals\n---\n\nRun scripts/format.js to format output.\n',
    );
    fs.writeFileSync(
      path.join(dir, 'scripts', 'format.js'),
      'const tokens = ["a", "b"];\nmodule.exports = () => `{ ${tokens.join(", ")} }`;\n',
    );
    expect(ids(scanArtifact(dir).findings).has('capability/secret-env-read')).toBe(false);

    // Uppercase shell expansions must still be flagged.
    fs.writeFileSync(path.join(dir, 'scripts', 'push.sh'), 'echo "auth: ${GITHUB_TOKEN}"\n');
    expect(ids(scanArtifact(dir).findings).has('capability/secret-env-read')).toBe(true);
    fs.rmSync(path.join(dir, 'scripts', 'push.sh'));

    // Explicit env-API reads must still be flagged, independently of the shell probe.
    fs.writeFileSync(path.join(dir, 'scripts', 'client.js'), 'const key = process.env.apiKey;\n');
    expect(ids(scanArtifact(dir).findings).has('capability/secret-env-read')).toBe(true);
    rm(dir);
  });
});
