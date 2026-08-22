import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadBenchmarkManifest, runBenchmark } from '../src/benchmark.js';

const MANIFEST = path.resolve('benchmark/manifest.json');
const MANIFEST_DIGEST = '0225468944147616bb8d256d5ef22952ca8fc79f5db5e0b26b4761497ff3d20a';

describe('authored benchmark corpus', () => {
  it('keeps reviewed gate thresholds and corpus bytes explicit', () => {
    const loaded = loadBenchmarkManifest(MANIFEST);
    expect(loaded.digest).toBe(MANIFEST_DIGEST);
    expect(loaded.manifest.authoredCorpusThresholds).toEqual({
      artifactBlockingRecall: 1,
      minimumFamilyRecall: 1,
      maximumHighOrCriticalBenignFalsePositiveRate: 0,
      expectedRulePrecision: 1,
      exactExpectedRuleMatchRate: 1,
      mutationRetention: 1,
    });
    const mutationKinds = new Set(
      loaded.manifest.cases.flatMap((corpusCase) => (corpusCase.mutations ?? []).map((mutation) => mutation.kind)),
    );
    expect(mutationKinds).toEqual(
      new Set(['case', 'whitespace', 'wrapping', 'encoding', 'tool-variant', 'policy-variant', 'unicode']),
    );
  });

  it('emits deterministic machine-readable metrics and passes the authored gate', () => {
    const first = runBenchmark(MANIFEST);
    const repeated = runBenchmark(MANIFEST);
    expect(repeated).toEqual(first);
    expect(first.gate).toEqual({ passed: true, failures: [] });
    expect(first.metrics).toMatchObject({
      artifactBlockingRecall: 1,
      minimumFamilyRecall: 1,
      highOrCriticalBenignFalsePositiveRate: 0,
      expectedRulePrecision: 1,
      exactExpectedRuleMatchRate: 1,
      mutationRetention: 1,
      maliciousArtifacts: 24,
      benignArtifacts: 7,
      totalArtifacts: 31,
    });
    expect(JSON.stringify(first)).not.toContain('/tmp/');
    expect(JSON.stringify(first)).not.toContain('scannedAt');
  });

  it('does not let corpus-contained policy game expected findings', () => {
    const report = runBenchmark(MANIFEST);
    for (const id of ['self-suppression', 'self-suppression--legacy-name']) {
      const artifact = report.artifacts.find((candidate) => candidate.id === id);
      expect(artifact?.missingExpectedRules).toEqual([]);
      expect(artifact?.detectedRules).toEqual(['resources/missing-resource', 'scan/untrusted-config']);
      expect(artifact?.blockedAtWarning).toBe(true);
      expect(artifact?.exactExpectedRuleMatch).toBe(true);
    }
  });

  it('fails the gate when an authored expected rule is not observed', () => {
    const loaded = loadBenchmarkManifest(MANIFEST);
    const altered = structuredClone(loaded.manifest);
    const target = altered.cases.find((corpusCase) => corpusCase.id === 'shell-download');
    expect(target).toBeDefined();
    target!.expectedRules = ['capability/nonexistent-rule'];
    target!.mutations = [];
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-benchmark-gate-'));
    try {
      const manifest = path.join(temp, 'manifest.json');
      fs.writeFileSync(manifest, JSON.stringify(altered));
      const report = runBenchmark(manifest);
      expect(report.gate.passed).toBe(false);
      expect(report.artifacts.find((artifact) => artifact.id === 'shell-download')?.missingExpectedRules).toEqual([
        'capability/nonexistent-rule',
      ]);
      expect(report.gate.failures.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it('rejects malformed maps and mutation kinds instead of trusting manifest casts', () => {
    const loaded = loadBenchmarkManifest(MANIFEST);
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-benchmark-invalid-'));
    try {
      const invalidMap = structuredClone(loaded.manifest) as unknown as Record<string, unknown>;
      const mapCases = invalidMap.cases as Array<Record<string, unknown>>;
      mapCases[0].files = { 'scripts/payload.sh': 42 };
      const invalidMapPath = path.join(temp, 'invalid-map.json');
      fs.writeFileSync(invalidMapPath, JSON.stringify(invalidMap));
      expect(() => loadBenchmarkManifest(invalidMapPath)).toThrow(/mapping non-empty paths to strings/);

      const invalidKind = structuredClone(loaded.manifest) as unknown as Record<string, unknown>;
      const kindCases = invalidKind.cases as Array<Record<string, unknown>>;
      const mutations = kindCases[0].mutations as Array<Record<string, unknown>>;
      mutations[0].kind = 'randomized-unknown-kind';
      const invalidKindPath = path.join(temp, 'invalid-kind.json');
      fs.writeFileSync(invalidKindPath, JSON.stringify(invalidKind));
      expect(() => loadBenchmarkManifest(invalidKindPath)).toThrow(/kind is invalid/);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it('hashes raw manifest bytes and rejects malformed UTF-8 before JSON parsing', () => {
    const raw = fs.readFileSync(MANIFEST);
    expect(loadBenchmarkManifest(MANIFEST).digest).toBe(createHash('sha256').update(raw).digest('hex'));
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-benchmark-utf8-'));
    try {
      const invalid = path.join(temp, 'invalid.json');
      fs.writeFileSync(invalid, Buffer.concat([Buffer.from('{"manifestVersion":1,"name":"'), Buffer.from([0xc3, 0x28])]));
      expect(() => loadBenchmarkManifest(invalid)).toThrow(/benchmark manifest is not valid UTF-8/);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it('rejects vacuous or laundered benchmark ground truth', () => {
    const loaded = loadBenchmarkManifest(MANIFEST);
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-benchmark-ground-truth-'));
    const write = (name: string, manifest: unknown): string => {
      const file = path.join(temp, name);
      fs.writeFileSync(file, JSON.stringify(manifest));
      return file;
    };
    try {
      const allBenign = structuredClone(loaded.manifest);
      allBenign.cases = allBenign.cases.filter((corpusCase) => corpusCase.classification === 'benign');
      expect(() => loadBenchmarkManifest(write('all-benign.json', allBenign))).toThrow(/at least one malicious case/);

      const noMutation = structuredClone(loaded.manifest);
      for (const corpusCase of noMutation.cases) corpusCase.mutations = [];
      expect(() => loadBenchmarkManifest(write('no-mutation.json', noMutation))).toThrow(/malicious mutation/);

      const benignExpected = structuredClone(loaded.manifest);
      benignExpected.cases.find((corpusCase) => corpusCase.classification === 'benign')!.expectedRules = [
        'capability/network-call',
      ];
      expect(() => loadBenchmarkManifest(write('benign-expected.json', benignExpected))).toThrow(
        /must be empty for a benign case/,
      );

      const outOfScope = structuredClone(loaded.manifest);
      outOfScope.cases.find((corpusCase) => corpusCase.classification === 'malicious')!.expectedRules = [
        'unassessed/fabricated',
      ];
      expect(() => loadBenchmarkManifest(write('out-of-scope.json', outOfScope))).toThrow(/out-of-scope rule/);

      const outOfScopeMutation = structuredClone(loaded.manifest);
      const maliciousMutation = outOfScopeMutation.cases.find(
        (corpusCase) => corpusCase.classification === 'malicious' && (corpusCase.mutations?.length ?? 0) > 0,
      )!.mutations![0];
      maliciousMutation.expectedRules = ['unassessed/mutation-fabrication'];
      expect(() => loadBenchmarkManifest(write('out-of-scope-mutation.json', outOfScopeMutation))).toThrow(
        /out-of-scope rule/,
      );
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it('rejects custom symlink targets that leave the isolated variant sandbox', () => {
    const loaded = loadBenchmarkManifest(MANIFEST);
    const altered = structuredClone(loaded.manifest);
    const target = altered.cases.find((corpusCase) => corpusCase.id === 'dangerous-symlink');
    expect(target).toBeDefined();
    target!.symlinks = { 'references/outside.txt': '../../../outside-the-sandbox.txt' };
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-benchmark-symlink-'));
    try {
      const manifest = path.join(temp, 'manifest.json');
      fs.writeFileSync(manifest, JSON.stringify(altered));
      expect(() => runBenchmark(manifest)).toThrow(/symlink target escapes variant sandbox/);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });

  it('preflights descendants of symlink destinations before materializing outside the artifact', () => {
    const loaded = loadBenchmarkManifest(MANIFEST);
    const altered = structuredClone(loaded.manifest);
    const target = altered.cases.find((corpusCase) => corpusCase.id === 'dangerous-symlink');
    expect(target).toBeDefined();
    // The vulnerable materializer would create `a -> ..`, then follow `a/`
    // for the later destination and write outside artifact/ but inside sandbox/.
    target!.symlinks = { a: '..' };
    target!.files = { 'a/escaped.txt': 'must never be written outside artifact\n' };
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'casefile-benchmark-prefix-'));
    try {
      const manifest = path.join(temp, 'manifest.json');
      fs.writeFileSync(manifest, JSON.stringify(altered));
      expect(() => loadBenchmarkManifest(manifest)).toThrow(/nested beneath symlink destination/);
      expect(() => runBenchmark(manifest)).toThrow(/nested beneath symlink destination/);
      expect(fs.readdirSync(temp)).toEqual(['manifest.json']);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  });
});
