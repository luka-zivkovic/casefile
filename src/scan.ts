import { isIgnored, loadConfig } from './config.js';
import { discover } from './discover.js';
import { contentHashResult } from './hash.js';
import { buildReport } from './report.js';
import type { Finding, Report } from './types.js';
import { walkArtifact } from './walk.js';
import { capabilityCheck } from './checks/capability.js';
import { finding, type CheckContext } from './checks/context.js';
import { injectionCheck } from './checks/injection.js';
import { qualityCheck } from './checks/quality.js';
import { resourceCheck } from './checks/resources.js';
import { structuralCheck } from './checks/structural.js';
import { supplyChainCheck } from './checks/supplychain.js';

const CHECKS = [structuralCheck, resourceCheck, qualityCheck, capabilityCheck, supplyChainCheck, injectionCheck];

const INCOMPLETE_ANALYSIS_RULES = new Set([
  'scan/config-invalid',
  'scan/file-too-large',
  'scan/line-truncated',
  'scan/invalid-utf8',
  'scan/identity-incomplete',
  'scan/unreadable-directory',
  'scan/unreadable-file',
]);

export interface ScanOptions {
  /** Explicit operator-owned suppression policy. */
  configPath?: string;
  /** Explicit opt-in to the insecure pre-0.2 artifact-local policy behavior. */
  trustArtifactConfig?: boolean;
  /** Turn any skipped/truncated/unreadable analysis into a critical finding. */
  strict?: boolean;
}

/**
 * Statically scan a skill dir, plugin dir, or marketplace root.
 * Throws DiscoveryError when the path cannot be classified.
 */
export function scanArtifact(inputPath: string, options: ScanOptions = {}): Report {
  const discovered = discover(inputPath);
  const walked = walkArtifact(discovered.root);
  const hashed = contentHashResult(discovered.root, walked);
  const ctx: CheckContext = {
    root: discovered.root,
    type: discovered.type,
    skills: discovered.skills,
    plugins: discovered.plugins,
    files: walked.files,
  };
  const findings = CHECKS.flatMap((check) => check(ctx));
  for (const gap of walked.gaps.filter((gap) => gap.kind === 'directory')) {
    findings.push(
      finding(
        'scan/unreadable-directory',
        'info',
        `directory could not be enumerated (${gap.code}); artifact identity and analysis are incomplete`,
        gap.rel,
      ),
    );
  }
  for (const gap of hashed.gaps.filter((gap) => gap.kind !== 'directory')) {
    findings.push(
      finding(
        'scan/identity-incomplete',
        'info',
        `${gap.kind} could not be hashed (${gap.code}); artifact identity is incomplete`,
        gap.rel,
      ),
    );
  }

  const config = loadConfig(discovered.root, {
    configPath: options.configPath,
    trustArtifactConfig: options.trustArtifactConfig,
  });
  if (config.ignoredArtifactConfig) {
    findings.push(
      finding(
        'scan/untrusted-config',
        'info',
        'artifact-local suppression policy was not trusted; pass an operator-owned --config or explicitly opt in to legacy behavior',
        config.ignoredArtifactConfig,
      ),
    );
  }
  if (config.error) {
    findings.push(
      finding(
        'scan/config-invalid',
        'info',
        config.error,
        config.file ?? '<operator-config>',
      ),
    );
  }
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) (isIgnored(f, config) ? suppressed : active).push(f);

  if (options.strict) {
    const seen = new Set<string>();
    for (const gap of findings.filter((f) => INCOMPLETE_ANALYSIS_RULES.has(f.ruleId))) {
      const key = `${gap.ruleId}\0${gap.file}\0${gap.line ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      active.push(
        finding(
          'scan/incomplete-analysis',
          'critical',
          `strict mode requires complete analysis; ${gap.ruleId} occurred`,
          gap.file,
          gap.line,
        ),
      );
    }
  }

  return buildReport(
    { type: discovered.type, path: discovered.root, contentHash: hashed.digest },
    active,
    ctx.files.length,
    suppressed,
    {
      source: config.source,
      strict: options.strict ?? false,
      ...(config.contentHash === undefined ? {} : { contentHash: config.contentHash }),
    },
  );
}
