import { isIgnored, loadConfig } from './config.js';
import { discover } from './discover.js';
import { contentHash } from './hash.js';
import { buildReport } from './report.js';
import type { Finding, Report } from './types.js';
import { walkFiles } from './walk.js';
import { capabilityCheck } from './checks/capability.js';
import { finding, type CheckContext } from './checks/context.js';
import { injectionCheck } from './checks/injection.js';
import { resourceCheck } from './checks/resources.js';
import { structuralCheck } from './checks/structural.js';
import { supplyChainCheck } from './checks/supplychain.js';

const CHECKS = [structuralCheck, resourceCheck, capabilityCheck, supplyChainCheck, injectionCheck];

/**
 * Statically scan a skill dir, plugin dir, or marketplace root.
 * Throws DiscoveryError when the path cannot be classified.
 */
export function scanArtifact(inputPath: string): Report {
  const discovered = discover(inputPath);
  const ctx: CheckContext = {
    root: discovered.root,
    type: discovered.type,
    skills: discovered.skills,
    plugins: discovered.plugins,
    files: walkFiles(discovered.root),
  };
  const findings = CHECKS.flatMap((check) => check(ctx));

  const config = loadConfig(discovered.root);
  if (config.error) {
    findings.push(finding('scan/config-invalid', 'info', config.error, 'skillguard.config.json'));
  }
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) (isIgnored(f, config) ? suppressed : active).push(f);

  return buildReport(
    { type: discovered.type, path: discovered.root, contentHash: contentHash(discovered.root) },
    active,
    ctx.files.length,
    suppressed,
  );
}
