#!/usr/bin/env node
/**
 * casefile CLI.
 *
 * Exit codes:
 *   0 — requested operation completed / lock verification is exact
 *   1 — scan gate failed or a valid lock has drifted
 *   2 — invalid lock or operational error
 */
import { Command, Option } from 'commander';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { DiscoveryError } from './discover.js';
import { createLock, LockValidationError, parseLock, verifyArtifact } from './lock.js';
import { atomicWriteText, validateExternalDestination, type SafeDestination } from './output.js';
import { renderMarkdown, TOOL_VERSION } from './report.js';
import { renderSarif } from './sarif.js';
import { scanArtifact } from './scan.js';
import { defaultDbPath, ReportStore } from './store.js';
import type { Report } from './types.js';

type FailOn = 'critical' | 'warning' | 'none';

function shouldFail(report: Report, failOn: FailOn): boolean {
  if (failOn === 'none') return false;
  if (failOn === 'critical') return report.summary.critical > 0;
  return report.summary.critical > 0 || report.summary.warning > 0;
}

function errorMessage(error: unknown): string {
  if (error instanceof LockValidationError) return `invalid lock: ${error.message}`;
  if (error instanceof DiscoveryError) return error.message;
  return (error as Error).message;
}

const program = new Command();
program
  .name('casefile')
  .description('npm audit for agent capabilities — static scanner for Claude Code skills and plugins')
  .version(TOOL_VERSION);

program
  .command('scan')
  .description('scan a skill dir, plugin dir, or marketplace root')
  .argument('<path>', 'path to the artifact')
  .option('--json', 'emit the machine-readable JSON report instead of text', false)
  .option('--sarif', 'emit SARIF 2.1.0 for security tooling (cannot be combined with --json)', false)
  .option('--out <file>', 'also write the report to a file')
  .option('--db <path>', 'sqlite store for scan history', defaultDbPath())
  .option('--config <file>', 'operator-owned suppression policy (artifact-local policy is ignored by default)')
  .option('--trust-artifact-config', 'explicitly use legacy artifact-local suppressions', false)
  .option('--strict', 'fail closed when any file analysis is skipped, truncated, or unreadable', false)
  .addOption(
    new Option('--fail-on <level>', 'exit 1 when findings at/above this severity exist')
      .choices(['critical', 'warning', 'none'])
      .default('critical'),
  )
  .option('--no-store', 'do not record this scan in the history store')
  .action((inputPath: string, opts: {
    json: boolean;
    sarif: boolean;
    out?: string;
    db: string;
    config?: string;
    trustArtifactConfig: boolean;
    strict: boolean;
    failOn: FailOn;
    store: boolean;
  }) => {
    if (opts.json && opts.sarif) {
      console.error('casefile: --json and --sarif are mutually exclusive');
      process.exitCode = 2;
      return;
    }
    let report: Report;
    try {
      report = scanArtifact(inputPath, {
        configPath: opts.config,
        trustArtifactConfig: opts.trustArtifactConfig,
        strict: opts.strict,
      });
    } catch (err) {
      const message = err instanceof DiscoveryError ? err.message : `scan failed: ${(err as Error).message}`;
      console.error(`casefile: ${message}`);
      process.exitCode = 2;
      return;
    }

    let outputDestination: SafeDestination | undefined;
    let databaseDestination: SafeDestination | undefined;
    try {
      if (opts.out !== undefined) {
        outputDestination = validateExternalDestination(opts.out, report.artifact.path, 'report output');
      }
      if (opts.store) {
        databaseDestination = validateExternalDestination(opts.db, report.artifact.path, 'history database');
      }
    } catch (error) {
      console.error(`casefile: ${errorMessage(error)}`);
      process.exitCode = 2;
      return;
    }

    const output = opts.sarif ? renderSarif(report) : opts.json ? JSON.stringify(report, null, 2) : renderMarkdown(report);
    if (outputDestination !== undefined) {
      try {
        atomicWriteText(outputDestination, output + '\n');
      } catch (error) {
        console.error(`casefile: could not write report atomically: ${errorMessage(error)}`);
        process.exitCode = 2;
        return;
      }
    }

    if (opts.store) {
      try {
        const store = new ReportStore(databaseDestination!.path);
        store.save(report);
        store.close();
      } catch (err) {
        // History persistence is best-effort; the scan result stands on its own.
        console.error(`casefile: warning: could not record scan history: ${(err as Error).message}`);
      }
    }

    console.log(output);
    process.exitCode = shouldFail(report, opts.failOn) ? 1 : 0;
  });

program
  .command('lock')
  .description('scan an artifact and write a deterministic evidence lock')
  .argument('<path>', 'path to the artifact')
  .requiredOption('--out <file>', 'lock file to write (must be outside the scanned artifact)')
  .option('--config <file>', 'operator-owned suppression policy')
  .option('--strict', 'fail closed when any file analysis is skipped, truncated, or unreadable', false)
  .action((inputPath: string, opts: { out: string; config?: string; strict: boolean }) => {
    try {
      // Lock workflows deliberately have no artifact-policy opt-in.
      const report = scanArtifact(inputPath, { configPath: opts.config, strict: opts.strict });
      const lock = createLock(report);
      const output = validateExternalDestination(opts.out, report.artifact.path, 'lock output');
      atomicWriteText(output, JSON.stringify(lock, null, 2) + '\n');
      console.log(`casefile lock: wrote ${output.path} (sha256:${lock.digest.digest})`);
      process.exitCode = 0;
    } catch (error) {
      console.error(`casefile: ${errorMessage(error)}`);
      process.exitCode = 2;
    }
  });

program
  .command('verify')
  .description('re-scan an artifact and compare it with a validated evidence lock')
  .argument('<path>', 'path to the artifact')
  .requiredOption('--lock <file>', 'lock file to validate and compare')
  .option('--config <file>', 'current operator-owned suppression policy')
  .option('--strict', 'use strict complete-analysis mode for the current scan', false)
  .option('--json', 'emit machine-readable verification details', false)
  .action((inputPath: string, opts: { lock: string; config?: string; strict: boolean; json: boolean }) => {
    try {
      // Authenticate the lock before discovery or scanning. The scan only uses
      // current CLI options; policy recorded in the artifact/lock is never loaded.
      const lock = parseLock(fs.readFileSync(path.resolve(opts.lock), 'utf-8'));
      const verification = verifyArtifact(inputPath, lock, {
        configPath: opts.config,
        strict: opts.strict,
      });
      if (opts.json) {
        console.log(
          JSON.stringify(
            {
              exact: verification.exact,
              lockDigest: verification.lock.digest,
              current: {
                tool: verification.report.tool,
                reportVersion: verification.report.reportVersion,
                artifact: {
                  type: verification.report.artifact.type,
                  contentHash: verification.report.artifact.contentHash,
                },
                policy: verification.report.policy,
                reportIdentity: verification.report.identity,
              },
              drift: verification.drift,
            },
            null,
            2,
          ),
        );
      } else if (verification.exact) {
        console.log(`casefile verify: exact match (sha256:${verification.lock.digest.digest})`);
      } else {
        const findings = verification.drift.findings;
        console.log('casefile verify: drift detected');
        console.log(`- artifact: ${verification.drift.artifact.changed ? 'changed' : 'unchanged'}`);
        console.log(`- policy: ${verification.drift.policy.changed ? 'changed' : 'unchanged'}`);
        console.log(`- report identity: ${verification.drift.reportIdentity.changed ? 'changed' : 'unchanged'}`);
        console.log(
          `- findings: ${findings.added.length} added, ${findings.removed.length} removed, ${findings.changed.length} changed`,
        );
      }
      process.exitCode = verification.exact ? 0 : 1;
    } catch (error) {
      console.error(`casefile: ${errorMessage(error)}`);
      process.exitCode = 2;
    }
  });

program
  .command('history')
  .description('list prior scans recorded for an artifact path')
  .argument('<path>', 'path to the artifact')
  .option('--db <path>', 'sqlite store for scan history', defaultDbPath())
  .option('--json', 'emit JSON rows', false)
  .action((inputPath: string, opts: { db: string; json: boolean }) => {
    let rows;
    try {
      const store = new ReportStore(opts.db);
      rows = store.history(inputPath);
      store.close();
    } catch (err) {
      console.error(`casefile: ${(err as Error).message}`);
      process.exitCode = 2;
      return;
    }
    if (opts.json) {
      console.log(
        JSON.stringify(
          rows.map((r) => ({
            contentHash: r.content_hash,
            scannedAt: r.scanned_at,
            artifactType: r.artifact_type,
            path: r.path,
            summary: (JSON.parse(r.report_json) as Report).summary,
          })),
          null,
          2,
        ),
      );
      return;
    }
    if (rows.length === 0) {
      console.log(`No recorded scans for ${path.resolve(inputPath)}`);
      return;
    }
    for (const r of rows) {
      const summary = (JSON.parse(r.report_json) as Report).summary;
      console.log(
        `${r.scanned_at}  ${r.artifact_type.padEnd(11)}  sha256:${r.content_hash.slice(0, 12)}…  ` +
          `${summary.critical} critical / ${summary.warning} warning / ${summary.info} info`,
      );
    }
  });

program.parse();
