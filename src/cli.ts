#!/usr/bin/env node
/**
 * casefile CLI.
 *
 * Exit codes:
 *   0 — scan completed, no findings at or above the --fail-on threshold
 *   1 — scan completed, findings at or above the --fail-on threshold
 *   2 — scan error (bad path, unclassifiable artifact, I/O failure)
 */
import { Command, Option } from 'commander';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { DiscoveryError } from './discover.js';
import { renderMarkdown, TOOL_VERSION } from './report.js';
import { scanArtifact } from './scan.js';
import { defaultDbPath, ReportStore } from './store.js';
import type { Report } from './types.js';

type FailOn = 'critical' | 'warning' | 'none';

function shouldFail(report: Report, failOn: FailOn): boolean {
  if (failOn === 'none') return false;
  if (failOn === 'critical') return report.summary.critical > 0;
  return report.summary.critical > 0 || report.summary.warning > 0;
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
  .option('--out <file>', 'also write the report to a file')
  .option('--db <path>', 'sqlite store for scan history', defaultDbPath())
  .addOption(
    new Option('--fail-on <level>', 'exit 1 when findings at/above this severity exist')
      .choices(['critical', 'warning', 'none'])
      .default('critical'),
  )
  .option('--no-store', 'do not record this scan in the history store')
  .action((inputPath: string, opts: { json: boolean; out?: string; db: string; failOn: FailOn; store: boolean }) => {
    let report: Report;
    try {
      report = scanArtifact(inputPath);
    } catch (err) {
      const message = err instanceof DiscoveryError ? err.message : `scan failed: ${(err as Error).message}`;
      console.error(`casefile: ${message}`);
      process.exitCode = 2;
      return;
    }

    if (opts.store) {
      try {
        const store = new ReportStore(opts.db);
        store.save(report);
        store.close();
      } catch (err) {
        // History persistence is best-effort; the scan result stands on its own.
        console.error(`casefile: warning: could not record scan history: ${(err as Error).message}`);
      }
    }

    const output = opts.json ? JSON.stringify(report, null, 2) : renderMarkdown(report);
    console.log(output);
    if (opts.out) {
      fs.writeFileSync(path.resolve(opts.out), output + '\n', 'utf-8');
    }
    process.exitCode = shouldFail(report, opts.failOn) ? 1 : 0;
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
