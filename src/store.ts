import Database from 'better-sqlite3';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Report } from './types.js';

export function defaultDbPath(): string {
  return path.join(os.homedir(), '.skillguard', 'skillguard.db');
}

export interface HistoryRow {
  content_hash: string;
  scanned_at: string;
  artifact_type: string;
  path: string;
  report_json: string;
}

export class ReportStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content_hash TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        artifact_type TEXT NOT NULL,
        path TEXT NOT NULL,
        report_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_reports_path ON reports(path);
      CREATE INDEX IF NOT EXISTS idx_reports_hash ON reports(content_hash);
    `);
  }

  save(report: Report): void {
    this.db
      .prepare(
        'INSERT INTO reports (content_hash, scanned_at, artifact_type, path, report_json) VALUES (?, ?, ?, ?, ?)',
      )
      .run(
        report.artifact.contentHash,
        report.scannedAt,
        report.artifact.type,
        report.artifact.path,
        JSON.stringify(report),
      );
  }

  /** Prior scans for an artifact path (newest first). */
  history(artifactPath: string): HistoryRow[] {
    const resolved = path.resolve(artifactPath);
    return this.db
      .prepare('SELECT content_hash, scanned_at, artifact_type, path, report_json FROM reports WHERE path = ? ORDER BY scanned_at DESC, id DESC')
      .all(resolved) as HistoryRow[];
  }

  close(): void {
    this.db.close();
  }
}
