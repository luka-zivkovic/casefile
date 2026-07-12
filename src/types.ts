export type Severity = 'critical' | 'warning' | 'info';

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  /** Path relative to the scanned artifact root. */
  file: string;
  line?: number;
}

export type ArtifactType = 'skill' | 'plugin' | 'marketplace';

export interface Artifact {
  type: ArtifactType;
  /** Absolute path of the artifact root. */
  path: string;
  /** sha256 over the sorted per-file sha256 hashes. */
  contentHash: string;
}

export interface ReportSummary {
  critical: number;
  warning: number;
  info: number;
  total: number;
  /** Findings suppressed via skillguard.config.json (not counted above). */
  suppressed: number;
  filesScanned: number;
}

export interface Report {
  reportVersion: 1;
  tool: { name: string; version: string };
  scannedAt: string;
  artifact: Artifact;
  findings: Finding[];
  /** Findings matched by a skillguard.config.json ignore rule: still listed,
   * but excluded from the summary counts and exit-code evaluation. */
  suppressed: Finding[];
  summary: ReportSummary;
}

/** A skill directory discovered inside an artifact. */
export interface SkillRef {
  /** Absolute path to the skill directory (contains SKILL.md). */
  dir: string;
  /** Plugin name if the skill belongs to a plugin, else undefined. */
  plugin?: string;
}

/** A plugin directory discovered inside an artifact. */
export interface PluginRef {
  /** Absolute path to the plugin directory (contains .claude-plugin/plugin.json). */
  dir: string;
}
