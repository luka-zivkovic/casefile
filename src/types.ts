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
  /** sha256 over canonical typed path/digest tuples for every artifact entry. */
  contentHash: string;
}

export interface ReportSummary {
  critical: number;
  warning: number;
  info: number;
  total: number;
  /** Findings suppressed via trusted operator policy (not counted above). */
  suppressed: number;
  filesScanned: number;
}

export interface ReportPolicy {
  /** No suppressions, explicit operator policy, or explicit legacy opt-in. */
  source: 'none' | 'explicit' | 'artifact-legacy';
  /** Fail closed when any content analysis is incomplete. */
  strict: boolean;
  /** SHA-256 of the exact trusted policy bytes, when policy was loaded. */
  contentHash?: string;
}

export interface ReportIdentity {
  algorithm: 'sha256';
  /** Digest of canonical report content, excluding time and absolute paths. */
  digest: string;
}

export interface Report {
  reportVersion: 2;
  tool: { name: string; version: string };
  scannedAt: string;
  artifact: Artifact;
  policy: ReportPolicy;
  findings: Finding[];
  /** Findings matched by a trusted suppression-policy rule: still listed,
   * but excluded from the summary counts and exit-code evaluation. */
  suppressed: Finding[];
  summary: ReportSummary;
  /** Stable identity suitable for future locking/signing. */
  identity: ReportIdentity;
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
