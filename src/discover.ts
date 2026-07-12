import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ArtifactType, PluginRef, SkillRef } from './types.js';
import { SKIP_DIRS, VENDORED_DIRS } from './walk.js';

export class DiscoveryError extends Error {}

export interface DiscoveredArtifact {
  type: ArtifactType;
  /** Absolute artifact root. */
  root: string;
  skills: SkillRef[];
  plugins: PluginRef[];
}

function isSkillDir(dir: string): boolean {
  return fs.existsSync(path.join(dir, 'SKILL.md'));
}

function isPluginDir(dir: string): boolean {
  return fs.existsSync(path.join(dir, '.claude-plugin', 'plugin.json'));
}

function isMarketplaceRoot(dir: string): boolean {
  if (fs.existsSync(path.join(dir, '.claude-plugin', 'marketplace.json'))) return true;
  const pluginsDir = path.join(dir, 'plugins');
  if (!fs.existsSync(pluginsDir)) return false;
  try {
    return fs
      .readdirSync(pluginsDir, { withFileTypes: true })
      .some((e) => e.isDirectory() && isPluginDir(path.join(pluginsDir, e.name)));
  } catch {
    return false;
  }
}

/**
 * Find every real SKILL.md under `root`, pruning `.git` and vendored dirs.
 * A SKILL.md inside node_modules etc. is third-party code: its files are
 * still content-scanned and hashed, but it is not treated as one of the
 * artifact's own skills for structural/resource quality rules.
 */
function findSkillDirs(root: string): string[] {
  const found: string[] = [];
  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    if (entries.some((e) => e.isFile() && e.name === 'SKILL.md')) found.push(dir);
    for (const e of entries) {
      if (e.isDirectory() && !e.isSymbolicLink() && !SKIP_DIRS.has(e.name) && !VENDORED_DIRS.has(e.name)) {
        walk(path.join(dir, e.name));
      }
    }
  };
  walk(root);
  return found.sort();
}

function pluginNameFor(skillDir: string, pluginRoot: string): string | undefined {
  try {
    const raw = fs.readFileSync(path.join(pluginRoot, '.claude-plugin', 'plugin.json'), 'utf-8');
    const parsed = JSON.parse(raw) as { name?: string };
    if (typeof parsed.name === 'string') return parsed.name;
  } catch {
    /* fall through */
  }
  return path.basename(pluginRoot);
}

function skillsOfPlugin(pluginRoot: string): SkillRef[] {
  return findSkillDirs(pluginRoot).map((dir) => ({
    dir,
    plugin: pluginNameFor(dir, pluginRoot),
  }));
}

/**
 * Classify `inputPath` as a skill dir, plugin dir, or marketplace root and
 * enumerate the skills/plugins it contains.
 */
export function discover(inputPath: string): DiscoveredArtifact {
  const root = path.resolve(inputPath);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(root);
  } catch {
    throw new DiscoveryError(`path does not exist: ${root}`);
  }
  if (!stat.isDirectory()) {
    throw new DiscoveryError(`path is not a directory: ${root}`);
  }

  if (isSkillDir(root) && !isPluginDir(root)) {
    return { type: 'skill', root, skills: [{ dir: root }], plugins: [] };
  }
  if (isPluginDir(root)) {
    return { type: 'plugin', root, skills: skillsOfPlugin(root), plugins: [{ dir: root }] };
  }
  if (isMarketplaceRoot(root)) {
    const pluginsDir = path.join(root, 'plugins');
    const plugins: PluginRef[] = [];
    if (fs.existsSync(pluginsDir)) {
      for (const e of fs.readdirSync(pluginsDir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
        const dir = path.join(pluginsDir, e.name);
        if (e.isDirectory() && isPluginDir(dir)) plugins.push({ dir });
      }
    }
    const skills = plugins.flatMap((p) => skillsOfPlugin(p.dir));
    return { type: 'marketplace', root, skills, plugins };
  }
  throw new DiscoveryError(
    `cannot classify ${root}: expected a skill dir (SKILL.md), a plugin dir (.claude-plugin/plugin.json), or a marketplace root`,
  );
}
