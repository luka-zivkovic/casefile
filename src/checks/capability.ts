/**
 * Capability audit: declared tool access, hooks that execute shell commands,
 * and bundled scripts scanned for network calls, pipe-to-shell, secret env
 * reads, out-of-tree writes, destructive deletes, and eval/exec of downloaded
 * content.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseFrontmatter } from '../frontmatter.js';
import type { Finding } from '../types.js';
import { isBinaryFile } from '../walk.js';
import { finding, relTo, type CheckContext } from './context.js';

const SCRIPT_EXTENSIONS = new Set([
  '.sh', '.bash', '.zsh', '.py', '.js', '.mjs', '.cjs', '.ts', '.rb', '.pl', '.ps1',
]);

interface LineRule {
  ruleId: string;
  severity: 'critical' | 'warning';
  pattern: RegExp;
  message: string;
}

// Order matters: the first matching rule in a category wins per line, and
// critical pipe-to-shell / eval-of-download rules must outrank the plain
// network-call rule.
const LINE_RULES: LineRule[] = [
  {
    ruleId: 'capability/pipe-to-shell',
    severity: 'critical',
    pattern: /\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|python3?|node|perl|ruby)\b/,
    message: 'downloads content and pipes it directly into an interpreter',
  },
  {
    ruleId: 'capability/eval-download',
    severity: 'critical',
    pattern:
      /(\b(eval|source|exec)\b[^\n]*\$\(\s*(curl|wget)\b)|(\b(sh|bash|zsh)\s+(-c\s+)?["']?\$\(\s*(curl|wget)\b)|(\b(sh|bash|zsh)\s+<\(\s*(curl|wget)\b)|(\beval\s*\(\s*(await\s+)?(fetch|.*\.(text|body))\b)/,
    message: 'evaluates or executes downloaded content',
  },
  {
    ruleId: 'capability/network-call',
    severity: 'warning',
    pattern:
      /(\b(curl|wget)\b)|(\bfetch\s*\()|(\bhttps?\.(request|get)\s*\()|(\burllib\.request\b)|(\brequests\.(get|post|put|delete|request)\b)|(\bXMLHttpRequest\b)|(\bnet\.(connect|createConnection)\b)|(\bsocket\.socket\b)/,
    message: 'makes a network call',
  },
  {
    ruleId: 'capability/secret-env-read',
    severity: 'warning',
    pattern:
      /(\$\{?[A-Z0-9_]*(API_?KEY|TOKEN|SECRET|PASSW(OR)?D|CREDENTIALS?)[A-Z0-9_]*\}?)|((process\.env|os\.environ|getenv)\s*[[(.]?\s*['"`]?[A-Za-z0-9_]*(API_?KEY|TOKEN|SECRET|PASSW(OR)?D|CREDENTIALS?)[A-Za-z0-9_]*)/i,
    message: 'reads a secret-looking environment variable (API key / token / secret)',
  },
  {
    ruleId: 'capability/destructive-delete',
    severity: 'critical',
    pattern: /\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*\s+)*-?[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+["']?(\/(\s|$|["'])|\$HOME\b|~\/?(\s|$))/,
    message: 'recursive force-delete of a root or home directory',
  },
  {
    ruleId: 'capability/rm-rf',
    severity: 'warning',
    pattern: /\brm\s+(-[a-zA-Z]*)*-[a-zA-Z]*(rf|fr)[a-zA-Z]*\b/,
    message: 'uses rm -rf (recursive force delete)',
  },
  {
    ruleId: 'capability/write-outside-artifact',
    severity: 'warning',
    pattern:
      /((>>?\s*)(\/(?!tmp\b|dev\/null)[A-Za-z0-9_.-]|~\/|\$HOME\b))|(\b(cp|mv|tee|install)\b[^\n]*\s(\/(?!tmp\b|dev\/null)[A-Za-z0-9_.-][^\s]*|~\/[^\s]+|\$HOME[^\s]*))/,
    message: 'writes to an absolute or home path outside the artifact directory',
  },
];

function scanText(text: string, relFile: string, context: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>(); // one finding per (rule, file)
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith('#') && !trimmed.startsWith('#!')) continue; // shell/python comments
    if (trimmed.startsWith('//')) continue;
    // A pipe-to-shell / eval-download match on THIS line subsumes the generic
    // network-call rule for THIS line only (other lines still report freely).
    let networkSubsumedHere = false;
    for (const rule of LINE_RULES) {
      if (rule.ruleId === 'capability/network-call' && networkSubsumedHere) continue;
      if (seen.has(rule.ruleId)) continue;
      if (rule.pattern.test(line)) {
        seen.add(rule.ruleId);
        findings.push(finding(rule.ruleId, rule.severity, `${context} ${rule.message}`, relFile, i + 1));
        if (rule.ruleId === 'capability/pipe-to-shell' || rule.ruleId === 'capability/eval-download') {
          networkSubsumedHere = true;
        }
      }
    }
  }
  return findings;
}

function isScriptFile(abs: string, rel: string): boolean {
  const ext = path.extname(abs).toLowerCase();
  if (SCRIPT_EXTENSIONS.has(ext)) return true;
  if (ext !== '') return false;
  // Extensionless files: treat as script when executable or shebanged.
  try {
    const stat = fs.statSync(abs);
    if (!stat.isFile()) return false;
    if ((stat.mode & 0o111) !== 0 && !isBinaryFile(abs)) return true;
    const fd = fs.openSync(abs, 'r');
    try {
      const buf = Buffer.alloc(2);
      const n = fs.readSync(fd, buf, 0, 2, 0);
      return n === 2 && buf.toString('utf-8') === '#!';
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return false;
  }
}

interface HookCommand {
  event: string;
  command: string;
}

function extractHookCommands(parsed: unknown): HookCommand[] {
  const out: HookCommand[] = [];
  if (typeof parsed !== 'object' || parsed === null) return out;
  const hooks = (parsed as Record<string, unknown>)['hooks'] ?? parsed;
  if (typeof hooks !== 'object' || hooks === null) return out;
  for (const [event, matchers] of Object.entries(hooks as Record<string, unknown>)) {
    if (!Array.isArray(matchers)) continue;
    for (const matcher of matchers) {
      const inner = (matcher as Record<string, unknown>)?.['hooks'];
      if (!Array.isArray(inner)) continue;
      for (const hook of inner) {
        const h = hook as Record<string, unknown>;
        if (h?.['type'] === 'command' && typeof h['command'] === 'string') {
          out.push({ event, command: h['command'] });
        }
      }
    }
  }
  return out;
}

export function capabilityCheck(ctx: CheckContext): Finding[] {
  const findings: Finding[] = [];

  // 1. Declared allowed-tools in skill frontmatter.
  for (const skill of ctx.skills) {
    const skillFile = path.join(skill.dir, 'SKILL.md');
    if (!fs.existsSync(skillFile)) continue;
    const relSkill = relTo(ctx.root, skillFile);
    let fm: Record<string, string>;
    try {
      ({ frontmatter: fm } = parseFrontmatter(fs.readFileSync(skillFile, 'utf-8')));
    } catch {
      continue;
    }
    const tools = fm['allowed-tools'];
    if (tools) {
      findings.push(finding('capability/allowed-tools', 'info', `skill declares allowed-tools: ${tools}`, relSkill));
      if (/(^|\s|,)\*(\s|,|$)/.test(tools) || /\bBash\b(?!\s*\()/.test(tools)) {
        findings.push(
          finding(
            'capability/broad-tools',
            'warning',
            'skill requests unscoped shell access (Bash without a command scope, or wildcard tools)',
            relSkill,
          ),
        );
      }
    }
  }

  // 2. Hooks that execute shell commands.
  for (const entry of ctx.files) {
    if (entry.isSymlink) continue;
    if (!/(^|\/)hooks\/.*\.json$|(^|\/)hooks\.json$/.test(entry.rel)) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(fs.readFileSync(entry.abs, 'utf-8'));
    } catch {
      findings.push(finding('capability/hook-json-invalid', 'warning', 'hook file is not valid JSON', entry.rel));
      continue;
    }
    for (const hook of extractHookCommands(parsed)) {
      const preview = hook.command.length > 100 ? hook.command.slice(0, 100) + '…' : hook.command;
      findings.push(
        finding(
          'capability/hook-shell-command',
          'warning',
          `${hook.event} hook executes a shell command automatically: ${preview}`,
          entry.rel,
        ),
      );
      findings.push(...scanText(hook.command, entry.rel, `${hook.event} hook command`));
    }
  }

  // 3. Bundled scripts.
  for (const entry of ctx.files) {
    if (entry.isSymlink) continue;
    if (!isScriptFile(entry.abs, entry.rel)) continue;
    if (isBinaryFile(entry.abs)) continue;
    const text = fs.readFileSync(entry.abs, 'utf-8');
    findings.push(...scanText(text, entry.rel, 'bundled script'));
  }

  return findings;
}
