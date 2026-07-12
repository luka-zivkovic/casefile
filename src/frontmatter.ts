/**
 * Tolerant YAML-ish frontmatter parser, ported faithfully from
 * overclock/tools/validate_skill.py.
 *
 * Rules (matching the real-world tolerance of the Python original):
 * - Frontmatter must open with `---` on the first line and close with a `---` line.
 * - Only top-level `key:` lines become entries.
 * - A value that is exactly a block-scalar indicator (`>`, `|`, `>-`, `|-`, `>+`, `|+`)
 *   starts a block scalar; subsequent indented lines are joined with single spaces.
 * - List items (`- value`) under a key with an empty value are captured and
 *   joined with `, ` — so `allowed-tools:\n  - "*"` yields `allowed-tools: "*"`
 *   and cannot bypass checks that inspect the value.
 * - Indented lines under a non-block key (nested maps) are opaque and ignored.
 * - Surrounding single/double quotes on plain values are stripped.
 */

const BLOCK_SCALAR = new Set(['>', '|', '>-', '|-', '>+', '|+']);

/** Optional leading `plugin:` namespace, then lowercase/digits/hyphens. */
export const NAME_RE = /^([a-z0-9][a-z0-9-]*:)?[a-z0-9][a-z0-9-]{0,62}$/;

export class FrontmatterError extends Error {}

export interface ParsedSkill {
  frontmatter: Record<string, string>;
  body: string;
  /** 1-indexed line where the body starts (line after closing ---). */
  bodyStartLine: number;
}

function stripQuotes(value: string): string {
  return value.replace(/^['"]+|['"]+$/g, '');
}

export function parseFrontmatter(text: string): ParsedSkill {
  const lines = text.split(/\r?\n/);
  if (lines.length === 0 || lines[0].trim() !== '---') {
    throw new FrontmatterError('SKILL.md must start with YAML frontmatter delimited by ---');
  }
  let end = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === '---') {
      end = i;
      break;
    }
  }
  if (end === -1) {
    throw new FrontmatterError('SKILL.md must contain a closing --- frontmatter delimiter');
  }

  const data: Record<string, string> = {};
  let cur: string | null = null;
  let inBlock = false;
  let inList = false;
  for (const line of lines.slice(1, end)) {
    if (!line.trim()) continue;
    // A list item under the current key: `- value` (indented or not).
    const li = /^\s*-\s+(.*)$/.exec(line);
    if (li && cur !== null && !inBlock && (inList || data[cur] === '')) {
      const item = stripQuotes(li[1].trim());
      data[cur] = data[cur] === '' ? item : `${data[cur]}, ${item}`;
      inList = true;
      continue;
    }
    const m = /^(\S[^:]*?):(.*)$/.exec(line);
    if (m && !/^\s/.test(line)) {
      // A top-level key.
      const key = m[1].trim();
      const val = m[2].trim();
      inList = false;
      if (BLOCK_SCALAR.has(val)) {
        data[key] = '';
        cur = key;
        inBlock = true;
      } else {
        data[key] = stripQuotes(val);
        cur = key;
        inBlock = false;
      }
    } else if (cur !== null && inBlock) {
      // Continuation of a block scalar.
      data[cur] = (data[cur] + ' ' + line.trim()).trim();
    }
    // else: nested map under a non-block key — opaque, ignored.
  }
  return { frontmatter: data, body: lines.slice(end + 1).join('\n'), bodyStartLine: end + 2 };
}
