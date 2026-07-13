/**
 * Prompt-injection heuristics over the artifact's model-facing text
 * (SKILL.md, markdown/text references, templates): known injection phrases,
 * imperatives hidden in HTML comments, instructions addressed to the model in
 * reference files, and zero-width / invisible unicode.
 */
import * as path from 'node:path';
import type { Finding } from '../types.js';
import { isBinaryFile } from '../walk.js';
import { finding, readTextChecked, splitLinesCapped, truncationFinding, type CheckContext } from './context.js';

const TEXT_EXT = new Set(['.md', '.markdown', '.txt', '.rst']);

const INJECTION_PHRASES: RegExp[] = [
  /ignore (all |any |your )?(previous|prior|earlier|above) (instructions|directions|rules|prompts)/i,
  /disregard (all |any |your )?(previous|prior|earlier|above|the) (instructions|directions|rules|system prompt)/i,
  /do not (tell|inform|alert|notify|warn) the (user|human)/i,
  /don'?t (tell|inform|alert|notify|warn) the (user|human)/i,
  /without (telling|informing|notifying|alerting) the (user|human)/i,
  /you must not (mention|reveal|disclose|tell)/i,
  /never (reveal|mention|disclose) (this|these instructions|the contents)/i,
  /hide (this|these instructions|the following) from the (user|human)/i,
  /do not (mention|show|display|reveal) (this|these instructions)/i,
  /pretend (this|you) (never|didn'?t)/i,
  /override (the |all |any )?(system prompt|safety|guardrails)/i,
];

const IMPERATIVE_IN_COMMENT =
  /\b(you (must|should|will|are))|\bignore\b|\bdo not\b|\bdon'?t\b|\balways\b|\bnever\b|\brun\b|\bexecute\b|\bsend\b|\bcurl\b|\bfetch\b/i;

/** Model-addressed concealment/override language in non-SKILL.md text files. */
const MODEL_ADDRESSED =
  /\b(claude|the assistant|the model|the ai|ai model|language model)\b[^.\n]{0,80}\b(must not|should not|never|secretly|silently|without (the )?user)/i;

const ZERO_WIDTH = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD]/g;
/** Pictographic (optionally with a variation selector) directly before/after an index.
 * Skin-tone modifiers (U+1F3FB\u2013U+1F3FF) are Emoji_Component, not Extended_Pictographic,
 * so they must be matched explicitly (e.g. the ZWJ in \uD83D\uDC69\uD83C\uDFFD\u200D\uD83D\uDCBB follows a skin tone). */
const EMOJI_BEFORE = /(\p{Extended_Pictographic}|[\u{1F3FB}-\u{1F3FF}])\uFE0F?$/u;
const EMOJI_AFTER = /^(\p{Extended_Pictographic}|[\u{1F3FB}-\u{1F3FF}])/u;

/** True when the char at `index` is a U+200D ZWJ acting as an emoji joiner
 * (person + ZWJ + laptop etc.), which is visible, standard unicode rather
 * than a hidden-text carrier. */
function isEmojiZwj(text: string, index: number): boolean {
  if (text[index] !== '\u200D') return false;
  return EMOJI_BEFORE.test(text.slice(Math.max(0, index - 8), index)) && EMOJI_AFTER.test(text.slice(index + 1, index + 9));
}
const BIDI_CONTROL = /[\u202A-\u202E\u2066-\u2069]/g;
/** Unicode "tag" characters (U+E0000–E007F): invisible ASCII mirror used for hidden prompts. */
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;

function isModelFacingText(rel: string): boolean {
  const base = path.basename(rel);
  if (base === 'SKILL.md') return true;
  return TEXT_EXT.has(path.extname(rel).toLowerCase());
}

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split('\n').length;
}

export function injectionCheck(ctx: CheckContext): Finding[] {
  const findings: Finding[] = [];

  for (const entry of ctx.files) {
    if (entry.isSymlink) continue;
    if (!isModelFacingText(entry.rel)) continue;
    if (isBinaryFile(entry.abs)) continue;
    const text = readTextChecked(entry, findings);
    if (text === null) continue;
    const isSkillMd = path.basename(entry.rel) === 'SKILL.md';
    const { lines, truncatedLines } = splitLinesCapped(text);
    if (truncatedLines.length > 0) findings.push(truncationFinding(entry.rel, truncatedLines));

    // 1. Known injection phrases.
    const phraseSeen = new Set<string>();
    for (let i = 0; i < lines.length; i++) {
      for (const re of INJECTION_PHRASES) {
        const m = re.exec(lines[i]);
        if (m && !phraseSeen.has(re.source)) {
          phraseSeen.add(re.source);
          findings.push(
            finding('injection/phrase', 'critical', `prompt-injection phrase: "${m[0]}"`, entry.rel, i + 1),
          );
        }
      }
    }

    // 2. HTML comments containing imperatives (invisible in rendered markdown).
    for (const m of text.matchAll(/<!--([\s\S]*?)-->/g)) {
      const content = m[1].trim();
      if (content && IMPERATIVE_IN_COMMENT.test(content)) {
        const preview = content.length > 80 ? content.slice(0, 80) + '…' : content;
        findings.push(
          finding(
            'injection/html-comment-imperative',
            'warning',
            `HTML comment contains an imperative hidden from rendered view: "${preview}"`,
            entry.rel,
            lineOf(text, m.index ?? 0),
          ),
        );
      }
    }

    // 3. Instructions addressed to the model hidden in reference files.
    if (!isSkillMd) {
      for (let i = 0; i < lines.length; i++) {
        const m = MODEL_ADDRESSED.exec(lines[i]);
        if (m) {
          findings.push(
            finding(
              'injection/model-addressed',
              'warning',
              `reference file addresses the model with concealment language: "${m[0]}"`,
              entry.rel,
              i + 1,
            ),
          );
          break; // one per file
        }
      }
    }

    // 4. Zero-width / invisible unicode (a single leading BOM is benign, and
    //    a ZWJ inside an emoji sequence is visible content, not hidden text).
    const zwMatches = [...text.matchAll(ZERO_WIDTH)].filter(
      (m) => !(m.index === 0 && m[0] === '\uFEFF') && !isEmojiZwj(text, m.index ?? 0),
    );
    if (zwMatches.length > 0) {
      findings.push(
        finding(
          'injection/zero-width-unicode',
          'warning',
          `${zwMatches.length} zero-width/invisible character(s) — can hide instructions from human review`,
          entry.rel,
          lineOf(text, zwMatches[0].index ?? 0),
        ),
      );
    }
    const bidi = text.match(BIDI_CONTROL);
    if (bidi && bidi.length > 0) {
      findings.push(
        finding(
          'injection/bidi-control',
          'warning',
          `${bidi.length} bidirectional control character(s) — can visually reorder text`,
          entry.rel,
          lineOf(text, text.search(BIDI_CONTROL)),
        ),
      );
    }
    const tags = text.match(TAG_CHARS);
    if (tags && tags.length > 0) {
      findings.push(
        finding(
          'injection/unicode-tag-chars',
          'critical',
          `${tags.length} invisible unicode tag character(s) (U+E0000–E007F) — a known hidden-prompt carrier`,
          entry.rel,
          lineOf(text, text.search(TAG_CHARS)),
        ),
      );
    }
  }
  return findings;
}
