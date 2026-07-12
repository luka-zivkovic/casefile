import { describe, expect, it } from 'vitest';
import { FrontmatterError, NAME_RE, parseFrontmatter } from '../src/frontmatter.js';

describe('parseFrontmatter', () => {
  it('parses top-level keys and strips quotes', () => {
    const { frontmatter, body } = parseFrontmatter('---\nname: "foo"\ndescription: bar\n---\nbody\n');
    expect(frontmatter.name).toBe('foo');
    expect(frontmatter.description).toBe('bar');
    expect(body.trim()).toBe('body');
  });

  it('joins block scalars and tolerates continuation lines', () => {
    const text = '---\ndescription: >-\n  first line\n  second line\n---\n';
    const { frontmatter } = parseFrontmatter(text);
    expect(frontmatter.description).toBe('first line second line');
  });

  it('captures list-form values instead of flattening them to empty', () => {
    const text = '---\nname: x\nallowed-tools:\n  - "*"\n  - Read\n---\n';
    const { frontmatter } = parseFrontmatter(text);
    expect(frontmatter['allowed-tools']).toBe('*, Read');
  });

  it('captures zero-indent list items', () => {
    const text = '---\nallowed-tools:\n- Bash\n---\n';
    const { frontmatter } = parseFrontmatter(text);
    expect(frontmatter['allowed-tools']).toBe('Bash');
  });

  it('ignores nested maps under a non-block key', () => {
    const text = '---\nname: n8n\ncompatibility:\n  requires: node\n  version: 20\ndescription: x\n---\n';
    const { frontmatter } = parseFrontmatter(text);
    expect(frontmatter.name).toBe('n8n');
    expect(frontmatter.description).toBe('x');
    expect(frontmatter.compatibility).toBe('');
  });

  it('throws when the opening delimiter is missing', () => {
    expect(() => parseFrontmatter('no frontmatter here')).toThrow(FrontmatterError);
  });

  it('throws when the closing delimiter is missing', () => {
    expect(() => parseFrontmatter('---\nname: x\nno close')).toThrow(FrontmatterError);
  });

  it('reports the body start line for accurate line numbers', () => {
    const { bodyStartLine } = parseFrontmatter('---\nname: x\n---\nline4\n');
    expect(bodyStartLine).toBe(4);
  });

  it('accepts plugin-namespaced names', () => {
    expect(NAME_RE.test('my-plugin:my-skill')).toBe(true);
    expect(NAME_RE.test('Bad Name')).toBe(false);
  });
});
