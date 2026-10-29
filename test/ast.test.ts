import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import type * as acorn from 'acorn';

import {
  calleeName,
  expressionToPathPattern,
  parseJs,
  staticString,
  staticValue,
  stringConstants,
} from '../src/util/ast.js';
import { LineIndex, redact } from '../src/util/text.js';
import { shannonEntropy, looksLikeHexDigest, looksLikeIdentifierRun } from '../src/util/entropy.js';
import { buildTree, normaliseSourcePath, renderTree } from '../src/util/tree.js';
import { safeOutputPath } from '../src/util/paths.js';

/** Parse an expression statement and hand back the expression node. */
function expression(source: string): acorn.AnyNode {
  const parsed = parseJs(`(${source});`);
  assert.ok(parsed.program, 'expression should parse');
  const statement = parsed.program.body[0];
  assert.ok(statement && statement.type === 'ExpressionStatement');
  return statement.expression as acorn.AnyNode;
}

describe('static evaluation', () => {
  it('evaluates literals, templates and arithmetic', () => {
    assert.equal(staticString(expression('"/api/v1"')), '/api/v1');
    assert.equal(staticString(expression('`/api/${"v2"}/users`')), '/api/v2/users');
    assert.equal(staticString(expression('"/api" + "/v3"')), '/api/v3');
    const numeric = staticValue(expression('2 * 3 + 1'));
    assert.deepEqual(numeric, { ok: true, value: 7 });
  });

  it('evaluates object and array literals', () => {
    const value = staticValue(expression('{ a: 1, b: ["x", "y"], c: { d: true } }'));
    assert.ok(value.ok);
    assert.deepEqual(value.value, { a: 1, b: ['x', 'y'], c: { d: true } });
  });

  it('refuses to evaluate anything that would require running code', () => {
    assert.equal(staticValue(expression('makeUrl()')).ok, false);
    assert.equal(staticValue(expression('window.location.href')).ok, false);
    assert.equal(staticValue(expression('{ [key]: 1 }')).ok, false);
  });

  it('resolves module-level string constants but ignores one-character names', () => {
    const parsed = parseJs('var apiRoot = "/api/v3"; var e = "/nope"; const token = "abc";');
    assert.ok(parsed.program);
    const consts = stringConstants(parsed.program);
    assert.equal(consts.get('apiRoot'), '/api/v3');
    assert.equal(consts.get('token'), 'abc');
    assert.equal(consts.has('e'), false, 'single-character names collide too often to trust');
  });

  it('drops a constant that is bound to two different values', () => {
    const parsed = parseJs('function a(){var base="/one"}function b(){var base="/two"}');
    assert.ok(parsed.program);
    assert.equal(stringConstants(parsed.program).has('base'), false);
  });

  it('falls back to script parsing for code that modules forbid', () => {
    // `with` is a syntax error under the implicit strict mode of a module,
    // but legal in a script — older UMD bundles still contain it.
    const parsed = parseJs('with (config) { url = base + path; }');
    assert.ok(parsed.program, 'should fall back to script parsing');
    assert.equal(parsed.sourceType, 'script');
  });

  it('reports a parse error for genuinely broken input', () => {
    const parsed = parseJs('function (((');
    assert.equal(parsed.program, null);
    assert.ok((parsed.error ?? '').length > 0);
  });
});

describe('path patterns', () => {
  it('names placeholders after the interpolated property', () => {
    const pattern = expressionToPathPattern(expression('`/api/users/${user.id}/roles`'));
    assert.deepEqual(pattern, { pattern: '/api/users/{id}/roles', params: ['id'], exact: false });
  });

  it('falls back to a generic placeholder for minified locals', () => {
    const pattern = expressionToPathPattern(expression('`/api/users/${e}`'));
    assert.equal(pattern?.pattern, '/api/users/{param}');
  });

  it('numbers repeated placeholder names', () => {
    const pattern = expressionToPathPattern(expression('`/a/${row.key}/b/${other.key}`'));
    assert.equal(pattern?.pattern, '/a/{key}/b/{key2}');
    assert.deepEqual(pattern?.params, ['key', 'key2']);
  });

  it('resolves concatenation against a constant table', () => {
    const consts = new Map([['apiRoot', '/api/v3']]);
    const pattern = expressionToPathPattern(expression('apiRoot + "/teams"'), consts);
    assert.equal(pattern?.pattern, '/api/v3/teams');
    assert.equal(pattern?.exact, true);
  });

  it('unwraps encodeURIComponent around a parameter', () => {
    const pattern = expressionToPathPattern(expression('`/q/${encodeURIComponent(query.term)}`'));
    assert.equal(pattern?.pattern, '/q/{term}');
  });

  it('prefers the fallback side of a logical default', () => {
    const pattern = expressionToPathPattern(expression('base || "/api/fallback"'));
    assert.equal(pattern?.pattern, '/api/fallback');
  });
});

describe('callee names', () => {
  it('resolves dotted callees', () => {
    assert.equal(calleeName(expression('axios.post')), 'axios.post');
    assert.equal(calleeName(expression('api.client.get')), 'api.client.get');
    assert.equal(calleeName(expression('map[key]')), null);
  });
});

describe('text utilities', () => {
  it('locates offsets as 1-based line and column', () => {
    const index = new LineIndex('abc\ndefg\nhi');
    assert.deepEqual(index.locate(0), { line: 1, column: 1 });
    assert.deepEqual(index.locate(4), { line: 2, column: 1 });
    assert.deepEqual(index.locate(7), { line: 2, column: 4 });
    assert.deepEqual(index.locate(9), { line: 3, column: 1 });
  });

  it('bounds the excerpt window on a single very long line', () => {
    const index = new LineIndex('x'.repeat(500_000));
    assert.ok(index.excerpt(250_000, 40).length < 120);
  });

  it('redacts a value while keeping its recognisable prefix', () => {
    const redacted = redact('sk_' + 'live_' + '51Nq8ZkD7yTbVrP2wXsHgM4aC');
    assert.ok(redacted.startsWith('sk_live_'));
    assert.ok(!redacted.includes('ZkD7yTbVrP2wXsHgM'));
    assert.ok(redacted.endsWith('M4aC'));
  });
});

describe('entropy heuristics', () => {
  it('scores a uniform string at zero and a mixed one higher', () => {
    assert.equal(shannonEntropy('aaaaaaaa'), 0);
    assert.ok(shannonEntropy('aK7vQ2mZ9rT4bN6xW1lP8yC3') > 4);
  });

  it('recognises hex digests and identifier runs', () => {
    assert.equal(looksLikeHexDigest('9f1c2d84b7e3a6150c4d8f2b91e7a3c5'), true);
    assert.equal(looksLikeHexDigest('AKIA' + '7QJ4MZ2W' + 'NVB3KD5P'), false);
    assert.equal(looksLikeIdentifierRun('onChangeHandlerFactory'), true);
    assert.equal(looksLikeIdentifierRun('aK7vQ2mZ9rT4bN6xW1lP8yC3'), false);
  });
});

describe('source path handling', () => {
  it('normalises bundler-specific source prefixes', () => {
    assert.equal(normaliseSourcePath('webpack://my-app/./src/api/client.ts'), 'src/api/client.ts');
    assert.equal(normaliseSourcePath('webpack-internal:///./app/page.tsx'), 'app/page.tsx');
    assert.equal(normaliseSourcePath('../../src/lib/auth.ts'), 'src/lib/auth.ts');
  });

  it('builds and renders a directory tree', () => {
    const tree = buildTree(['src/a.ts', 'src/nested/b.ts', 'src/nested/c.ts']);
    const rendered = renderTree(tree).join('\n');
    assert.ok(rendered.includes('└── nested') || rendered.includes('├── nested'));
    assert.ok(rendered.includes('b.ts'));
    assert.ok(rendered.includes('c.ts'));
  });

  it('keeps hostile source paths inside the output directory', () => {
    const root = '/tmp/out';
    assert.equal(safeOutputPath(root, '../../../../etc/cron.d/evil'), '/tmp/out/etc/cron.d/evil');
    assert.equal(safeOutputPath(root, '/etc/passwd'), '/tmp/out/etc/passwd');
    assert.equal(safeOutputPath(root, 'C:\\Windows\\system.ini'), '/tmp/out/Windows/system.ini');
    assert.equal(safeOutputPath(root, 'webpack://app/./src/x.ts'), '/tmp/out/app/src/x.ts');
    assert.ok(safeOutputPath(root, '').startsWith('/tmp/out/'));
  });
});
