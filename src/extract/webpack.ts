import type * as acorn from 'acorn';
import * as walk from 'acorn-walk';

import type { ChunkFinding, Location } from '../types.js';
import { calleeName, propertyKeyName, staticValue } from '../util/ast.js';
import type { LineIndex } from '../util/text.js';
import { emptyResult, type FrameworkContext, type FrameworkResult } from './context.js';

const FAILED = Symbol('not-statically-evaluable');
type Evaluated = string | undefined | typeof FAILED;

/** A static `{ id: value }` lookup table keyed by the chunk-id parameter. */
interface ChunkMap {
  entries: Map<string, string>;
  /** True when the values look like content hashes rather than names. */
  hashes: boolean;
}

/**
 * Enumerate webpack chunks from the runtime's own filename function.
 *
 * Webpack's runtime contains, in effect, a complete directory listing of the
 * application's lazily loaded code:
 *
 *   r.u = e => "static/chunks/" + ({179:"admin-panel"}[e] || e) + "." +
 *              {179:"9f1c2d84"}[e] + ".js"
 *
 * Reading the chunk-id tables out of that function and re-running the string
 * concatenation for each id yields the exact URL of every chunk, including
 * the ones that are only reached from a code path no visitor ever triggers —
 * admin panels, feature-flagged screens, internal tools. A regex scraper
 * cannot produce these, because the filenames do not exist as strings
 * anywhere in the bundle; they are assembled at request time.
 */
export function extractWebpack(
  context: FrameworkContext,
  program: acorn.Program,
): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;
  const text = asset.text;

  const isWebpack =
    text.includes('__webpack_require__') ||
    text.includes('webpackChunk') ||
    text.includes('__webpack_modules__') ||
    text.includes('webpackJsonp');
  if (!isWebpack) return result;

  const { line, column } = lines.locate(0);
  const location: Location = { asset: asset.id, line, column };
  const details: string[] = [];

  const publicPath = findPublicPath(program);
  if (publicPath !== null) details.push(`publicPath=${publicPath}`);

  const found = new Map<string, ChunkFinding>();
  let templatesSeen = 0;

  walk.simple(program, {
    FunctionExpression(node) {
      templatesSeen += harvest(node, found, lines, asset.id) ? 1 : 0;
    },
    ArrowFunctionExpression(node) {
      templatesSeen += harvest(node, found, lines, asset.id) ? 1 : 0;
    },
    FunctionDeclaration(node) {
      templatesSeen += harvest(node, found, lines, asset.id) ? 1 : 0;
    },
  });

  result.chunks.push(...found.values());
  if (found.size > 0) {
    details.push(`chunk ids enumerated: ${found.size}`);
    details.push(`filename templates reconstructed: ${templatesSeen}`);
  }

  if (/__webpack_require__\.federation|remoteEntry|__webpack_share_scopes__/.test(text)) {
    details.push('module federation detected');
    result.notes.push(
      `${asset.id}: module federation runtime present. Remote containers resolve chunk names at runtime, so the chunk list for remotes will be incomplete.`,
    );
  }

  if (details.length > 0) {
    result.frameworks.push({ name: 'webpack', details, evidence: [location] });
  }
  return result;
}

/** `__webpack_require__.p = "https://cdn.example.com/_next/"`. */
function findPublicPath(program: acorn.Program): string | null {
  let result: string | null = null;
  walk.simple(program, {
    AssignmentExpression(node) {
      if (result !== null) return;
      if (node.left.type !== 'MemberExpression' || node.left.computed) return;
      const property = propertyKeyName(node.left.property as acorn.AnyNode);
      if (property !== 'p') return;
      const name = calleeName(node.left as acorn.AnyNode) ?? '';
      if (!/(^|\.)p$/.test(name)) return;
      const value = staticValue(node.right as acorn.AnyNode);
      if (value.ok && typeof value.value === 'string' && value.value.length > 0) {
        result = value.value;
      }
    },
  });
  return result;
}

/** Try to read one single-parameter function as a chunk filename template. */
function harvest(
  node: acorn.Function & acorn.AnyNode,
  into: Map<string, ChunkFinding>,
  lines: LineIndex,
  assetId: string,
): boolean {
  if (node.params.length !== 1) return false;
  const param = node.params[0];
  if (!param || param.type !== 'Identifier') return false;

  const body = returnedExpression(node);
  if (!body) return false;
  // A template must concatenate — a function that just returns a map lookup
  // is a name table, handled through the maps it contains.
  if (body.type !== 'BinaryExpression' && body.type !== 'TemplateLiteral') return false;

  const maps = collectChunkMaps(body, param.name);
  if (maps.length === 0) return false;

  const ids = new Set<string>();
  for (const map of maps) for (const id of map.entries.keys()) ids.add(id);
  if (ids.size === 0 || ids.size > 20000) return false;

  const nameMap = maps.find((map) => !map.hashes);
  const { line, column } = lines.locate(node.start);
  let produced = 0;

  for (const id of ids) {
    const file = evaluate(body, param.name, id);
    if (file === FAILED || file === undefined) continue;
    if (file.length === 0 || file.length > 400) continue;
    if (!/\.(js|mjs|css)$/.test(file)) continue;
    produced += 1;

    const key = file;
    const existing = into.get(key);
    const name = nameMap?.entries.get(id);
    if (existing) {
      if (name && !existing.name) existing.name = name;
      continue;
    }
    into.set(key, {
      id,
      file,
      ...(name ? { name } : {}),
      lazy: true,
      provenance: 'webpack-chunk-map',
      locations: [{ asset: assetId, line, column }],
    });
  }

  return produced > 0;
}

/** The expression a function returns, for both concise and block bodies. */
function returnedExpression(node: acorn.Function): acorn.AnyNode | null {
  const body = node.body;
  if (body.type !== 'BlockStatement') return body as acorn.AnyNode;
  if (body.body.length === 0) return null;
  for (const statement of body.body) {
    if (statement.type === 'ReturnStatement' && statement.argument) {
      return statement.argument as acorn.AnyNode;
    }
  }
  return null;
}

/** Every `{…}[param]` lookup table inside an expression. */
function collectChunkMaps(node: acorn.AnyNode, param: string): ChunkMap[] {
  const maps: ChunkMap[] = [];

  const visit = (current: acorn.AnyNode): void => {
    if (
      current.type === 'MemberExpression' &&
      current.computed &&
      current.property.type === 'Identifier' &&
      current.property.name === param &&
      (current.object as acorn.AnyNode).type === 'ObjectExpression'
    ) {
      const value = staticValue(current.object as acorn.AnyNode);
      if (value.ok && typeof value.value === 'object' && value.value !== null) {
        const entries = new Map<string, string>();
        for (const [key, entry] of Object.entries(value.value as Record<string, unknown>)) {
          if (typeof entry === 'string' || typeof entry === 'number') {
            entries.set(key, String(entry));
          }
        }
        if (entries.size > 0) {
          const values = [...entries.values()];
          const hashes = values.every((item) => /^[0-9a-f]{6,}$/i.test(item));
          maps.push({ entries, hashes });
        }
      }
    }
    for (const child of children(current)) visit(child);
  };

  visit(node);
  return maps;
}

function children(node: acorn.AnyNode): acorn.AnyNode[] {
  const out: acorn.AnyNode[] = [];
  for (const value of Object.values(node as unknown as Record<string, unknown>)) {
    if (Array.isArray(value)) {
      for (const item of value) if (isNode(item)) out.push(item);
    } else if (isNode(value)) out.push(value);
  }
  return out;
}

function isNode(value: unknown): value is acorn.AnyNode {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { type?: unknown }).type === 'string' &&
    typeof (value as { start?: unknown }).start === 'number'
  );
}

/**
 * Re-run the filename concatenation with one concrete chunk id substituted.
 *
 * Nothing is executed: this is a string-only interpreter over the subset of
 * expressions webpack emits (literals, `+`, template literals, the chunk-id
 * parameter, static map lookups and `||` fallbacks). Anything else fails and
 * the chunk is skipped rather than guessed at.
 */
function evaluate(node: acorn.AnyNode, param: string, id: string): Evaluated {
  switch (node.type) {
    case 'Literal':
      return typeof node.value === 'string' || typeof node.value === 'number'
        ? String(node.value)
        : FAILED;

    case 'Identifier':
      return node.name === param ? id : FAILED;

    case 'TemplateLiteral': {
      let out = '';
      for (let index = 0; index < node.quasis.length; index += 1) {
        out += node.quasis[index]?.value.cooked ?? '';
        const slot = node.expressions[index];
        if (!slot) continue;
        const value = evaluate(slot as acorn.AnyNode, param, id);
        if (value === FAILED) return FAILED;
        out += value ?? '';
      }
      return out;
    }

    case 'BinaryExpression': {
      if (node.operator !== '+' || node.left.type === 'PrivateIdentifier') return FAILED;
      const left = evaluate(node.left as acorn.AnyNode, param, id);
      const right = evaluate(node.right as acorn.AnyNode, param, id);
      if (left === FAILED || right === FAILED) return FAILED;
      return (left ?? '') + (right ?? '');
    }

    case 'LogicalExpression': {
      const left = evaluate(node.left as acorn.AnyNode, param, id);
      if (node.operator === '||' || node.operator === '??') {
        if (left !== FAILED && left !== undefined && left !== '') return left;
        return evaluate(node.right as acorn.AnyNode, param, id);
      }
      return FAILED;
    }

    case 'MemberExpression': {
      if (
        !node.computed ||
        node.property.type !== 'Identifier' ||
        node.property.name !== param ||
        (node.object as acorn.AnyNode).type !== 'ObjectExpression'
      ) {
        return FAILED;
      }
      const object = staticValue(node.object as acorn.AnyNode);
      if (!object.ok || typeof object.value !== 'object' || object.value === null) return FAILED;
      const entry = (object.value as Record<string, unknown>)[id];
      if (entry === undefined) return undefined; // Map miss: let `||` handle it.
      return typeof entry === 'string' || typeof entry === 'number' ? String(entry) : FAILED;
    }

    case 'CallExpression': {
      // `encodeURIComponent(e)` and friends do not change the shape we want.
      const name = calleeName(node.callee as acorn.AnyNode);
      const first = node.arguments[0];
      if (name && /encodeURIComponent|String|encodeURI/.test(name) && first) {
        return evaluate(first as acorn.AnyNode, param, id);
      }
      return FAILED;
    }

    default:
      return FAILED;
  }
}
