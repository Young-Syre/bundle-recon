import * as acorn from 'acorn';

/** Acorn parse with the fallbacks a bundle scanner needs. */
export interface ParseResult {
  program: acorn.Program | null;
  error?: string;
  /** `module` or `script`, whichever parsed. */
  sourceType?: 'module' | 'script';
}

const PARSE_BASE: acorn.Options = {
  ecmaVersion: 'latest',
  allowHashBang: true,
  allowAwaitOutsideFunction: true,
  allowReturnOutsideFunction: true,
  allowSuperOutsideMethod: true,
  allowImportExportEverywhere: true,
  ranges: false,
  locations: false,
};

/**
 * Parse JavaScript. Built assets are inconsistent about module vs script
 * (a webpack runtime chunk is a script, an ESM entry is a module, and some
 * UMD bundles parse only as script because they use `with` or bare `return`),
 * so try both before giving up.
 */
export function parseJs(text: string): ParseResult {
  try {
    return {
      program: acorn.parse(text, { ...PARSE_BASE, sourceType: 'module' }),
      sourceType: 'module',
    };
  } catch (moduleError) {
    try {
      return {
        program: acorn.parse(text, { ...PARSE_BASE, sourceType: 'script' }),
        sourceType: 'script',
      };
    } catch {
      return {
        program: null,
        error: moduleError instanceof Error ? moduleError.message : String(moduleError),
      };
    }
  }
}

export type StaticResult = { ok: true; value: unknown } | { ok: false };

const FAIL: StaticResult = { ok: false };

/** The name of an object/class property key, when it is statically known. */
export function propertyKeyName(node: acorn.AnyNode): string | null {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'PrivateIdentifier') return `#${node.name}`;
  if (node.type === 'Literal') {
    const { value } = node;
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'bigint') return String(value);
  }
  return null;
}

/**
 * Evaluate a node to a plain JavaScript value, but only when it is entirely
 * literal. No function calls, no property reads, no `this`: a bundle scanner
 * must never execute target code, so anything that would require evaluation
 * fails closed.
 *
 * `consts` lets simple module-level string bindings resolve, which is what
 * makes `var n = "/api/v2"; fetch(n + "/users")` readable in minified output.
 */
export function staticValue(
  node: acorn.AnyNode | null | undefined,
  consts?: ReadonlyMap<string, string>,
  depth = 0,
): StaticResult {
  if (!node || depth > 12) return FAIL;

  switch (node.type) {
    case 'Literal':
      return { ok: true, value: node.value };

    case 'Identifier': {
      if (node.name === 'undefined') return { ok: true, value: undefined };
      if (node.name === 'NaN') return { ok: true, value: Number.NaN };
      if (node.name === 'Infinity') return { ok: true, value: Number.POSITIVE_INFINITY };
      const resolved = consts?.get(node.name);
      return resolved === undefined ? FAIL : { ok: true, value: resolved };
    }

    case 'TemplateLiteral': {
      if (node.expressions.length === 0) {
        return { ok: true, value: node.quasis.map((q) => q.value.cooked ?? '').join('') };
      }
      let out = '';
      for (let i = 0; i < node.quasis.length; i += 1) {
        out += node.quasis[i]?.value.cooked ?? '';
        const expression = node.expressions[i];
        if (expression) {
          const inner = staticValue(expression, consts, depth + 1);
          if (!inner.ok) return FAIL;
          out += String(inner.value);
        }
      }
      return { ok: true, value: out };
    }

    case 'ArrayExpression': {
      const out: unknown[] = [];
      for (const element of node.elements) {
        if (element === null) {
          out.push(undefined);
          continue;
        }
        if (element.type === 'SpreadElement') return FAIL;
        const inner = staticValue(element, consts, depth + 1);
        if (!inner.ok) return FAIL;
        out.push(inner.value);
      }
      return { ok: true, value: out };
    }

    case 'ObjectExpression': {
      const out: Record<string, unknown> = {};
      for (const property of node.properties) {
        if (property.type !== 'Property' || property.computed || property.kind !== 'init') {
          return FAIL;
        }
        const key = propertyKeyName(property.key);
        if (key === null) return FAIL;
        const inner = staticValue(property.value as acorn.AnyNode, consts, depth + 1);
        if (!inner.ok) return FAIL;
        out[key] = inner.value;
      }
      return { ok: true, value: out };
    }

    case 'UnaryExpression': {
      const inner = staticValue(node.argument, consts, depth + 1);
      if (!inner.ok) return FAIL;
      switch (node.operator) {
        case '-':
          return { ok: true, value: -(inner.value as number) };
        case '+':
          return { ok: true, value: +(inner.value as number) };
        case '!':
          return { ok: true, value: !inner.value };
        case 'void':
          return { ok: true, value: undefined };
        case 'typeof':
          return { ok: true, value: typeof inner.value };
        default:
          return FAIL;
      }
    }

    case 'BinaryExpression': {
      if (node.left.type === 'PrivateIdentifier') return FAIL;
      const left = staticValue(node.left, consts, depth + 1);
      const right = staticValue(node.right, consts, depth + 1);
      if (!left.ok || !right.ok) return FAIL;
      const a = left.value as number;
      const b = right.value as number;
      switch (node.operator) {
        case '+':
          return { ok: true, value: (a as unknown as string) + (b as unknown as string) };
        case '-':
          return { ok: true, value: a - b };
        case '*':
          return { ok: true, value: a * b };
        case '/':
          return { ok: true, value: a / b };
        case '%':
          return { ok: true, value: a % b };
        default:
          return FAIL;
      }
    }

    case 'ConditionalExpression': {
      const test = staticValue(node.test, consts, depth + 1);
      if (!test.ok) return FAIL;
      return staticValue(test.value ? node.consequent : node.alternate, consts, depth + 1);
    }

    case 'ParenthesizedExpression':
      return staticValue(node.expression as acorn.AnyNode, consts, depth + 1);

    default:
      return FAIL;
  }
}

/** Convenience: a static string, or null. */
export function staticString(
  node: acorn.AnyNode | null | undefined,
  consts?: ReadonlyMap<string, string>,
): string | null {
  const result = staticValue(node, consts);
  return result.ok && typeof result.value === 'string' ? result.value : null;
}

/**
 * Collect module-level-ish string bindings: `const API = "/api/v2"`.
 *
 * Deliberately scope-blind — minified bundles reuse one-letter names in
 * dozens of scopes, so a name bound to two different literals is dropped
 * rather than guessed at. Single-character names are skipped entirely; the
 * collision rate makes them worse than useless.
 */
export function stringConstants(program: acorn.Program): Map<string, string> {
  const found = new Map<string, string>();
  const poisoned = new Set<string>();

  const visit = (node: acorn.AnyNode): void => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') {
      const name = node.id.name;
      const value = node.init?.type === 'Literal' ? node.init.value : undefined;
      if (typeof value === 'string' && name.length > 1) {
        const existing = found.get(name);
        if (existing !== undefined && existing !== value) poisoned.add(name);
        else found.set(name, value);
      } else if (node.init) {
        // Rebound to something non-literal: no longer safe to substitute.
        poisoned.add(name);
      }
    }
    if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier') {
      poisoned.add(node.left.name);
    }
    for (const child of childNodes(node)) visit(child);
  };

  visit(program);
  for (const name of poisoned) found.delete(name);
  return found;
}

/** Enumerate the direct child nodes of an AST node. */
export function childNodes(node: acorn.AnyNode): acorn.AnyNode[] {
  const out: acorn.AnyNode[] = [];
  for (const value of Object.values(node as unknown as Record<string, unknown>)) {
    if (Array.isArray(value)) {
      for (const item of value) if (isNode(item)) out.push(item);
    } else if (isNode(value)) {
      out.push(value);
    }
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

export interface PathPattern {
  /** The path with non-static segments replaced by `{name}` placeholders. */
  pattern: string;
  /** Placeholder names, in order. */
  params: string[];
  /** True when every segment resolved statically. */
  exact: boolean;
}

/**
 * Turn a request-URL expression into a path pattern.
 *
 * This is the difference between reporting `"/api/v2/users/"` (a bare string
 * fragment, which is what a regex scraper sees) and `/api/v2/users/{id}`
 * (a route a tester can actually call).
 */
export function expressionToPathPattern(
  node: acorn.AnyNode | null | undefined,
  consts?: ReadonlyMap<string, string>,
): PathPattern | null {
  if (!node) return null;
  const params: string[] = [];
  const used = new Map<string, number>();

  const placeholder = (expression: acorn.AnyNode): string => {
    const base = paramName(expression);
    const seen = used.get(base) ?? 0;
    used.set(base, seen + 1);
    const name = seen === 0 ? base : `${base}${seen + 1}`;
    params.push(name);
    return `{${name}}`;
  };

  let exact = true;

  const render = (expression: acorn.AnyNode, depth: number): string | null => {
    if (depth > 12) return null;

    const literal = staticValue(expression, consts, 0);
    if (literal.ok && (typeof literal.value === 'string' || typeof literal.value === 'number')) {
      return String(literal.value);
    }

    switch (expression.type) {
      case 'TemplateLiteral': {
        let out = '';
        for (let i = 0; i < expression.quasis.length; i += 1) {
          out += expression.quasis[i]?.value.cooked ?? '';
          const slot = expression.expressions[i];
          if (slot) {
            const inner = render(slot, depth + 1);
            if (inner === null) {
              exact = false;
              out += placeholder(slot);
            } else {
              out += inner;
            }
          }
        }
        return out;
      }

      case 'BinaryExpression': {
        if (expression.operator !== '+' || expression.left.type === 'PrivateIdentifier') return null;
        const left = render(expression.left, depth + 1);
        const right = render(expression.right, depth + 1);
        if (left === null && right === null) return null;
        exact = exact && left !== null && right !== null;
        return (
          (left ?? placeholder(expression.left)) + (right ?? placeholder(expression.right))
        );
      }

      case 'CallExpression': {
        // Wrappers that do not change the path's shape.
        const callee = expression.callee;
        const name =
          callee.type === 'Identifier'
            ? callee.name
            : callee.type === 'MemberExpression'
              ? propertyKeyName(callee.property as acorn.AnyNode)
              : null;
        const unwrap = new Set(['encodeURIComponent', 'encodeURI', 'String', 'toString', 'trim']);
        const first = expression.arguments[0];
        if (name && unwrap.has(name) && first && first.type !== 'SpreadElement') {
          // The wrapper does not change the path's shape, so name the
          // placeholder after what is being encoded, not after the encoder.
          const inner = render(first, depth + 1);
          if (inner !== null) return inner;
          exact = false;
          return placeholder(first);
        }
        return null;
      }

      case 'ConditionalExpression': {
        // Prefer whichever branch yields a usable path.
        const consequent = render(expression.consequent, depth + 1);
        if (consequent !== null) {
          exact = false;
          return consequent;
        }
        const alternate = render(expression.alternate, depth + 1);
        if (alternate !== null) exact = false;
        return alternate;
      }

      case 'LogicalExpression': {
        // `base || "/api"` — the fallback is the interesting half.
        const right = render(expression.right, depth + 1);
        if (right !== null) {
          exact = false;
          return right;
        }
        return render(expression.left, depth + 1);
      }

      default:
        return null;
    }
  };

  const pattern = render(node, 0);
  if (pattern === null) return null;
  return { pattern, params, exact };
}

/**
 * Derive a readable placeholder name from an interpolated expression.
 *
 * Property names survive minification (bundlers do not rename properties by
 * default), so `user.id` yields `{id}`. A bare identifier does not survive,
 * and a one- or two-character local tells a reader nothing, so those fall
 * back to the generic placeholder rather than emitting `{e}`.
 */
function paramName(node: acorn.AnyNode): string {
  if (node.type === 'MemberExpression' && !node.computed) {
    const property = propertyKeyName(node.property as acorn.AnyNode);
    if (property) return property.replace(/[^A-Za-z0-9_]/g, '') || 'param';
  }
  const raw = rawName(node);
  if (!raw || raw.length <= 2) return 'param';
  return raw.replace(/[^A-Za-z0-9_]/g, '') || 'param';
}

function rawName(node: acorn.AnyNode): string | null {
  switch (node.type) {
    case 'Identifier':
      return node.name;
    case 'MemberExpression':
      return node.computed ? rawName(node.object as acorn.AnyNode) : propertyKeyName(node.property as acorn.AnyNode);
    case 'CallExpression':
      return node.callee.type === 'Identifier' ? node.callee.name : null;
    case 'AwaitExpression':
      return rawName(node.argument);
    case 'ChainExpression':
      return rawName(node.expression as acorn.AnyNode);
    default:
      return null;
  }
}

/** Resolve the dotted name of a callee, e.g. `axios.post` or `api.client.get`. */
export function calleeName(node: acorn.AnyNode): string | null {
  switch (node.type) {
    case 'Identifier':
      return node.name;
    case 'MemberExpression': {
      if (node.computed) return null;
      const object = calleeName(node.object as acorn.AnyNode);
      const property = propertyKeyName(node.property as acorn.AnyNode);
      if (property === null) return null;
      return object === null ? property : `${object}.${property}`;
    }
    case 'ChainExpression':
      return calleeName(node.expression as acorn.AnyNode);
    case 'ThisExpression':
      return 'this';
    default:
      return null;
  }
}

/** Find a property on an object literal by name. */
export function findProperty(
  node: acorn.AnyNode,
  name: string,
): acorn.AnyNode | null {
  if (node.type !== 'ObjectExpression') return null;
  for (const property of node.properties) {
    if (property.type !== 'Property' || property.computed) continue;
    if (propertyKeyName(property.key) === name) return property.value as acorn.AnyNode;
  }
  return null;
}
