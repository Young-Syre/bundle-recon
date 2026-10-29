import type * as acorn from 'acorn';
import * as walk from 'acorn-walk';

import type { Location, RouteFinding } from '../types.js';
import { calleeName, propertyKeyName, staticValue } from '../util/ast.js';
import { jsonScriptById } from './html.js';
import { scanPayload } from './payload.js';
import { emptyResult, mergeResults, type FrameworkContext, type FrameworkResult } from './context.js';

/** Nuxt 2 and Nuxt 3 hydration payloads. */
export function extractNuxt(context: FrameworkContext): FrameworkResult {
  const results: FrameworkResult[] = [];
  if (context.asset.kind === 'html') results.push(extractNuxtData(context));
  if (context.program) results.push(extractNuxtGlobal(context, context.program));
  return mergeResults(results);
}

/**
 * Nuxt 2: `window.__NUXT__ = {…}` — or, more often in production, an IIFE
 * that rebuilds the object from a deduplicated argument list.
 *
 * The object literal form is evaluated statically. The IIFE form cannot be,
 * so the extractor falls back to reading only the properties whose values are
 * literal, which is still enough to recover `config.public` (where Nuxt puts
 * `apiBase`) in most builds.
 */
export function extractNuxtGlobal(
  context: FrameworkContext,
  program: acorn.Program,
): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;
  if (!asset.text.includes('__NUXT__')) return result;

  walk.simple(program, {
    AssignmentExpression(node) {
      if (node.left.type !== 'MemberExpression') return;
      const name = calleeName(node.left as acorn.AnyNode);
      if (name !== 'window.__NUXT__' && name !== 'self.__NUXT__' && name !== '__NUXT__') return;

      const { line, column } = lines.locate(node.start);
      const location: Location = { asset: asset.id, line, column };
      result.frameworks.push({
        name: 'nuxt',
        details: ['window.__NUXT__ hydration payload'],
        evidence: [location],
      });

      const value = staticValue(node.right as acorn.AnyNode);
      if (value.ok) {
        result.payloads.push(...scanPayload(value.value, { source: '__NUXT__', location }));
        result.routes.push(...routeFromPayload(value.value, location));
        return;
      }

      // IIFE form: salvage the statically known leaves.
      const target = unwrapIife(node.right as acorn.AnyNode);
      if (target) {
        result.payloads.push(...partialObjectScan(target, location, context));
        result.notes.push(
          `${asset.id}: window.__NUXT__ is a function-wrapped payload; only literal leaves were recovered.`,
        );
      }
    },
  });

  return result;
}

/** `routePath` in the payload is the route the server rendered. */
function routeFromPayload(value: unknown, location: Location): RouteFinding[] {
  if (typeof value !== 'object' || value === null) return [];
  const routePath = (value as { routePath?: unknown }).routePath;
  if (typeof routePath !== 'string' || !routePath.startsWith('/')) return [];
  return [
    {
      route: routePath,
      framework: 'nuxt',
      kind: routePath.startsWith('/api/') ? 'api' : 'page',
      dynamic: /[:[]/.test(routePath),
      provenance: 'nuxt-payload',
      locations: [location],
    },
  ];
}

/** `(function(a,b){return {…}})(…)` -> the returned object expression. */
function unwrapIife(node: acorn.AnyNode): acorn.AnyNode | null {
  if (node.type === 'ObjectExpression') return node;
  if (node.type !== 'CallExpression') return null;
  const callee = node.callee;
  if (callee.type !== 'FunctionExpression' && callee.type !== 'ArrowFunctionExpression') return null;
  const body = callee.body;
  if (body.type === 'ObjectExpression') return body;
  if (body.type !== 'BlockStatement') return null;
  for (const statement of body.body) {
    if (statement.type === 'ReturnStatement' && statement.argument) {
      return statement.argument as acorn.AnyNode;
    }
  }
  return null;
}

/** Walk an object literal, keeping only the branches that are fully literal. */
function partialObjectScan(
  node: acorn.AnyNode,
  location: Location,
  context: FrameworkContext,
): ReturnType<typeof scanPayload> {
  const out: ReturnType<typeof scanPayload> = [];

  const visit = (current: acorn.AnyNode, prefix: string, depth: number): void => {
    if (depth > 8 || out.length > 150) return;
    if (current.type !== 'ObjectExpression') return;
    for (const property of current.properties) {
      if (property.type !== 'Property' || property.computed) continue;
      const key = propertyKeyName(property.key);
      if (key === null) continue;
      const path = prefix === '' ? key : `${prefix}.${key}`;
      const value = property.value as acorn.AnyNode;
      const literal = staticValue(value, context.consts);
      if (literal.ok) {
        out.push(...scanPayload(literal.value, { source: '__NUXT__', location, prefix: path }));
      } else {
        visit(value, path, depth + 1);
      }
    }
  };

  visit(node, '', 0);
  return out;
}

/**
 * Nuxt 3: `<script type="application/json" id="__NUXT_DATA__">`.
 *
 * The body is devalue-encoded — a flat array where entries reference each
 * other by index — so key names are mostly absent. The scanner therefore
 * leans on value shape (URLs, API paths, emails) rather than key names here.
 */
export function extractNuxtData(context: FrameworkContext): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;
  const block = jsonScriptById(asset.text, '__NUXT_DATA__');
  if (!block) return result;

  const { line, column } = lines.locate(block.offset);
  const location: Location = { asset: asset.id, line, column };
  result.frameworks.push({
    name: 'nuxt',
    details: ['__NUXT_DATA__ (Nuxt 3, devalue-encoded)'],
    evidence: [location],
  });

  try {
    const parsed: unknown = JSON.parse(block.json);
    result.payloads.push(...scanPayload(parsed, { source: '__NUXT_DATA__', location }));
  } catch (error) {
    result.notes.push(
      `${asset.id}: __NUXT_DATA__ present but not parseable as JSON (${
        error instanceof Error ? error.message : String(error)
      }).`,
    );
  }
  return result;
}
