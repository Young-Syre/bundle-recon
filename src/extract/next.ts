import type * as acorn from 'acorn';
import * as walk from 'acorn-walk';

import type { ChunkFinding, Location, RouteFinding } from '../types.js';
import { propertyKeyName, staticValue } from '../util/ast.js';
import { jsonScriptById } from './html.js';
import { scanPayload } from './payload.js';
import { emptyResult, mergeResults, type FrameworkContext, type FrameworkResult } from './context.js';
import { normalisePath } from './endpoints.js';

/** Pages-router entries that are framework internals, not navigable routes. */
const INTERNAL_PAGES = new Set(['/_app', '/_document', '/_error', '/404', '/500']);

/** Next.js extraction entry point: dispatches on what the asset actually is. */
export function extractNext(context: FrameworkContext): FrameworkResult {
  const results: FrameworkResult[] = [];
  const { asset } = context;

  if (asset.kind === 'html') {
    results.push(extractNextData(context));
    results.push(extractFlightFromHtml(context));
  }

  if (context.program) {
    if (/_buildManifest/.test(asset.id)) results.push(extractBuildManifest(context, context.program));
    if (/_ssgManifest/.test(asset.id)) results.push(extractSsgManifest(context, context.program));
    results.push(extractFlightPushes(context, context.program));
  }

  return mergeResults(results);
}

/** `/_next/static/<buildId>/_buildManifest.js` -> the build id. */
export function buildIdFromAssetPath(id: string): string | null {
  const match = /_next\/static\/([^/]+)\/(?:_buildManifest|_ssgManifest|_middlewareManifest)/.exec(id);
  const candidate = match?.[1];
  if (!candidate) return null;
  if (['chunks', 'css', 'media', 'development'].includes(candidate)) return null;
  return candidate;
}

/**
 * Parse `_buildManifest.js`.
 *
 * Every Next.js pages-router route is a key in this object, including dynamic
 * segments (`/blog/[slug]`) and API-adjacent pages — this is a complete route
 * list handed over by the framework, which is strictly better than guessing
 * routes from link text. Next has shipped at least three spellings of the
 * file (a plain object, a function-wrapped object that dedupes chunk strings,
 * and a `sortedPages`-only variant), so the extractor keys off the shape that
 * is common to all of them: string keys beginning with `/` whose value is an
 * array, plus the `sortedPages` array.
 */
export function extractBuildManifest(
  context: FrameworkContext,
  program: acorn.Program,
): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;
  const buildId = buildIdFromAssetPath(asset.id);
  const seen = new Map<string, RouteFinding>();

  const add = (route: string, node: acorn.AnyNode, assets: string[]): void => {
    if (!route.startsWith('/')) return;
    const { line, column } = lines.locate(node.start);
    const existing = seen.get(route);
    if (existing) {
      if (assets.length > 0 && (existing.assets?.length ?? 0) === 0) existing.assets = assets;
      return;
    }
    seen.set(route, {
      route,
      framework: 'next',
      kind: INTERNAL_PAGES.has(route) ? 'internal' : route.startsWith('/api/') ? 'api' : 'page',
      dynamic: /\[.+\]/.test(route),
      ...(assets.length > 0 ? { assets } : {}),
      provenance: 'next-build-manifest',
      locations: [{ asset: asset.id, line, column }],
    });
  };

  walk.simple(program, {
    ObjectExpression(node) {
      for (const property of node.properties) {
        if (property.type !== 'Property' || property.computed) continue;
        const key = propertyKeyName(property.key);
        if (key === null) continue;

        if (key === '__rewrites') {
          result.notes.push(
            `${asset.id}: build manifest declares __rewrites — rewrite sources and destinations extracted as routes.`,
          );
          extractRewrites(property.value as acorn.AnyNode, context, result);
          continue;
        }

        if (key === 'sortedPages') {
          const value = staticValue(property.value as acorn.AnyNode);
          if (value.ok && Array.isArray(value.value)) {
            for (const entry of value.value) {
              if (typeof entry === 'string') add(entry, property.value as acorn.AnyNode, []);
            }
          }
          continue;
        }

        if (!key.startsWith('/')) continue;
        if ((property.value as acorn.AnyNode).type !== 'ArrayExpression') continue;

        // The function-wrapped manifest form replaces shared chunk names with
        // parameters, so the array is only partly literal. Take the strings
        // that are there rather than discarding the whole entry.
        const files: string[] = [];
        for (const element of (property.value as acorn.ArrayExpression).elements) {
          if (element && element.type === 'Literal' && typeof element.value === 'string') {
            files.push(element.value);
          }
        }
        add(key, property.key as acorn.AnyNode, files);
      }
    },
  });

  result.routes.push(...seen.values());

  // Chunk file names inside the manifest name per-route chunks and, for the
  // app router, the route segments themselves.
  const files = new Set<string>();
  for (const route of result.routes) for (const file of route.assets ?? []) files.add(file);
  result.routes.push(...routesFromChunkPaths(files, { asset: asset.id, line: 1, column: 1 }));

  if (result.routes.length > 0) {
    const { line, column } = lines.locate(0);
    result.frameworks.push({
      name: 'next',
      details: [
        `pages-router routes: ${result.routes.filter((r) => r.provenance === 'next-build-manifest').length}`,
        ...(buildId ? [`buildId=${buildId}`] : []),
      ],
      evidence: [{ asset: asset.id, line, column }],
    });
  }

  return result;
}

/** `__rewrites: { beforeFiles: [{source, destination}], … }`. */
function extractRewrites(
  node: acorn.AnyNode,
  context: FrameworkContext,
  result: FrameworkResult,
): void {
  const { asset, lines } = context;
  walk.simple(node as acorn.AnyNode & acorn.Program, {
    ObjectExpression(inner) {
      const source = inner.properties.find(
        (property) =>
          property.type === 'Property' && propertyKeyName(property.key) === 'source',
      );
      const destination = inner.properties.find(
        (property) =>
          property.type === 'Property' && propertyKeyName(property.key) === 'destination',
      );
      if (!source || source.type !== 'Property') return;
      const sourceValue = staticValue(source.value as acorn.AnyNode);
      if (!sourceValue.ok || typeof sourceValue.value !== 'string') return;
      const { line, column } = lines.locate(inner.start);

      result.routes.push({
        route: sourceValue.value,
        framework: 'next',
        kind: sourceValue.value.startsWith('/api/') ? 'api' : 'page',
        dynamic: /[:[*]/.test(sourceValue.value),
        provenance: 'next-build-manifest',
        locations: [{ asset: asset.id, line, column }],
      });

      if (destination && destination.type === 'Property') {
        const destinationValue = staticValue(destination.value as acorn.AnyNode);
        if (destinationValue.ok && typeof destinationValue.value === 'string') {
          const normalised = normalisePath(destinationValue.value.replace(/:([a-zA-Z_]\w*)/g, '{$1}'));
          if (normalised) {
            result.endpoints.push({
              path: normalised,
              method: 'UNKNOWN',
              client: 'next-rewrite',
              params: [],
              provenance: 'next-build-manifest',
              confidence: 'medium',
              locations: [{ asset: asset.id, line, column }],
              evidence: `rewrite ${sourceValue.value} -> ${destinationValue.value}`,
            });
          }
        }
      }
    },
  });
}

/** `_ssgManifest.js`: the set of statically generated pages. */
export function extractSsgManifest(
  context: FrameworkContext,
  program: acorn.Program,
): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;

  walk.simple(program, {
    ArrayExpression(node) {
      const value = staticValue(node);
      if (!value.ok || !Array.isArray(value.value)) return;
      const routes = value.value.filter(
        (entry): entry is string => typeof entry === 'string' && entry.startsWith('/'),
      );
      if (routes.length === 0) return;
      const { line, column } = lines.locate(node.start);
      for (const route of routes) {
        result.routes.push({
          route,
          framework: 'next',
          kind: INTERNAL_PAGES.has(route) ? 'internal' : 'page',
          dynamic: /\[.+\]/.test(route),
          prerendered: true,
          provenance: 'next-ssg-manifest',
          locations: [{ asset: asset.id, line, column }],
        });
      }
    },
  });

  if (result.routes.length > 0) {
    result.frameworks.push({
      name: 'next',
      details: [`statically generated routes: ${result.routes.length}`],
      evidence: [{ asset: asset.id, line: 1, column: 1 }],
    });
  }
  return result;
}

/** `<script id="__NEXT_DATA__" type="application/json">` in server-rendered HTML. */
export function extractNextData(context: FrameworkContext): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;
  const block = jsonScriptById(asset.text, '__NEXT_DATA__');
  if (!block) return result;

  const { line, column } = lines.locate(block.offset);
  const location: Location = { asset: asset.id, line, column };

  let data: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(block.json);
    if (typeof parsed !== 'object' || parsed === null) return result;
    data = parsed as Record<string, unknown>;
  } catch (error) {
    result.notes.push(
      `${asset.id}: found __NEXT_DATA__ but could not parse it as JSON (${
        error instanceof Error ? error.message : String(error)
      }).`,
    );
    return result;
  }

  const buildId = typeof data['buildId'] === 'string' ? (data['buildId'] as string) : null;
  const page = typeof data['page'] === 'string' ? (data['page'] as string) : null;
  const details = [
    'server-rendered (pages router)',
    ...(buildId ? [`buildId=${buildId}`] : []),
    ...(page ? [`page=${page}`] : []),
    ...(typeof data['assetPrefix'] === 'string' ? [`assetPrefix=${String(data['assetPrefix'])}`] : []),
  ];
  result.frameworks.push({ name: 'next', details, evidence: [location] });

  if (page) {
    result.routes.push({
      route: page,
      framework: 'next',
      kind: INTERNAL_PAGES.has(page) ? 'internal' : page.startsWith('/api/') ? 'api' : 'page',
      dynamic: /\[.+\]/.test(page),
      provenance: 'next-data',
      locations: [location],
    });
  }

  result.payloads.push(...scanPayload(data, { source: '__NEXT_DATA__', location }));

  if (buildId) {
    result.notes.push(
      `${asset.id}: buildId ${buildId} — route manifests are at /_next/static/${buildId}/_buildManifest.js and _ssgManifest.js.`,
    );
  }
  return result;
}

/** App-router flight payloads embedded in HTML as `self.__next_f.push(...)`. */
function extractFlightFromHtml(context: FrameworkContext): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;
  if (!asset.text.includes('__next_f')) return result;

  const pattern = /self\.__next_f\.push\(\s*\[\s*\d+\s*,\s*("(?:\\.|[^"\\])*")/g;
  const strings: string[] = [];
  let match: RegExpExecArray | null;
  let firstOffset = -1;
  while ((match = pattern.exec(asset.text)) !== null) {
    if (firstOffset < 0) firstOffset = match.index;
    const raw = match[1];
    if (!raw) continue;
    try {
      strings.push(JSON.parse(raw) as string);
    } catch {
      // A chunked flight row can be split across pushes; skip unparseable parts.
    }
  }
  if (strings.length === 0) return result;

  const { line, column } = lines.locate(Math.max(0, firstOffset));
  const location: Location = { asset: asset.id, line, column };
  result.frameworks.push({
    name: 'next',
    details: ['app-router (RSC flight payload present)', `flight rows: ${strings.length}`],
    evidence: [location],
  });
  result.notes.push(
    `${asset.id}: ${strings.length} self.__next_f flight rows decoded; app-router segments and chunk files below come from them.`,
  );

  harvestFlight(strings.join(''), location, result);
  return result;
}

/** The same payload, when it reaches us as a standalone JS chunk. */
function extractFlightPushes(context: FrameworkContext, program: acorn.Program): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;
  if (!asset.text.includes('__next_f')) return result;

  const strings: string[] = [];
  let offset = 0;
  walk.simple(program, {
    CallExpression(node) {
      const callee = node.callee;
      if (callee.type !== 'MemberExpression') return;
      const method = propertyKeyName(callee.property as acorn.AnyNode);
      if (method !== 'push') return;
      if (!/__next_f/.test(asset.text.slice(callee.start, callee.end))) return;
      offset = offset === 0 ? node.start : offset;
      const value = staticValue(node.arguments[0] as acorn.AnyNode);
      if (value.ok && Array.isArray(value.value)) {
        for (const entry of value.value) if (typeof entry === 'string') strings.push(entry);
      }
    },
  });

  if (strings.length === 0) return result;
  const { line, column } = lines.locate(offset);
  const location: Location = { asset: asset.id, line, column };
  result.frameworks.push({
    name: 'next',
    details: ['app-router (RSC flight payload present)'],
    evidence: [location],
  });
  harvestFlight(strings.join(''), location, result);
  return result;
}

/**
 * Pull structure out of a concatenated RSC flight payload.
 *
 * Flight rows are not JSON — they are a line-oriented stream of module
 * references (`3:I[4821,["static/chunks/app/admin/page-….js"],"default"]`)
 * and element trees. Rather than implement the format, this harvests the two
 * things that are unambiguous in it: chunk file paths and segment paths.
 */
function harvestFlight(payload: string, location: Location, result: FrameworkResult): void {
  const files = new Set<string>();
  const filePattern = /(?:static\/(?:chunks|css)\/[A-Za-z0-9._/[\]()@-]+?\.(?:js|css))/g;
  let match: RegExpExecArray | null;
  while ((match = filePattern.exec(payload)) !== null) files.add(match[0]);

  for (const file of files) {
    result.chunks.push({
      id: file,
      file,
      lazy: false,
      provenance: 'next-flight',
      locations: [location],
    });
  }
  result.routes.push(...routesFromChunkPaths(files, location));
}

/**
 * Derive route patterns from Next.js chunk file paths.
 *
 * The app router has no `_buildManifest` equivalent, but webpack names its
 * chunks after the segment directory — `static/chunks/app/(shop)/orders/
 * [id]/page-9f2.js` is route `/orders/[id]`. Route groups in parentheses and
 * parallel-route `@slot` segments are layout-only and are stripped, exactly
 * as the framework does when it builds the URL.
 */
export function routesFromChunkPaths(
  files: Iterable<string>,
  location: Location,
): RouteFinding[] {
  const out = new Map<string, RouteFinding>();

  for (const file of files) {
    const app = /(?:^|\/)app\/(.*)\/(page|route|default)-[A-Za-z0-9_-]+\.js$/.exec(file);
    const appRoot = /(?:^|\/)app\/(page|route)-[A-Za-z0-9_-]+\.js$/.exec(file);
    const pages = /(?:^|\/)pages\/(.+?)-[A-Za-z0-9]{8,}\.js$/.exec(file);

    let route: string | null = null;
    let kind: RouteFinding['kind'] = 'page';

    if (appRoot) {
      route = '/';
      kind = appRoot[1] === 'route' ? 'api' : 'page';
    } else if (app?.[1]) {
      const segments = app[1]
        .split('/')
        .filter((segment) => !/^\(.*\)$/.test(segment) && !segment.startsWith('@'));
      route = `/${segments.join('/')}`;
      kind = app[2] === 'route' ? 'api' : 'page';
    } else if (pages?.[1]) {
      const name = pages[1];
      route = name === 'index' ? '/' : `/${name.replace(/\/index$/, '')}`;
      kind = route.startsWith('/api/') ? 'api' : INTERNAL_PAGES.has(route) ? 'internal' : 'page';
    }

    if (route === null || route === '') continue;
    if (route.startsWith('/api/') || route === '/api') kind = 'api';
    if (INTERNAL_PAGES.has(route)) kind = 'internal';
    if (out.has(route)) continue;

    out.set(route, {
      route,
      framework: 'next',
      kind,
      dynamic: /\[.+\]/.test(route),
      provenance: 'next-flight',
      locations: [location],
    });
  }

  return [...out.values()];
}

/** Merge route findings: one row per route pattern. */
export function mergeRoutes(routes: readonly RouteFinding[]): RouteFinding[] {
  const byRoute = new Map<string, RouteFinding>();
  for (const route of routes) {
    const existing = byRoute.get(route.route);
    if (!existing) {
      byRoute.set(route.route, { ...route, locations: [...route.locations] });
      continue;
    }
    if (route.prerendered) existing.prerendered = true;
    if (route.assets && (existing.assets?.length ?? 0) === 0) existing.assets = route.assets;
    if (existing.kind === 'page' && route.kind !== 'page') existing.kind = route.kind;
    for (const location of route.locations) {
      const duplicate = existing.locations.some(
        (candidate) => candidate.asset === location.asset && candidate.line === location.line,
      );
      if (!duplicate && existing.locations.length < 6) existing.locations.push(location);
    }
  }
  return [...byRoute.values()].sort((a, b) => a.route.localeCompare(b.route));
}

/** Merge chunk findings and mark the ones nothing references. */
export function mergeChunks(
  chunks: readonly ChunkFinding[],
  referenced: ReadonlySet<string>,
): ChunkFinding[] {
  const byKey = new Map<string, ChunkFinding>();
  for (const chunk of chunks) {
    const key = chunk.file ?? chunk.id;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...chunk, locations: [...chunk.locations] });
      continue;
    }
    if (chunk.name && !existing.name) existing.name = chunk.name;
    if (chunk.file && !existing.file) existing.file = chunk.file;
    existing.lazy = existing.lazy && chunk.lazy;
  }
  for (const chunk of byKey.values()) {
    if (chunk.file && referenced.has(chunk.file)) chunk.lazy = false;
  }
  return [...byKey.values()].sort((a, b) => (a.file ?? a.id).localeCompare(b.file ?? b.id));
}
