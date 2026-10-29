import type { ChunkFinding, Location, RouteFinding } from '../types.js';
import { buildTree } from '../util/tree.js';
import { emptyResult, type FrameworkContext, type FrameworkResult } from './context.js';

/**
 * Build manifests that ship as JSON next to the bundles.
 *
 * Vite's `manifest.json` is the most useful of these: it maps every original
 * source path to its built file. That gives the project's internal module
 * layout — the same thing a source map gives — from a file that teams
 * routinely deploy on purpose, because `build.manifest` is needed for
 * server-side asset injection.
 */
export function extractManifests(context: FrameworkContext): FrameworkResult {
  const { asset } = context;
  if (asset.kind !== 'json') return emptyResult();

  let parsed: unknown;
  try {
    parsed = JSON.parse(asset.text);
  } catch {
    return emptyResult();
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return emptyResult();
  }

  const record = parsed as Record<string, unknown>;
  if (isViteManifest(record)) return viteManifest(record, context);
  if (isCraAssetManifest(record)) return craAssetManifest(record, context);
  return emptyResult();
}

interface ViteEntry {
  file: string;
  src?: string;
  isEntry?: boolean;
  isDynamicEntry?: boolean;
  imports?: string[];
  dynamicImports?: string[];
  css?: string[];
  assets?: string[];
}

function isViteManifest(record: Record<string, unknown>): boolean {
  const values = Object.values(record).slice(0, 10);
  if (values.length === 0) return false;
  return values.every(
    (value) =>
      typeof value === 'object' &&
      value !== null &&
      typeof (value as { file?: unknown }).file === 'string',
  );
}

function isCraAssetManifest(record: Record<string, unknown>): boolean {
  return (
    typeof record['files'] === 'object' &&
    record['files'] !== null &&
    Array.isArray(record['entrypoints'])
  );
}

function viteManifest(
  record: Record<string, unknown>,
  context: FrameworkContext,
): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;
  const { line, column } = lines.locate(0);
  const location: Location = { asset: asset.id, line, column };

  const entries = new Map<string, ViteEntry>();
  for (const [key, value] of Object.entries(record)) {
    if (typeof value !== 'object' || value === null) continue;
    const entry = value as ViteEntry;
    if (typeof entry.file !== 'string') continue;
    entries.set(key, entry);
  }

  const dynamicOnly = new Set<string>();
  const eager = new Set<string>();
  for (const entry of entries.values()) {
    for (const dynamic of entry.dynamicImports ?? []) dynamicOnly.add(dynamic);
    for (const statik of entry.imports ?? []) eager.add(statik);
  }

  const chunks: ChunkFinding[] = [];
  const sources: string[] = [];

  for (const [key, entry] of entries) {
    const source = entry.src ?? key;
    if (!source.startsWith('_') && /\.[a-z]+$/i.test(source)) sources.push(source);

    chunks.push({
      id: key,
      file: entry.file,
      name: source,
      lazy: Boolean(entry.isDynamicEntry) || (dynamicOnly.has(key) && !entry.isEntry && !eager.has(key)),
      provenance: 'vite-manifest',
      locations: [location],
    });
    for (const css of entry.css ?? []) {
      chunks.push({
        id: css,
        file: css,
        lazy: false,
        provenance: 'vite-manifest',
        locations: [location],
      });
    }
  }

  result.chunks.push(...chunks);
  result.routes.push(...routesFromSourcePaths(sources, 'vite', location));
  result.frameworks.push({
    name: 'vite',
    details: [
      `manifest entries: ${entries.size}`,
      `entry points: ${[...entries.values()].filter((entry) => entry.isEntry).length}`,
      `dynamic chunks: ${chunks.filter((chunk) => chunk.lazy).length}`,
    ],
    evidence: [location],
  });

  if (sources.length > 0) {
    const unique = [...new Set(sources)].sort();
    result.sourcemaps.push({
      asset: asset.id,
      discovery: 'vite-manifest',
      mapLocation: asset.id,
      sourceCount: unique.length,
      withContent: 0,
      sources: unique,
      tree: buildTree(unique),
      highlights: unique.filter((source) =>
        /(^|\/)(api|admin|internal|auth|config|middleware)/i.test(source),
      ),
    });
    result.notes.push(
      `${asset.id}: Vite manifest exposes ${unique.length} original source paths (layout only — no file contents).`,
    );
  }

  return result;
}

function craAssetManifest(
  record: Record<string, unknown>,
  context: FrameworkContext,
): FrameworkResult {
  const result = emptyResult();
  const { asset, lines } = context;
  const { line, column } = lines.locate(0);
  const location: Location = { asset: asset.id, line, column };

  const files = record['files'] as Record<string, unknown>;
  const entrypoints = (record['entrypoints'] as unknown[]).filter(
    (entry): entry is string => typeof entry === 'string',
  );

  for (const [key, value] of Object.entries(files)) {
    if (typeof value !== 'string') continue;
    if (!/\.(js|css)$/.test(value)) continue;
    result.chunks.push({
      id: key,
      file: value.replace(/^\.?\//, ''),
      name: key,
      lazy: !entrypoints.some((entry) => value.endsWith(entry.replace(/^\.?\//, ''))),
      provenance: 'webpack-chunk-map',
      locations: [location],
    });
  }

  result.frameworks.push({
    name: 'webpack',
    details: [`create-react-app asset-manifest.json with ${result.chunks.length} files`],
    evidence: [location],
  });
  return result;
}

/**
 * File-based routing conventions: `src/pages/users/[id].vue` -> `/users/[id]`.
 *
 * Reported with the framework's own bracket syntax rather than translated,
 * so the output matches what a developer would grep for in the repository.
 */
export function routesFromSourcePaths(
  sources: readonly string[],
  framework: RouteFinding['framework'],
  location: Location,
): RouteFinding[] {
  const out = new Map<string, RouteFinding>();

  for (const source of sources) {
    const match = /(?:^|\/)(?:src\/)?(?:pages|views|routes)\/(.+)\.(?:vue|[jt]sx?|svelte)$/.exec(
      source,
    );
    const relative = match?.[1];
    if (!relative) continue;
    const segments = relative
      .split('/')
      .filter((segment) => !/^\(.*\)$/.test(segment) && !segment.startsWith('_'));
    if (segments.length === 0) continue;
    const last = segments[segments.length - 1];
    if (last === 'index') segments.pop();
    const route = `/${segments.join('/')}` || '/';
    if (out.has(route)) continue;
    out.set(route, {
      route,
      framework,
      kind: route.startsWith('/api/') ? 'api' : 'page',
      dynamic: /[[\]:]|\.\.\./.test(route),
      provenance: 'vite-manifest',
      locations: [location],
    });
  }

  return [...out.values()];
}
