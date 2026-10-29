import * as fs from 'node:fs/promises';
import * as path from 'node:path';

import type {
  AnalyseOptions,
  Asset,
  AssetSummary,
  ChunkFinding,
  EndpointFinding,
  FrameworkFinding,
  GraphQLFinding,
  OpenApiFinding,
  PayloadFinding,
  ReconError,
  ReconReport,
  RouteFinding,
  Section,
  SecretFinding,
  SourcemapFinding,
  Target,
} from './types.js';
import { NAME, VERSION } from './version.js';
import { LineIndex } from './util/text.js';
import { kindFromPath } from './util/paths.js';
import { parseJs, stringConstants } from './util/ast.js';
import { extractEndpoints, mergeEndpoints } from './extract/endpoints.js';
import { extractSecrets, mergeSecrets } from './extract/secrets.js';
import { extractApiDocs } from './extract/apidocs.js';
import { extractManifests } from './extract/manifests.js';
import { extractNext, mergeChunks, mergeRoutes } from './extract/next.js';
import { extractNuxt } from './extract/nuxt.js';
import { extractWebpack } from './extract/webpack.js';
import { extractScriptTags } from './extract/html.js';
import { emptyResult, mergeResults, type FrameworkContext, type FrameworkResult } from './extract/context.js';
import {
  countRecoveredSources,
  decodeDataUri,
  findSourceMappingAnnotation,
  loadSourcemap,
  looksLikeSourcemap,
  originalPosition,
  writeRecoveredSources,
} from './extract/sourcemaps.js';

export const DEFAULT_MAX_ASSET_BYTES = 24 * 1024 * 1024;
const MAX_RECOVERED_SCAN_BYTES = 8 * 1024 * 1024;
const MAX_RECOVERED_SCAN_FILES = 500;

/**
 * Resolves a `sourceMappingURL` to the map's JSON text.
 *
 * The returned `id` canonically identifies the map (an absolute path on disk,
 * or an absolute URL) so that a map consumed through an annotation is not
 * then analysed a second time as an asset in its own right.
 */
export type SourcemapResolver = (
  asset: Asset,
  url: string,
) => Promise<{ text: string; id: string } | null>;

const SCANNABLE = new Set(['.js', '.mjs', '.cjs', '.jsx', '.html', '.htm', '.json', '.map', '.txt']);

/** Analyse a single already-downloaded asset. */
export async function analyseFile(
  file: string,
  options: AnalyseOptions = {},
): Promise<ReconReport> {
  const absolute = path.resolve(file);
  const asset = await readAsset(absolute, path.basename(absolute));
  return analyseAssets([asset], { kind: 'file', value: absolute }, options, diskResolver());
}

/**
 * Analyse every scannable asset in a directory tree.
 *
 * This is the offline path: point it at `.next/static`, a `dist/` folder, or
 * a directory of assets saved from a proxy, and nothing touches the network.
 */
export async function analyseDirectory(
  directory: string,
  options: AnalyseOptions = {},
): Promise<ReconReport> {
  const absolute = path.resolve(directory);
  const files = await collectFiles(absolute);
  const assets: Asset[] = [];
  const errors: ReconError[] = [];

  for (const file of files) {
    try {
      assets.push(await readAsset(file, path.relative(absolute, file)));
    } catch (error) {
      errors.push({
        asset: path.relative(absolute, file),
        stage: 'read',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const report = await analyseAssets(
    assets,
    { kind: 'directory', value: absolute },
    options,
    diskResolver(),
  );
  report.errors.unshift(...errors);
  return report;
}

/** Analyse a list of assets that a caller has already gathered. */
export async function analyseAssets(
  assets: readonly Asset[],
  target: Target,
  options: AnalyseOptions = {},
  resolveSourcemap?: SourcemapResolver,
): Promise<ReconReport> {
  const started = Date.now();
  const maxBytes = options.maxAssetBytes ?? DEFAULT_MAX_ASSET_BYTES;
  const includeStringLiterals = options.includeStringLiterals ?? true;
  const followSourcemaps = options.followSourcemaps ?? true;

  const summaries: AssetSummary[] = [];
  const errors: ReconError[] = [];
  const notes: string[] = [];
  const endpoints: EndpointFinding[] = [];
  const secrets: SecretFinding[] = [];
  const graphql: GraphQLFinding[] = [];
  const openapi: OpenApiFinding[] = [];
  const sourcemaps: SourcemapFinding[] = [];
  const frameworkResults: FrameworkResult[] = [];
  const referencedFiles = new Set<string>();

  let recoveredScannedBytes = 0;
  let recoveredScannedFiles = 0;
  let unparseableRecovered = 0;

  // Maps are analysed last: a map reached through a bundle's
  // `sourceMappingURL` is recorded here, so the same file arriving in the
  // asset list is not reported a second time.
  const consumedMaps = new Set<string>();
  const ordered = [
    ...assets.filter((asset) => !looksLikeSourcemap(asset)),
    ...assets.filter((asset) => looksLikeSourcemap(asset)),
  ];

  for (const asset of ordered) {
    if (asset.bytes > maxBytes) {
      summaries.push({ id: asset.id, kind: asset.kind, bytes: asset.bytes });
      notes.push(
        `${asset.id}: skipped, ${asset.bytes} bytes exceeds the ${maxBytes}-byte limit (raise it with --max-asset-bytes).`,
      );
      continue;
    }

    const lines = new LineIndex(asset.text);

    // ---- source maps ------------------------------------------------------
    if (looksLikeSourcemap(asset)) {
      if (!followSourcemaps) {
        summaries.push({ id: asset.id, kind: asset.kind, bytes: asset.bytes });
        continue;
      }
      const identity = asset.file ?? asset.url ?? asset.id;
      if (consumedMaps.has(identity)) {
        summaries.push({ id: asset.id, kind: asset.kind, bytes: asset.bytes });
        continue;
      }
      try {
        const loaded = await loadSourcemap(asset.text, {
          asset: asset.id,
          discovery: 'direct',
          mapLocation: asset.id,
        });
        if (options.outDir && loaded.contents.size > 0) {
          loaded.finding.written = await writeRecoveredSources(
            loaded.contents,
            options.outDir,
            asset.id,
          );
        }
        sourcemaps.push(loaded.finding);
        const recovered = scanRecoveredSources(
          loaded.contents,
          asset.id,
          options,
          includeStringLiterals,
        );
        endpoints.push(...recovered.endpoints);
        secrets.push(...recovered.secrets);
        notes.push(...recovered.notes);
        recoveredScannedBytes += recovered.bytes;
        recoveredScannedFiles += recovered.files;
        unparseableRecovered += recovered.unparseable;
        loaded.consumer.destroy();
      } catch (error) {
        errors.push({
          asset: asset.id,
          stage: 'sourcemap',
          message: error instanceof Error ? error.message : String(error),
        });
      }
      summaries.push({ id: asset.id, kind: asset.kind, bytes: asset.bytes });
      continue;
    }

    // ---- javascript -------------------------------------------------------
    const subAssets: Asset[] = [asset];
    if (asset.kind === 'html') {
      subAssets.push(...inlineScripts(asset, referencedFiles));
    }

    for (const current of subAssets) {
      const currentLines = current === asset ? lines : new LineIndex(current.text);
      const parsed =
        current.kind === 'javascript' ? parseJs(current.text) : { program: null, error: undefined };
      const consts = parsed.program ? stringConstants(parsed.program) : new Map<string, string>();

      if (current === asset) {
        summaries.push({
          id: current.id,
          kind: current.kind,
          bytes: current.bytes,
          ...(current.kind === 'javascript' ? { parsed: parsed.program !== null } : {}),
          ...(parsed.error ? { parseError: parsed.error } : {}),
        });
        if (current.kind === 'javascript' && !parsed.program) {
          errors.push({ asset: current.id, stage: 'parse', message: parsed.error ?? 'parse failed' });
        }
      }

      const frameworkContext: FrameworkContext = {
        asset: current,
        program: parsed.program,
        lines: currentLines,
        consts,
      };

      if (parsed.program) {
        endpoints.push(
          ...extractEndpoints({
            asset: current,
            program: parsed.program,
            consts,
            lines: currentLines,
            // Every string in a route manifest is a route, and the framework
            // extractors already read them structurally. Scraping literals
            // out of these files would duplicate the route list under
            // "endpoints" with no method and no call site.
            includeStringLiterals: includeStringLiterals && !isRouteManifest(current.id),
          }),
        );
      }

      secrets.push(
        ...extractSecrets({
          asset: current,
          lines: currentLines,
          showSecrets: options.showSecrets ?? false,
          onCap: (note) => notes.push(note),
        }),
      );

      const docs = extractApiDocs({
        assetId: current.id,
        text: current.text,
        lines: currentLines,
        isJson: current.kind === 'json',
      });
      openapi.push(...docs.openapi);
      graphql.push(...docs.graphql);
      endpoints.push(...docs.endpoints);
      notes.push(...docs.notes);

      frameworkResults.push(extractNext(frameworkContext));
      frameworkResults.push(extractNuxt(frameworkContext));
      frameworkResults.push(extractManifests(frameworkContext));
      if (parsed.program) {
        frameworkResults.push(extractWebpack(frameworkContext, parsed.program));
      }

      // ---- source map referenced by this asset ----------------------------
      if (followSourcemaps && parsed.program !== null) {
        const annotation = findSourceMappingAnnotation(current.text);
        if (annotation) {
          try {
            const resolved = annotation.inline
              ? { text: decodeDataUri(annotation.url), id: `${current.id}#inline` }
              : resolveSourcemap
                ? await resolveSourcemap(current, annotation.url)
                : null;
            const json = resolved?.text ?? null;
            if (resolved) consumedMaps.add(resolved.id);

            if (json === null) {
              notes.push(
                `${current.id}: declares sourceMappingURL=${truncate(annotation.url)} but the map could not be read.`,
              );
            } else {
              const loaded = await loadSourcemap(json, {
                asset: current.id,
                discovery: annotation.inline ? 'inline-data-uri' : 'comment',
                ...(annotation.inline ? {} : { mapLocation: annotation.url }),
              });

              if (options.outDir && loaded.contents.size > 0) {
                loaded.finding.written = await writeRecoveredSources(
                  loaded.contents,
                  options.outDir,
                  current.id,
                );
              }
              sourcemaps.push(loaded.finding);

              // Map this asset's call sites back to their original files.
              for (const endpoint of endpoints) {
                if (endpoint.originalLocation) continue;
                const location = endpoint.locations.find((item) => item.asset === current.id);
                if (!location) continue;
                const mapped = originalPosition(loaded.consumer, location.line, location.column);
                if (mapped) endpoint.originalLocation = mapped;
              }

              const recovered = scanRecoveredSources(
                loaded.contents,
                current.id,
                options,
                includeStringLiterals,
              );
              endpoints.push(...recovered.endpoints);
              secrets.push(...recovered.secrets);
              notes.push(...recovered.notes);
              recoveredScannedBytes += recovered.bytes;
              recoveredScannedFiles += recovered.files;
              unparseableRecovered += recovered.unparseable;

              if (loaded.finding.withContent === 0) {
                notes.push(
                  `${current.id}: source map found but it carries no sourcesContent — original paths recovered, file contents not.`,
                );
              }
              loaded.consumer.destroy();
            }
          } catch (error) {
            errors.push({
              asset: current.id,
              stage: 'sourcemap',
              message: error instanceof Error ? error.message : String(error),
            });
          }
        }
      }
    }
  }

  if (recoveredScannedFiles > 0) {
    notes.push(
      `Scanned ${recoveredScannedFiles} recovered original sources (${Math.round(
        recoveredScannedBytes / 1024,
      )} KiB) for endpoints and secrets.` +
        (unparseableRecovered > 0
          ? ` ${unparseableRecovered} of them could not be AST-parsed (TypeScript or JSX syntax) and ${
              unparseableRecovered === 1 ? 'was' : 'were'
            } text-scanned only.`
          : ''),
    );
  }

  const framework = mergeResults(frameworkResults);
  endpoints.push(...framework.endpoints);
  sourcemaps.push(...framework.sourcemaps);
  notes.push(...framework.notes);

  const chunks: ChunkFinding[] = framework.chunks;
  for (const asset of assets) referencedFiles.add(asset.id.replace(/^\/+/, ''));

  const report: ReconReport = {
    tool: { name: NAME, version: VERSION },
    generatedAt: new Date().toISOString(),
    target,
    assets: summaries,
    frameworks: mergeFrameworks(framework.frameworks),
    routes: mergeRoutes(framework.routes),
    endpoints: mergeEndpoints(endpoints),
    chunks: mergeChunks(chunks, referencedFiles),
    sourcemaps,
    secrets: mergeSecrets(secrets),
    graphql,
    openapi,
    payloads: dedupePayloads(framework.payloads),
    notes: [...new Set(notes)],
    errors,
    stats: {
      assets: summaries.length,
      bytes: summaries.reduce((sum, summary) => sum + summary.bytes, 0),
      endpoints: 0,
      routes: 0,
      chunks: 0,
      secrets: 0,
      recoveredSources: countRecoveredSources(sourcemaps),
      durationMs: Date.now() - started,
    },
  };

  // A literal that is simply a known route is a route, not an endpoint.
  const routePatterns = new Set(report.routes.map((route) => route.route));
  report.endpoints = report.endpoints.filter(
    (endpoint) => !(endpoint.provenance === 'string-literal' && routePatterns.has(endpoint.path)),
  );

  report.stats.endpoints = report.endpoints.length;
  report.stats.routes = report.routes.length;
  report.stats.chunks = report.chunks.length;
  report.stats.secrets = report.secrets.length;

  return applySections(report, options.only);
}

/** Blank out the sections the caller did not ask for. */
export function applySections(report: ReconReport, only?: Section[]): ReconReport {
  if (!only || only.length === 0) return report;
  const wanted = new Set(only);
  if (!wanted.has('endpoints')) report.endpoints = [];
  if (!wanted.has('routes')) report.routes = [];
  if (!wanted.has('secrets')) report.secrets = [];
  if (!wanted.has('sourcemaps')) report.sourcemaps = [];
  if (!wanted.has('chunks')) report.chunks = [];
  if (!wanted.has('payloads')) report.payloads = [];
  if (!wanted.has('graphql')) report.graphql = [];
  if (!wanted.has('openapi')) report.openapi = [];
  if (!wanted.has('frameworks')) report.frameworks = [];
  return report;
}

/**
 * Scan source files recovered from a map.
 *
 * Original sources are the best possible input: an unminified `fetch()` call
 * carries its real variable names, and a committed credential that the
 * minifier inlined is plainly visible. TypeScript and JSX will not parse with
 * a plain JavaScript parser, so those are text-scanned for secrets and
 * counted rather than silently dropped.
 */
function scanRecoveredSources(
  contents: Map<string, string>,
  parentId: string,
  options: AnalyseOptions,
  includeStringLiterals: boolean,
): {
  endpoints: EndpointFinding[];
  secrets: SecretFinding[];
  notes: string[];
  bytes: number;
  files: number;
  unparseable: number;
} {
  const endpoints: EndpointFinding[] = [];
  const secrets: SecretFinding[] = [];
  const notes: string[] = [];
  let bytes = 0;
  let files = 0;
  let unparseable = 0;

  for (const [source, text] of contents) {
    if (files >= MAX_RECOVERED_SCAN_FILES || bytes >= MAX_RECOVERED_SCAN_BYTES) break;
    if (source.includes('node_modules/')) continue;
    files += 1;
    bytes += Buffer.byteLength(text);

    const asset: Asset = {
      id: `${parentId} » ${source}`,
      kind: 'javascript',
      text,
      bytes: Buffer.byteLength(text),
    };
    const lines = new LineIndex(text);

    secrets.push(
      ...extractSecrets({
        asset,
        lines,
        showSecrets: options.showSecrets ?? false,
        onCap: (note) => notes.push(note),
      }),
    );

    const parsed = parseJs(text);
    if (!parsed.program) {
      unparseable += 1;
      continue;
    }
    endpoints.push(
      ...extractEndpoints({
        asset,
        program: parsed.program,
        consts: stringConstants(parsed.program),
        lines,
        includeStringLiterals,
      }),
    );
  }

  return { endpoints, secrets, notes, bytes, files, unparseable };
}

/** Inline `<script>` bodies, as synthetic JavaScript assets. */
function inlineScripts(asset: Asset, referenced: Set<string>): Asset[] {
  const out: Asset[] = [];
  let index = 0;
  for (const tag of extractScriptTags(asset.text)) {
    if (tag.src) {
      referenced.add(tag.src.replace(/^\/+/, ''));
      continue;
    }
    const type = (tag.type ?? '').toLowerCase();
    if (type !== '' && !/javascript|module|ecmascript/.test(type)) continue;
    if (tag.content.trim().length === 0) continue;
    index += 1;
    out.push({
      id: `${asset.id}#inline-script-${index}`,
      kind: 'javascript',
      text: tag.content,
      bytes: Buffer.byteLength(tag.content),
    });
  }
  return out;
}

function mergeFrameworks(findings: readonly FrameworkFinding[]): FrameworkFinding[] {
  const byName = new Map<string, FrameworkFinding>();
  for (const finding of findings) {
    const existing = byName.get(finding.name);
    if (!existing) {
      byName.set(finding.name, { ...finding, details: [...finding.details], evidence: [...finding.evidence] });
      continue;
    }
    for (const detail of finding.details) {
      if (!existing.details.includes(detail)) existing.details.push(detail);
    }
    for (const evidence of finding.evidence) {
      if (existing.evidence.length < 6) existing.evidence.push(evidence);
    }
    if (finding.version && !existing.version) existing.version = finding.version;
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function dedupePayloads(payloads: readonly PayloadFinding[]): PayloadFinding[] {
  const byKey = new Map<string, PayloadFinding>();
  for (const payload of payloads) {
    const key = `${payload.source}::${payload.key}::${payload.value}`;
    if (!byKey.has(key)) byKey.set(key, payload);
  }
  return [...byKey.values()].sort((a, b) => a.key.localeCompare(b.key));
}

/** Files whose string content is a route list rather than request paths. */
function isRouteManifest(id: string): boolean {
  return /(_buildManifest|_ssgManifest|_middlewareManifest)\.js$/.test(id);
}

function truncate(value: string, max = 80): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

/** Read one file from disk into an Asset. */
export async function readAsset(file: string, id: string): Promise<Asset> {
  const text = await fs.readFile(file, 'utf8');
  return {
    id: id.split(path.sep).join('/'),
    kind: kindFromPath(file),
    text,
    bytes: Buffer.byteLength(text),
    file,
  };
}

/** Resolve `sourceMappingURL` against the asset's own directory on disk. */
export function diskResolver(): SourcemapResolver {
  return async (asset, url) => {
    if (!asset.file) return null;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) return null; // Absolute URL: offline mode cannot fetch it.
    const target = path.resolve(path.dirname(asset.file), url.split('?')[0] ?? url);
    try {
      return { text: await fs.readFile(target, 'utf8'), id: target };
    } catch {
      return null;
    }
  };
}

/** Recursively list the files worth scanning under a directory. */
export async function collectFiles(directory: string, depth = 0): Promise<string[]> {
  if (depth > 12) return [];
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const out: string[] = [];
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      out.push(...(await collectFiles(full, depth + 1)));
    } else if (entry.isFile()) {
      if (SCANNABLE.has(path.extname(entry.name).toLowerCase())) out.push(full);
    }
  }
  return out.sort();
}

export { emptyResult };
