import type { AnalyseOptions, Asset, ReconError, ReconReport } from '../types.js';
import { analyseAssets, DEFAULT_MAX_ASSET_BYTES, type SourcemapResolver } from '../analyse.js';
import { kindFromPath } from '../util/paths.js';
import { extractLinkHrefs, extractScriptTags, jsonScriptById } from '../extract/html.js';
import { DEFAULT_HTTP_OPTIONS, HttpClient, type HttpOptions } from './http.js';
import { EMPTY_ROBOTS, crawlDelay, isAllowed, parseRobots, type Robots } from './robots.js';

export interface FetchModeOptions extends AnalyseOptions {
  http?: Partial<HttpOptions>;
  /** Honour robots.txt. Default true. */
  respectRobots?: boolean;
  /** Hard cap on assets fetched. Default 60. */
  maxAssets?: number;
  /** Probe for well-known build manifests. Default true. */
  probeManifests?: boolean;
  /** Probe `<asset>.map` when no sourceMappingURL is declared. Default true. */
  probeSourcemaps?: boolean;
  onProgress?: (message: string) => void;
}

/** Well-known manifests that are cheap to check and high value when present. */
const MANIFEST_PATHS = [
  '/.vite/manifest.json',
  '/manifest.json',
  '/asset-manifest.json',
  '/build/manifest.json',
  '/static/manifest.json',
];

/**
 * Fetch an application's assets and analyse them.
 *
 * Crawling is intentionally shallow and same-origin: the entry document, the
 * scripts and module preloads it declares, the framework's own build
 * manifests, and any source maps those assets point at. The goal is the
 * build output, not the site, so there is no link-following.
 */
export async function analyseUrl(
  target: string,
  options: FetchModeOptions = {},
): Promise<ReconReport> {
  const entry = new URL(target);
  // The HTTP truncation limit and the analysis skip limit are the same number.
  // They were not: maxBytes was hard-coded at 16 MiB while --max-asset-bytes
  // defaults to 24 and only governed the skip decision, so an asset between
  // the two was truncated by a limit the operator could not configure -- and
  // the note said "the configured byte limit". A truncated .map then fails
  // JSON.parse and is dropped as a parse error rather than a size one, which
  // is the headline feature on any large app.
  const byteLimit = options.maxAssetBytes ?? DEFAULT_MAX_ASSET_BYTES;
  // A request that produces nothing is reported with its reason. Without this,
  // DNS failure, TLS rejection, timeout and a WAF reset all look the same to
  // the operator: an empty report.
  const fetchErrors: ReconError[] = [];
  const httpOptions: Partial<HttpOptions> = {
    maxBytes: byteLimit,
    onError: (url, error) => {
      fetchErrors.push({
        asset: safePath(url),
        stage: 'fetch',
        message: error instanceof Error ? error.message : String(error),
      });
    },
    ...options.http,
  };
  const client = new HttpClient(httpOptions);
  const maxAssets = options.maxAssets ?? 60;
  const respectRobots = options.respectRobots ?? true;
  const notes: string[] = [];
  const progress = options.onProgress ?? ((): void => {});

  // ---- robots.txt ---------------------------------------------------------
  let robots: Robots = EMPTY_ROBOTS;
  if (respectRobots) {
    const response = await client.get(new URL('/robots.txt', entry).toString());
    if (response && response.status === 200 && /^\s*(user-agent|#|sitemap)/im.test(response.body)) {
      robots = parseRobots(response.body);
      const delay = crawlDelay(robots, client.userAgent);
      notes.push(
        `robots.txt parsed: ${robots.groups.length} group(s)` +
          (delay !== undefined ? `, crawl-delay ${delay}s` : '') +
          (robots.sitemaps.length > 0 ? `, ${robots.sitemaps.length} sitemap(s) declared` : ''),
      );
      for (const sitemap of robots.sitemaps.slice(0, 5)) {
        notes.push(`robots.txt declares sitemap: ${sitemap}`);
      }
      if (delay !== undefined && delay > 0) {
        const perSecond = 1 / Math.max(delay, 0.001);
        if (perSecond < (httpOptions.requestsPerSecond ?? DEFAULT_HTTP_OPTIONS.requestsPerSecond)) {
          notes.push(
            `Rate reduced to ${perSecond.toFixed(2)} req/s to respect the declared crawl-delay.`,
          );
        }
      }
    } else {
      notes.push('robots.txt absent or unparseable; proceeding with the configured rate limit.');
    }
  } else {
    notes.push('robots.txt not consulted (--no-respect-robots).');
  }

  const delaySeconds = respectRobots ? crawlDelay(robots, client.userAgent) : undefined;
  const throttled =
    delaySeconds !== undefined && delaySeconds > 0
      ? new HttpClient({
          ...httpOptions,
          requestsPerSecond: Math.min(
            httpOptions.requestsPerSecond ?? DEFAULT_HTTP_OPTIONS.requestsPerSecond,
            1 / delaySeconds,
          ),
        })
      : client;

  const cache = new Map<string, string | null>();
  const assets: Asset[] = [];
  const fetched = new Set<string>();

  const allowed = (url: URL): boolean => {
    if (url.origin !== entry.origin) return false;
    if (!respectRobots) return true;
    return isAllowed(robots, throttled.userAgent, url.pathname + url.search);
  };

  const take = async (url: string, label?: string): Promise<string | null> => {
    if (cache.has(url)) return cache.get(url) ?? null;
    if (fetched.size >= maxAssets) return null;
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return null;
    }
    if (!allowed(parsed)) {
      notes.push(`skipped ${parsed.pathname} (${parsed.origin !== entry.origin ? 'cross-origin' : 'disallowed by robots.txt'})`);
      cache.set(url, null);
      return null;
    }

    fetched.add(url);
    progress(`GET ${parsed.pathname}${label ? ` (${label})` : ''}`);
    const response = await throttled.get(url);
    if (!response || response.status >= 400) {
      cache.set(url, null);
      return null;
    }
    if (response.offOrigin !== null) {
      // The target redirected off the origin we were authorised for. The hop is
      // reported and the request to that origin is never made, so nothing can
      // be attributed to the in-scope path that did not come from it.
      notes.push(
        `${parsed.pathname}: redirected to ${response.offOrigin} (cross-origin); not followed.`,
      );
      cache.set(url, null);
      return null;
    }
    if (response.truncated) {
      notes.push(
        `${parsed.pathname}: response truncated at ${byteLimit} bytes (--max-asset-bytes).`,
      );
    }
    cache.set(url, response.body);
    return response.body;
  };

  const addAsset = (url: string, body: string): Asset => {
    const parsed = new URL(url);
    const asset: Asset = {
      id: parsed.pathname + (parsed.search || ''),
      kind: kindFromUrl(parsed),
      text: body,
      bytes: Buffer.byteLength(body),
      url,
    };
    assets.push(asset);
    return asset;
  };

  // ---- entry document -----------------------------------------------------
  const entryBody = await take(entry.toString(), 'entry');
  if (entryBody === null) {
    throw new Error(`could not fetch ${entry.toString()} (blocked, unreachable, or error status)`);
  }
  const entryAsset = addAsset(entry.toString(), entryBody);
  if (entryAsset.kind === 'other') entryAsset.kind = 'html';

  // ---- declared scripts and module preloads -------------------------------
  const candidates: string[] = [];
  for (const tag of extractScriptTags(entryBody)) {
    if (tag.src) candidates.push(tag.src);
  }
  for (const href of extractLinkHrefs(entryBody, /(^|\s)(modulepreload|preload)(\s|$)/i)) {
    candidates.push(href);
  }
  const scriptUrls = new Set<string>();
  for (const candidate of candidates) {
    try {
      const resolved = new URL(candidate, entry);
      if (!/\.(js|mjs|json)(\?|$)/i.test(resolved.pathname + resolved.search)) continue;
      scriptUrls.add(resolved.toString());
    } catch {
      // Ignore unparseable src values.
    }
  }

  // ---- framework build manifests ------------------------------------------
  const buildIds = new Set<string>();
  for (const url of scriptUrls) {
    const match = /_next\/static\/([^/]+)\//.exec(url);
    const id = match?.[1];
    if (id && !['chunks', 'css', 'media', 'development'].includes(id)) buildIds.add(id);
  }
  const nextData = jsonScriptById(entryBody, '__NEXT_DATA__');
  if (nextData) {
    try {
      const parsed: unknown = JSON.parse(nextData.json);
      const buildId = (parsed as { buildId?: unknown } | null)?.buildId;
      if (typeof buildId === 'string') buildIds.add(buildId);
    } catch {
      // Handled by the extractor, which reports the parse failure.
    }
  }
  for (const buildId of buildIds) {
    scriptUrls.add(new URL(`/_next/static/${buildId}/_buildManifest.js`, entry).toString());
    scriptUrls.add(new URL(`/_next/static/${buildId}/_ssgManifest.js`, entry).toString());
  }
  if (options.probeManifests ?? true) {
    for (const manifest of MANIFEST_PATHS) {
      scriptUrls.add(new URL(manifest, entry).toString());
    }
  }

  // ---- fetch the assets ---------------------------------------------------
  const ordered = [...scriptUrls];
  const results = await mapLimit(ordered, (httpOptions.concurrency ?? DEFAULT_HTTP_OPTIONS.concurrency), async (url) => {
    const body = await take(url);
    return body === null ? null : { url, body };
  });
  for (const result of results) {
    if (result) addAsset(result.url, result.body);
  }

  // ---- source maps --------------------------------------------------------
  const resolver: SourcemapResolver = async (asset, url) => {
    if (!asset.url) return null;
    try {
      const resolved = new URL(url, asset.url).toString();
      const text = await take(resolved, 'source map');
      return text === null ? null : { text, id: resolved };
    } catch {
      return null;
    }
  };

  if (options.probeSourcemaps ?? true) {
    const probes = assets
      .filter((asset) => asset.kind === 'javascript' && asset.url)
      .filter((asset) => !/sourceMappingURL/.test(asset.text))
      .map((asset) => `${(asset.url as string).split('?')[0]}.map`);

    const probeResults = await mapLimit(
      [...new Set(probes)].slice(0, Math.max(0, maxAssets - fetched.size)),
      httpOptions.concurrency ?? DEFAULT_HTTP_OPTIONS.concurrency,
      async (url) => {
        const body = await take(url, 'source map probe');
        return body === null ? null : { url, body };
      },
    );
    let hits = 0;
    for (const result of probeResults) {
      if (!result) continue;
      if (!/"version"\s*:\s*3/.test(result.body.slice(0, 400))) continue;
      hits += 1;
      addAsset(result.url, result.body);
    }
    notes.push(
      `Probed ${probeResults.length} undeclared .map sibling(s); ${hits} were reachable source maps.`,
    );
  }

  const report = await analyseAssets(assets, { kind: 'url', value: entry.toString() }, options, resolver);
  report.notes.unshift(...notes);
  report.errors.push(...fetchErrors);
  report.notes.push(`HTTP requests issued: ${client.requests + (throttled === client ? 0 : throttled.requests)}`);
  return report;
}

/** The path of a URL, or the whole string if it will not parse. */
function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

function kindFromUrl(url: URL): Asset['kind'] {
  const kind = kindFromPath(url.pathname);
  if (kind !== 'other') return kind;
  return url.pathname === '/' || url.pathname.endsWith('/') ? 'html' : 'other';
}

/** Run an async mapper over a list with a concurrency cap, preserving order. */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  mapper: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const workers = new Array(Math.max(1, Math.min(limit, items.length))).fill(null).map(
    async () => {
      for (;;) {
        const index = cursor;
        cursor += 1;
        if (index >= items.length) return;
        results[index] = await mapper(items[index] as T, index);
      }
    },
  );
  await Promise.all(workers);
  return results;
}
