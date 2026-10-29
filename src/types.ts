/**
 * Public type surface for bundle-recon.
 *
 * Every extractor contributes findings to a single `ReconReport`. Findings
 * carry provenance (which asset, which byte offset, which extractor) so a
 * consumer can always get back to the evidence.
 */

export type AssetKind =
  | 'javascript'
  | 'html'
  | 'json'
  | 'sourcemap'
  | 'css'
  | 'other';

/** One unit of input: a file on disk, or a response body fetched over HTTP. */
export interface Asset {
  /** Display identifier — a path relative to the scan root, or a URL. */
  id: string;
  kind: AssetKind;
  text: string;
  /** Byte length of the asset as read. */
  bytes: number;
  /** Absolute URL the asset was fetched from, when known. */
  url?: string;
  /** Absolute path on disk, when known. */
  file?: string;
}

export interface Location {
  /** `Asset.id` this finding came from. */
  asset: string;
  /** 1-based line. */
  line: number;
  /** 1-based column. */
  column: number;
}

/** Where a finding's evidence came from. Drives the "why trust this" column. */
export type Provenance =
  | 'ast-call' // a resolved fetch/axios/XHR call site
  | 'string-literal' // a bare URL-shaped string in the bundle
  | 'next-build-manifest'
  | 'next-ssg-manifest'
  | 'next-data'
  | 'next-flight'
  | 'nuxt-payload'
  | 'vite-manifest'
  | 'webpack-chunk-map'
  | 'sourcemap'
  | 'openapi'
  | 'graphql'
  | 'secret-rule';

export type Confidence = 'high' | 'medium' | 'low';

export type HttpMethod =
  | 'GET'
  | 'HEAD'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'DELETE'
  | 'OPTIONS'
  | 'UNKNOWN';

export interface EndpointFinding {
  /** Normalised path or absolute URL, with `{param}` placeholders. */
  path: string;
  method: HttpMethod;
  /** The client that issued the call, e.g. `fetch`, `axios.post`, `xhr`. */
  client?: string;
  /** Names of interpolated path parameters, in order of appearance. */
  params: string[];
  provenance: Provenance;
  confidence: Confidence;
  locations: Location[];
  /** Original source position, if a source map let us map the call site back. */
  originalLocation?: OriginalPosition;
  /** Short, redacted source snippet for human review. */
  evidence?: string;
}

export interface RouteFinding {
  /** Route pattern as the framework declares it, e.g. `/blog/[slug]`. */
  route: string;
  framework: 'next' | 'nuxt' | 'vite' | 'unknown';
  /** `page` for a routable page, `internal` for `/_app`-style entries. */
  kind: 'page' | 'api' | 'internal';
  /** True when the route declares a dynamic segment. */
  dynamic: boolean;
  /** Asset files the framework associates with this route. */
  assets?: string[];
  /** True when the route is listed as statically generated (Next SSG manifest). */
  prerendered?: boolean;
  provenance: Provenance;
  locations: Location[];
}

export interface ChunkFinding {
  /** Chunk id as the runtime knows it. */
  id: string;
  /** Reconstructed URL path, e.g. `static/chunks/4821.9f1c2d.js`. */
  file?: string;
  /** Human-readable chunk name, when the runtime carries a name map. */
  name?: string;
  /** True when nothing in the scanned assets references this chunk directly. */
  lazy: boolean;
  provenance: Provenance;
  locations: Location[];
}

export interface OriginalPosition {
  source: string;
  line: number | null;
  column: number | null;
  name?: string | null;
}

export interface SourcemapFinding {
  /** Asset the map was discovered from. */
  asset: string;
  /** How the map was located. */
  discovery:
    | 'comment'
    | 'inline-data-uri'
    | 'sibling-file'
    | 'direct'
    /** Original paths came from a build manifest, not a source map. */
    | 'vite-manifest';
  /** Resolved location of the map (path or URL), when not inline. */
  mapLocation?: string;
  /** Number of entries in `sources`. */
  sourceCount: number;
  /** Number of `sources` that shipped their original text in `sourcesContent`. */
  withContent: number;
  /** Normalised original source paths. */
  sources: string[];
  /** Directory tree rebuilt from `sources`. */
  tree: TreeNode;
  /** Paths written to disk when `--out` was supplied. */
  written?: string[];
  /** Interesting original paths (routes, config, internal modules). */
  highlights: string[];
}

export interface TreeNode {
  name: string;
  children: TreeNode[];
  /** True for a leaf that corresponds to an original source file. */
  file: boolean;
  /** True when the file shipped its original text. */
  hasContent?: boolean;
}

/**
 * Whether a credential of this shape is *meant* to be in a public bundle.
 *
 * - `secret`   — never belongs in client code; treat as a finding.
 * - `public`   — published by design (Stripe publishable key, Firebase web
 *                config). Reported for recon value, not as a vulnerability.
 * - `depends`  — the same shape covers both cases and only context decides
 *                (a Google API key, a Supabase JWT). The rationale says which
 *                way the evidence points.
 */
export type Exposure = 'secret' | 'public' | 'depends';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecretFinding {
  /** Stable rule id, e.g. `stripe-secret-key`. */
  rule: string;
  title: string;
  provider?: string;
  /** `confirmed-shape` when a vendor-specific format matched; else heuristic. */
  classification: 'confirmed-shape' | 'heuristic';
  exposure: Exposure;
  severity: Severity;
  /** Redacted unless `--show-secrets` was passed. */
  value: string;
  /** Shannon entropy of the matched value, in bits per character. */
  entropy: number;
  /** Why this was reported, and what the exposure call rests on. */
  rationale: string;
  /** Suggested next step for a tester. */
  nextStep?: string;
  /** True when the value looks like vendor documentation or a placeholder. */
  placeholder?: boolean;
  locations: Location[];
  /** Redacted one-line context. */
  context?: string;
  provenance: Provenance;
}

export interface GraphQLFinding {
  operation: 'query' | 'mutation' | 'subscription' | 'fragment';
  name?: string;
  /** Top-level selected fields. */
  fields: string[];
  /** Declared variables, e.g. `$id: ID!`. */
  variables: string[];
  locations: Location[];
}

export interface OpenApiFinding {
  /** `openapi` or `swagger`, with the declared version. */
  spec: string;
  title?: string;
  /** Declared server URLs / basePath. */
  servers: string[];
  operations: { method: HttpMethod; path: string; operationId?: string }[];
  locations: Location[];
}

/** An interesting value lifted out of a server-rendered hydration payload. */
export interface PayloadFinding {
  /** Which payload it came from. */
  source: '__NEXT_DATA__' | 'self.__next_f' | '__NUXT__' | '__NUXT_DATA__';
  /** Dotted path within the payload, e.g. `props.pageProps.apiBase`. */
  key: string;
  /** Redacted when it tripped a secret rule. */
  value: string;
  /** Why this key was surfaced. */
  reason: string;
  locations: Location[];
}

export interface FrameworkFinding {
  name: 'next' | 'nuxt' | 'vite' | 'webpack' | 'react' | 'svelte' | 'remix';
  /** Version string, only when the bundle states one. */
  version?: string;
  /** Extra detail, e.g. `app-router`, `buildId=AbC123`. */
  details: string[];
  evidence: Location[];
}

export interface AssetSummary {
  id: string;
  kind: AssetKind;
  bytes: number;
  /** True when the asset parsed as JavaScript. */
  parsed?: boolean;
  /** Parse error, when the asset looked like JS but would not parse. */
  parseError?: string;
}

export interface ReconError {
  asset?: string;
  stage: string;
  message: string;
}

export interface ReconStats {
  assets: number;
  bytes: number;
  endpoints: number;
  routes: number;
  chunks: number;
  secrets: number;
  recoveredSources: number;
  durationMs: number;
}

export interface Target {
  kind: 'file' | 'directory' | 'url';
  value: string;
}

export interface ReconReport {
  tool: { name: string; version: string };
  generatedAt: string;
  target: Target;
  assets: AssetSummary[];
  frameworks: FrameworkFinding[];
  routes: RouteFinding[];
  endpoints: EndpointFinding[];
  chunks: ChunkFinding[];
  sourcemaps: SourcemapFinding[];
  secrets: SecretFinding[];
  graphql: GraphQLFinding[];
  openapi: OpenApiFinding[];
  payloads: PayloadFinding[];
  notes: string[];
  errors: ReconError[];
  stats: ReconStats;
}

export type Section =
  | 'endpoints'
  | 'routes'
  | 'secrets'
  | 'sourcemaps'
  | 'chunks'
  | 'payloads'
  | 'graphql'
  | 'openapi'
  | 'frameworks';

export interface AnalyseOptions {
  /** Restrict the report to these sections. Empty/undefined means all. */
  only?: Section[];
  /** Directory to write recovered source-map sources into. */
  outDir?: string;
  /** Print unredacted secret values. Off by default. */
  showSecrets?: boolean;
  /** Follow `sourceMappingURL` to sibling `.map` files on disk. Default true. */
  followSourcemaps?: boolean;
  /** Include bare URL-shaped string literals (the LinkFinder baseline). */
  includeStringLiterals?: boolean;
  /** Maximum asset size to parse, in bytes. Default 24 MiB. */
  maxAssetBytes?: number;
}
