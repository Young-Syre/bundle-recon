import type * as acorn from 'acorn';

import type {
  Asset,
  ChunkFinding,
  EndpointFinding,
  FrameworkFinding,
  PayloadFinding,
  RouteFinding,
  SourcemapFinding,
} from '../types.js';
import type { LineIndex } from '../util/text.js';

/** Everything a framework extractor needs about one asset. */
export interface FrameworkContext {
  asset: Asset;
  /** Null when the asset is not JavaScript, or failed to parse. */
  program: acorn.Program | null;
  lines: LineIndex;
  consts: ReadonlyMap<string, string>;
}

/** What a framework extractor contributes to the report. */
export interface FrameworkResult {
  routes: RouteFinding[];
  chunks: ChunkFinding[];
  endpoints: EndpointFinding[];
  payloads: PayloadFinding[];
  frameworks: FrameworkFinding[];
  /** Original source paths recovered from a build manifest. */
  sourcemaps: SourcemapFinding[];
  notes: string[];
}

export function emptyResult(): FrameworkResult {
  return {
    routes: [],
    chunks: [],
    endpoints: [],
    payloads: [],
    frameworks: [],
    sourcemaps: [],
    notes: [],
  };
}

export function mergeResults(results: readonly FrameworkResult[]): FrameworkResult {
  const out = emptyResult();
  for (const result of results) {
    out.routes.push(...result.routes);
    out.chunks.push(...result.chunks);
    out.endpoints.push(...result.endpoints);
    out.payloads.push(...result.payloads);
    out.frameworks.push(...result.frameworks);
    out.sourcemaps.push(...result.sourcemaps);
    out.notes.push(...result.notes);
  }
  return out;
}
