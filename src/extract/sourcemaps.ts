import * as fs from 'node:fs/promises';
import * as path from 'node:path';

import { SourceMapConsumer, type RawIndexMap, type RawSourceMap } from 'source-map';

import type { Asset, OriginalPosition, SourcemapFinding } from '../types.js';
import { buildTree, countFiles, normaliseSourcePath } from '../util/tree.js';
import { safeOutputPath } from '../util/paths.js';

/** A `sourceMappingURL` annotation found in an asset. */
export interface SourceMappingAnnotation {
  /** The raw URL, which may be a `data:` URI. */
  url: string;
  /** Character offset of the annotation. */
  offset: number;
  inline: boolean;
}

/**
 * Find the `sourceMappingURL` annotation.
 *
 * Both comment forms are accepted, including the deprecated `//@` spelling
 * that older builds still emit, and the trailing annotation wins — that is
 * what browsers do when a file carries more than one.
 */
export function findSourceMappingAnnotation(text: string): SourceMappingAnnotation | null {
  const pattern = /(?:\/\/|\/\*)[#@]\s*sourceMappingURL\s*=\s*([^\s'"*]+)\s*(?:\*\/)?/g;
  let last: SourceMappingAnnotation | null = null;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const url = match[1];
    if (!url) continue;
    last = { url, offset: match.index, inline: url.startsWith('data:') };
  }
  return last;
}

/** Decode a `data:` source-map URI into raw JSON text. */
export function decodeDataUri(uri: string): string | null {
  const match = /^data:([^,]*),(.*)$/s.exec(uri);
  if (!match) return null;
  const meta = match[1] ?? '';
  const payload = match[2] ?? '';
  try {
    if (/;base64/i.test(meta)) return Buffer.from(payload, 'base64').toString('utf8');
    return decodeURIComponent(payload);
  } catch {
    return null;
  }
}

/** A parsed source map, plus the consumer needed to map positions back. */
export interface LoadedSourcemap {
  finding: SourcemapFinding;
  consumer: SourceMapConsumer;
  /** Original text per normalised source path, where the map shipped it. */
  contents: Map<string, string>;
}

/** Paths worth calling out in a report, in priority order. */
const HIGHLIGHT_PATTERNS: readonly RegExp[] = [
  /(^|\/)\.env/i,
  /(^|\/)(secrets?|credentials?)\b/i,
  /(^|\/)(middleware|proxy)\.[cm]?[jt]sx?$/i,
  /(^|\/)(app|pages)\/api\//i,
  /(^|\/)api\//i,
  /(^|\/)(admin|internal|private|staff|ops)\//i,
  /(^|\/)(auth|session|permission|rbac|acl)/i,
  /(^|\/)(config|settings|constants)\.[cm]?[jt]sx?$/i,
  /(^|\/)(config|settings|env)\//i,
  /(^|\/)(route|server|action)s?\.[cm]?[jt]sx?$/i,
];

/**
 * Parse a source map and describe what it gives away.
 *
 * `sources` alone is valuable even without `sourcesContent`: the original
 * directory layout names internal modules, feature flags and admin areas that
 * the minified output never mentions.
 */
export async function loadSourcemap(
  rawJson: string,
  options: {
    asset: string;
    discovery: SourcemapFinding['discovery'];
    mapLocation?: string;
  },
): Promise<LoadedSourcemap> {
  const parsed: unknown = JSON.parse(rawJson);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('source map is not a JSON object');
  }
  const map = parsed as RawSourceMap | RawIndexMap;
  const consumer = await new SourceMapConsumer(map as RawSourceMap);

  const contents = new Map<string, string>();
  const normalised: string[] = [];
  let withContent = 0;

  for (const source of consumer.sources) {
    const key = normaliseSourcePath(source);
    normalised.push(key);
    const content = consumer.sourceContentFor(source, true);
    if (typeof content === 'string' && content.length > 0) {
      withContent += 1;
      if (!contents.has(key)) contents.set(key, content);
    }
  }

  const unique = [...new Set(normalised)].sort();
  const tree = buildTree(unique);
  markContent(tree, '', contents);

  const highlights: string[] = [];
  for (const pattern of HIGHLIGHT_PATTERNS) {
    for (const source of unique) {
      if (source.includes('node_modules/')) continue;
      if (pattern.test(source) && !highlights.includes(source)) highlights.push(source);
    }
  }

  const finding: SourcemapFinding = {
    asset: options.asset,
    discovery: options.discovery,
    ...(options.mapLocation ? { mapLocation: options.mapLocation } : {}),
    sourceCount: consumer.sources.length,
    withContent,
    sources: unique,
    tree,
    highlights: highlights.slice(0, 40),
  };

  return { finding, consumer, contents };
}

function markContent(
  node: ReturnType<typeof buildTree>,
  prefix: string,
  contents: Map<string, string>,
): void {
  for (const child of node.children) {
    const full = prefix === '' ? child.name : `${prefix}/${child.name}`;
    if (child.file) child.hasContent = contents.has(full);
    else markContent(child, full, contents);
  }
}

/**
 * Write recovered original sources to disk.
 *
 * Source paths come from the target and are therefore untrusted; every path
 * goes through `safeOutputPath`, so a map claiming `../../../etc/passwd`
 * writes inside the output directory or not at all.
 */
export async function writeRecoveredSources(
  contents: Map<string, string>,
  outDir: string,
  subdirectory: string,
): Promise<string[]> {
  const root = path.resolve(outDir, sanitiseSubdirectory(subdirectory));
  const written: string[] = [];
  for (const [source, content] of contents) {
    const target = safeOutputPath(root, source);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, content, 'utf8');
    written.push(path.relative(path.resolve(outDir), target));
  }
  written.sort();
  return written;
}

function sanitiseSubdirectory(name: string): string {
  const flat = name.replace(/^https?:\/\//, '').replace(/[^A-Za-z0-9._-]+/g, '_');
  return flat.replace(/^_+|_+$/g, '').slice(0, 120) || 'asset';
}

/** Map a generated position back to the original file, if the map covers it. */
export function originalPosition(
  consumer: SourceMapConsumer,
  line: number,
  column: number,
): OriginalPosition | null {
  const mapped = consumer.originalPositionFor({ line, column: Math.max(0, column - 1) });
  if (!mapped.source) return null;
  return {
    source: normaliseSourcePath(mapped.source),
    line: mapped.line,
    column: mapped.column,
    ...(mapped.name ? { name: mapped.name } : {}),
  };
}

/** Count how many original source files a set of findings recovered. */
export function countRecoveredSources(findings: readonly SourcemapFinding[]): number {
  return findings.reduce((sum, finding) => sum + countFiles(finding.tree), 0);
}

/** True when an asset is itself a source map rather than a bundle. */
export function looksLikeSourcemap(asset: Asset): boolean {
  if (asset.kind === 'sourcemap') return true;
  const head = asset.text.slice(0, 400);
  return /"version"\s*:\s*3/.test(head) && /"(sources|sections)"\s*:/.test(head);
}
