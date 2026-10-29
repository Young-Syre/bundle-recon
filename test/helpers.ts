import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseJs, stringConstants } from '../src/util/ast.js';
import { LineIndex } from '../src/util/text.js';
import type { Asset } from '../src/types.js';
import type { FrameworkContext } from '../src/extract/context.js';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Absolute path to a file under test/fixtures. */
export function fixture(...parts: string[]): string {
  return path.resolve(here, '..', '..', 'test', 'fixtures', ...parts);
}

/** Build an in-memory JavaScript asset with everything the extractors need. */
export function jsContext(id: string, text: string): FrameworkContext & { asset: Asset } {
  const parsed = parseJs(text);
  if (!parsed.program) throw new Error(`fixture source did not parse: ${parsed.error ?? ''}`);
  return {
    asset: { id, kind: 'javascript', text, bytes: Buffer.byteLength(text) },
    program: parsed.program,
    lines: new LineIndex(text),
    consts: stringConstants(parsed.program),
  };
}

/** Build an in-memory HTML asset. */
export function htmlContext(id: string, text: string): FrameworkContext & { asset: Asset } {
  return {
    asset: { id, kind: 'html', text, bytes: Buffer.byteLength(text) },
    program: null,
    lines: new LineIndex(text),
    consts: new Map(),
  };
}

/** Build an in-memory JSON asset. */
export function jsonContext(id: string, text: string): FrameworkContext & { asset: Asset } {
  return {
    asset: { id, kind: 'json', text, bytes: Buffer.byteLength(text) },
    program: null,
    lines: new LineIndex(text),
    consts: new Map(),
  };
}
