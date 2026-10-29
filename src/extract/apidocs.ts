import type {
  EndpointFinding,
  GraphQLFinding,
  HttpMethod,
  Location,
  OpenApiFinding,
} from '../types.js';
import type { LineIndex } from '../util/text.js';
import { normalisePath } from './endpoints.js';

export interface ApiDocsContext {
  assetId: string;
  text: string;
  lines: LineIndex;
  /** True when the asset is a standalone JSON document. */
  isJson: boolean;
}

export interface ApiDocsResult {
  openapi: OpenApiFinding[];
  graphql: GraphQLFinding[];
  endpoints: EndpointFinding[];
  notes: string[];
}

const HTTP_METHODS = new Set([
  'get',
  'put',
  'post',
  'delete',
  'options',
  'head',
  'patch',
  'trace',
]);

/** OpenAPI/Swagger documents and GraphQL operations embedded in an asset. */
export function extractApiDocs(context: ApiDocsContext): ApiDocsResult {
  return {
    ...extractOpenApi(context),
    graphql: extractGraphQL(context),
  };
}

/**
 * Recover an OpenAPI or Swagger document.
 *
 * Bundled specs show up more often than you would expect: a generated client
 * may embed the whole document, and an API-explorer page ships it to the
 * browser outright. When one is present it is the single best artefact in a
 * scan — a complete, authoritative list of operations.
 */
export function extractOpenApi(
  context: ApiDocsContext,
): Pick<ApiDocsResult, 'openapi' | 'endpoints' | 'notes'> {
  const openapi: OpenApiFinding[] = [];
  const endpoints: EndpointFinding[] = [];
  const notes: string[] = [];
  const { text, lines, assetId } = context;

  const documents: { value: Record<string, unknown>; offset: number }[] = [];

  if (context.isJson) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (isSpec(parsed)) documents.push({ value: parsed, offset: 0 });
    } catch {
      // Not valid JSON overall; fall through to the embedded scan.
    }
  }

  if (documents.length === 0) {
    const anchor = /"(?:openapi|swagger)"\s*:\s*"(\d[^"]{0,20})"/g;
    let match: RegExpExecArray | null;
    while ((match = anchor.exec(text)) !== null) {
      const document = enclosingJsonObject(text, match.index);
      if (document && isSpec(document.value)) documents.push(document);
      if (documents.length >= 4) break;
    }
  }

  for (const { value, offset } of documents) {
    const { line, column } = lines.locate(offset);
    const location: Location = { asset: assetId, line, column };

    const version =
      typeof value['openapi'] === 'string'
        ? `openapi ${String(value['openapi'])}`
        : `swagger ${String(value['swagger'])}`;

    const info = asRecord(value['info']);
    const title = info && typeof info['title'] === 'string' ? (info['title'] as string) : undefined;

    const servers: string[] = [];
    if (Array.isArray(value['servers'])) {
      for (const server of value['servers']) {
        const record = asRecord(server);
        if (record && typeof record['url'] === 'string') servers.push(record['url'] as string);
      }
    }
    if (typeof value['host'] === 'string') {
      const schemes = Array.isArray(value['schemes'])
        ? (value['schemes'] as unknown[]).filter((item): item is string => typeof item === 'string')
        : ['https'];
      const basePath = typeof value['basePath'] === 'string' ? (value['basePath'] as string) : '';
      for (const scheme of schemes) servers.push(`${scheme}://${String(value['host'])}${basePath}`);
    }

    const operations: OpenApiFinding['operations'] = [];
    const paths = asRecord(value['paths']);
    if (paths) {
      for (const [path, item] of Object.entries(paths)) {
        const record = asRecord(item);
        if (!record) continue;
        for (const [method, operation] of Object.entries(record)) {
          if (!HTTP_METHODS.has(method.toLowerCase())) continue;
          const detail = asRecord(operation);
          const operationId =
            detail && typeof detail['operationId'] === 'string'
              ? (detail['operationId'] as string)
              : undefined;
          operations.push({
            method: method.toUpperCase() as HttpMethod,
            path,
            ...(operationId ? { operationId } : {}),
          });

          const normalised = normalisePath(path.replace(/\{([^}]+)\}/g, '{$1}'));
          if (normalised) {
            endpoints.push({
              path: normalised,
              method: method.toUpperCase() as HttpMethod,
              client: 'openapi',
              params: [...path.matchAll(/\{([^}]+)\}/g)].map((parameter) => parameter[1] ?? ''),
              provenance: 'openapi',
              confidence: 'high',
              locations: [location],
              ...(operationId ? { evidence: `operationId ${operationId}` } : {}),
            });
          }
        }
      }
    }

    openapi.push({
      spec: version,
      ...(title ? { title } : {}),
      servers: [...new Set(servers)],
      operations: operations.sort((a, b) => a.path.localeCompare(b.path)),
      locations: [location],
    });
    notes.push(
      `${assetId}: embedded ${version} document with ${operations.length} operations — authoritative endpoint list.`,
    );
  }

  return { openapi, endpoints, notes };
}

function isSpec(value: unknown): value is Record<string, unknown> {
  const record = asRecord(value);
  if (!record) return false;
  const declared =
    typeof record['openapi'] === 'string' || typeof record['swagger'] === 'string';
  return declared && (record['paths'] !== undefined || record['components'] !== undefined);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * Find the JSON object that encloses an offset, inside a larger file.
 *
 * Scans backwards for plausible object starts (a `{` followed by a quoted
 * key) and forwards with a string-aware brace matcher. Bounded on both sides
 * so a pathological asset cannot turn this into a quadratic scan.
 */
export function enclosingJsonObject(
  text: string,
  offset: number,
): { value: Record<string, unknown>; offset: number } | null {
  const windowStart = Math.max(0, offset - 16_384);
  const candidates: number[] = [];
  for (let index = windowStart; index < offset; index += 1) {
    if (text[index] !== '{') continue;
    const next = /^\s*"/.test(text.slice(index + 1, index + 4));
    if (next) candidates.push(index);
  }

  for (const start of candidates) {
    const end = matchBraces(text, start);
    if (end <= offset) continue;
    try {
      const parsed: unknown = JSON.parse(text.slice(start, end + 1));
      const record = asRecord(parsed);
      if (record) return { value: record, offset: start };
    } catch {
      // Keep trying later candidates.
    }
  }
  return null;
}

/** Index of the `}` matching the `{` at `start`, or -1. Respects strings. */
export function matchBraces(text: string, start: number, limit = 8_388_608): number {
  let depth = 0;
  let inString = false;
  let escaped = false;
  const end = Math.min(text.length, start + limit);

  for (let index = start; index < end; index += 1) {
    const char = text[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') inString = true;
    else if (char === '{') depth += 1;
    else if (char === '}') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

/** Characters that may appear in a GraphQL document but not much else. */
const GRAPHQL_BODY = /^[\s\w{}:(),.$![\]@="'#/+*-]*$/;
const NOT_GRAPHQL = /(=>|\bfunction\b|\breturn\b|\bvar\b|\bconst\b|\blet\b|;|\|\||&&|\+\+)/;

/**
 * Extract GraphQL operation documents.
 *
 * Operation text survives minification because it is string data, so the
 * document, its variables and its top-level selections can be read straight
 * out of the bundle. Those selections are the schema surface worth probing —
 * far more targeted than hitting `/graphql` with a blind introspection query.
 */
export function extractGraphQL(context: ApiDocsContext): GraphQLFinding[] {
  const { text, lines, assetId } = context;
  const out = new Map<string, GraphQLFinding>();
  const pattern =
    /\b(query|mutation|subscription|fragment)\s+([A-Za-z_]\w*)?\s*(?:on\s+([A-Za-z_]\w*)\s*)?(\([^)]{0,600}\))?\s*\{/g;

  let match: RegExpExecArray | null;
  let guard = 0;
  while ((match = pattern.exec(text)) !== null && guard < 2000) {
    guard += 1;
    const keyword = match[1] as GraphQLFinding['operation'];
    const name = match[2];
    const variablesText = match[4] ?? '';
    const braceStart = match.index + match[0].length - 1;
    const braceEnd = matchBraces(text, braceStart, 200_000);
    if (braceEnd < 0) continue;

    const body = text.slice(braceStart + 1, braceEnd);
    if (body.length < 2 || body.length > 100_000) continue;
    if (!GRAPHQL_BODY.test(body) || NOT_GRAPHQL.test(body)) continue;

    const fields = topLevelFields(body);
    if (fields.length === 0) continue;

    const variables = [...variablesText.matchAll(/\$(\w+)\s*:\s*([\w![\]]+)/g)].map(
      (variable) => `$${variable[1] ?? ''}: ${variable[2] ?? ''}`,
    );

    const { line, column } = lines.locate(match.index);
    const key = `${keyword}:${name ?? '(anonymous)'}:${fields.join(',')}`;
    if (out.has(key)) continue;
    out.set(key, {
      operation: keyword,
      ...(name ? { name } : {}),
      fields,
      variables,
      locations: [{ asset: assetId, line, column }],
    });
  }

  return [...out.values()].sort(
    (a, b) => a.operation.localeCompare(b.operation) || (a.name ?? '').localeCompare(b.name ?? ''),
  );
}

/** The field names selected at the top level of a selection set. */
function topLevelFields(body: string): string[] {
  const fields: string[] = [];
  let depth = 0;
  let token = '';
  let skippingArguments = 0;

  const flush = (): void => {
    const name = token.trim().replace(/:$/, '');
    token = '';
    if (name.length === 0) return;
    if (name.startsWith('...') || name.startsWith('@') || name.startsWith('$')) return;
    if (!/^[A-Za-z_]\w*$/.test(name)) return;
    if (name === 'on' || name === 'fragment') return;
    if (!fields.includes(name)) fields.push(name);
  };

  for (const char of body) {
    if (skippingArguments > 0) {
      if (char === '(') skippingArguments += 1;
      else if (char === ')') skippingArguments -= 1;
      continue;
    }
    if (char === '(') {
      skippingArguments = 1;
      if (depth === 0) flush();
      continue;
    }
    if (char === '{') {
      if (depth === 0) flush();
      depth += 1;
      token = '';
      continue;
    }
    if (char === '}') {
      depth = Math.max(0, depth - 1);
      token = '';
      continue;
    }
    if (depth > 0) continue;
    if (/[\s,]/.test(char)) {
      flush();
      continue;
    }
    token += char;
  }
  flush();

  // An alias (`alias: field`) leaves the alias in place, which is the name the
  // client actually sends, so it is kept as-is.
  return fields.slice(0, 60);
}
