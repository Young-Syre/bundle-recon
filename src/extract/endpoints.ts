import type * as acorn from 'acorn';
import * as walk from 'acorn-walk';

import type { Asset, Confidence, EndpointFinding, HttpMethod } from '../types.js';
import type { LineIndex } from '../util/text.js';
import { oneLine } from '../util/text.js';
import {
  calleeName,
  expressionToPathPattern,
  findProperty,
  propertyKeyName,
  staticString,
} from '../util/ast.js';

const METHODS: readonly HttpMethod[] = [
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
];

/** Property names that are HTTP verbs on an axios-style client. */
const VERB_METHODS = new Map<string, HttpMethod>([
  ['get', 'GET'],
  ['head', 'HEAD'],
  ['post', 'POST'],
  ['put', 'PUT'],
  ['patch', 'PATCH'],
  ['delete', 'DELETE'],
  ['del', 'DELETE'],
  ['options', 'OPTIONS'],
]);

/**
 * Receiver names that are plausibly an HTTP client. Without this gate,
 * `cache.get(key)` and `map.get(id)` flood the output — `.get()` is the most
 * common method name in JavaScript.
 */
const CLIENT_RECEIVERS =
  /^(\$?_?)(axios|http|https|api|apis|apiClient|client|request|req|rest|fetcher|fetch|service|svc|agent|instance|ky|got|superagent|xhr|transport|gateway|backend|sdk)$/i;

/** Hosts that appear in bundles as XML/JSON namespaces, never as endpoints. */
const NAMESPACE_HOSTS = new Set([
  'www.w3.org',
  'schema.org',
  'json-schema.org',
  'www.inkscape.org',
  'creativecommons.org',
  'purl.org',
  'ns.adobe.com',
  'sodipodi.sourceforge.net',
  'xmlns.com',
  'gmpg.org',
  'ogp.me',
]);

const ASSET_EXTENSION =
  /\.(png|jpe?g|gif|svg|webp|avif|ico|bmp|tiff?|woff2?|ttf|eot|otf|css|scss|sass|less|map|mp[34]|m4a|wav|ogg|webm|mov|wasm|zip|gz|br|pdf|docx?|xlsx?|md|lock|ya?ml|license|txt)$/i;

const MIME_PREFIX =
  /^(text|image|application|audio|video|font|multipart|message|model)\/[a-z0-9]/i;

export interface EndpointContext {
  asset: Asset;
  program: acorn.Program;
  consts: ReadonlyMap<string, string>;
  lines: LineIndex;
  /** Include bare URL-shaped string literals as low-confidence findings. */
  includeStringLiterals: boolean;
}

/**
 * Extract request call sites from a parsed asset.
 *
 * The goal is a callable request, not a string that contains a slash: the
 * method comes from the call (the verb property, an `init.method`, or
 * `xhr.open`'s first argument) and template interpolations become named
 * `{param}` placeholders.
 */
export function extractEndpoints(context: EndpointContext): EndpointFinding[] {
  const out: EndpointFinding[] = [];
  const { asset, program, consts, lines } = context;

  const record = (
    node: acorn.AnyNode,
    path: string,
    method: HttpMethod,
    client: string,
    params: string[],
    confidence: Confidence,
  ): void => {
    const normalised = normalisePath(path);
    if (!normalised) return;
    const { line, column } = lines.locate(node.start);
    out.push({
      path: normalised,
      method,
      client,
      params,
      provenance: 'ast-call',
      confidence,
      locations: [{ asset: asset.id, line, column }],
      evidence: oneLine(lines.excerpt(node.start, 70), 140),
    });
  };

  const fromArgument = (
    argument: acorn.AnyNode | undefined,
  ): { path: string; params: string[]; exact: boolean } | null => {
    if (!argument || argument.type === 'SpreadElement') return null;
    const pattern = expressionToPathPattern(argument, consts);
    if (!pattern || pattern.pattern.trim() === '') return null;
    return { path: pattern.pattern, params: pattern.params, exact: pattern.exact };
  };

  walk.simple(program, {
    CallExpression(node) {
      const name = calleeName(node.callee as acorn.AnyNode);
      if (!name) return;
      const parts = name.split('.');
      const last = parts[parts.length - 1] ?? '';
      const receiver = parts.length > 1 ? (parts[parts.length - 2] ?? '') : '';

      // --- fetch(url, init) -------------------------------------------------
      if (last === 'fetch' && (parts.length === 1 || receiver === 'window' || receiver === 'globalThis' || receiver === 'self')) {
        const target = fromArgument(node.arguments[0] as acorn.AnyNode | undefined);
        if (!target) return;
        const method = methodFromInit(node.arguments[1] as acorn.AnyNode | undefined, consts);
        record(node, target.path, method, 'fetch', target.params, target.exact ? 'high' : 'high');
        return;
      }

      // --- axios.get(url) / api.post(url) ----------------------------------
      const verb = VERB_METHODS.get(last);
      if (verb && parts.length > 1 && CLIENT_RECEIVERS.test(receiver)) {
        const target = fromArgument(node.arguments[0] as acorn.AnyNode | undefined);
        if (!target) return;
        record(
          node,
          target.path,
          verb,
          `${receiver}.${last}`,
          target.params,
          receiver.toLowerCase() === 'axios' ? 'high' : 'medium',
        );
        return;
      }

      // --- axios({url, method}) / axios.request({...}) / ky(url, {method}) --
      if (
        name === 'axios' ||
        last === 'request' ||
        (last === 'ajax' && CLIENT_RECEIVERS.test(receiver)) ||
        (last === 'ajax' && receiver === '$')
      ) {
        const config = node.arguments.find(
          (argument) => argument.type === 'ObjectExpression',
        ) as acorn.AnyNode | undefined;
        const first = node.arguments[0] as acorn.AnyNode | undefined;
        const urlNode =
          config && findProperty(config, 'url')
            ? findProperty(config, 'url')
            : first && first.type !== 'ObjectExpression'
              ? first
              : null;
        const target = fromArgument(urlNode ?? undefined);
        if (!target) return;
        const method =
          methodFromConfig(config, consts) ??
          methodFromInit(node.arguments[1] as acorn.AnyNode | undefined, consts);
        record(node, target.path, method, name, target.params, 'medium');
        return;
      }

      // --- xhr.open(method, url) -------------------------------------------
      if (last === 'open' && node.arguments.length >= 2) {
        const verbLiteral = staticString(node.arguments[0] as acorn.AnyNode, consts);
        const method = normaliseMethod(verbLiteral);
        if (!verbLiteral || method === 'UNKNOWN') return;
        const target = fromArgument(node.arguments[1] as acorn.AnyNode | undefined);
        if (!target) return;
        record(node, target.path, method, 'XMLHttpRequest', target.params, 'high');
        return;
      }

      // --- navigator.sendBeacon(url) ---------------------------------------
      if (last === 'sendBeacon') {
        const target = fromArgument(node.arguments[0] as acorn.AnyNode | undefined);
        if (target) record(node, target.path, 'POST', 'sendBeacon', target.params, 'high');
      }
    },

    NewExpression(node) {
      const name = calleeName(node.callee as acorn.AnyNode);
      if (!name) return;
      const target = fromArgument(node.arguments[0] as acorn.AnyNode | undefined);
      if (!target) return;

      if (name === 'Request') {
        const method = methodFromInit(node.arguments[1] as acorn.AnyNode | undefined, consts);
        record(node, target.path, method, 'Request', target.params, 'high');
      } else if (name === 'WebSocket') {
        record(node, target.path, 'UNKNOWN', 'WebSocket', target.params, 'high');
      } else if (name === 'EventSource') {
        record(node, target.path, 'GET', 'EventSource', target.params, 'high');
      }
    },
  });

  if (context.includeStringLiterals) {
    out.push(...extractUrlLiterals(context));
  }

  return out;
}

/**
 * The LinkFinder-style baseline: URL-shaped string literals with no call site.
 *
 * Kept separate, marked `string-literal` and reported at low confidence, so
 * that the structured findings above are not buried in it.
 */
export function extractUrlLiterals(context: EndpointContext): EndpointFinding[] {
  const out: EndpointFinding[] = [];
  const { asset, program, lines } = context;

  const consider = (node: acorn.AnyNode, raw: string): void => {
    const normalised = normalisePath(raw);
    if (!normalised) return;
    const { line, column } = lines.locate(node.start);
    out.push({
      path: normalised,
      method: 'UNKNOWN',
      params: [],
      provenance: 'string-literal',
      confidence: 'low',
      locations: [{ asset: asset.id, line, column }],
    });
  };

  walk.simple(program, {
    Literal(node) {
      if (typeof node.value === 'string') consider(node, node.value);
    },
    TemplateLiteral(node) {
      const pattern = expressionToPathPattern(node, context.consts);
      if (pattern) consider(node, pattern.pattern);
    },
  });

  return out;
}

/** `{ method: "POST" }` on a fetch init / axios config. */
function methodFromInit(
  node: acorn.AnyNode | undefined,
  consts: ReadonlyMap<string, string>,
): HttpMethod {
  return methodFromConfig(node, consts) ?? 'GET';
}

function methodFromConfig(
  node: acorn.AnyNode | null | undefined,
  consts: ReadonlyMap<string, string>,
): HttpMethod | null {
  if (!node || node.type !== 'ObjectExpression') return null;
  for (const key of ['method', 'type']) {
    const value = findProperty(node, key);
    if (!value) continue;
    const method = normaliseMethod(staticString(value, consts));
    if (method !== 'UNKNOWN') return method;
  }
  return null;
}

function normaliseMethod(value: string | null | undefined): HttpMethod {
  if (!value) return 'UNKNOWN';
  const upper = value.trim().toUpperCase();
  return (METHODS as readonly string[]).includes(upper) ? (upper as HttpMethod) : 'UNKNOWN';
}

/**
 * Decide whether a string is worth reporting as a request path, and canonicalise it.
 *
 * Returns null for the things that make naive extractors unusable: MIME types,
 * XML namespaces, static asset filenames, regex sources and CSS fragments.
 */
export function normalisePath(raw: string): string | null {
  let value = raw.trim();
  if (value.length < 2 || value.length > 2048) return null;
  if (/[\s<>"'`\\]/.test(value)) return null;
  if (MIME_PREFIX.test(value)) return null;
  // Regex sources and CSS selectors masquerade as paths.
  if (/[\^$*|[\]()]/.test(value)) return null;

  const isAbsolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
  const isProtocolRelative = value.startsWith('//') && !value.startsWith('///');

  if (isAbsolute || isProtocolRelative) {
    let parsed: URL;
    try {
      parsed = new URL(isProtocolRelative ? `https:${value}` : value);
    } catch {
      return null;
    }
    if (!/^(https?|wss?):$/.test(parsed.protocol)) return null;
    if (NAMESPACE_HOSTS.has(parsed.hostname)) return null;
    if (!parsed.hostname.includes('.') && parsed.hostname !== 'localhost') return null;
    if (ASSET_EXTENSION.test(parsed.pathname)) return null;
    value = isProtocolRelative ? value : parsed.toString().replace(/\/$/, parsed.pathname === '/' ? '/' : '');
    return value;
  }

  if (!value.startsWith('/')) return null;
  if (value === '/' || /^\/{2,}$/.test(value)) return null;
  if (value.length < 4) return null;
  if (ASSET_EXTENSION.test(value.split('?')[0] ?? value)) return null;
  // Must contain at least one letter: `/1/2/3` is almost always a format string.
  if (!/[a-z]/i.test(value)) return null;
  // Single-letter segments, and bare asset directories like `/_next/` or
  // `/static/`, are not endpoints.
  if (/^\/[a-z]\/?$/i.test(value)) return null;
  if (/^\/[A-Za-z0-9_.-]+\/$/.test(value)) return null;
  return value.replace(/\/{2,}/g, '/');
}

const PROVENANCE_RANK: Record<string, number> = {
  'ast-call': 4,
  openapi: 3,
  'next-data': 2,
  'string-literal': 1,
};

const CONFIDENCE_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

/**
 * Merge endpoint findings, keyed by method + path.
 *
 * A path seen both as a resolved `fetch()` call and as a bare literal is one
 * endpoint; the stronger provenance wins and the locations are unioned.
 */
export function mergeEndpoints(findings: EndpointFinding[]): EndpointFinding[] {
  const byKey = new Map<string, EndpointFinding>();

  for (const finding of findings) {
    const key = `${finding.method} ${finding.path}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...finding, locations: [...finding.locations] });
      continue;
    }
    for (const location of finding.locations) {
      const duplicate = existing.locations.some(
        (candidate) =>
          candidate.asset === location.asset &&
          candidate.line === location.line &&
          candidate.column === location.column,
      );
      if (!duplicate) existing.locations.push(location);
    }
    const better =
      (PROVENANCE_RANK[finding.provenance] ?? 0) > (PROVENANCE_RANK[existing.provenance] ?? 0);
    if (better) {
      existing.provenance = finding.provenance;
      existing.client = finding.client ?? existing.client;
      existing.evidence = finding.evidence ?? existing.evidence;
      if (finding.params.length > 0) existing.params = finding.params;
    }
    if (CONFIDENCE_RANK[finding.confidence] > CONFIDENCE_RANK[existing.confidence]) {
      existing.confidence = finding.confidence;
    }
    if (finding.originalLocation && !existing.originalLocation) {
      existing.originalLocation = finding.originalLocation;
    }
  }

  // Concatenated paths leave their pieces behind as separate literals:
  // `fetch(root + "/teams/" + id + "/invitations")` yields `/teams/` and
  // `/invitations` alongside the resolved `/api/v3/teams/{teamId}/invitations`.
  // Those fragments are not endpoints, so a bare literal is dropped when a
  // resolved call site already contains it.
  const resolved = [...byKey.values()].filter(
    (finding) => finding.provenance !== 'string-literal',
  );

  const redundant = (finding: EndpointFinding): boolean => {
    if (finding.provenance !== 'string-literal') return false;
    return resolved.some(
      (other) => other.path !== finding.path && other.path.includes(finding.path),
    ) || resolved.some((other) => other.path === finding.path);
  };

  return [...byKey.values()]
    .filter((finding) => !redundant(finding))
    .sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
}
