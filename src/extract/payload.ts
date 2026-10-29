import type { Location, PayloadFinding } from '../types.js';
import { redact } from '../util/text.js';

/** Leaf key names that are worth surfacing out of a hydration payload. */
const INTERESTING_KEY =
  /^(?:api|apis|apiBase|apiUrl|apiHost|apiKey|baseUrl|baseURL|basePath|endpoint|endpoints|url|uri|href|host|hostname|origin|cdn|cdnUrl|assetPrefix|graphql|graphqlUrl|ws|wss|socketUrl|env|environment|stage|region|bucket|tenant|tenantId|clientId|appId|projectId|publicKey|anonKey|token|accessToken|idToken|refreshToken|sessionToken|csrfToken|secret|password|flag|flags|feature|features|featureFlags|debug|devMode|version|buildId|revision|commit|email|userId|userEmail|role|roles|permissions|isAdmin|isStaff|admin|internal)$/i;

/** Substrings that make any key interesting, e.g. `stripePublishableKey`. */
const INTERESTING_SUBSTRING =
  /(url|uri|endpoint|host|token|secret|apikey|api_key|password|credential|flag|feature|bucket|webhook|graphql)/i;

/** Keys whose values are redacted on the way out. */
const SENSITIVE_KEY = /(secret|password|passwd|token|credential|private)/i;

const URL_LIKE = /^(?:https?:\/\/|wss?:\/\/|\/\/)[^\s]+$/i;
const PATH_LIKE = /^\/(?:api|graphql|v\d|_next\/|internal|admin)[^\s]*$/i;
const EMAIL_LIKE = /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i;

export interface PayloadScanOptions {
  source: PayloadFinding['source'];
  location: Location;
  /** Stop after this many findings. Default 150. */
  max?: number;
  /** Prefix for reported key paths, e.g. `props`. */
  prefix?: string;
}

/**
 * Walk a hydration payload and surface the values a tester cares about.
 *
 * Server-rendered payloads are the richest single source in a modern app:
 * they routinely carry API base URLs, feature-flag state, the build id,
 * internal hostnames and — when a developer over-serialises — real user
 * records. Reporting the whole blob is useless, so this picks leaves by key
 * name and by value shape.
 */
export function scanPayload(value: unknown, options: PayloadScanOptions): PayloadFinding[] {
  const out: PayloadFinding[] = [];
  const max = options.max ?? 150;
  const seen = new Set<unknown>();

  const visit = (node: unknown, keyPath: string, depth: number): void => {
    if (out.length >= max || depth > 12) return;

    if (Array.isArray(node)) {
      // Long arrays are lists of records; a sample is enough to characterise them.
      node.slice(0, 20).forEach((item, index) => visit(item, `${keyPath}[${index}]`, depth + 1));
      return;
    }

    if (typeof node === 'object' && node !== null) {
      if (seen.has(node)) return;
      seen.add(node);
      for (const [key, child] of Object.entries(node)) {
        visit(child, keyPath === '' ? key : `${keyPath}.${key}`, depth + 1);
      }
      return;
    }

    const leafKey = keyPath.split('.').pop()?.replace(/\[\d+\]$/, '') ?? '';
    const reason = reasonFor(leafKey, node);
    if (!reason) return;

    out.push({
      source: options.source,
      key: keyPath,
      value: formatValue(leafKey, node),
      reason,
      locations: [options.location],
    });
  };

  visit(value, options.prefix ?? '', 0);
  return out;
}

function reasonFor(key: string, value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'object') return null;

  if (typeof value === 'string') {
    if (value.length === 0 || value.length > 4096) return null;
    if (URL_LIKE.test(value)) return 'value is an absolute URL';
    if (PATH_LIKE.test(value)) return 'value is an API or internal path';
    if (EMAIL_LIKE.test(value)) return 'value is an email address';
  }

  if (INTERESTING_KEY.test(key)) return 'key names a configuration or identity value';
  if (INTERESTING_SUBSTRING.test(key)) return 'key name suggests configuration';
  if (typeof value === 'boolean' && /^(is|has|can|enable|allow|show)[A-Z]/.test(key)) {
    return 'boolean flag in server-rendered state';
  }
  return null;
}

function formatValue(key: string, value: unknown): string {
  const text = typeof value === 'string' ? value : String(value);
  if (SENSITIVE_KEY.test(key) && text.length > 12) return redact(text);
  return text.length > 200 ? `${text.slice(0, 199)}…` : text;
}
