import { createHash } from 'node:crypto';

import type { Asset, SecretFinding, Severity } from '../types.js';
import type { LineIndex } from '../util/text.js';
import { oneLine, redact } from '../util/text.js';
import {
  distinctRatio,
  looksLikeHexDigest,
  looksLikeIdentifierRun,
  looksLikeProse,
  shannonEntropy,
} from '../util/entropy.js';
import { PLACEHOLDER_PATTERNS, SECRET_RULES, type SecretRule } from './rules.js';

export interface SecretContext {
  asset: Asset;
  lines: LineIndex;
  /** Print full values instead of redacting. */
  showSecrets: boolean;
  /** Extra rules, for callers embedding the library. */
  rules?: readonly SecretRule[];
  /** Called when one of the extraction caps is reached, so it can be reported. */
  onCap?: (note: string) => void;
}

/**
 * How many matches one rule may produce in one asset before it stops.
 *
 * A minified bundle with a pathological pattern can otherwise spend the whole
 * run in one regex. When it fires, say so: silently stopping at 5,000 looks
 * identical to having found everything.
 */
export const MAX_MATCHES_PER_RULE = 5000;

/**
 * Longest matched value kept. Above this it is almost always a concatenated
 * blob rather than one credential -- but it does discard the claim-heavy JWTs
 * the `jwt` rule exists to decode, so it is reported too.
 */
export const MAX_VALUE_LENGTH = 600;

interface Range {
  start: number;
  end: number;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Regions of an asset that must never produce a secret finding.
 *
 * These are the four things that generate essentially all of the false
 * positives in entropy-based scanners:
 *
 *  1. inline source maps (`sourceMappingURL=data:application/json;base64,…`)
 *  2. embedded assets (sprites, fonts, favicons) as `data:` URIs
 *  3. any very long unbroken base64 run — a serialised blob of some kind
 *  4. hex digest tables (integrity hashes, i18n checksums, icon path data)
 */
export function excludedRanges(text: string): Range[] {
  const ranges: Range[] = [];
  const patterns = [
    /sourceMappingURL\s*=\s*data:[^\s'"`)]+/gi,
    /data:[a-z0-9.+-]+\/[a-z0-9.+-]+(?:;charset=[a-z0-9-]+)?;base64,[A-Za-z0-9+/=]+/gi,
    /[A-Za-z0-9+/]{512,}={0,2}/g,
    /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){8,}/g,
  ];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      ranges.push({ start: match.index, end: match.index + match[0].length });
      if (match[0].length === 0) pattern.lastIndex += 1;
    }
  }
  ranges.sort((a, b) => a.start - b.start);

  // Merge overlaps so containment checks stay a single binary search.
  const merged: Range[] = [];
  for (const range of ranges) {
    const last = merged[merged.length - 1];
    if (last && range.start <= last.end) last.end = Math.max(last.end, range.end);
    else merged.push({ ...range });
  }
  return merged;
}

function contains(ranges: readonly Range[], offset: number): boolean {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const range = ranges[mid] as Range;
    if (offset < range.start) hi = mid - 1;
    else if (offset >= range.end) lo = mid + 1;
    else return true;
  }
  return false;
}

function isPlaceholder(value: string): boolean {
  // A URI carries a hostname, and hostnames legitimately contain words like
  // `example`. Judging a connection string by placeholder wording would
  // downgrade a real credential because of where it points.
  if (value.includes('://')) return false;
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(value));
}

/**
 * Filters for heuristic rules that have no context gate.
 *
 * A rule that already requires vendor wording nearby has earned its match;
 * applying "looks like a hash" to it would make the rule unable to fire at
 * all (a Twilio auth token *is* 32 hex characters). So these only run for
 * ungated heuristics.
 */
function looksLikeNoise(value: string): string | null {
  if (looksLikeHexDigest(value)) return 'value is a hex digest (content hash, git sha or MD5)';
  if (looksLikeIdentifierRun(value)) return 'value is a minified identifier, not a key';
  if (looksLikeProse(value)) return 'value is mostly English words';
  if (distinctRatio(value) < 0.3) return 'value has too few distinct characters';
  if (/^\d+$/.test(value)) return 'value is all digits';
  if (/^#[0-9a-f]{3,8}$/i.test(value)) return 'value is a CSS colour';
  if (value.includes('${') || value.includes('{{')) return 'value is a template placeholder';
  if (/^(?:https?:)?\/\//.test(value) || value.startsWith('/')) return 'value is a URL or path';
  if (/^\d{4}-\d{2}-\d{2}/.test(value)) return 'value is a date';
  if (/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(value)) return 'value is a MIME type';
  if (/^[A-Za-z0-9_-]+\.(?:js|mjs|cjs|css|json|map|woff2?)$/i.test(value)) {
    return 'value is an asset filename';
  }
  return null;
}

interface RawFinding extends SecretFinding {
  /** Character offset in the asset, kept for post-processing. */
  offset: number;
}

/** Fields extracted from a Firebase web config block. */
export interface FirebaseConfig {
  /** Offset of the `authDomain` key that anchored the match — what we report. */
  anchor: number;
  /** Bounds of the window the fields were read from. */
  start: number;
  end: number;
  /**
   * Tightest span that covers the matched fields themselves.
   *
   * The reclassification has to test against this and not against the window.
   * The window is `anchor - 700` to `anchor + 900`, so a server-side `AIza`
   * key 400 characters of unrelated code away from a real Firebase config was
   * relabelled "Firebase web config", exposure public, severity info, next
   * step "Do not report as a leak" -- turning the tool's most important
   * false-positive control into a false-negative control over the most
   * valuable member of the class.
   */
  fieldStart: number;
  fieldEnd: number;
  fields: Record<string, string>;
}

/**
 * Locate Firebase web configuration blocks.
 *
 * This is structural rather than regex-per-key: the config is only meaningful
 * as a group, and the group is what tells us the neighbouring `AIza…` key is
 * public by design rather than a leak.
 */
export function findFirebaseConfigs(text: string): FirebaseConfig[] {
  const out: FirebaseConfig[] = [];
  const anchor = /["']?authDomain["']?\s*:/g;
  let match: RegExpExecArray | null;

  while ((match = anchor.exec(text)) !== null) {
    const start = Math.max(0, match.index - 700);
    const end = Math.min(text.length, match.index + 900);
    const window = text.slice(start, end);
    if (!/["']?apiKey["']?\s*:/.test(window)) continue;
    if (!/["']?projectId["']?\s*:/.test(window)) continue;

    const fields: Record<string, string> = {};
    const keys = [
      'apiKey',
      'authDomain',
      'projectId',
      'storageBucket',
      'messagingSenderId',
      'appId',
      'databaseURL',
      'measurementId',
    ];
    let fieldStart = Number.POSITIVE_INFINITY;
    let fieldEnd = Number.NEGATIVE_INFINITY;
    for (const key of keys) {
      const field = new RegExp(`["']?${key}["']?\\s*:\\s*["']([^"']{1,200})["']`).exec(window);
      if (field?.[1] === undefined) continue;
      fields[key] = field[1];
      fieldStart = Math.min(fieldStart, start + field.index);
      fieldEnd = Math.max(fieldEnd, start + field.index + field[0].length);
    }
    if (Object.keys(fields).length < 3) continue;
    out.push({ anchor: match.index, start, end, fieldStart, fieldEnd, fields });
  }
  return out;
}

/** Run every secret rule over one asset. */
export function extractSecrets(context: SecretContext): SecretFinding[] {
  const { asset, lines, showSecrets, onCap } = context;
  // Every raw value matched in this asset, so a context window can be swept
  // for credentials other than the one its own finding matched.
  const matched: string[] = [];
  const text = asset.text;
  const skip = excludedRanges(text);
  const rules = context.rules ?? SECRET_RULES;
  const firebase = findFirebaseConfigs(text);
  const findings: RawFinding[] = [];

  const show = (value: string): string => (showSecrets ? value : redact(value));

  for (const rule of rules) {
    const pattern = new RegExp(
      rule.pattern.source,
      rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`,
    );
    let match: RegExpExecArray | null;
    let guard = 0;

    while ((match = pattern.exec(text)) !== null) {
      if (match[0].length === 0) {
        // An empty match consumes no budget: the counter used to be
        // incremented before this check, so an empty-matching pattern burned
        // the cap without producing anything.
        pattern.lastIndex += 1;
        continue;
      }
      guard += 1;
      if (guard > MAX_MATCHES_PER_RULE) {
        onCap?.(
          `${asset.id}: ${rule.id} stopped after ${MAX_MATCHES_PER_RULE} matches; later matches in this asset were not examined.`,
        );
        break;
      }

      const groupIndex = rule.group ?? 0;
      const value = match[groupIndex];
      if (value === undefined || value.length === 0) continue;
      if (value.length > MAX_VALUE_LENGTH) {
        onCap?.(
          `${asset.id}: ${rule.id} matched a value of ${value.length} characters, above the ${MAX_VALUE_LENGTH}-character limit; it was skipped.`,
        );
        continue;
      }

      const offsetInMatch = groupIndex === 0 ? 0 : match[0].indexOf(value);
      const offset = match.index + (offsetInMatch < 0 ? 0 : offsetInMatch);
      if (contains(skip, offset)) continue;

      const contextWindow = text.slice(
        Math.max(0, offset - 140),
        Math.min(text.length, offset + value.length + 140),
      );

      if (rule.requireContext && !rule.requireContext.test(contextWindow)) continue;

      const entropy = shannonEntropy(value);
      if (rule.minEntropy !== undefined && entropy < rule.minEntropy) continue;

      if (rule.classification === 'heuristic' && !rule.requireContext) {
        if (looksLikeNoise(value) !== null) continue;
      }

      const override = rule.refine?.({ value, context: contextWindow, entropy });
      if (override?.discard) continue;

      const placeholder = isPlaceholder(value);
      const { line, column } = lines.locate(offset);
      matched.push(value);

      findings.push({
        offset,
        rule: rule.id,
        title: override?.title ?? rule.title,
        ...(override?.provider ?? rule.provider ? { provider: override?.provider ?? rule.provider } : {}),
        classification: rule.classification,
        exposure: override?.exposure ?? rule.exposure,
        severity: placeholder ? 'info' : (override?.severity ?? rule.severity),
        value: show(value),
        fingerprint: fingerprintOf(value),
        entropy: Number(entropy.toFixed(2)),
        rationale: placeholder
          ? `${override?.rationale ?? rule.rationale} The value matches a documentation or placeholder pattern, so it is reported at informational severity rather than suppressed.`
          : (override?.rationale ?? rule.rationale),
        ...(override?.nextStep ?? rule.nextStep ? { nextStep: override?.nextStep ?? rule.nextStep } : {}),
        ...(placeholder ? { placeholder: true } : {}),
        locations: [{ asset: asset.id, line, column }],
        context: oneLine(redactWithin(contextWindow, value, showSecrets), 160),
        provenance: 'secret-rule',
      });
    }
  }

  // A key sitting inside a Firebase web config is published on purpose. This
  // reclassification is the single most important false-positive control in
  // the tool: an unqualified "Google API key leaked" on a Firebase app is the
  // report that gets a researcher ignored.
  for (const finding of findings) {
    if (finding.rule !== 'google-api-key') continue;
    const block = firebase.find(
      (config) => finding.offset >= config.fieldStart && finding.offset <= config.fieldEnd,
    );
    if (!block) continue;
    finding.exposure = 'public';
    finding.severity = 'info';
    finding.title = 'Google API key (Firebase web config)';
    finding.rationale =
      'The key appears inside a Firebase web configuration block alongside authDomain and projectId. Firebase requires this key in the browser; it identifies the project rather than authenticating the caller.';
    finding.nextStep =
      'Do not report as a leak. Test the project instead: Firestore and Storage security rules, and open Realtime Database reads.';
  }

  for (const config of firebase) {
    const { line, column } = lines.locate(config.anchor);
    const detail = Object.entries(config.fields)
      .filter(([key]) => key !== 'apiKey')
      .map(([key, value]) => `${key}=${value}`)
      .join(', ');
    findings.push({
      offset: config.anchor,
      rule: 'firebase-web-config',
      title: 'Firebase web app configuration',
      provider: 'Firebase',
      classification: 'confirmed-shape',
      exposure: 'public',
      severity: 'info',
      value: config.fields['projectId'] ?? '(project id not found)',
      fingerprint: fingerprintOf(config.fields['projectId'] ?? `firebase:${asset.id}:${config.anchor}`),
      entropy: 0,
      rationale:
        'A complete Firebase web config. Every field here is designed to ship to browsers — the SDK cannot initialise without them. This is recon, not a vulnerability.',
      nextStep:
        'Use it: check Firestore/Storage rules, try an unauthenticated read of the Realtime Database at databaseURL + "/.json", and enumerate the storage bucket.',
      locations: [{ asset: asset.id, line, column }],
      context: oneLine(detail, 200),
      provenance: 'secret-rule',
    });
  }

  const kept = dropWeakerDuplicates(findings).map(({ offset: _offset, ...finding }) => finding);
  return kept.map((finding) =>
    finding.context === undefined
      ? finding
      : { ...finding, context: scrubContext(finding.context, matched, showSecrets) },
  );
}

/** A short, non-reversible identifier for a credential value. */
function fingerprintOf(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 16);
}

/** Redact the credential inside a context snippet so the snippet is safe to paste. */
function redactWithin(snippet: string, value: string, showSecrets: boolean): string {
  if (showSecrets) return snippet;
  return snippet.split(value).join(redact(value));
}

/**
 * Redact *every* credential found in the asset from a context snippet, not just
 * the one its own finding matched.
 *
 * A context window is a slice of surrounding source, and credentials cluster:
 * an AWS key id and its secret access key are usually two lines apart, inside a
 * single config object. Redacting only the matched value therefore left the
 * neighbour in plain text -- visible in `--format json`, which emits `context`,
 * while the text and markdown renderers happened not to print it. The guarantee
 * the tool documents is that values are redacted by default including in JSON,
 * so the sweep has to be over the whole set.
 *
 * Longest first, so a value that contains a shorter one is replaced before the
 * shorter match can fragment it.
 */
function scrubContext(snippet: string, matched: readonly string[], showSecrets: boolean): string {
  if (showSecrets || snippet.length === 0) return snippet;
  let out = snippet;
  for (const value of [...new Set(matched)].sort((a, b) => b.length - a.length)) {
    if (value.length > 8 && out.includes(value)) {
      out = out.split(value).join(redact(value));
    }
  }
  return out;
}

/**
 * When two rules match the same value, keep the one that knows more.
 * A Supabase anon JWT also matches `generic-assigned-secret`; reporting both
 * is how a tool ends up with three findings for one string.
 */
function dropWeakerDuplicates(findings: RawFinding[]): RawFinding[] {
  const confirmed = new Set(
    findings.filter((f) => f.classification === 'confirmed-shape').map((f) => f.fingerprint),
  );
  return findings.filter(
    (finding) =>
      finding.classification === 'confirmed-shape' || !confirmed.has(finding.fingerprint),
  );
}

/** Merge findings across assets: one row per (rule, value), locations unioned. */
export function mergeSecrets(findings: SecretFinding[]): SecretFinding[] {
  const byKey = new Map<string, SecretFinding>();
  for (const finding of findings) {
    const key = `${finding.rule}::${finding.fingerprint}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...finding, locations: [...finding.locations] });
      continue;
    }
    for (const location of finding.locations) {
      if (existing.locations.length >= 8) break;
      const duplicate = existing.locations.some(
        (candidate) => candidate.asset === location.asset && candidate.line === location.line,
      );
      if (!duplicate) existing.locations.push(location);
    }
  }

  return [...byKey.values()].sort((a, b) => {
    const exposureRank = (finding: SecretFinding): number =>
      finding.exposure === 'secret' ? 0 : finding.exposure === 'depends' ? 1 : 2;
    return (
      exposureRank(a) - exposureRank(b) ||
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.rule.localeCompare(b.rule)
    );
  });
}
