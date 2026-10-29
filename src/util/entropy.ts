/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** Proportion of distinct characters — catches `aaaaaaaa...` style padding. */
export function distinctRatio(value: string): number {
  if (value.length === 0) return 0;
  return new Set(value).size / value.length;
}

/**
 * True when a string is plausibly a hex digest (content hash, sourcemap hash,
 * git sha). These dominate the false-positive budget of entropy-only scanners.
 */
export function looksLikeHexDigest(value: string): boolean {
  return /^[0-9a-f]{7,}$/i.test(value) && !/^[0-9]+$/.test(value);
}

/** True when a string is a run of base64 characters with no separators. */
export function looksLikeBase64(value: string): boolean {
  return /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

/**
 * Heuristic: a run of minifier-generated identifiers. Minified bundles are
 * full of things like `onChangeHandlerFactory` concatenations that clear a
 * naive entropy threshold while carrying no secret.
 */
export function looksLikeIdentifierRun(value: string): boolean {
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(value)) return false;
  // Camel/Pascal case with no digits is overwhelmingly code, not a key.
  return !/\d/.test(value) || /^[A-Za-z_$]+\d{1,3}$/.test(value);
}

const WORDS = [
  'abcdef',
  'application',
  'authorization',
  'background',
  'children',
  'component',
  'container',
  'development',
  'production',
  'placeholder',
  'transform',
  'undefined',
];

/** True when the value is mostly English words glued together. */
export function looksLikeProse(value: string): boolean {
  const lower = value.toLowerCase();
  let covered = 0;
  for (const word of WORDS) {
    let from = 0;
    for (;;) {
      const at = lower.indexOf(word, from);
      if (at === -1) break;
      covered += word.length;
      from = at + word.length;
    }
  }
  return covered / value.length > 0.5;
}
