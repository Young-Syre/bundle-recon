import * as path from 'node:path';

/**
 * Turn an attacker-influenced source path into a path that is guaranteed to
 * stay inside `root`.
 *
 * `sources` entries in a source map come from the target, not from us. A map
 * claiming `../../../../etc/cron.d/x` or `C:\Windows\x` must not be able to
 * write outside the directory the operator chose with `--out`.
 */
export function safeOutputPath(root: string, source: string): string {
  const cleaned = source
    // eslint-disable-next-line no-control-regex
    .replace(/\u0000/g, '')
    .replace(/^[a-zA-Z]:[\\/]/, '') // Windows drive root
    .replace(/\\/g, '/');

  const segments = cleaned
    .split('/')
    .map((segment) => segment.trim())
    .filter(
      (segment) =>
        segment.length > 0 &&
        segment !== '.' &&
        segment !== '..' &&
        !/^[a-z-]+:$/i.test(segment), // scheme leftovers, e.g. `webpack:`
    )
    .map((segment) => segment.replace(/[<>:"|?*]/g, '_'));

  const relative = segments.length > 0 ? segments.join('/') : 'unnamed-source';
  const resolvedRoot = path.resolve(root);
  const target = path.resolve(resolvedRoot, relative);

  // Belt and braces: reject anything that still escapes after resolution.
  if (target !== resolvedRoot && !target.startsWith(resolvedRoot + path.sep)) {
    return path.join(resolvedRoot, 'unsafe-source');
  }
  return target;
}

/** Classify an asset by extension. */
export function kindFromPath(name: string): 'javascript' | 'html' | 'json' | 'sourcemap' | 'css' | 'other' {
  const lower = name.split('?')[0]?.split('#')[0]?.toLowerCase() ?? '';
  if (lower.endsWith('.map')) return 'sourcemap';
  if (/\.(m|c)?jsx?$/.test(lower) || /\.tsx?$/.test(lower)) return 'javascript';
  if (/\.html?$/.test(lower)) return 'html';
  if (lower.endsWith('.json')) return 'json';
  if (lower.endsWith('.css')) return 'css';
  return 'other';
}
