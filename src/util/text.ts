/** Utilities for turning byte offsets into human-readable locations. */

/** Precomputed line start offsets, for O(log n) offset -> line/column. */
export class LineIndex {
  private readonly starts: number[];

  constructor(private readonly text: string) {
    const starts = [0];
    for (let i = 0; i < text.length; i += 1) {
      if (text.charCodeAt(i) === 10) starts.push(i + 1);
    }
    this.starts = starts;
  }

  /** 1-based line and column for a 0-based character offset. */
  locate(offset: number): { line: number; column: number } {
    const clamped = Math.max(0, Math.min(offset, this.text.length));
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((this.starts[mid] as number) <= clamped) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: clamped - (this.starts[lo] as number) + 1 };
  }

  /**
   * A single-line excerpt around an offset. Minified bundles have lines
   * hundreds of kilobytes long, so the window is always bounded.
   */
  excerpt(offset: number, radius = 60): string {
    const start = Math.max(0, offset - radius);
    const end = Math.min(this.text.length, offset + radius);
    const slice = this.text.slice(start, end).replace(/\s+/g, ' ').trim();
    return (start > 0 ? '…' : '') + slice + (end < this.text.length ? '…' : '');
  }
}

/**
 * Redact a credential-shaped value: keep enough to recognise the vendor
 * prefix and to correlate two reports, drop enough that pasting a report into
 * a ticket does not leak the key.
 */
export function redact(value: string, keepStart = 8, keepEnd = 4): string {
  if (value.length <= keepStart + keepEnd + 3) {
    // Too short to redact meaningfully without hiding the shape entirely.
    return value.slice(0, Math.max(2, keepStart)) + '…';
  }
  const hidden = value.length - keepStart - keepEnd;
  return `${value.slice(0, keepStart)}…[${hidden} chars]…${value.slice(-keepEnd)}`;
}

/** Collapse whitespace and cap length, for table cells. */
export function oneLine(value: string, max = 120): string {
  const flat = value.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}
