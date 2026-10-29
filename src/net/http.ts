import { VERSION } from '../version.js';

export const DEFAULT_USER_AGENT = `bundle-recon/${VERSION} (+https://github.com/Young-Syre/bundle-recon)`;

export interface HttpOptions {
  userAgent: string;
  /** Maximum simultaneous requests. */
  concurrency: number;
  /** Upper bound on requests per second across all workers. */
  requestsPerSecond: number;
  timeoutMs: number;
  headers: Record<string, string>;
  /** Response bodies larger than this are truncated. */
  maxBytes: number;
}

export const DEFAULT_HTTP_OPTIONS: HttpOptions = {
  userAgent: DEFAULT_USER_AGENT,
  concurrency: 4,
  requestsPerSecond: 5,
  timeoutMs: 15_000,
  headers: {},
  maxBytes: 16 * 1024 * 1024,
};

export interface HttpResponse {
  url: string;
  status: number;
  contentType: string;
  body: string;
  bytes: number;
  truncated: boolean;
}

/**
 * A small rate-limited, concurrency-capped HTTP client.
 *
 * Both limits are enforced here rather than at the call sites, so no code
 * path can accidentally hammer a target: `concurrency` bounds requests in
 * flight and `requestsPerSecond` bounds the rate at which new ones start.
 */
export class HttpClient {
  private readonly options: HttpOptions;
  private active = 0;
  private readonly waiting: (() => void)[] = [];
  private nextSlot = 0;
  /** Requests attempted, including failures. */
  public requests = 0;

  constructor(options: Partial<HttpOptions> = {}) {
    this.options = { ...DEFAULT_HTTP_OPTIONS, ...options };
    if (this.options.concurrency < 1) this.options.concurrency = 1;
    if (this.options.requestsPerSecond <= 0) this.options.requestsPerSecond = 1;
  }

  get userAgent(): string {
    return this.options.userAgent;
  }

  async get(url: string): Promise<HttpResponse | null> {
    await this.acquire();
    try {
      await this.throttle();
      this.requests += 1;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.options.timeoutMs);
      try {
        const response = await fetch(url, {
          redirect: 'follow',
          signal: controller.signal,
          headers: {
            'user-agent': this.options.userAgent,
            accept: '*/*',
            ...this.options.headers,
          },
        });

        const buffer = await response.arrayBuffer();
        const truncated = buffer.byteLength > this.options.maxBytes;
        const slice = truncated ? buffer.slice(0, this.options.maxBytes) : buffer;
        return {
          url: response.url || url,
          status: response.status,
          contentType: response.headers.get('content-type') ?? '',
          body: Buffer.from(slice).toString('utf8'),
          bytes: buffer.byteLength,
          truncated,
        };
      } finally {
        clearTimeout(timer);
      }
    } catch {
      return null;
    } finally {
      this.release();
    }
  }

  private async acquire(): Promise<void> {
    if (this.active < this.options.concurrency) {
      this.active += 1;
      return;
    }
    await new Promise<void>((resolve) => this.waiting.push(resolve));
    this.active += 1;
  }

  private release(): void {
    this.active -= 1;
    const next = this.waiting.shift();
    if (next) next();
  }

  /** Space request starts out so the configured rate is never exceeded. */
  private async throttle(): Promise<void> {
    const interval = 1000 / this.options.requestsPerSecond;
    const now = Date.now();
    const slot = Math.max(now, this.nextSlot);
    this.nextSlot = slot + interval;
    const wait = slot - now;
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
  }
}
