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
  /**
   * Called with the reason a request produced nothing. Without it a DNS
   * failure, a TLS rejection, a timeout and a WAF reset are indistinguishable
   * to the caller, so an operator whose fetch returns nothing cannot tell
   * "host unreachable" from "403 on every asset".
   */
  onError: ((url: string, error: unknown) => void) | null;
}

/** How many same-origin redirects to follow before giving up. */
const MAX_REDIRECTS = 5;

export const DEFAULT_HTTP_OPTIONS: HttpOptions = {
  userAgent: DEFAULT_USER_AGENT,
  concurrency: 4,
  requestsPerSecond: 5,
  timeoutMs: 15_000,
  headers: {},
  maxBytes: 16 * 1024 * 1024,
  onError: null,
};

export interface HttpResponse {
  url: string;
  status: number;
  contentType: string;
  body: string;
  bytes: number;
  truncated: boolean;
  /**
   * Set when a redirect pointed off the origin that was requested. The request
   * to that origin is *not* made: the body is empty and the caller reports the
   * hop rather than ingesting it.
   */
  offOrigin: string | null;
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
        // 'manual', not 'follow'. The caller has already decided this origin is
        // in scope; letting fetch follow a 302 means the target chooses the
        // next host, and an operator authorised for one host is walked onto
        // another by the target's own redirect. Worse, the body then came back
        // attributed to the in-scope path, so a secret found on the other host
        // was reported at a URL where it does not exist.
        const origin = new URL(url).origin;
        let current = url;
        for (let hop = 0; ; hop += 1) {
          const response = await fetch(current, {
            redirect: 'manual',
            signal: controller.signal,
            headers: {
              'user-agent': this.options.userAgent,
              accept: '*/*',
              ...this.options.headers,
            },
          });

          const location = response.headers.get('location');
          if (response.status >= 300 && response.status < 400 && location !== null) {
            const target = new URL(location, current);
            if (target.origin !== origin) {
              return {
                url: current,
                status: response.status,
                contentType: response.headers.get('content-type') ?? '',
                body: '',
                bytes: 0,
                truncated: false,
                offOrigin: target.origin,
              };
            }
            if (hop >= MAX_REDIRECTS) {
              this.options.onError?.(url, new Error(`more than ${MAX_REDIRECTS} redirects`));
              return null;
            }
            current = target.toString();
            continue;
          }

          const buffer = await response.arrayBuffer();
          const truncated = buffer.byteLength > this.options.maxBytes;
          const slice = truncated ? buffer.slice(0, this.options.maxBytes) : buffer;
          return {
            url: current,
            status: response.status,
            contentType: response.headers.get('content-type') ?? '',
            body: Buffer.from(slice).toString('utf8'),
            bytes: buffer.byteLength,
            truncated,
            offOrigin: null,
          };
        }
      } finally {
        clearTimeout(timer);
      }
    } catch (error) {
      this.options.onError?.(url, error);
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
    // No increment here: release() handed this slot over without freeing it.
  }

  private release(): void {
    const next = this.waiting.shift();
    if (next) {
      // Hand the slot straight to the waiter rather than freeing it and
      // letting the waiter take it again. Decrementing first left a microtask
      // in which a fresh acquire() saw a free slot and took it, after which
      // the resolved waiter incremented as well -- so `active` could reach
      // concurrency + 1 and the cap the README promises was off by one.
      next();
      return;
    }
    this.active -= 1;
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
