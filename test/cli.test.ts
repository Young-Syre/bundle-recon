import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SECTIONS, UsageError, parseArgs } from '../src/cli-args.js';
import { parseRobots, crawlDelay, isAllowed } from '../src/net/robots.js';
import { DEFAULT_USER_AGENT, HttpClient } from '../src/net/http.js';
import { mapLimit } from '../src/net/crawl.js';
import { NAME, VERSION } from '../src/version.js';

describe('argument parsing', () => {
  it('asks for help with no arguments', () => {
    assert.equal(parseArgs([]), 'help');
    assert.equal(parseArgs(['--help']), 'help');
    assert.equal(parseArgs(['scan', '.', '-h']), 'help');
    assert.equal(parseArgs(['--version']), 'version');
  });

  it('parses a scan invocation with several targets', () => {
    const options = parseArgs(['scan', './dist', './other.js', '--format', 'markdown']);
    assert.notEqual(options, 'help');
    if (options === 'help' || options === 'version') throw new Error('unreachable');
    assert.equal(options.command, 'scan');
    assert.deepEqual(options.targets, ['./dist', './other.js']);
    assert.equal(options.format, 'markdown');
  });

  it('accepts both --flag value and --flag=value', () => {
    const spaced = parseArgs(['scan', '.', '--out', 'recovered']);
    const joined = parseArgs(['scan', '.', '--out=recovered']);
    if (spaced === 'help' || spaced === 'version') throw new Error('unreachable');
    if (joined === 'help' || joined === 'version') throw new Error('unreachable');
    assert.equal(spaced.analyse.outDir, 'recovered');
    assert.equal(joined.analyse.outDir, 'recovered');
  });

  it('validates the section list', () => {
    const options = parseArgs(['scan', '.', '--only', 'endpoints,secrets']);
    if (options === 'help' || options === 'version') throw new Error('unreachable');
    assert.deepEqual(options.analyse.only, ['endpoints', 'secrets']);
    assert.throws(() => parseArgs(['scan', '.', '--only', 'nonsense']), UsageError);
    assert.equal(SECTIONS.length, 9);
  });

  it('honours robots.txt unless told otherwise', () => {
    const fetchDefault = parseArgs(['fetch', 'https://example.com']);
    if (fetchDefault === 'help' || fetchDefault === 'version') throw new Error('unreachable');
    assert.equal(fetchDefault.fetch.respectRobots, true);

    const opted = parseArgs(['fetch', 'https://example.com', '--no-respect-robots']);
    if (opted === 'help' || opted === 'version') throw new Error('unreachable');
    assert.equal(opted.fetch.respectRobots, false);
  });

  it('parses repeatable headers and rate limits', () => {
    const options = parseArgs([
      'fetch',
      'https://example.com',
      '--header',
      'Authorization: Bearer abc',
      '--header',
      'X-Trace: 1',
      '--rate',
      '2',
      '--concurrency',
      '1',
    ]);
    if (options === 'help' || options === 'version') throw new Error('unreachable');
    assert.deepEqual(options.fetch.headers, { Authorization: 'Bearer abc', 'X-Trace': '1' });
    assert.equal(options.fetch.requestsPerSecond, 2);
    assert.equal(options.fetch.concurrency, 1);
  });

  it('rejects malformed invocations', () => {
    assert.throws(() => parseArgs(['analyse', '.']), UsageError);
    assert.throws(() => parseArgs(['scan']), UsageError);
    assert.throws(() => parseArgs(['fetch']), UsageError);
    assert.throws(() => parseArgs(['fetch', 'https://a.com', 'https://b.com']), UsageError);
    assert.throws(() => parseArgs(['fetch', 'file:///etc/passwd']), UsageError);
    assert.throws(() => parseArgs(['fetch', 'not a url']), UsageError);
    assert.throws(() => parseArgs(['scan', '.', '--format', 'xml']), UsageError);
    assert.throws(() => parseArgs(['scan', '.', '--rate', '-1']), UsageError);
    assert.throws(() => parseArgs(['scan', '.', '--header', 'nocolon']), UsageError);
    assert.throws(() => parseArgs(['scan', '.', '--nope']), UsageError);
    assert.throws(() => parseArgs(['scan', '.', '--out']), UsageError);
  });
});

describe('robots.txt', () => {
  const robots = parseRobots(
    [
      'User-agent: *',
      'Disallow: /admin',
      'Allow: /admin/public',
      'Crawl-delay: 2',
      '',
      'User-agent: bundle-recon',
      'Disallow: /private',
      '',
      'Sitemap: https://example.com/sitemap.xml',
    ].join('\n'),
  );

  it('parses groups, rules, crawl delay and sitemaps', () => {
    assert.equal(robots.groups.length, 2);
    assert.deepEqual(robots.sitemaps, ['https://example.com/sitemap.xml']);
    assert.equal(crawlDelay(robots, 'SomeOtherBot'), 2);
  });

  it('prefers the most specific user-agent group', () => {
    assert.equal(isAllowed(robots, 'bundle-recon/0.1.0', '/private'), false);
    assert.equal(
      isAllowed(robots, 'bundle-recon/0.1.0', '/admin'),
      true,
      'our own group does not disallow /admin, and groups do not merge',
    );
    assert.equal(isAllowed(robots, 'SomeOtherBot', '/admin'), false);
  });

  it('lets the longest matching rule win', () => {
    assert.equal(isAllowed(robots, 'SomeOtherBot', '/admin/public/page'), true);
    assert.equal(isAllowed(robots, 'SomeOtherBot', '/admin/secret'), false);
  });

  it('supports wildcards and end-anchors', () => {
    const wild = parseRobots('User-agent: *\nDisallow: /*.json$\nDisallow: /api/*/internal');
    assert.equal(isAllowed(wild, 'x', '/data.json'), false);
    assert.equal(isAllowed(wild, 'x', '/data.json?v=1'), true, '$ anchors the match');
    assert.equal(isAllowed(wild, 'x', '/api/v2/internal/health'), false);
    assert.equal(isAllowed(wild, 'x', '/api/v2/public'), true);
  });

  it('allows everything when robots.txt is absent or empty', () => {
    assert.equal(isAllowed(parseRobots(''), 'x', '/anything'), true);
    assert.equal(isAllowed(parseRobots('User-agent: *\nDisallow:'), 'x', '/anything'), true);
  });
});

describe('http client defaults', () => {
  it('identifies itself and clamps nonsense limits', () => {
    assert.match(DEFAULT_USER_AGENT, /^bundle-recon\//);
    assert.match(DEFAULT_USER_AGENT, /github\.com\/Young-Syre\/bundle-recon/);
    const client = new HttpClient({ concurrency: 0, requestsPerSecond: 0, userAgent: 'x' });
    assert.equal(client.userAgent, 'x');
    assert.equal(client.requests, 0);
  });

  it('runs a bounded number of mappers at once', async () => {
    let inFlight = 0;
    let peak = 0;
    const results = await mapLimit([1, 2, 3, 4, 5, 6, 7, 8], 3, async (value) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight -= 1;
      return value * 2;
    });
    assert.deepEqual(results, [2, 4, 6, 8, 10, 12, 14, 16]);
    assert.ok(peak <= 3, `concurrency cap exceeded: ${peak}`);
  });
});

describe('package metadata', () => {
  it('keeps the exported version in step with package.json', () => {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      name: string;
      version: string;
      dependencies: Record<string, string>;
    };
    assert.equal(manifest.version, VERSION);
    assert.equal(manifest.name, NAME);
  });

  it('pins every runtime dependency to an exact version', () => {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    assert.deepEqual(Object.keys(manifest.dependencies).sort(), [
      'acorn',
      'acorn-walk',
      'source-map',
    ]);
    for (const [name, range] of Object.entries(manifest.dependencies)) {
      assert.match(range, /^\d+\.\d+\.\d+$/, `${name} must be pinned exactly, got ${range}`);
    }
  });
});
