import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import * as fs from 'node:fs';

import { extractNext, mergeChunks, mergeRoutes, routesFromChunkPaths } from '../src/extract/next.js';
import { extractNuxt } from '../src/extract/nuxt.js';
import { extractManifests } from '../src/extract/manifests.js';
import { extractWebpack } from '../src/extract/webpack.js';
import type { ChunkFinding, RouteFinding } from '../src/types.js';
import { fixture, htmlContext, jsContext, jsonContext } from './helpers.js';

function routeFor(routes: RouteFinding[], pattern: string): RouteFinding {
  const match = routes.find((route) => route.route === pattern);
  assert.ok(match, `expected route ${pattern}; got ${routes.map((r) => r.route).join(', ')}`);
  return match;
}

function chunkFor(chunks: ChunkFinding[], file: string): ChunkFinding {
  const match = chunks.find((chunk) => chunk.file === file);
  assert.ok(match, `expected chunk ${file}; got ${chunks.map((c) => c.file).join(', ')}`);
  return match;
}

describe('next.js _buildManifest', () => {
  const source = fs.readFileSync(
    fixture('next', '_next', 'static', 'Wq3kZ1xTestBuild', '_buildManifest.js'),
    'utf8',
  );
  const result = extractNext(
    jsContext('_next/static/Wq3kZ1xTestBuild/_buildManifest.js', source),
  );
  const routes = mergeRoutes(result.routes);

  it('enumerates every page route, including dynamic segments', () => {
    routeFor(routes, '/');
    routeFor(routes, '/login');
    assert.equal(routeFor(routes, '/blog/[slug]').dynamic, true);
    assert.equal(routeFor(routes, '/admin/users/[id]').dynamic, true);
    routeFor(routes, '/internal/feature-toggles');
  });

  it('survives the function-wrapped manifest form', () => {
    assert.ok(routes.length >= 7, 'the deduplicated/function-wrapped form must still yield routes');
  });

  it('marks framework internals as internal rather than pages', () => {
    assert.equal(routeFor(routes, '/_app').kind, 'internal');
    assert.equal(routeFor(routes, '/_error').kind, 'internal');
  });

  it('attaches the chunk files a route loads', () => {
    const assets = routeFor(routes, '/blog/[slug]').assets ?? [];
    assert.ok(assets.some((file) => file.includes('blog/[slug]')));
  });

  it('recovers the build id from the asset path', () => {
    const framework = result.frameworks.find((item) => item.name === 'next');
    assert.ok(framework);
    assert.ok(framework.details.some((detail) => detail === 'buildId=Wq3kZ1xTestBuild'));
  });

  it('extracts rewrite sources as routes and destinations as endpoints', () => {
    routeFor(routes, '/health');
    routeFor(routes, '/u/:handle');
    const destinations = result.endpoints.map((endpoint) => endpoint.path);
    assert.ok(destinations.includes('/api/internal/health'));
    assert.ok(
      destinations.includes('/api/v1/profiles/{handle}'),
      'Express-style :params are rendered as {params}',
    );
  });
});

describe('next.js _ssgManifest', () => {
  it('marks the listed routes as prerendered', () => {
    const source = fs.readFileSync(
      fixture('next', '_next', 'static', 'Wq3kZ1xTestBuild', '_ssgManifest.js'),
      'utf8',
    );
    const routes = mergeRoutes(
      extractNext(jsContext('_next/static/Wq3kZ1xTestBuild/_ssgManifest.js', source)).routes,
    );
    assert.equal(routes.length, 3);
    assert.equal(routeFor(routes, '/blog/[slug]').prerendered, true);
    assert.equal(routeFor(routes, '/login').prerendered, true);
  });
});

describe('next.js __NEXT_DATA__', () => {
  const source = fs.readFileSync(fixture('next', 'pages.html'), 'utf8');
  const result = extractNext(htmlContext('pages.html', source));

  it('recovers the rendered page, build id and asset prefix', () => {
    const framework = result.frameworks.find((item) => item.name === 'next');
    assert.ok(framework);
    assert.ok(framework.details.includes('buildId=Wq3kZ1xTestBuild'));
    assert.ok(framework.details.includes('page=/blog/[slug]'));
    assert.ok(framework.details.includes('assetPrefix=https://cdn.example.internal'));
    assert.equal(routeFor(mergeRoutes(result.routes), '/blog/[slug]').provenance, 'next-data');
  });

  it('surfaces API base URLs, flags and leaked user fields from props', () => {
    const byKey = new Map(result.payloads.map((payload) => [payload.key, payload]));
    assert.equal(
      byKey.get('props.pageProps.apiBase')?.value,
      'https://api-staging.example.internal/v3',
    );
    assert.ok(byKey.has('props.pageProps.graphqlUrl'));
    assert.ok(byKey.has('props.pageProps.featureFlags.showAdminTools'));
    assert.equal(byKey.get('props.pageProps.viewer.email')?.value, 'qa-bot@example.internal');
    assert.equal(byKey.get('runtimeConfig.uploadEndpoint')?.reason, 'value is an API or internal path');
  });

  it('points at the route manifests for the recovered build id', () => {
    assert.ok(result.notes.some((note) => note.includes('_buildManifest.js')));
  });
});

describe('next.js app router flight payload', () => {
  const source = fs.readFileSync(fixture('next', 'app.html'), 'utf8');
  const result = extractNext(htmlContext('app.html', source));
  const routes = mergeRoutes(result.routes);

  it('detects the app router', () => {
    const framework = result.frameworks.find((item) => item.name === 'next');
    assert.ok(framework);
    assert.ok(framework.details.some((detail) => detail.includes('app-router')));
  });

  it('derives app routes from chunk segment paths', () => {
    routeFor(routes, '/');
    routeFor(routes, '/admin/settings');
    assert.equal(
      routeFor(routes, '/billing').route,
      '/billing',
      'a (group) segment is layout-only and is stripped from the URL',
    );
    assert.equal(routeFor(routes, '/api/webhooks/[provider]').kind, 'api');
    assert.equal(routeFor(routes, '/api/webhooks/[provider]').dynamic, true);
  });

  it('lists the referenced chunk files', () => {
    const files = result.chunks.map((chunk) => chunk.file);
    assert.ok(files.includes('static/chunks/app/admin/settings/page-4d5e6f70.js'));
    assert.ok(files.includes('static/chunks/webpack-7f0e1d2c.js'));
  });

  it('strips parallel-route slots as well as groups', () => {
    const derived = routesFromChunkPaths(
      ['static/chunks/app/(shop)/@modal/orders/[id]/page-9f2a1b3c.js'],
      { asset: 'x', line: 1, column: 1 },
    );
    assert.equal(derived[0]?.route, '/orders/[id]');
  });
});

describe('webpack runtime chunk map', () => {
  const source = fs.readFileSync(fixture('webpack', 'runtime.js'), 'utf8');
  const context = jsContext('runtime.js', source);
  const result = extractWebpack(context, context.program!);
  const chunks = mergeChunks(result.chunks, new Set());

  it('reconstructs lazily loaded chunk URLs that appear nowhere as strings', () => {
    assert.equal(chunkFor(chunks, 'static/chunks/admin-dashboard.9f1c2d84.js').name, 'admin-dashboard');
    chunkFor(chunks, 'static/chunks/billing-portal.7b3e5a10.js');
    chunkFor(chunks, 'static/chunks/feature-experiments.1c4d6f22.js');
    assert.equal(
      source.includes('admin-dashboard.9f1c2d84.js'),
      false,
      'the filename is assembled at runtime, so no scraper can find it as a literal',
    );
  });

  it('falls back to the chunk id when the name table has no entry', () => {
    const chunk = chunkFor(chunks, 'static/chunks/961.44aa55bb.js');
    assert.equal(chunk.id, '961');
    assert.equal(chunk.name, undefined);
  });

  it('reads the CSS filename function too', () => {
    chunkFor(chunks, 'static/css/c0ffee11.css');
    chunkFor(chunks, 'static/css/bada5511.css');
  });

  it('records the public path', () => {
    const framework = result.frameworks.find((item) => item.name === 'webpack');
    assert.ok(framework);
    assert.ok(framework.details.includes('publicPath=/_next/'));
  });

  it('marks a chunk eager once something references it', () => {
    const referenced = mergeChunks(result.chunks, new Set(['static/chunks/961.44aa55bb.js']));
    assert.equal(chunkFor(referenced, 'static/chunks/961.44aa55bb.js').lazy, false);
    assert.equal(chunkFor(referenced, 'static/chunks/billing-portal.7b3e5a10.js').lazy, true);
  });

  it('warns that module federation degrades the chunk list', () => {
    const federated = jsContext(
      'remote.js',
      'var __webpack_require__={};__webpack_require__.federation={};var __webpack_share_scopes__={};',
    );
    const output = extractWebpack(federated, federated.program!);
    assert.ok(output.notes.some((note) => note.includes('module federation')));
  });
});

describe('vite manifest', () => {
  const source = fs.readFileSync(fixture('vite', 'manifest.json'), 'utf8');
  const result = extractManifests(jsonContext('manifest.json', source));

  it('recovers the original source layout without any source map', () => {
    const map = result.sourcemaps[0];
    assert.ok(map);
    assert.equal(map.discovery, 'vite-manifest');
    assert.equal(map.withContent, 0, 'a manifest gives paths, never file contents');
    assert.ok(map.sources.includes('src/lib/internal/rbac.ts'));
    assert.ok(map.highlights.includes('src/lib/internal/rbac.ts'));
  });

  it('marks dynamic entries as lazy and entry points as eager', () => {
    const chunks = mergeChunks(result.chunks, new Set());
    assert.equal(chunkFor(chunks, 'assets/AuditLog-F9a0b1c2.js').lazy, true);
    assert.equal(chunkFor(chunks, 'assets/main-C4f2bd91.js').lazy, false);
  });

  it('derives file-based routes from the source paths', () => {
    const routes = mergeRoutes(result.routes);
    routeFor(routes, '/');
    assert.equal(routeFor(routes, '/users/[id]').dynamic, true);
  });

  it('ignores JSON that is not a build manifest', () => {
    const output = extractManifests(jsonContext('package.json', '{"name":"x","version":"1.0.0"}'));
    assert.equal(output.chunks.length, 0);
    assert.equal(output.frameworks.length, 0);
  });
});

describe('nuxt payload', () => {
  const source = fs.readFileSync(fixture('nuxt', 'index.html'), 'utf8');
  const html = htmlContext('index.html', source);
  // The payload lives in an inline script, so analyse it as JavaScript.
  const inline = source.slice(source.indexOf('window.__NUXT__'), source.lastIndexOf('</script>'));
  const result = extractNuxt(jsContext('index.html#inline-script-1', inline));

  it('reads the public runtime config, which is where Nuxt keeps apiBase', () => {
    const byKey = new Map(result.payloads.map((payload) => [payload.key, payload.value]));
    assert.equal(byKey.get('config.public.apiBase'), 'https://nuxt-api.example.internal/api');
    assert.equal(byKey.get('config.public.websocketUrl'), 'wss://nuxt-api.example.internal/socket');
  });

  it('reports the rendered route', () => {
    assert.equal(routeFor(mergeRoutes(result.routes), '/dashboard').framework, 'nuxt');
  });

  it('detects Nuxt 3 __NUXT_DATA__ as well', () => {
    const nuxt3 = htmlContext(
      'nuxt3.html',
      '<script type="application/json" id="__NUXT_DATA__">["Reactive",1,{"url":"https://n3.example.internal/api"}]</script>',
    );
    const output = extractNuxt(nuxt3);
    assert.ok(output.frameworks.some((item) => item.details[0]?.includes('__NUXT_DATA__')));
    assert.ok(output.payloads.some((payload) => payload.value.includes('n3.example.internal')));
  });

  it('ignores HTML with no Nuxt payload', () => {
    assert.equal(extractNuxt(htmlContext('plain.html', '<p>hello</p>')).frameworks.length, 0);
  });
});
