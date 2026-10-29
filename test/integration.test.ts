import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { analyseDirectory, analyseFile } from '../src/analyse.js';
import { formatReport } from '../src/report/index.js';
import type { ReconReport } from '../src/types.js';
import { fixture } from './helpers.js';

const report: ReconReport = await analyseDirectory(fixture());

describe('end-to-end scan of the fixture tree', () => {
  it('produces a complete, well-formed report', () => {
    assert.equal(report.tool.name, 'bundle-recon');
    assert.equal(report.target.kind, 'directory');
    assert.ok(report.stats.assets >= 10);
    assert.ok(report.stats.bytes > 0);
    assert.equal(report.errors.length, 0, JSON.stringify(report.errors));
  });

  it('detects every framework present in the fixtures', () => {
    const names = report.frameworks.map((framework) => framework.name).sort();
    assert.deepEqual(names, ['next', 'nuxt', 'vite', 'webpack']);
  });

  it('recovers an endpoint that exists only in the source map', () => {
    const recovered = report.endpoints.find(
      (endpoint) => endpoint.path === '/api/v2/internal/debug-dump',
    );
    assert.ok(recovered, 'dead-code-eliminated endpoint should come back from sourcesContent');
    assert.equal(recovered.method, 'POST');
    assert.ok(recovered.locations[0]?.asset.includes('src/api/client.js'));
  });

  it('maps minified call sites back to their original source', () => {
    const endpoint = report.endpoints.find((item) => item.path === '/api/v2/users/{id}');
    assert.ok(endpoint);
    assert.equal(endpoint.method, 'PATCH');
    assert.equal(endpoint.originalLocation?.source, 'src/api/client.js');
    assert.equal(endpoint.originalLocation?.line, 4);
  });

  it('keeps routes and endpoints in separate sections', () => {
    const endpointPaths = new Set(report.endpoints.map((endpoint) => endpoint.path));
    for (const route of report.routes) {
      const literalTwin = report.endpoints.find(
        (endpoint) => endpoint.path === route.route && endpoint.provenance === 'string-literal',
      );
      assert.equal(literalTwin, undefined, `${route.route} should not also be a bare endpoint`);
    }
    assert.ok(endpointPaths.has('/api/v2/sessions'));
  });

  it('separates credentials by whether they are meant to be public', () => {
    const secret = report.secrets.filter((finding) => finding.exposure === 'secret');
    const publicByDesign = report.secrets.filter((finding) => finding.exposure === 'public');
    assert.ok(secret.length >= 10);
    assert.ok(publicByDesign.length >= 6);

    const rules = new Set(publicByDesign.map((finding) => finding.rule));
    assert.ok(rules.has('stripe-publishable-key'));
    assert.ok(rules.has('firebase-web-config'));
    assert.ok(rules.has('google-api-key'));

    for (const finding of report.secrets) {
      assert.ok(finding.rationale.length > 30, `${finding.rule} rationale is too thin`);
      assert.ok(finding.locations.length > 0);
    }
  });

  it('never reports a public-by-design credential above informational severity', () => {
    for (const finding of report.secrets) {
      if (finding.exposure === 'public') assert.equal(finding.severity, 'info');
    }
  });

  it('finds no credentials at all in the false-positive fixture', () => {
    const fromNoise = report.secrets.filter((finding) =>
      finding.locations.some((location) => location.asset.endsWith('noise.js')),
    );
    assert.deepEqual(fromNoise.map((finding) => finding.rule), []);
  });

  it('enumerates lazy webpack chunks nobody links to', () => {
    const lazy = report.chunks.filter((chunk) => chunk.lazy).map((chunk) => chunk.file);
    assert.ok(lazy.includes('static/chunks/admin-dashboard.9f1c2d84.js'));
    assert.ok(lazy.includes('static/chunks/feature-experiments.1c4d6f22.js'));
  });

  it('counts the recovered original sources', () => {
    assert.ok(report.stats.recoveredSources >= 3);
    assert.equal(report.stats.secrets, report.secrets.length);
    assert.equal(report.stats.routes, report.routes.length);
  });

  it('analyses a source map handed to it directly, without duplicating it', () => {
    assert.equal(
      report.sourcemaps.filter((map) => map.sources.includes('src/api/client.js')).length,
      1,
      'a map consumed through sourceMappingURL must not be reported twice',
    );
  });
});

describe('output formats', () => {
  it('renders text with the sections a reader needs', () => {
    const text = formatReport(report, 'text');
    assert.match(text, /^bundle-recon \d+\.\d+\.\d+ — directory /);
    assert.match(text, /ENDPOINTS \(\d+\)/);
    assert.match(text, /ROUTES \(\d+\)/);
    assert.match(text, /SECRETS — public by design \(not vulnerabilities\)/);
    assert.match(text, /SOURCE MAPS/);
    assert.ok(!text.includes('\u001b['), 'text output must stay free of escape codes');
  });

  it('renders valid JSON that round-trips', () => {
    const json = formatReport(report, 'json');
    const parsed = JSON.parse(json) as ReconReport;
    assert.equal(parsed.endpoints.length, report.endpoints.length);
    assert.equal(parsed.tool.name, 'bundle-recon');
  });

  it('renders markdown with escaped table cells', () => {
    const markdown = formatReport(report, 'markdown');
    assert.match(markdown, /^# bundle-recon report/);
    assert.match(markdown, /\| Method \| Path \|/);
    assert.match(markdown, /Public by design/);
    for (const row of markdown.split('\n').filter((line) => line.startsWith('| '))) {
      const cells = row.split(' | ').length;
      assert.ok(cells >= 2, `malformed table row: ${row}`);
    }
  });
});

describe('option handling', () => {
  it('restricts the report to the requested sections', async () => {
    const only = await analyseDirectory(fixture(), { only: ['secrets'] });
    assert.ok(only.secrets.length > 0);
    assert.deepEqual(only.endpoints, []);
    assert.deepEqual(only.routes, []);
    assert.deepEqual(only.chunks, []);
  });

  it('can skip bare URL literals entirely', async () => {
    const strict = await analyseDirectory(fixture(), { includeStringLiterals: false });
    assert.equal(
      strict.endpoints.filter((endpoint) => endpoint.provenance === 'string-literal').length,
      0,
    );
    assert.ok(strict.endpoints.length > 0, 'resolved call sites survive');
  });

  it('can leave source maps alone', async () => {
    const noMaps = await analyseDirectory(fixture('bundle'), { followSourcemaps: false });
    assert.equal(noMaps.sourcemaps.length, 0);
    assert.equal(
      noMaps.endpoints.some((endpoint) => endpoint.path === '/api/v2/internal/debug-dump'),
      false,
    );
  });

  it('writes recovered sources to --out', async () => {
    const outDir = await fs.mkdtemp(path.join(os.tmpdir(), 'bundle-recon-out-'));
    try {
      const written = await analyseDirectory(fixture('bundle'), { outDir });
      const map = written.sourcemaps.find((item) => item.written && item.written.length > 0);
      assert.ok(map, 'the fixture map ships sourcesContent, so files should be written');
      const recovered = await fs.readFile(
        path.join(outDir, 'app.min.js', 'src', 'api', 'client.js'),
        'utf8',
      );
      assert.match(recovered, /debug-dump/);
    } finally {
      await fs.rm(outDir, { recursive: true, force: true });
    }
  });

  it('analyses a single file', async () => {
    const single = await analyseFile(fixture('webpack', 'runtime.js'));
    assert.equal(single.target.kind, 'file');
    assert.equal(single.assets.length, 1);
    assert.ok(single.chunks.length >= 5);
  });

  it('records a parse failure instead of throwing', async () => {
    const broken = await fs.mkdtemp(path.join(os.tmpdir(), 'bundle-recon-broken-'));
    try {
      await fs.writeFile(path.join(broken, 'broken.js'), 'function ((( {', 'utf8');
      const result = await analyseDirectory(broken);
      assert.equal(result.errors.length, 1);
      assert.equal(result.errors[0]?.stage, 'parse');
      assert.equal(result.assets[0]?.parsed, false);
    } finally {
      await fs.rm(broken, { recursive: true, force: true });
    }
  });

  it('skips an asset above the size limit and says so', async () => {
    const big = await analyseDirectory(fixture('bundle'), { maxAssetBytes: 10 });
    assert.ok(big.notes.some((note) => note.includes('exceeds the 10-byte limit')));
    assert.equal(big.endpoints.length, 0);
  });
});
