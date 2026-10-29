import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { extractEndpoints, mergeEndpoints, normalisePath } from '../src/extract/endpoints.js';
import type { EndpointFinding } from '../src/types.js';
import { jsContext } from './helpers.js';

function endpoints(source: string, includeStringLiterals = false): EndpointFinding[] {
  const context = jsContext('fixture.js', source);
  return mergeEndpoints(
    extractEndpoints({
      asset: context.asset,
      program: context.program!,
      consts: context.consts,
      lines: context.lines,
      includeStringLiterals,
    }),
  );
}

function find(list: EndpointFinding[], method: string, path: string): EndpointFinding {
  const match = list.find((item) => item.method === method && item.path === path);
  assert.ok(match, `expected ${method} ${path} in ${JSON.stringify(list.map((i) => `${i.method} ${i.path}`))}`);
  return match;
}

describe('request call sites', () => {
  it('reads the method out of a fetch init object', () => {
    const found = endpoints('fetch("/api/v2/sessions", { method: "POST" });');
    assert.equal(found.length, 1);
    const finding = find(found, 'POST', '/api/v2/sessions');
    assert.equal(finding.client, 'fetch');
    assert.equal(finding.provenance, 'ast-call');
    assert.equal(finding.confidence, 'high');
  });

  it('defaults a fetch with no init to GET', () => {
    find(endpoints('fetch("/api/v2/me");'), 'GET', '/api/v2/me');
  });

  it('keeps template parameters as named placeholders', () => {
    const finding = find(
      endpoints('fetch(`/api/v2/users/${user.id}/roles`, { method: "PUT" });'),
      'PUT',
      '/api/v2/users/{id}/roles',
    );
    assert.deepEqual(finding.params, ['id']);
  });

  it('reads axios verb methods', () => {
    find(endpoints('axios.get("/api/v2/projects");'), 'GET', '/api/v2/projects');
    find(endpoints('axios.delete("/api/v2/projects/1");'), 'DELETE', '/api/v2/projects/1');
  });

  it('reads an axios config object', () => {
    find(
      endpoints('axios({ url: "/api/v2/invoices", method: "patch" });'),
      'PATCH',
      '/api/v2/invoices',
    );
  });

  it('reads the method from XMLHttpRequest.open', () => {
    const finding = find(
      endpoints('const x = new XMLHttpRequest(); x.open("DELETE", "/api/v2/tokens/current");'),
      'DELETE',
      '/api/v2/tokens/current',
    );
    assert.equal(finding.client, 'XMLHttpRequest');
  });

  it('reads Request, WebSocket, EventSource and sendBeacon', () => {
    find(endpoints('new Request("/api/v2/graph", { method: "POST" });'), 'POST', '/api/v2/graph');
    find(
      endpoints('new WebSocket("wss://events.example.internal/stream");'),
      'UNKNOWN',
      'wss://events.example.internal/stream',
    );
    find(endpoints('new EventSource("/api/v2/events");'), 'GET', '/api/v2/events');
    find(endpoints('navigator.sendBeacon("/api/v2/telemetry");'), 'POST', '/api/v2/telemetry');
  });

  it('accepts .get on a client-shaped receiver and ignores Map.get', () => {
    find(endpoints('apiClient.get("/api/v2/teams");'), 'GET', '/api/v2/teams');
    assert.equal(endpoints('cache.get("/api/v2/teams");').length, 0);
    assert.equal(endpoints('settingsMap.get("/api/v2/teams");').length, 0);
  });

  it('resolves a base path held in a module constant', () => {
    find(
      endpoints('var apiRoot = "/api/v3"; fetch(apiRoot + "/teams", { method: "GET" });'),
      'GET',
      '/api/v3/teams',
    );
  });
});

describe('path normalisation', () => {
  it('accepts request paths and absolute URLs', () => {
    assert.equal(normalisePath('/api/v2/users'), '/api/v2/users');
    assert.equal(normalisePath('/api//v2///users'), '/api/v2/users');
    assert.equal(normalisePath('https://api.example.com/v1/ping'), 'https://api.example.com/v1/ping');
  });

  it('rejects the strings that make naive scrapers unusable', () => {
    assert.equal(normalisePath('application/json'), null, 'MIME type');
    assert.equal(normalisePath('text/html; charset=utf-8'), null, 'MIME type with parameters');
    assert.equal(normalisePath('http://www.w3.org/2000/svg'), null, 'XML namespace');
    assert.equal(normalisePath('/logo-4f2b.svg'), null, 'static asset');
    assert.equal(normalisePath('/fonts/inter.woff2'), null, 'font asset');
    assert.equal(normalisePath('/^\\/api\\/(.*)$/'), null, 'regular expression source');
    assert.equal(normalisePath('/'), null, 'root alone');
    assert.equal(normalisePath('/a'), null, 'single short segment');
    assert.equal(normalisePath('/_next/'), null, 'asset directory');
    assert.equal(normalisePath('relative/path'), null, 'not rooted');
    assert.equal(normalisePath('/has spaces'), null, 'whitespace');
    assert.equal(normalisePath('/1/2/3'), null, 'no letters');
  });
});

describe('merging', () => {
  it('drops a bare literal that a resolved call already covers', () => {
    const found = endpoints(
      'var apiRoot = "/api/v3"; fetch(apiRoot + "/teams/" + team.teamId + "/invitations", { method: "POST" });',
      true,
    );
    const paths = found.map((finding) => finding.path);
    assert.ok(paths.includes('/api/v3/teams/{teamId}/invitations'));
    assert.ok(!paths.includes('/teams/'), 'concatenation fragments are not endpoints');
    assert.ok(!paths.includes('/invitations'));
  });

  it('unions locations for the same method and path', () => {
    const merged = mergeEndpoints([
      {
        path: '/api/v2/x',
        method: 'GET',
        params: [],
        provenance: 'string-literal',
        confidence: 'low',
        locations: [{ asset: 'a.js', line: 1, column: 1 }],
      },
      {
        path: '/api/v2/x',
        method: 'GET',
        params: [],
        provenance: 'ast-call',
        confidence: 'high',
        client: 'fetch',
        locations: [{ asset: 'b.js', line: 2, column: 3 }],
      },
    ]);
    assert.equal(merged.length, 1);
    assert.equal(merged[0]?.provenance, 'ast-call');
    assert.equal(merged[0]?.confidence, 'high');
    assert.equal(merged[0]?.locations.length, 2);
  });
});
