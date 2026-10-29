#!/usr/bin/env node
/**
 * Generate the source-map fixture pair.
 *
 * The minified bundle and its map have to agree byte for byte, so both are
 * emitted from one script rather than hand-written. Everything here is
 * synthetic: there is no real application behind it.
 *
 * Run with:  node scripts/build-fixtures.mjs
 */
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SourceMapGenerator } from 'source-map';

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(here, '..', 'test', 'fixtures', 'bundle');

/** The built asset: one line, as a real minified ESM chunk would be. */
const minified =
  '"use strict";' +
  'function u(e){return fetch(`/api/v2/users/${e.id}`,{method:"PATCH",headers:{"content-type":"application/json"}})}' +
  'async function s(){const e=await fetch("/api/v2/sessions",{method:"POST"});return e.json()}' +
  'function c(e){return axios.get(`/api/v2/projects/${e.projectId}/members`)}' +
  'function d(){const e=new XMLHttpRequest;return e.open("DELETE","/api/v2/tokens/current"),e}' +
  'const f={newBilling:!0,adminAuditLog:!1};' +
  'const l=new WebSocket("wss://events.example.internal/stream");' +
  'navigator.sendBeacon("/api/v2/telemetry/page-view");' +
  'const p=`query AdminUsers($cursor: String!, $limit: Int!){users(first: $limit, after: $cursor){id email role lastSeenAt}}`;' +
  'export{u as updateUser,s as createSession,c as projectMembers,d as revokeToken,f as flags,l as events,p as adminUsersQuery};';

/**
 * Original source shipped inside the map. Plain JavaScript, so a JavaScript
 * parser can read it — which is how the recovered-source scan finds the
 * dev-only endpoint that dead-code elimination removed from the bundle.
 */
const clientSource = `const API_BASE = '/api/v2';

export async function updateUser(user) {
  return fetch(\`\${API_BASE}/users/\${user.id}\`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
  });
}

export async function createSession() {
  const response = await fetch(\`\${API_BASE}/sessions\`, { method: 'POST' });
  return response.json();
}

export function projectMembers(project) {
  return axios.get(\`\${API_BASE}/projects/\${project.projectId}/members\`);
}

export function revokeToken() {
  const request = new XMLHttpRequest();
  request.open('DELETE', \`\${API_BASE}/tokens/current\`);
  return request;
}

export const events = new WebSocket('wss://events.example.internal/stream');

navigator.sendBeacon(\`\${API_BASE}/telemetry/page-view\`);

if (process.env.NODE_ENV !== 'production') {
  // Stripped from the production bundle by dead-code elimination. The
  // pre-transform source is still shipped inside the source map, so this
  // endpoint is recoverable even though it is absent from app.min.js.
  void fetch('/api/v2/internal/debug-dump', { method: 'POST' });
}
`;

/**
 * A TypeScript source. A JavaScript parser cannot read it, so it is
 * text-scanned for credentials and counted as unparseable — which is exactly
 * what the tool reports.
 */
const flagsSource = `export interface Flags {
  newBilling: boolean;
  adminAuditLog: boolean;
}

export const flags: Flags = { newBilling: true, adminAuditLog: false };

// Used only by the local seeding script. Fabricated value; never valid.
export const devSeedToken = 'ghp_3bV7nQ2mZ9rT4bN6xW1lP8yC3dF5hJ8kL2nM';
`;

const generator = new SourceMapGenerator({ file: 'app.min.js' });

/** Map a marker in the generated line back to an original position. */
const mapMarker = (marker, source, line, column, name) => {
  const generatedColumn = minified.indexOf(marker);
  if (generatedColumn < 0) throw new Error(`marker not found: ${marker}`);
  generator.addMapping({
    generated: { line: 1, column: generatedColumn },
    original: { line, column },
    source,
    ...(name ? { name } : {}),
  });
};

mapMarker('"use strict"', 'src/api/client.js', 1, 0);
mapMarker('function u(e)', 'src/api/client.js', 3, 0, 'updateUser');
mapMarker('fetch(`/api/v2/users/', 'src/api/client.js', 4, 9, 'fetch');
mapMarker('async function s()', 'src/api/client.js', 10, 0, 'createSession');
mapMarker('fetch("/api/v2/sessions"', 'src/api/client.js', 11, 25, 'fetch');
mapMarker('function c(e)', 'src/api/client.js', 16, 0, 'projectMembers');
mapMarker('axios.get(', 'src/api/client.js', 17, 9, 'axios');
mapMarker('function d()', 'src/api/client.js', 21, 2, 'revokeToken');
mapMarker('const f={newBilling', 'src/config/flags.ts', 6, 0, 'flags');
mapMarker('const l=new WebSocket', 'src/api/client.js', 25, 0, 'events');
// Referenced with no content: the admin module's path is recoverable, its
// source text is not. This is the common production case.
mapMarker('const p=`query AdminUsers', 'src/admin/panel.tsx', 12, 2, 'adminUsersQuery');

generator.setSourceContent('src/api/client.js', clientSource);
generator.setSourceContent('src/config/flags.ts', flagsSource);

const map = JSON.parse(generator.toString());
// Order the sources so the fixture is stable across runs.
const written = {
  version: 3,
  file: 'app.min.js',
  sourceRoot: 'webpack:///',
  sources: map.sources,
  sourcesContent: map.sourcesContent,
  names: map.names,
  mappings: map.mappings,
};

await fs.mkdir(outDir, { recursive: true });
await fs.writeFile(
  path.join(outDir, 'app.min.js'),
  `${minified}\n//# sourceMappingURL=app.min.js.map\n`,
  'utf8',
);
await fs.writeFile(path.join(outDir, 'app.min.js.map'), `${JSON.stringify(written, null, 2)}\n`, 'utf8');

// A second, tiny asset: a module-level string constant joined onto a path.
// Kept separate from the minified bundle because real minifiers inline
// single-use constants, and this exercises the case where they do not.
await fs.writeFile(
  path.join(outDir, 'consts.js'),
  [
    'var apiRoot = "/api/v3";',
    'export function listTeams() {',
    '  return fetch(apiRoot + "/teams", { method: "GET" });',
    '}',
    'export function inviteMember(team) {',
    '  return fetch(apiRoot + "/teams/" + team.teamId + "/invitations", { method: "POST" });',
    '}',
    '',
  ].join('\n'),
  'utf8',
);

console.log(`wrote ${outDir}/app.min.js, app.min.js.map, consts.js`);
