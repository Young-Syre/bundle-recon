import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import * as fs from 'node:fs';

import { extractGraphQL, extractOpenApi, matchBraces } from '../src/extract/apidocs.js';
import { LineIndex } from '../src/util/text.js';
import { fixture } from './helpers.js';

function docsContext(id: string, text: string, isJson: boolean) {
  return { assetId: id, text, lines: new LineIndex(text), isJson };
}

describe('openapi extraction', () => {
  const source = fs.readFileSync(fixture('openapi', 'spec.json'), 'utf8');
  const result = extractOpenApi(docsContext('spec.json', source, true));

  it('reads the spec version, title and server', () => {
    const spec = result.openapi[0];
    assert.ok(spec);
    assert.equal(spec.spec, 'openapi 3.0.3');
    assert.equal(spec.title, 'Fixture Billing API');
    assert.deepEqual(spec.servers, ['https://api.example.internal/v2']);
  });

  it('enumerates every operation with its method', () => {
    const operations = result.openapi[0]?.operations ?? [];
    assert.equal(operations.length, 5);
    assert.ok(operations.some((op) => op.method === 'POST' && op.path === '/invoices'));
    assert.ok(operations.some((op) => op.method === 'DELETE' && op.path === '/invoices/{invoiceId}'));
    assert.ok(
      operations.some((op) => op.operationId === 'reconcileLedger'),
      'operationIds are kept as evidence',
    );
  });

  it('promotes operations to endpoints at high confidence', () => {
    assert.equal(result.endpoints.length, 5);
    for (const endpoint of result.endpoints) {
      assert.equal(endpoint.provenance, 'openapi');
      assert.equal(endpoint.confidence, 'high');
    }
  });

  it('finds a spec embedded inside a JavaScript bundle', () => {
    const embedded = `var spec = {"openapi":"3.0.0","info":{"title":"Embedded"},"paths":{"/ping":{"get":{}}}};`;
    const output = extractOpenApi(docsContext('bundle.js', embedded, false));
    assert.equal(output.openapi.length, 1);
    assert.equal(output.openapi[0]?.title, 'Embedded');
  });

  it('reads swagger 2 host, basePath and schemes as servers', () => {
    const swagger = `{"swagger":"2.0","host":"api.example.internal","basePath":"/v1","schemes":["https"],"paths":{"/users":{"get":{}}}}`;
    const output = extractOpenApi(docsContext('swagger.json', swagger, true));
    assert.deepEqual(output.openapi[0]?.servers, ['https://api.example.internal/v1']);
  });

  it('ignores JSON that is not a spec', () => {
    const output = extractOpenApi(docsContext('x.json', '{"openapi":"3.0.0"}', true));
    assert.equal(output.openapi.length, 0, 'a version with no paths or components is not a spec');
  });
});

describe('graphql extraction', () => {
  it('reads the operation name, variables and top-level fields', () => {
    const source =
      'const Q = `query AdminUsers($cursor: String!, $limit: Int!) { users(first: $limit, after: $cursor) { id email role } totalCount }`;';
    const [operation] = extractGraphQL(docsContext('bundle.js', source, false));
    assert.ok(operation);
    assert.equal(operation.operation, 'query');
    assert.equal(operation.name, 'AdminUsers');
    assert.deepEqual(operation.variables, ['$cursor: String!', '$limit: Int!']);
    assert.deepEqual(operation.fields, ['users', 'totalCount']);
  });

  it('reads mutations and fragments', () => {
    const found = extractGraphQL(
      docsContext(
        'bundle.js',
        'gql`mutation DeleteAccount($id: ID!) { deleteAccount(id: $id) { ok } }` + gql`fragment UserCore on User { id email }`',
        false,
      ),
    );
    assert.ok(found.some((item) => item.operation === 'mutation' && item.name === 'DeleteAccount'));
    assert.ok(found.some((item) => item.operation === 'fragment' && item.name === 'UserCore'));
  });

  it('does not mistake JavaScript for a GraphQL document', () => {
    const source = 'function query(x) { return x.map((y) => y + 1); } const mutation = { a: 1 };';
    assert.deepEqual(extractGraphQL(docsContext('bundle.js', source, false)), []);
  });
});

describe('brace matching', () => {
  it('ignores braces inside strings', () => {
    const text = '{"a":"}{","b":1}';
    assert.equal(matchBraces(text, 0), text.length - 1);
  });

  it('returns -1 for an unbalanced object', () => {
    assert.equal(matchBraces('{"a":1', 0), -1);
  });
});
