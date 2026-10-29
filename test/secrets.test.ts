import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import * as fs from 'node:fs';

import { excludedRanges, extractSecrets, findFirebaseConfigs, mergeSecrets } from '../src/extract/secrets.js';
import { SECRET_RULES } from '../src/extract/rules.js';
import type { SecretFinding } from '../src/types.js';
import { LineIndex } from '../src/util/text.js';
import { FIXTURE_CREDENTIALS, renderCredentialsFixture } from './credentials-fixture.js';
import { fixture } from './helpers.js';

function scan(text: string, id = 'fixture.js', showSecrets = true): SecretFinding[] {
  return mergeSecrets(
    extractSecrets({
      asset: { id, kind: 'javascript', text, bytes: Buffer.byteLength(text) },
      lines: new LineIndex(text),
      showSecrets,
    }),
  );
}

const credentials = scan(renderCredentialsFixture(), 'credentials.js');
const noise = scan(fs.readFileSync(fixture('secrets', 'noise.js'), 'utf8'), 'noise.js');

function rule(findings: SecretFinding[], id: string): SecretFinding {
  const match = findings.find((finding) => finding.rule === id);
  assert.ok(match, `expected rule '${id}'; got ${findings.map((f) => f.rule).join(', ')}`);
  return match;
}

describe('secret rules', () => {
  it('has a unique id, a rationale and a global-safe pattern for every rule', () => {
    const seen = new Set<string>();
    for (const item of SECRET_RULES) {
      assert.ok(!seen.has(item.id), `duplicate rule id ${item.id}`);
      seen.add(item.id);
      assert.ok(item.rationale.length > 40, `${item.id} needs a real rationale`);
      assert.ok(item.title.length > 0);
      assert.ok(item.pattern.flags.includes('g'), `${item.id} pattern must be global`);
    }
    assert.ok(SECRET_RULES.length >= 20);
  });
});

describe('credentials that must not be public', () => {
  it('finds the vendor-prefixed keys and marks them secret', () => {
    for (const id of [
      'aws-access-key-id',
      'stripe-secret-key',
      'github-token',
      'slack-token',
      'sendgrid-api-key',
      'openai-api-key',
      'npm-token',
      'private-key-pem',
    ]) {
      const finding = rule(credentials, id);
      assert.equal(finding.exposure, 'secret', `${id} should be exposure=secret`);
      assert.equal(finding.classification, 'confirmed-shape');
    }
  });

  it('finds the AWS secret key only because AWS context is nearby', () => {
    const finding = rule(credentials, 'aws-secret-access-key');
    assert.equal(finding.classification, 'heuristic');
    assert.equal(finding.severity, 'critical');
    assert.equal(
      scan(`const value = "${FIXTURE_CREDENTIALS.__AWS_SECRET_ACCESS_KEY__}";`).length,
      0,
      'the same 40-character shape with no AWS context must not be reported',
    );
  });

  it('finds a Twilio auth token only with Twilio context', () => {
    const finding = rule(credentials, 'twilio-auth-token');
    assert.equal(finding.exposure, 'secret');
    assert.equal(
      scan('const buildHash = "9f3b7c2e5a814d6098b1c4e7f20a5d83";').length,
      0,
      'bare 32-character hex is a build hash, not a credential',
    );
  });

  it('decodes a Supabase service_role JWT and escalates it', () => {
    const finding = rule(credentials, 'jwt');
    assert.equal(finding.title, 'Supabase service_role JWT');
    assert.equal(finding.exposure, 'secret');
    assert.equal(finding.severity, 'critical');
    assert.match(finding.rationale, /service_role/);
  });

  it('treats a password-bearing database URI as a credential', () => {
    const finding = rule(credentials, 'database-connection-string');
    assert.equal(finding.exposure, 'secret');
    assert.equal(finding.severity, 'critical');
    assert.equal(finding.placeholder, undefined, 'a hostname containing "example" is not a placeholder');
  });

  it('flags a high-entropy value behind a credential-shaped name', () => {
    const finding = rule(credentials, 'generic-assigned-secret');
    assert.equal(finding.classification, 'heuristic');
    assert.equal(finding.exposure, 'depends');
  });
});

describe('credentials that are public by design', () => {
  it('does not call a Stripe publishable key a vulnerability', () => {
    const finding = rule(credentials, 'stripe-publishable-key');
    assert.equal(finding.exposure, 'public');
    assert.equal(finding.severity, 'info');
  });

  it('reports a Firebase web config as recon, not as a leak', () => {
    const finding = rule(credentials, 'firebase-web-config');
    assert.equal(finding.exposure, 'public');
    assert.equal(finding.severity, 'info');
    assert.equal(finding.value, 'demo-app-1234');
    assert.match(finding.context ?? '', /storageBucket=/);
    assert.match(finding.nextStep ?? '', /Realtime Database/);
  });

  it('reclassifies the Google API key inside that Firebase config', () => {
    const finding = rule(credentials, 'google-api-key');
    assert.equal(finding.exposure, 'public');
    assert.equal(finding.severity, 'info');
    assert.match(finding.title, /Firebase/);
    assert.match(finding.nextStep ?? '', /Do not report as a leak/);
  });

  it('keeps a standalone Google API key as context-dependent', () => {
    const finding = rule(scan('const mapsKey = "AIzaSyB7Kq2Mv9Rt4Bn6Xw1Lp8Yc3dF5hJ8kL2n";'), 'google-api-key');
    assert.equal(finding.exposure, 'depends');
    assert.equal(finding.severity, 'medium');
  });

  it('separates an anon Supabase JWT from a service_role one', () => {
    const anonOnly = scan(
      'const k = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF3cnR5dWlvcGFzZGZnaGprbHp4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6MjA4Mjg0NDgwMH0.4nQ2mZ9rT4bN6xW1lP8yC3dF5hJ8kL2nM7pQ9rT4vW6";',
    );
    const finding = rule(anonOnly, 'jwt');
    assert.equal(finding.title, 'Supabase anon JWT');
    assert.equal(finding.exposure, 'public');
    assert.equal(finding.severity, 'info');
  });

  it('marks OAuth client IDs, account SIDs and pk Mapbox tokens public', () => {
    assert.equal(rule(credentials, 'google-oauth-client-id').exposure, 'public');
    assert.equal(rule(credentials, 'twilio-account-sid').exposure, 'public');
    assert.equal(rule(credentials, 'mapbox-token').exposure, 'public');
  });

  it('treats a localhost database URI as a dev leftover', () => {
    const finding = rule(
      scan('const dev = "postgresql://postgres@localhost:5432/dev";'),
      'database-connection-string',
    );
    assert.equal(finding.exposure, 'public');
    assert.equal(finding.severity, 'info');
  });

  it('never reports a public-by-design finding above informational', () => {
    for (const finding of credentials.filter((item) => item.exposure === 'public')) {
      assert.equal(finding.severity, 'info', `${finding.rule} must not raise severity`);
    }
  });
});

describe('false positives', () => {
  it('reports nothing at all for the noise fixture', () => {
    assert.deepEqual(
      noise.map((finding) => `${finding.rule}:${finding.value}`),
      [],
      'content hashes, SRI digests, data URIs and minified identifiers are not credentials',
    );
  });

  it('excludes inline source maps and data URIs from scanning', () => {
    const text =
      'var a=1;\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbXX0=\n';
    const ranges = excludedRanges(text);
    assert.equal(ranges.length, 1);
    assert.ok(ranges[0]!.start < text.indexOf('base64'));
  });

  it('downgrades a documented example key rather than hiding it', () => {
    const finding = rule(scan('const k = "AKIAIOSFODNN7EXAMPLE";'), 'aws-access-key-id');
    assert.equal(finding.placeholder, true);
    assert.equal(finding.severity, 'info');
    assert.match(finding.rationale, /placeholder pattern/);
  });

  it('discards base64 that only looks like a JWT', () => {
    assert.equal(scan('const x = "eyJhbGciOiJub3Rqc29u.bm90anNvbg.c2ln";').length, 0);
  });

  it('redacts values by default', () => {
    const key = 'sk_' + 'live_' + '51Nq8ZkD7yTbVrP2wXsHgM4aC';
    const [finding] = scan(`const k = "${key}";`, 'a.js', false);
    assert.ok(finding);
    assert.ok(finding.value.startsWith('sk_live_'));
    assert.ok(!finding.value.includes('ZkD7yTbVrP2wXsHgM4aC'));
    assert.ok(!(finding.context ?? '').includes('ZkD7yTbVrP2wXsHgM4aC'));
  });
});

describe('no credential reaches a context snippet', () => {
  // The regression this guards: context windows are slices of surrounding
  // source, and credentials cluster -- an AWS key id and its secret access key
  // sit two lines apart in one config object. Redacting only each finding's own
  // matched value left the neighbour in plain text, which `--format json`
  // emitted (it prints `context`) while the text and markdown renderers did
  // not. Asserting against every literal in the fixture, rather than against a
  // list someone has to remember to extend, is the point.
  const fixtureLiterals = (): string[] => {
    const text = renderCredentialsFixture();
    const found = new Set<string>();
    for (const match of text.matchAll(/'([^'\n]{12,})'|`([^`]{12,})`/g)) {
      const value = match[1] ?? match[2];
      if (value) found.add(value);
    }
    return [...found];
  };

  it('redacts every secret literal out of every context, not just the matched one', () => {
    const literals = fixtureLiterals();
    assert.ok(literals.length > 10, `expected many literals, got ${literals.length}`);

    // scan()'s third argument defaults to showSecrets = true for the other
    // suites in this file, so redaction has to be asked for explicitly here.
    const redacted = scan(renderCredentialsFixture(), 'credentials.js', false);
    const contexts = redacted.map((finding) => finding.context ?? '').join('\n');

    // The Firebase web config is reported precisely so a reader can act on it:
    // the project id, auth domain and bucket are what you need to go and test
    // the security rules, and the SDK cannot initialise without shipping them
    // to the browser. Redacting those would remove the finding's only value, so
    // they are excluded here deliberately rather than by oversight -- and the
    // next test asserts they are still present.
    const publicByDesign = (value: string): boolean =>
      value.includes('demo-app-1234') || value.includes('482910374651');

    const leaked = literals.filter((value) => !publicByDesign(value) && contexts.includes(value));
    assert.deepEqual(leaked, [], `context snippets leaked: ${leaked.join(', ')}`);
  });

  it('keeps the public-by-design Firebase fields, which are the finding', () => {
    const redacted = scan(renderCredentialsFixture(), 'credentials.js', false);
    const config = redacted.find((finding) => finding.rule === 'firebase-web-config');
    assert.ok(config, 'the Firebase config finding should be raised');
    assert.match(config.context ?? '', /demo-app-1234/);
    assert.equal(config.exposure, 'public');
    assert.equal(config.severity, 'info');
  });

  it('still shows them when secrets are requested', () => {
    const shown = scan(renderCredentialsFixture(), 'credentials.js', true);
    const contexts = shown.map((finding) => finding.context ?? '').join('\n');
    const anyPresent = fixtureLiterals().some((value) => contexts.includes(value));
    assert.equal(anyPresent, true, 'showSecrets must not redact the context');
  });

  it('leaves a context that contains no credential untouched', () => {
    const [finding] = scan('const awsKey = "AKIA" + "IOSFODNN7EXAMPLE";\nconst port = 8080;\n');
    // Nothing to redact here beyond the matched value itself; the sweep must not
    // mangle ordinary surrounding source.
    if (finding?.context) {
      assert.ok(!finding.context.includes('\u2026\u2026'), 'double-redaction of the same span');
    }
  });
});

describe('firebase config detection', () => {
  it('requires apiKey, authDomain and projectId together', () => {
    assert.equal(findFirebaseConfigs('{ authDomain: "x.firebaseapp.com" }').length, 0);
    const configs = findFirebaseConfigs(
      '{apiKey:"AIzaSyB7Kq2Mv9Rt4Bn6Xw1Lp8Yc3dF5hJ8kL2n",authDomain:"a.firebaseapp.com",projectId:"a"}',
    );
    assert.equal(configs.length, 1);
    assert.equal(configs[0]?.fields['projectId'], 'a');
  });
});
