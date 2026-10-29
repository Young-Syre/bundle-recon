# bundle-recon

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](./tsconfig.json)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20deps-3-lightgrey.svg)](#dependencies)
[![tests](https://github.com/Young-Syre/bundle-recon/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/bundle-recon/actions/workflows/tests.yml)

Recover attack surface from a modern JavaScript application's built assets: API
endpoints with their HTTP methods, complete route manifests, lazily loaded
chunks nothing links to, original source layout from source maps, and
credential candidates that are classified by whether they are *supposed* to be
public.

Offline by default. `bundle-recon scan ./dist` touches nothing but your disk.

---

## Prior art, and what this adds

[LinkFinder](https://github.com/GerbenJavado/LinkFinder),
[jsluice](https://github.com/BishopFox/jsluice) and
[getJS](https://github.com/003random/getJS) already do the obvious thing well:
pull URL-shaped strings out of JavaScript. jsluice in particular does it with a
real parser rather than a regex. If all you need is "what paths are mentioned in
this file", use one of those — they are mature, fast, and this tool is not
trying to replace them.

bundle-recon exists because the most useful structures in a modern build are
**not URL-shaped strings**, and no amount of grepping will produce them:

- A Next.js route list lives in `_buildManifest.js` as **object keys**, not as
  linked URLs. `/admin/users/[id]` is in there whether or not anything on the
  public site links to it.
- A webpack lazy chunk's filename **does not exist as a string anywhere in the
  bundle**. It is assembled at request time from two lookup tables inside the
  runtime. You have to read the tables and re-run the concatenation.
- A source map's `sources` array gives you the **original directory layout** —
  `src/lib/internal/rbac.ts`, `app/(admin)/billing/page.tsx` — and
  `sourcesContent` gives you the pre-transform code, including branches that
  dead-code elimination removed from the shipped bundle.
- An HTTP method comes from the **call site**, not from the string. `"/api/v2/users/"`
  is a fragment; `PATCH /api/v2/users/{id}` is something you can actually send.
- A `pk_live_…` Stripe key and an `sk_live_…` Stripe key have the same entropy.
  One is a vulnerability and one is how Stripe.js works. A tool that cannot tell
  them apart costs its user credibility every time they file a report.

This tool goes after those five things specifically. It still does the bare
string-literal pass as a baseline, but labels it `string-literal` at low
confidence so it never crowds out the structured findings.

---

## Sources

| Source | What you get | Why it matters |
| --- | --- | --- |
| `.js.map` (declared, inline `data:` URI, or probed sibling) | `sources` + `sourcesContent`: original paths, original code | Original module layout names internal areas the minified output never mentions. Dead-code-eliminated branches are still in `sourcesContent`. |
| Source map position mapping | Each minified call site mapped to `original/file.ts:line` | Turns `app.min.js:1:4821` into a file a developer can open. |
| Next.js `_buildManifest.js` | Every pages-router route, dynamic segments included, plus per-route chunk files and `__rewrites` | The framework's own complete route list, including unlinked routes. Rewrite destinations expose the proxied backend. |
| Next.js `_ssgManifest.js` | Which routes are statically generated | Distinguishes prerendered pages from server-rendered ones, which changes what is worth probing. |
| Next.js `__NEXT_DATA__` | `buildId`, rendered page, `assetPrefix`, and selected values out of `props` | Props routinely carry API base URLs, feature-flag state, internal hostnames and occasionally real user records. The `buildId` is what you need to fetch the route manifests. |
| Next.js App Router `self.__next_f` RSC payloads | App-router detection, referenced chunk files, and route segments derived from them | The App Router has no `_buildManifest` equivalent. Chunk paths like `static/chunks/app/admin/settings/page-4d5e.js` are the route list. |
| Nuxt `window.__NUXT__` / `__NUXT_DATA__` | Hydration payload, `config.public` (where Nuxt puts `apiBase`), rendered route | Same value as `__NEXT_DATA__`, different framework. |
| Vite `manifest.json` | Original source path for every built file; dynamic vs entry chunks | Gives the source layout a source map would give, from a file teams deploy deliberately. |
| webpack runtime `__webpack_require__.u` / `.miniCssF` | Full URL of every chunk id, plus chunk names and `publicPath` | Enumerates lazily loaded code nothing links to. These filenames are built at runtime and appear in no string. |
| CRA `asset-manifest.json` | Built file list and entry points | Same idea, older toolchain. |
| `fetch` / `axios` / XHR / `Request` / `WebSocket` / `EventSource` / `sendBeacon` call sites | Method + path with `{named}` placeholders | A callable request rather than a string fragment. |
| Embedded OpenAPI / Swagger documents | Every operation with its method, `operationId` and servers | When present, an authoritative endpoint list. |
| GraphQL operation documents | Operation type, name, variables with types, top-level selections | More targeted than blind introspection, and works when introspection is disabled. |
| Credential patterns + entropy + context | Classified candidates, each marked public-by-design or not | See [Credential classification](#credential-classification). |

---

## Install

```bash
git clone https://github.com/Young-Syre/bundle-recon.git
cd bundle-recon
npm install
npm run build
npm test
```

Then run it with `node dist/src/cli.js`, or `npm link` to get `bundle-recon` on
your `PATH`.

Requires Node 20 or newer (the fetch mode uses the built-in `fetch`).

---

## Usage

### Offline — assets you already have

```bash
# A build directory
bundle-recon scan ./dist

# A Next.js static output tree
bundle-recon scan ./.next/static --format markdown

# Specific files, including a map you downloaded separately
bundle-recon scan ./app.min.js ./app.min.js.map --only secrets,sourcemaps

# Write every recovered original source to disk
bundle-recon scan ./dist --out ./recovered
```

### Fetch mode — download the assets first

```bash
bundle-recon fetch https://app.example.com
bundle-recon fetch https://app.example.com --rate 2 --concurrency 2 --format json
bundle-recon fetch https://app.example.com --header 'Cookie: session=…' --max-assets 20
```

Fetch mode prints an authorisation banner to stderr, honours `robots.txt` by
default (including `Crawl-delay`), stays same-origin *including across
redirects* — a 3xx pointing off the entry origin is reported and not followed,
so the target cannot walk you onto a host you are not authorised for — caps
concurrency and request rate, and never follows page links — it fetches the entry document, the
scripts and module preloads that document declares, the framework's own build
manifests, and any source maps those assets point at. Nothing else.

### Options

| Flag | Effect |
| --- | --- |
| `--format text\|json\|markdown` | Output format. Default `text`. |
| `--only <sections>` | Comma-separated: `endpoints`, `routes`, `secrets`, `sourcemaps`, `chunks`, `payloads`, `graphql`, `openapi`, `frameworks`. |
| `--out <dir>` | Write source-map-recovered originals here. Paths are sanitised; a map claiming `../../../etc/cron.d/x` writes inside `<dir>` or not at all. |
| `--output <file>` | Write the report to a file instead of stdout. |
| `--show-secrets` | Print credential values in full. Redacted by default, including in JSON. |
| `--no-string-literals` | Drop the bare-URL-literal pass; keep only resolved call sites and framework manifests. |
| `--no-follow-sourcemaps` | Do not read, resolve or probe source maps. |
| `--max-asset-bytes <n>` | Skip assets above this size. Default 24 MiB. |
| `--concurrency <n>` / `--rate <n>` / `--timeout <ms>` | Fetch-mode request limits. Defaults 4, 5/s, 15000 ms. |
| `--user-agent <s>` / `--header 'N: v'` | Fetch-mode request headers. `--header` is repeatable. |
| `--max-assets <n>` | Hard cap on assets fetched. Default 60. |
| `--no-respect-robots` | Ignore `robots.txt`. Honoured by default. |
| `--no-probe-manifests` / `--no-probe-sourcemaps` | Skip the well-known-manifest and `.map`-sibling probes. |
| `--quiet` | No progress output on stderr. |

---

## Worked example

Run against this repository's own synthetic fixtures — a minified bundle, its
generated source map, and a small second module:

```console
$ bundle-recon scan test/fixtures/bundle
bundle-recon 0.1.0 — directory /work/bundle-recon/test/fixtures/bundle
3 asset(s), 2.9 KiB scanned in 21 ms

SOURCE MAPS (1, 3 original source paths)
----------------------------------------
  app.min.js
    discovery: comment (app.min.js.map); 3 sources, 2 with original content
    notable paths:
      src/api/client.js
      src/admin/panel.tsx
      src/config/flags.ts
    recovered layout:
      .
      └── src
          ├── admin
          │   └── panel.tsx (no content)
          ├── api
          │   └── client.js
          └── config
              └── flags.ts

ENDPOINTS (9)
-------------
  POST    /api/v2/internal/debug-dump                          fetch            ast-call             app.min.js » src/api/client.js:33:8
  GET     /api/v2/projects/{projectId}/members                 axios.get        ast-call             app.min.js:1:239  <- src/api/client.js:17
  POST    /api/v2/sessions                                     fetch            ast-call             app.min.js:1:160  <- src/api/client.js:11
  POST    /api/v2/telemetry/page-view                          sendBeacon       ast-call             app.min.js:1:486  <- src/api/client.js:25
  DELETE  /api/v2/tokens/current                               XMLHttpRequest   ast-call             app.min.js:1:339  <- src/api/client.js:21
  PATCH   /api/v2/users/{id}                                   fetch            ast-call             app.min.js:1:35  <- src/api/client.js:4
  GET     /api/v3/teams                                        fetch            ast-call             consts.js:3:10
  POST    /api/v3/teams/{teamId}/invitations                   fetch            ast-call             consts.js:6:10
  UNKNOWN wss://events.example.internal/stream                 WebSocket        ast-call             app.min.js:1:432  <- src/api/client.js:25

GRAPHQL OPERATIONS (1)
----------------------
  query         AdminUsers
    variables: $cursor: String!, $limit: Int!
    fields: users

SECRETS — not public by design (1)
----------------------------------
  [critical] GitHub access token
      value:      ghp_3bV7…[28 chars]…L2nM
      where:      app.min.js » src/config/flags.ts:9:30
      evidence:   confirmed-shape, entropy 5.02 bits/char
      why:        GitHub prefixes every token type (ghp_ personal, gho_ OAuth, ghu_ user-to-server, ghs_ server-to-server, ghr_ refresh). None are public.
      next step:  Report for revocation. Scope can be confirmed with an unauthenticated-to-you /user call only with the owner's permission.

NOTES
-----
  - Scanned 2 recovered original sources (1 KiB) for endpoints and secrets. 1 of them could not be AST-parsed (TypeScript or JSX syntax) and was text-scanned only.
```

Three things in that output are worth pointing at.

**`POST /api/v2/internal/debug-dump` is not in the bundle.** Its location is
`app.min.js » src/api/client.js:33` — a recovered original source, not the
shipped asset. The call sits inside a `process.env.NODE_ENV !== 'production'`
branch that dead-code elimination removed from the build. The pre-transform
source is still shipped inside the source map, so the endpoint is still there to
find. No scanner that only reads `app.min.js` can produce this line.

**Every other endpoint carries a method and an original source position.**
`PATCH /api/v2/users/{id}` came from a `fetch` whose init object said
`method: 'PATCH'`, with the template parameter named after the property that
filled it; `<- src/api/client.js:4` is the source map pointing at the line a
developer would open.

**`src/admin/panel.tsx (no content)`** is a module the map names but does not
ship the text of. The path alone tells you there is an admin panel in this
application, which the minified output never says.

### Webpack chunks nothing links to

```console
$ bundle-recon scan test/fixtures/webpack --only chunks
bundle-recon 0.1.0 — directory /work/bundle-recon/test/fixtures/webpack
1 asset(s), 933 B scanned in 11 ms

CHUNKS (6, 6 not referenced by any scanned asset)
-------------------------------------------------
  lazy   static/chunks/961.44aa55bb.js                              961
  lazy   static/chunks/admin-dashboard.9f1c2d84.js                  117          admin-dashboard
  lazy   static/chunks/billing-portal.7b3e5a10.js                   254          billing-portal
  lazy   static/chunks/feature-experiments.1c4d6f22.js              803          feature-experiments
  lazy   static/css/bada5511.css                                    254
  lazy   static/css/c0ffee11.css                                    117
```

`grep -r 'admin-dashboard.9f1c2d84.js'` over that fixture finds nothing: the
string does not exist. The runtime builds it from a name table and a hash table
keyed by chunk id, and bundle-recon reads both tables and re-runs the
concatenation for every id. Chunk `961` has no entry in the name table, so the
runtime falls back to the bare id — and so does this tool.

---

## Credential classification

There are 30 pattern rules plus one structural detector (the Firebase web
config, which is only meaningful as a group of fields rather than as a single
string). Two things decide how a candidate is reported.

**Classification** — `confirmed-shape` means a vendor-specific format matched
(`sk_live_`, `AKIA` + 16, three base64url segments that decode as a JWT).
`heuristic` means entropy plus context, with no vendor format to rely on.

**Exposure** — whether a credential of that shape is *meant* to be in a public
bundle. This is the column that matters. Reporting a Stripe publishable key as
a leak is the fastest way to have the rest of your report ignored.

| Rule | Classification | Public by design | Default severity |
| --- | --- | --- | --- |
| `aws-access-key-id` (`AKIA`/`ASIA`/…) | confirmed-shape | no | high |
| `aws-secret-access-key` | heuristic (requires AWS context) | no | critical |
| `stripe-secret-key` (`sk_live_`, `rk_live_`) | confirmed-shape | **no** | critical |
| `stripe-publishable-key` (`pk_live_`, `pk_test_`) | confirmed-shape | **yes** | info |
| `github-token`, `github-fine-grained-pat`, `gitlab-token` | confirmed-shape | no | critical |
| `slack-token`, `slack-webhook` | confirmed-shape | no | critical / high |
| `sendgrid-api-key` | confirmed-shape | no | critical |
| `openai-api-key`, `anthropic-api-key` | confirmed-shape | no | critical |
| `npm-token`, `shopify-access-token`, `azure-storage-key` | confirmed-shape | no | critical |
| `private-key-pem` | confirmed-shape | no | critical |
| `gcp-service-account-json` | confirmed-shape | no | critical |
| `fcm-server-key` (legacy FCM) | confirmed-shape | **no** | high |
| `firebase-web-config` (`apiKey` + `authDomain` + `projectId`) | confirmed-shape — detected structurally, not by pattern | **yes** | info |
| `google-api-key` (`AIza…`) | confirmed-shape | **depends** — `public` when inside a Firebase config | medium / info |
| `google-oauth-client-id` | confirmed-shape | **yes** | info |
| `jwt`, `role=service_role` (Supabase) | confirmed-shape | **no** | critical |
| `jwt`, `role=anon` (Supabase) | confirmed-shape | **yes** | info |
| `jwt`, `alg=none` | confirmed-shape | no | high |
| `jwt`, expired | confirmed-shape | depends | info |
| `mapbox-token` `sk.` / `pk.` | confirmed-shape | **no** / **yes** | high / info |
| `twilio-api-key-sid` (`SK…`) | confirmed-shape | depends — half a credential pair | medium |
| `twilio-account-sid` (`AC…`) | confirmed-shape | **yes** — an identifier, not a credential | info |
| `twilio-auth-token` | heuristic (requires Twilio context) | no | critical |
| `algolia-api-key` | heuristic (requires Algolia context) | depends — admin vs search-only | critical / info |
| `database-connection-string` | confirmed-shape | depends — password present? localhost? | critical / medium / info |
| `basic-auth-url` (`scheme://user:pass@host`) | confirmed-shape | no | high |
| `generic-assigned-secret` | heuristic | depends | medium |

Every finding carries a `why` line stating what the exposure call rests on, and
most carry a `next step`. The public-by-design ones are still reported, because
they are useful recon — a Firebase web config hands you the project id, the
storage bucket and the Realtime Database URL, which is where the actual
misconfiguration usually is — but they are reported as informational and never
as a vulnerability.

### Suppressing the usual false positives

Four kinds of data produce nearly all of the noise in entropy-based scanners,
and each is excluded before any rule runs:

- Inline source maps (`sourceMappingURL=data:application/json;base64,…`).
- Embedded assets as `data:` URIs — sprites, favicons, fonts.
- Any unbroken base64 run over 512 characters: a serialised blob of some kind.
- Long runs of `\uXXXX` escapes, which is what an i18n bundle looks like.

On top of that, an ungated heuristic rule discards values that are hex digests
(content hashes, git shas, MD5s), minified identifier runs, English prose,
URLs, paths, dates, MIME types, CSS colours, asset filenames or template
placeholders. A heuristic rule that *does* require vendor context nearby — a
Twilio auth token genuinely is 32 hex characters — skips those filters, because
the context has already earned the match.

A value that matches a documentation or scaffolding pattern
(`AKIAIOSFODNN7EXAMPLE`, `YOUR_API_KEY`, `aaaaaaaa`) is reported at
informational severity with a `placeholder` flag rather than suppressed: a
placeholder shipping to production is still worth a line. The placeholder check
deliberately does not apply to URIs, so a real credential pointing at
`db.prod.example.net` is not downgraded because its hostname contains the word
"example".

The test suite asserts all of this from both directions.
`test/fixtures/secrets/credentials.js` holds real-shaped (fabricated) keys and
the public-by-design cases, and
`test/fixtures/secrets/noise.js` holds nothing but false-positive bait — content
hashes, an SRI digest, a `data:` sprite, an embedded font, a minified identifier
run, a CSS colour, an ISO date. The suite asserts that the noise fixture
produces **zero** findings, that no public-by-design finding is ever raised
above informational, and that a bare 32-hex string with no Twilio context and a
bare 40-char base64 string with no AWS context are both silently dropped.

That credential fixture is **generated, not committed**. It is rendered from
`test/fixtures/secrets/credentials.js.in` by the `test` script, which
substitutes five values that hosted secret scanners match on sight — the AWS
key id and secret, and the Stripe, Slack and Twilio identifiers. GitHub's push
protection refuses a push containing any of them, fixture or not, and it is
right to: it cannot tell a scanner's corpus from a leak. The values are
reassembled from fragments in `test/credentials-fixture.ts`, so the shape exists
in the working tree, where the rules need it, and in no commit.

Lowering the entropy instead would have been the wrong fix. bundle-recon applies
an entropy floor, so a placeholder like `EXAMPLE_FAKE_KEY` stops matching —
correctly — and the rule under test stops being exercised. A secret-scanner's
fixtures have to look random; that is the thing being detected.

---

## Programmatic API

```ts
import { analyseDirectory, analyseFile, analyseUrl, formatReport } from 'bundle-recon';

const report = await analyseDirectory('./dist', { includeStringLiterals: false });

for (const endpoint of report.endpoints) {
  if (endpoint.provenance !== 'ast-call') continue;
  console.log(endpoint.method, endpoint.path, endpoint.originalLocation?.source);
}

console.log(formatReport(report, 'markdown'));
```

All three entry points return the same typed `ReconReport`. The individual
extractors (`extractEndpoints`, `extractSecrets`, `extractWebpack`,
`extractNext`, `loadSourcemap`, `parseRobots`, …) and the rule table
(`SECRET_RULES`) are exported too, so you can add your own rules or embed one
extractor without the rest.

---

## Authorised use only

`scan` reads local files and never opens a socket. `fetch` sends HTTP requests
to the host you name.

**Run `fetch` only against systems you own or have written permission to test,
and only within the scope and rate limits of that permission.** Point it at a
host you are not authorised to test and you are, at minimum, doing unauthorised
scanning; depending on jurisdiction it may be a criminal offence. The tool
prints this as a banner every time, honours `robots.txt` unless you explicitly
turn that off, stays same-origin even when the target redirects elsewhere, and
caps both concurrency and request rate — but none of that constitutes
authorisation. That part is on you.

A finding from this tool is a lead, not a report. Verify it, establish real
impact, and respect the program's disclosure rules.

---

## Limitations

Stated plainly, because a recon tool that overstates its coverage is worse than
no tool.

- **Static only. Nothing is executed.** Every value is read out of an AST or a
  parsed document. A path assembled at runtime from data the server returns is
  invisible here. For runtime coverage you want a browser and a proxy, not this.
- **Source maps are usually absent in production.** The sourcemap path is
  opportunistic: it pays off well when a map is reachable and contributes
  nothing when it is not. Treat it as a bonus, not as the plan.
- **Obfuscated bundles degrade badly.** Control-flow flattening, string-array
  rotation and `eval`-based packers defeat static extraction by design. You will
  get the string-literal baseline and little else.
- **webpack 5 module federation is incomplete.** Remote containers resolve chunk
  names from a manifest fetched at runtime, so chunks belonging to remotes
  cannot be enumerated from the host bundle. The tool detects federation and
  says so in the report rather than implying the chunk list is complete.
- **Turbopack and framework internals move.** Next.js has shipped at least three
  spellings of `_buildManifest.js`; the extractor keys off the shape common to
  all of them rather than a specific format, but a future layout could still
  need work. App-router route derivation depends on webpack's chunk-naming
  convention, which Turbopack does not always match.
- **RSC flight payloads are harvested, not parsed.** The flight format is not
  JSON and is not stable. Only the two unambiguous things in it — chunk file
  paths and segment paths — are extracted.
- **Credential extraction has two caps, and says when it hits them.** One rule
  stops after 5,000 matches in a single asset, and a matched value longer than
  600 characters is skipped — which does discard the claim-heavy session tokens
  the `jwt` rule exists to decode. Both are reported as notes rather than
  applied silently, because a cap that fires quietly looks exactly like having
  found everything.
- **HTML is scanned with regexes, not parsed.** Everything this tool wants out
  of a document (`<script>` bodies and sources, JSON payload blocks, preload
  hints) is machine-generated by a framework. Hand-written HTML with unusual
  quoting may be read imperfectly.
- **TypeScript and JSX recovered from source maps are not AST-parsed.** `acorn`
  is a JavaScript parser. Recovered `.ts`/`.tsx` sources are text-scanned for
  credentials — which works fine — but not walked for call sites. The report
  states how many files this affected.
- **File-based route inference is convention-based.** Routes derived from Vite
  manifest source paths or Next.js chunk paths assume the standard conventions.
  The evidence path is always shown so you can judge it; `provenance` says where
  each route came from.
- **`generic-assigned-secret` is a lead, not a finding.** A high-entropy string
  behind a name like `apiKey` is exactly as likely to be a public client key.
  That is why it is `exposure: depends` rather than `secret`.
- **No authentication flow support in fetch mode.** You can pass headers and
  cookies with `--header`, but there is no login automation. For an
  authenticated build, download the assets with a browser and use `scan`.

---

## Dependencies

Three runtime dependencies, all pinned exactly, all load-bearing:

| Package | Version | Why |
| --- | --- | --- |
| [`acorn`](https://github.com/acornjs/acorn) | `8.19.0` | The JavaScript parser. Reading a method off a `fetch` init object, resolving a template literal into a path pattern, and re-running a webpack filename concatenation all need a real AST; regexes cannot do any of it. acorn is small, standards-tracking, and ships its own TypeScript definitions for the full node set. |
| [`acorn-walk`](https://github.com/acornjs/acorn) | `8.3.5` | acorn's companion walker. Typed visitors over `acorn.AnyNode`, which keeps the extractors honest under `strict` TypeScript. Writing a correct walker by hand would be more code and more bugs for no benefit. |
| [`source-map`](https://github.com/mozilla/source-map) | `0.7.6` | Mozilla's source-map consumer. Used for both halves of the sourcemap work: enumerating `sources`/`sourcesContent`, and `originalPositionFor` to map a minified call site back to its original file and line. The VLQ mapping decoder and index-map handling are not worth reimplementing. Also used by `scripts/build-fixtures.mjs` to *generate* the test fixture's map, so the fixture is a real source map rather than a hand-written approximation. |

Dev dependencies are `typescript` and `@types/node`. There is no test framework,
no bundler and no lint toolchain: tests run on `node:test`, and the build is
`tsc`.

---

## Development

```bash
npm run build       # tsc, strict
npm test            # build, then node:test over dist/test
npm run typecheck   # tsc --noEmit
```

Tests use no network. `test/fixtures/` holds small, synthetic, hand-written
fixtures; `scripts/build-fixtures.mjs` regenerates the minified bundle and its
source map as a matched pair.

Every credential value in the fixtures is fabricated. The shapes are real so the
rules fire; the values were never valid anywhere.

## License

MIT — see [LICENSE](./LICENSE). Copyright (c) 2026 David Nichols.
