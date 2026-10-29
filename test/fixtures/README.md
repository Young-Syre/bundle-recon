# Fixtures

Small, synthetic assets written by hand for the test suite. Nothing here came
from a real application.

| Path | What it exercises |
| --- | --- |
| `bundle/app.min.js`, `bundle/app.min.js.map` | A minified ESM chunk and a real source map, generated as a matched pair by `scripts/build-fixtures.mjs`. The map ships `sourcesContent` for two of three sources, so the third exercises path-only recovery. |
| `bundle/consts.js` | A path built by concatenating a module-level string constant. |
| `next/_next/static/Wq3kZ1xTestBuild/_buildManifest.js` | The function-wrapped manifest form, with `__rewrites` and `sortedPages`. |
| `next/_next/static/Wq3kZ1xTestBuild/_ssgManifest.js` | The `new Set([…])` prerendered-route form. |
| `next/pages.html` | A `__NEXT_DATA__` payload with an API base URL, feature flags and a viewer record. |
| `next/app.html` | App Router `self.__next_f` flight pushes referencing app-segment chunks, including a route group and a dynamic API route. |
| `webpack/runtime.js` | A runtime chunk's `.u` and `.miniCssF` filename functions with name and hash tables. One chunk id appears only in the hash table. |
| `vite/manifest.json` | A Vite build manifest with entries, dynamic entries and CSS. |
| `openapi/spec.json` | An OpenAPI 3.0.3 document. |
| `nuxt/index.html` | A Nuxt 2 `window.__NUXT__` payload including `config.public`. |
| `secrets/credentials.js.in` | Template for the credential fixture: real-shaped but fabricated credentials, alongside the public-by-design cases (Stripe publishable key, Firebase web config, Supabase anon JWT, OAuth client id, Twilio account SID, `pk.` Mapbox token). Rendered to `secrets/credentials.js` by the `test` script; that rendered file is gitignored. |
| `secrets/noise.js` | False-positive bait only. The suite asserts this file yields zero findings. |

**Every credential value here is fabricated.** The formats are correct so the
rules fire; the values were never valid for any account anywhere. Do not treat
them as live secrets, and do not copy them into anything that would.

Five of those shapes are matched by hosted secret scanners, GitHub's push
protection among them, which will reject a push that contains them even inside a
fixture. Those five are therefore not stored as contiguous literals anywhere in
this repository. They are reassembled from fragments at test time by
`test/credentials-fixture.ts`, which renders `secrets/credentials.js.in` into
`secrets/credentials.js` before the suite runs. The rendered file is gitignored.

The obvious alternative — swapping in obviously-fake low-entropy placeholders —
does not work here, and the reason is worth stating: bundle-recon has an entropy
floor, so it correctly refuses to flag a value that does not look random. A
placeholder would make the fixture stop exercising the rule it exists for.
