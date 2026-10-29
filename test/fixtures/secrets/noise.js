/*
 * bundle-recon test fixture: false-positive bait.
 *
 * Nothing in this file is a credential. Every value here is something an
 * entropy-threshold scanner reports and a useful tool does not: content
 * hashes, subresource integrity digests, embedded assets, minified
 * identifier runs, i18n blobs and CSS tokens.
 */

const buildHash = '9f1c2d84b7e3a6150c4d8f2b91e7a3c5';
const chunkHashes = {
  main: 'd41d8cd98f00b204e9800998ecf8427e',
  vendor: '5eb63bbbe01eeed093cb22bb8f5acdc3',
  runtime: '098f6bcd4621d373cade4e832627b4f6',
};

const integrity =
  'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';

const commit = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const iconSprite =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==';

const inlineFont =
  'data:font/woff2;base64,d09GMgABAAAAAAZgABAAAAAACywAAAYQAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAABmAGVAQsGmAZgHIJAGABNgIkA1wEIAWFVAeBGwyzBVRs';

// Minifier output: high entropy by any character-frequency measure, no secret.
const minified =
  'onChangeHandlerFactoryWithDebounceAndTrailingEdgeInvocationSupport';

const cssToken = '#1f2a37';
const isoDate = '2026-03-14T09:21:07.512Z';
const mimeType = 'application/vnd.api+json';
const assetFile = 'runtime-4f2bd91c.js';
const placeholderKey = 'YOUR_API_KEY_HERE';
const repeated = 'aaaaaaaaaaaaaaaaaaaaaaaa';

export default {
  buildHash,
  chunkHashes,
  integrity,
  commit,
  iconSprite,
  inlineFont,
  minified,
  cssToken,
  isoDate,
  mimeType,
  assetFile,
  placeholderKey,
  repeated,
};
