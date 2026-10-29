/*
 * bundle-recon test fixture: a webpack runtime chunk.
 *
 * Trimmed to the parts that matter — the chunk-id tables and the filename
 * function that assembles a URL from them. Chunk 961 appears only in the
 * hash table, so its name falls back to the id, exactly as webpack does.
 */
(() => {
  var __webpack_modules__ = {};
  var __webpack_require__ = function (moduleId) {
    return __webpack_modules__[moduleId];
  };

  __webpack_require__.u = (chunkId) =>
    'static/chunks/' +
    ({ 117: 'admin-dashboard', 254: 'billing-portal', 803: 'feature-experiments' }[chunkId] ||
      chunkId) +
    '.' +
    { 117: '9f1c2d84', 254: '7b3e5a10', 803: '1c4d6f22', 961: '44aa55bb' }[chunkId] +
    '.js';

  __webpack_require__.miniCssF = (chunkId) =>
    'static/css/' + { 117: 'c0ffee11', 254: 'bada5511' }[chunkId] + '.css';

  __webpack_require__.p = '/_next/';

  self.webpackChunk_app = self.webpackChunk_app || [];
})();
