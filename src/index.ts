/**
 * bundle-recon — recover attack surface from built JavaScript assets.
 *
 * Programmatic entry points:
 *
 * ```ts
 * import { analyseDirectory, formatReport } from 'bundle-recon';
 *
 * const report = await analyseDirectory('./.next/static');
 * console.log(formatReport(report, 'markdown'));
 * ```
 */

export { analyseAssets, analyseDirectory, analyseFile, collectFiles, readAsset } from './analyse.js';
export { analyseUrl, type FetchModeOptions } from './net/crawl.js';
export { formatReport, formatMarkdown, formatText, type ReportFormat } from './report/index.js';
export { NAME, VERSION } from './version.js';
export { parseArgs, SECTIONS, UsageError, USAGE, type CliOptions } from './cli-args.js';

export { SECRET_RULES, type SecretRule, type RuleMatch, type RuleOverride } from './extract/rules.js';
export { extractSecrets, findFirebaseConfigs, excludedRanges } from './extract/secrets.js';
export { extractEndpoints, mergeEndpoints, normalisePath } from './extract/endpoints.js';
export {
  extractBuildManifest,
  extractNext,
  extractNextData,
  extractSsgManifest,
  routesFromChunkPaths,
} from './extract/next.js';
export { extractNuxt } from './extract/nuxt.js';
export { extractManifests } from './extract/manifests.js';
export { extractWebpack } from './extract/webpack.js';
export { extractApiDocs, extractGraphQL, extractOpenApi } from './extract/apidocs.js';
export {
  findSourceMappingAnnotation,
  loadSourcemap,
  decodeDataUri,
  writeRecoveredSources,
} from './extract/sourcemaps.js';
export { parseRobots, isAllowed, crawlDelay } from './net/robots.js';
export { HttpClient, DEFAULT_USER_AGENT, type HttpOptions } from './net/http.js';
export { buildTree, renderTree, normaliseSourcePath } from './util/tree.js';
export { shannonEntropy } from './util/entropy.js';
export { safeOutputPath } from './util/paths.js';

export type * from './types.js';
