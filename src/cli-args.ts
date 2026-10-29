import type { AnalyseOptions, Section } from './types.js';
import type { ReportFormat } from './report/index.js';
import { NAME, VERSION } from './version.js';

export const SECTIONS: readonly Section[] = [
  'endpoints',
  'routes',
  'secrets',
  'sourcemaps',
  'chunks',
  'payloads',
  'graphql',
  'openapi',
  'frameworks',
];

export const USAGE = `${NAME} ${VERSION} — recover attack surface from built JavaScript assets

USAGE
  ${NAME} scan <dir-or-file...>   analyse assets already on disk (no network)
  ${NAME} fetch <url>            download an application's assets, then analyse

COMMON OPTIONS
  --format <text|json|markdown>  output format (default: text)
  --only <sections>              comma-separated subset of:
                                 ${SECTIONS.join(', ')}
  --out <dir>                    write source-map-recovered original files here
  --output <file>                write the report to a file instead of stdout
  --show-secrets                 print credential values unredacted
  --no-string-literals           skip bare URL-shaped literals (keep only
                                 resolved call sites and framework manifests)
  --no-follow-sourcemaps         do not read or resolve source maps
  --max-asset-bytes <n>          skip assets larger than this (default: 25165824)
  -h, --help                     show this help
  -v, --version                  show the version

FETCH-MODE OPTIONS
  --concurrency <n>              simultaneous requests (default: 4)
  --rate <n>                     requests per second (default: 5)
  --timeout <ms>                 per-request timeout (default: 15000)
  --user-agent <string>          override the User-Agent header
  --header '<Name>: <value>'     extra request header (repeatable)
  --max-assets <n>               hard cap on assets fetched (default: 60)
  --no-respect-robots            ignore robots.txt (honoured by default)
  --no-probe-manifests           do not probe well-known build manifests
  --no-probe-sourcemaps          do not probe for undeclared .map siblings
  --quiet                        no progress output on stderr

EXAMPLES
  ${NAME} scan ./dist --format markdown
  ${NAME} scan ./app.js ./app.js.map --only secrets,sourcemaps
  ${NAME} scan ./.next/static --out ./recovered
  ${NAME} fetch https://app.example.com --rate 2 --format json
`;

export interface CliOptions {
  command: 'scan' | 'fetch';
  targets: string[];
  format: ReportFormat;
  analyse: AnalyseOptions;
  outputFile?: string;
  quiet: boolean;
  fetch: {
    concurrency: number;
    requestsPerSecond: number;
    timeoutMs: number;
    userAgent?: string;
    headers: Record<string, string>;
    maxAssets: number;
    respectRobots: boolean;
    probeManifests: boolean;
    probeSourcemaps: boolean;
  };
}

export class UsageError extends Error {}

/** Hand-rolled argument parsing: no dependency, and the contract stays visible. */
export function parseArgs(argv: readonly string[]): CliOptions | 'help' | 'version' {
  if (argv.length === 0) return 'help';
  if (argv.includes('-h') || argv.includes('--help')) return 'help';
  if (argv.includes('-v') || argv.includes('--version')) return 'version';

  const command = argv[0];
  if (command !== 'scan' && command !== 'fetch') {
    throw new UsageError(`unknown command '${String(command)}' (expected 'scan' or 'fetch')`);
  }

  const options: CliOptions = {
    command,
    targets: [],
    format: 'text',
    analyse: {},
    quiet: false,
    fetch: {
      concurrency: 4,
      requestsPerSecond: 5,
      timeoutMs: 15_000,
      headers: {},
      maxAssets: 60,
      respectRobots: true,
      probeManifests: true,
      probeSourcemaps: true,
    },
  };

  const rest = argv.slice(1);
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index] as string;

    if (!argument.startsWith('--')) {
      options.targets.push(argument);
      continue;
    }

    const equals = argument.indexOf('=');
    const flag = equals < 0 ? argument : argument.slice(0, equals);
    const inlineValue = equals < 0 ? undefined : argument.slice(equals + 1);
    const next = (): string => {
      if (inlineValue !== undefined) return inlineValue;
      const value = rest[index + 1];
      if (value === undefined || value.startsWith('--')) {
        throw new UsageError(`${flag} requires a value`);
      }
      index += 1;
      return value;
    };
    const number = (): number => {
      const raw = next();
      const value = Number(raw);
      if (!Number.isFinite(value) || value <= 0) {
        throw new UsageError(`${flag} expects a positive number, got '${raw}'`);
      }
      return value;
    };

    switch (flag) {
      case '--format': {
        const value = next();
        if (value !== 'text' && value !== 'json' && value !== 'markdown') {
          throw new UsageError(`--format expects text, json or markdown (got '${value}')`);
        }
        options.format = value;
        break;
      }
      case '--only': {
        const requested = next()
          .split(',')
          .map((part) => part.trim())
          .filter((part) => part.length > 0);
        for (const section of requested) {
          if (!(SECTIONS as readonly string[]).includes(section)) {
            throw new UsageError(
              `--only: unknown section '${section}' (expected one of ${SECTIONS.join(', ')})`,
            );
          }
        }
        options.analyse.only = requested as Section[];
        break;
      }
      case '--out':
        options.analyse.outDir = next();
        break;
      case '--output':
        options.outputFile = next();
        break;
      case '--show-secrets':
        options.analyse.showSecrets = true;
        break;
      case '--no-string-literals':
        options.analyse.includeStringLiterals = false;
        break;
      case '--no-follow-sourcemaps':
        options.analyse.followSourcemaps = false;
        break;
      case '--max-asset-bytes':
        options.analyse.maxAssetBytes = number();
        break;
      case '--concurrency':
        options.fetch.concurrency = number();
        break;
      case '--rate':
        options.fetch.requestsPerSecond = number();
        break;
      case '--timeout':
        options.fetch.timeoutMs = number();
        break;
      case '--user-agent':
        options.fetch.userAgent = next();
        break;
      case '--header': {
        const raw = next();
        const separator = raw.indexOf(':');
        if (separator < 1) throw new UsageError(`--header expects 'Name: value' (got '${raw}')`);
        options.fetch.headers[raw.slice(0, separator).trim()] = raw.slice(separator + 1).trim();
        break;
      }
      case '--max-assets':
        options.fetch.maxAssets = number();
        break;
      case '--respect-robots':
        options.fetch.respectRobots = true;
        break;
      case '--no-respect-robots':
        options.fetch.respectRobots = false;
        break;
      case '--no-probe-manifests':
        options.fetch.probeManifests = false;
        break;
      case '--no-probe-sourcemaps':
        options.fetch.probeSourcemaps = false;
        break;
      case '--quiet':
        options.quiet = true;
        break;
      default:
        throw new UsageError(`unknown option '${flag}'`);
    }
  }

  if (options.targets.length === 0) {
    throw new UsageError(
      command === 'scan' ? 'scan needs at least one file or directory' : 'fetch needs a URL',
    );
  }
  if (command === 'fetch' && options.targets.length > 1) {
    throw new UsageError('fetch takes a single URL');
  }
  if (command === 'fetch') {
    let url: URL;
    try {
      url = new URL(options.targets[0] as string);
    } catch {
      throw new UsageError(`'${String(options.targets[0])}' is not a valid URL`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new UsageError(`fetch expects an http(s) URL (got '${url.protocol}')`);
    }
  }

  return options;
}

export const AUTHORISATION_BANNER = [
  '',
  '  ┌──────────────────────────────────────────────────────────────────────┐',
  '  │  AUTHORISED USE ONLY                                                 │',
  '  │                                                                      │',
  '  │  fetch mode sends HTTP requests to the target you named. Run it only │',
  '  │  against systems you own or have written permission to test, and     │',
  '  │  within the scope and rate limits of that permission.                │',
  '  └──────────────────────────────────────────────────────────────────────┘',
  '',
].join('\n');
