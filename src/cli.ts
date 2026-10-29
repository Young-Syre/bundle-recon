#!/usr/bin/env node
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

import type { AnalyseOptions, ReconReport } from './types.js';
import { analyseAssets, analyseDirectory, collectFiles, diskResolver, readAsset } from './analyse.js';
import { analyseUrl } from './net/crawl.js';
import { formatReport } from './report/index.js';
import { NAME, VERSION } from './version.js';
import { AUTHORISATION_BANNER, USAGE, UsageError, parseArgs } from './cli-args.js';

async function run(argv: readonly string[]): Promise<number> {
  const parsed = parseArgs(argv);
  if (parsed === 'help') {
    process.stdout.write(USAGE);
    return 0;
  }
  if (parsed === 'version') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  let report: ReconReport;

  if (parsed.command === 'fetch') {
    process.stderr.write(AUTHORISATION_BANNER);
    const url = parsed.targets[0] as string;
    report = await analyseUrl(url, {
      ...parsed.analyse,
      respectRobots: parsed.fetch.respectRobots,
      maxAssets: parsed.fetch.maxAssets,
      probeManifests: parsed.fetch.probeManifests,
      probeSourcemaps: parsed.fetch.probeSourcemaps,
      http: {
        concurrency: parsed.fetch.concurrency,
        requestsPerSecond: parsed.fetch.requestsPerSecond,
        timeoutMs: parsed.fetch.timeoutMs,
        headers: parsed.fetch.headers,
        ...(parsed.fetch.userAgent ? { userAgent: parsed.fetch.userAgent } : {}),
      },
      ...(parsed.quiet
        ? {}
        : { onProgress: (message: string) => process.stderr.write(`  ${message}\n`) }),
    });
  } else {
    report = await scan(parsed.targets, parsed.analyse);
  }

  const output = formatReport(report, parsed.format);
  if (parsed.outputFile) {
    await fs.mkdir(path.dirname(path.resolve(parsed.outputFile)), { recursive: true });
    await fs.writeFile(parsed.outputFile, output, 'utf8');
    process.stderr.write(`report written to ${parsed.outputFile}\n`);
  } else {
    process.stdout.write(output);
  }
  return 0;
}

/** Offline scan over any mix of files and directories. */
async function scan(targets: readonly string[], options: AnalyseOptions): Promise<ReconReport> {
  if (targets.length === 1) {
    const only = targets[0] as string;
    const stats = await fs.stat(only);
    if (stats.isDirectory()) return analyseDirectory(only, options);
  }

  const assets = [];
  for (const target of targets) {
    const absolute = path.resolve(target);
    const stats = await fs.stat(absolute);
    if (stats.isDirectory()) {
      for (const file of await collectFiles(absolute)) {
        assets.push(await readAsset(file, path.relative(path.dirname(absolute), file)));
      }
    } else {
      assets.push(await readAsset(absolute, path.basename(absolute)));
    }
  }

  return analyseAssets(
    assets,
    { kind: 'file', value: targets.map((target) => path.resolve(target)).join(', ') },
    options,
    diskResolver(),
  );
}

run(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    if (error instanceof UsageError) {
      process.stderr.write(`${NAME}: ${error.message}\n\nRun '${NAME} --help' for usage.\n`);
      process.exitCode = 1;
      return;
    }
    process.stderr.write(`${NAME}: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  });
