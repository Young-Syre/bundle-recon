import type { ReconReport, SecretFinding } from '../types.js';
import { renderTree } from '../util/tree.js';
import { oneLine } from '../util/text.js';

/** Human-readable report. Plain text, no escape codes, safe to pipe. */
export function formatText(report: ReconReport): string {
  const out: string[] = [];
  const line = (value = ''): void => {
    out.push(value);
  };

  line(`${report.tool.name} ${report.tool.version} — ${report.target.kind} ${report.target.value}`);
  line(
    `${report.stats.assets} asset(s), ${formatBytes(report.stats.bytes)} scanned in ${report.stats.durationMs} ms`,
  );

  if (report.frameworks.length > 0) {
    line();
    line(heading('FRAMEWORKS'));
    for (const framework of report.frameworks) {
      line(`  ${framework.name}${framework.version ? ` ${framework.version}` : ''}`);
      for (const detail of framework.details) line(`    - ${detail}`);
    }
  }

  if (report.sourcemaps.length > 0) {
    line();
    const recovered = report.stats.recoveredSources;
    line(heading(`SOURCE MAPS (${report.sourcemaps.length}, ${recovered} original source paths)`));
    for (const map of report.sourcemaps) {
      line(`  ${map.asset}`);
      line(
        `    discovery: ${map.discovery}${map.mapLocation ? ` (${map.mapLocation})` : ''}; ` +
          `${map.sourceCount} sources, ${map.withContent} with original content`,
      );
      if (map.written && map.written.length > 0) {
        line(`    wrote ${map.written.length} file(s) to the output directory`);
      }
      if (map.highlights.length > 0) {
        line('    notable paths:');
        for (const highlight of map.highlights.slice(0, 12)) line(`      ${highlight}`);
      }
      const tree = renderTree(map.tree, 60);
      line('    recovered layout:');
      for (const row of tree) line(`      ${row}`);
    }
  }

  if (report.routes.length > 0) {
    line();
    line(heading(`ROUTES (${report.routes.length})`));
    for (const route of report.routes) {
      const flags = [
        route.dynamic ? 'dynamic' : '',
        route.prerendered ? 'prerendered' : '',
      ]
        .filter(Boolean)
        .join(',');
      line(
        `  ${pad(route.kind, 9)}${pad(route.route, 48)} ${pad(flags, 20)} ${route.framework}:${route.provenance}`,
      );
    }
  }

  if (report.endpoints.length > 0) {
    line();
    line(heading(`ENDPOINTS (${report.endpoints.length})`));
    for (const endpoint of report.endpoints) {
      const where = endpoint.locations[0];
      const origin = endpoint.originalLocation
        ? `  <- ${endpoint.originalLocation.source}:${endpoint.originalLocation.line ?? '?'}`
        : '';
      line(
        `  ${pad(endpoint.method, 8)}${pad(endpoint.path, 52)} ${pad(endpoint.client ?? '', 16)} ` +
          `${pad(endpoint.provenance, 20)} ${where ? `${where.asset}:${where.line}:${where.column}` : ''}${origin}`,
      );
    }
  }

  if (report.chunks.length > 0) {
    line();
    const lazy = report.chunks.filter((chunk) => chunk.lazy).length;
    line(heading(`CHUNKS (${report.chunks.length}, ${lazy} not referenced by any scanned asset)`));
    for (const chunk of report.chunks) {
      const id = chunk.id === chunk.file ? '' : chunk.id;
      line(
        `  ${pad(chunk.lazy ? 'lazy' : 'eager', 7)}${pad(chunk.file ?? chunk.id, 58)} ${pad(id, 12)} ${chunk.name ?? ''}`.trimEnd(),
      );
    }
  }

  if (report.openapi.length > 0) {
    line();
    line(heading('OPENAPI / SWAGGER'));
    for (const spec of report.openapi) {
      line(`  ${spec.spec}${spec.title ? ` — ${spec.title}` : ''}`);
      for (const server of spec.servers) line(`    server: ${server}`);
      for (const operation of spec.operations.slice(0, 200)) {
        line(
          `    ${pad(operation.method, 8)}${pad(operation.path, 48)} ${operation.operationId ?? ''}`,
        );
      }
    }
  }

  if (report.graphql.length > 0) {
    line();
    line(heading(`GRAPHQL OPERATIONS (${report.graphql.length})`));
    for (const operation of report.graphql) {
      line(`  ${pad(operation.operation, 14)}${operation.name ?? '(anonymous)'}`);
      if (operation.variables.length > 0) line(`    variables: ${operation.variables.join(', ')}`);
      line(`    fields: ${operation.fields.join(', ')}`);
    }
  }

  if (report.payloads.length > 0) {
    line();
    line(heading(`HYDRATION PAYLOAD VALUES (${report.payloads.length})`));
    for (const payload of report.payloads) {
      line(`  ${pad(payload.source, 16)}${pad(payload.key, 44)} ${oneLine(payload.value, 60)}`);
      line(`    ${payload.reason}`);
    }
  }

  const secretSections: [string, SecretFinding[]][] = [
    ['SECRETS — not public by design', report.secrets.filter((s) => s.exposure === 'secret')],
    ['SECRETS — depends on context', report.secrets.filter((s) => s.exposure === 'depends')],
    ['SECRETS — public by design (not vulnerabilities)', report.secrets.filter((s) => s.exposure === 'public')],
  ];

  for (const [title, findings] of secretSections) {
    if (findings.length === 0) continue;
    line();
    line(heading(`${title} (${findings.length})`));
    for (const finding of findings) {
      const where = finding.locations[0];
      line(
        `  [${finding.severity}] ${finding.title}${finding.placeholder ? ' (placeholder value)' : ''}`,
      );
      line(`      value:      ${finding.value}`);
      line(
        `      where:      ${where ? `${where.asset}:${where.line}:${where.column}` : 'unknown'}` +
          (finding.locations.length > 1 ? ` (+${finding.locations.length - 1} more)` : ''),
      );
      line(
        `      evidence:   ${finding.classification}, entropy ${finding.entropy.toFixed(2)} bits/char`,
      );
      line(`      why:        ${finding.rationale}`);
      if (finding.nextStep) line(`      next step:  ${finding.nextStep}`);
    }
  }

  if (report.notes.length > 0) {
    line();
    line(heading('NOTES'));
    for (const note of report.notes) line(`  - ${note}`);
  }

  if (report.errors.length > 0) {
    line();
    line(heading(`ERRORS (${report.errors.length})`));
    for (const error of report.errors) {
      line(`  [${error.stage}] ${error.asset ?? '-'}: ${error.message}`);
    }
  }

  if (isEmpty(report)) {
    line();
    line('No findings. Either the assets carry nothing recoverable, or the bundle');
    line('is obfuscated beyond static analysis — see "Limitations" in the README.');
  }

  line();
  return out.join('\n');
}

function isEmpty(report: ReconReport): boolean {
  return (
    report.endpoints.length === 0 &&
    report.routes.length === 0 &&
    report.secrets.length === 0 &&
    report.sourcemaps.length === 0 &&
    report.chunks.length === 0 &&
    report.payloads.length === 0 &&
    report.graphql.length === 0 &&
    report.openapi.length === 0
  );
}

function heading(title: string): string {
  return `${title}\n${'-'.repeat(title.length)}`;
}

function pad(value: string, width: number): string {
  return value.length >= width ? `${value} ` : value.padEnd(width, ' ');
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}
