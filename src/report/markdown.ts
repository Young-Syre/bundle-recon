import type { ReconReport, SecretFinding } from '../types.js';
import { renderTree } from '../util/tree.js';
import { oneLine } from '../util/text.js';
import { formatBytes } from './text.js';

/** Markdown report, for pasting into a ticket or a findings document. */
export function formatMarkdown(report: ReconReport): string {
  const out: string[] = [];
  const line = (value = ''): void => {
    out.push(value);
  };

  line(`# bundle-recon report`);
  line();
  line(`- **Target:** \`${report.target.value}\` (${report.target.kind})`);
  line(`- **Generated:** ${report.generatedAt}`);
  line(`- **Tool:** ${report.tool.name} ${report.tool.version}`);
  line(
    `- **Scanned:** ${report.stats.assets} asset(s), ${formatBytes(report.stats.bytes)}, ${report.stats.durationMs} ms`,
  );
  line();

  if (report.frameworks.length > 0) {
    line('## Frameworks');
    line();
    line('| Framework | Details |');
    line('| --- | --- |');
    for (const framework of report.frameworks) {
      line(`| \`${framework.name}\` | ${escape(framework.details.join('; '))} |`);
    }
    line();
  }

  if (report.sourcemaps.length > 0) {
    line('## Source maps');
    line();
    line('| Asset | Discovery | Sources | With content | Written |');
    line('| --- | --- | --- | --- | --- |');
    for (const map of report.sourcemaps) {
      line(
        `| \`${escape(map.asset)}\` | ${map.discovery} | ${map.sourceCount} | ${map.withContent} | ${
          map.written?.length ?? 0
        } |`,
      );
    }
    line();
    for (const map of report.sourcemaps) {
      if (map.highlights.length > 0) {
        line(`**Notable original paths (${escape(map.asset)})**`);
        line();
        for (const highlight of map.highlights.slice(0, 20)) line(`- \`${escape(highlight)}\``);
        line();
      }
      line(`<details><summary>Recovered layout — ${escape(map.asset)}</summary>`);
      line();
      line('```');
      for (const row of renderTree(map.tree, 300)) line(row);
      line('```');
      line();
      line('</details>');
      line();
    }
  }

  if (report.routes.length > 0) {
    line('## Routes');
    line();
    line('| Route | Kind | Dynamic | Prerendered | Source |');
    line('| --- | --- | --- | --- | --- |');
    for (const route of report.routes) {
      line(
        `| \`${escape(route.route)}\` | ${route.kind} | ${route.dynamic ? 'yes' : 'no'} | ${
          route.prerendered ? 'yes' : '—'
        } | ${route.framework}/${route.provenance} |`,
      );
    }
    line();
  }

  if (report.endpoints.length > 0) {
    line('## Endpoints');
    line();
    line('| Method | Path | Client | Provenance | Confidence | Location | Original source |');
    line('| --- | --- | --- | --- | --- | --- | --- |');
    for (const endpoint of report.endpoints) {
      const where = endpoint.locations[0];
      const original = endpoint.originalLocation
        ? `\`${escape(endpoint.originalLocation.source)}:${endpoint.originalLocation.line ?? '?'}\``
        : '—';
      line(
        `| ${endpoint.method} | \`${escape(endpoint.path)}\` | ${escape(endpoint.client ?? '—')} | ${
          endpoint.provenance
        } | ${endpoint.confidence} | ${
          where ? `\`${escape(where.asset)}:${where.line}:${where.column}\`` : '—'
        } | ${original} |`,
      );
    }
    line();
  }

  if (report.chunks.length > 0) {
    line('## Chunks');
    line();
    line('| Id | File | Name | Referenced |');
    line('| --- | --- | --- | --- |');
    for (const chunk of report.chunks) {
      line(
        `| \`${escape(chunk.id)}\` | \`${escape(chunk.file ?? '—')}\` | ${escape(
          chunk.name ?? '—',
        )} | ${chunk.lazy ? 'no (lazy)' : 'yes'} |`,
      );
    }
    line();
  }

  if (report.openapi.length > 0) {
    line('## OpenAPI / Swagger');
    line();
    for (const spec of report.openapi) {
      line(`### ${escape(spec.spec)}${spec.title ? ` — ${escape(spec.title)}` : ''}`);
      line();
      if (spec.servers.length > 0) {
        for (const server of spec.servers) line(`- Server: \`${escape(server)}\``);
        line();
      }
      line('| Method | Path | operationId |');
      line('| --- | --- | --- |');
      for (const operation of spec.operations) {
        line(
          `| ${operation.method} | \`${escape(operation.path)}\` | ${escape(
            operation.operationId ?? '—',
          )} |`,
        );
      }
      line();
    }
  }

  if (report.graphql.length > 0) {
    line('## GraphQL operations');
    line();
    line('| Operation | Name | Variables | Top-level fields |');
    line('| --- | --- | --- | --- |');
    for (const operation of report.graphql) {
      line(
        `| ${operation.operation} | ${escape(operation.name ?? '(anonymous)')} | ${escape(
          operation.variables.join(', ') || '—',
        )} | ${escape(operation.fields.join(', '))} |`,
      );
    }
    line();
  }

  if (report.payloads.length > 0) {
    line('## Hydration payload values');
    line();
    line('| Source | Key | Value | Why |');
    line('| --- | --- | --- | --- |');
    for (const payload of report.payloads) {
      line(
        `| \`${payload.source}\` | \`${escape(payload.key)}\` | ${escape(
          oneLine(payload.value, 80),
        )} | ${escape(payload.reason)} |`,
      );
    }
    line();
  }

  if (report.secrets.length > 0) {
    line('## Credential candidates');
    line();
    line(
      'The **Public by design** column is the one that matters: a Stripe publishable key or a Firebase web config is *supposed* to be in the bundle and is not a finding.',
    );
    line();
    line('| Severity | Finding | Public by design | Classification | Value | Location |');
    line('| --- | --- | --- | --- | --- | --- |');
    for (const finding of report.secrets) {
      line(
        `| ${finding.severity} | ${escape(finding.title)} | ${exposureLabel(finding)} | ${
          finding.classification
        } | \`${escape(finding.value)}\` | ${location(finding)} |`,
      );
    }
    line();
    for (const finding of report.secrets) {
      line(`### ${escape(finding.title)} — ${finding.severity}`);
      line();
      line(`- **Public by design:** ${exposureLabel(finding)}`);
      line(`- **Value:** \`${escape(finding.value)}\``);
      line(`- **Classification:** ${finding.classification}, entropy ${finding.entropy.toFixed(2)} bits/char`);
      line(`- **Location:** ${location(finding)}`);
      if (finding.placeholder) line('- **Note:** value matches a documentation/placeholder pattern.');
      line(`- **Why:** ${escape(finding.rationale)}`);
      if (finding.nextStep) line(`- **Next step:** ${escape(finding.nextStep)}`);
      line();
    }
  }

  if (report.notes.length > 0) {
    line('## Notes');
    line();
    for (const note of report.notes) line(`- ${escape(note)}`);
    line();
  }

  if (report.errors.length > 0) {
    line('## Errors');
    line();
    for (const error of report.errors) {
      line(`- \`${error.stage}\` ${escape(error.asset ?? '-')}: ${escape(error.message)}`);
    }
    line();
  }

  return out.join('\n');
}

function exposureLabel(finding: SecretFinding): string {
  switch (finding.exposure) {
    case 'public':
      return 'yes — expected in client code';
    case 'depends':
      return 'depends on context';
    default:
      return 'no';
  }
}

function location(finding: SecretFinding): string {
  const where = finding.locations[0];
  if (!where) return '—';
  const extra = finding.locations.length > 1 ? ` (+${finding.locations.length - 1})` : '';
  return `\`${escape(where.asset)}:${where.line}:${where.column}\`${extra}`;
}

function escape(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}
