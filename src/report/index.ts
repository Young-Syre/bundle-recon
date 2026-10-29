import type { ReconReport } from '../types.js';
import { formatMarkdown } from './markdown.js';
import { formatText } from './text.js';

export type ReportFormat = 'text' | 'json' | 'markdown';

export function formatReport(report: ReconReport, format: ReportFormat): string {
  switch (format) {
    case 'json':
      return `${JSON.stringify(report, null, 2)}\n`;
    case 'markdown':
      return formatMarkdown(report);
    default:
      return formatText(report);
  }
}

export { formatMarkdown, formatText };
