/**
 * A deliberately small robots.txt implementation.
 *
 * Only what is needed to honour a target's stated crawl policy: user-agent
 * groups, Allow/Disallow with `*` and `$`, longest-match-wins precedence, and
 * Crawl-delay. Sitemap lines are parsed because they are a useful hint about
 * route structure.
 */

export interface RobotsRule {
  allow: boolean;
  /** The path pattern, as written. */
  pattern: string;
}

export interface RobotsGroup {
  agents: string[];
  rules: RobotsRule[];
  crawlDelay?: number;
}

export interface Robots {
  groups: RobotsGroup[];
  sitemaps: string[];
  /** True when the file was fetched and parsed. */
  present: boolean;
}

export const EMPTY_ROBOTS: Robots = { groups: [], sitemaps: [], present: false };

export function parseRobots(text: string): Robots {
  const groups: RobotsGroup[] = [];
  const sitemaps: string[] = [];
  let current: RobotsGroup | null = null;
  let expectingAgents = false;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split('#')[0]?.trim() ?? '';
    if (line === '') continue;
    const separator = line.indexOf(':');
    if (separator < 0) continue;
    const field = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();

    switch (field) {
      case 'user-agent': {
        if (!current || !expectingAgents) {
          current = { agents: [], rules: [] };
          groups.push(current);
          expectingAgents = true;
        }
        current.agents.push(value.toLowerCase());
        break;
      }
      case 'disallow':
      case 'allow': {
        if (!current) {
          current = { agents: ['*'], rules: [] };
          groups.push(current);
        }
        expectingAgents = false;
        current.rules.push({ allow: field === 'allow', pattern: value });
        break;
      }
      case 'crawl-delay': {
        if (current) {
          const delay = Number.parseFloat(value);
          if (Number.isFinite(delay) && delay >= 0) current.crawlDelay = delay;
          expectingAgents = false;
        }
        break;
      }
      case 'sitemap': {
        if (value !== '') sitemaps.push(value);
        break;
      }
      default:
        break;
    }
  }

  return { groups, sitemaps, present: true };
}

/** The group that applies to a user agent: most specific match, else `*`. */
export function groupFor(robots: Robots, userAgent: string): RobotsGroup | null {
  const agent = userAgent.toLowerCase();
  let best: RobotsGroup | null = null;
  let bestLength = -1;

  for (const group of robots.groups) {
    for (const candidate of group.agents) {
      if (candidate === '*') continue;
      if (agent.includes(candidate) && candidate.length > bestLength) {
        best = group;
        bestLength = candidate.length;
      }
    }
  }
  if (best) return best;
  return robots.groups.find((group) => group.agents.includes('*')) ?? null;
}

/** Longest-match-wins, Allow beating Disallow on an equal-length tie. */
export function isAllowed(robots: Robots, userAgent: string, pathname: string): boolean {
  if (!robots.present) return true;
  const group = groupFor(robots, userAgent);
  if (!group || group.rules.length === 0) return true;

  let decision = true;
  let bestLength = -1;

  for (const rule of group.rules) {
    if (rule.pattern === '') {
      // `Disallow:` with an empty value means "allow everything".
      continue;
    }
    if (!matches(rule.pattern, pathname)) continue;
    const length = rule.pattern.length;
    if (length > bestLength || (length === bestLength && rule.allow)) {
      decision = rule.allow;
      bestLength = length;
    }
  }
  return decision;
}

export function crawlDelay(robots: Robots, userAgent: string): number | undefined {
  return groupFor(robots, userAgent)?.crawlDelay;
}

function matches(pattern: string, pathname: string): boolean {
  const anchored = pattern.endsWith('$');
  const body = anchored ? pattern.slice(0, -1) : pattern;
  const parts = body.split('*').map(escapeRegExp);
  const source = `^${parts.join('.*')}${anchored ? '$' : ''}`;
  try {
    return new RegExp(source).test(pathname);
  } catch {
    return false;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
