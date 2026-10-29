/**
 * Minimal HTML tag scanning.
 *
 * Deliberately regex-based and deliberately not a parser: the only things we
 * need out of a server-rendered page are script sources, inline script
 * bodies, JSON payload blocks and preload hints. A real DOM would be a large
 * dependency for that, and every structure we care about is machine-generated
 * by a framework rather than hand-written. The trade-off is documented in the
 * README's limitations section.
 */

export interface ScriptTag {
  /** Raw attribute text. */
  attributes: string;
  src?: string;
  type?: string;
  id?: string;
  /** Inline body, empty for external scripts. */
  content: string;
  /** Character offset of the tag's content within the document. */
  contentOffset: number;
}

const SCRIPT = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const SELF_CLOSING_SCRIPT = /<script\b([^>]*?)\/?>(?=\s*(?:<|$))/gi;

export function attributeValue(attributes: string, name: string): string | undefined {
  const quoted = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)')`, 'i').exec(attributes);
  if (quoted) return quoted[2] ?? quoted[3];
  const bare = new RegExp(`\\b${name}\\s*=\\s*([^\\s>]+)`, 'i').exec(attributes);
  return bare?.[1];
}

/** All `<script>` elements, inline and external. */
export function extractScriptTags(html: string): ScriptTag[] {
  const out: ScriptTag[] = [];
  const seen = new Set<number>();

  SCRIPT.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SCRIPT.exec(html)) !== null) {
    const attributes = match[1] ?? '';
    const content = match[2] ?? '';
    seen.add(match.index);
    out.push({
      attributes,
      ...pick(attributes),
      content,
      contentOffset: match.index + (match[0].length - content.length - '</script>'.length),
    });
  }

  // `<script src=… />` written self-closing has no closing tag to match above.
  SELF_CLOSING_SCRIPT.lastIndex = 0;
  while ((match = SELF_CLOSING_SCRIPT.exec(html)) !== null) {
    if (seen.has(match.index)) continue;
    const attributes = match[1] ?? '';
    if (!/\bsrc\s*=/.test(attributes)) continue;
    out.push({ attributes, ...pick(attributes), content: '', contentOffset: match.index });
  }

  return out;
}

function pick(attributes: string): Pick<ScriptTag, 'src' | 'type' | 'id'> {
  const src = attributeValue(attributes, 'src');
  const type = attributeValue(attributes, 'type');
  const id = attributeValue(attributes, 'id');
  return {
    ...(src ? { src } : {}),
    ...(type ? { type } : {}),
    ...(id ? { id } : {}),
  };
}

/** `href` values from `<link>` elements whose `rel` matches. */
export function extractLinkHrefs(html: string, rel: RegExp): string[] {
  const out: string[] = [];
  const pattern = /<link\b([^>]*)>/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(html)) !== null) {
    const attributes = match[1] ?? '';
    const relation = attributeValue(attributes, 'rel');
    const href = attributeValue(attributes, 'href');
    if (href && relation && rel.test(relation)) out.push(href);
  }
  return out;
}

/** The body of a `<script type="application/json">` block with the given id. */
export function jsonScriptById(html: string, id: string): { json: string; offset: number } | null {
  for (const tag of extractScriptTags(html)) {
    if (tag.id === id && tag.content.trim().length > 0) {
      return { json: tag.content, offset: tag.contentOffset };
    }
  }
  return null;
}
