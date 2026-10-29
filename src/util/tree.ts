import type { TreeNode } from '../types.js';

/**
 * Normalise a source-map `sources` entry into something that looks like a
 * repository path. Bundlers emit a zoo of prefixes:
 *
 *   webpack://my-app/./src/api/client.ts
 *   webpack-internal:///./app/page.tsx
 *   ../../src/lib/auth.ts
 *   file:///home/ci/build/src/main.ts
 */
export function normaliseSourcePath(source: string): string {
  let path = source;
  path = path.replace(/^webpack-internal:\/{2,3}/, '');
  path = path.replace(/^webpack:\/{2,3}/, '');
  path = path.replace(/^(rollup|vite|turbopack|rsbuild|esbuild):\/{2,3}/, '');
  path = path.replace(/^file:\/{2,3}/, '/');
  // Strip a leading project-name segment webpack inserts before `./`.
  path = path.replace(/^([^/]+)\/\.\//, '');
  path = path.replace(/^\.\//, '');
  while (path.startsWith('../')) path = path.slice(3);
  path = path.replace(/^\/+/, '');
  return path === '' ? source : path;
}

/** Build a directory tree from a flat list of paths. */
export function buildTree(paths: Iterable<string>, rootName = '.'): TreeNode {
  const root: TreeNode = { name: rootName, children: [], file: false };
  for (const path of paths) {
    const parts = path.split('/').filter((part) => part.length > 0);
    let node = root;
    parts.forEach((part, index) => {
      const isLeaf = index === parts.length - 1;
      let child = node.children.find((c) => c.name === part && c.file === isLeaf);
      if (!child) {
        child = { name: part, children: [], file: isLeaf };
        node.children.push(child);
      }
      node = child;
    });
  }
  sort(root);
  return root;
}

function sort(node: TreeNode): void {
  node.children.sort((a, b) => {
    if (a.file !== b.file) return a.file ? 1 : -1;
    return a.name.localeCompare(b.name);
  });
  for (const child of node.children) sort(child);
}

/** Render a tree with box-drawing characters, capped at `maxLines`. */
export function renderTree(node: TreeNode, maxLines = 200): string[] {
  const lines: string[] = [node.name];
  let truncated = false;

  const walk = (current: TreeNode, prefix: string): void => {
    current.children.forEach((child, index) => {
      if (lines.length >= maxLines) {
        truncated = true;
        return;
      }
      const last = index === current.children.length - 1;
      const marker = child.hasContent === false && child.file ? ' (no content)' : '';
      lines.push(`${prefix}${last ? '└── ' : '├── '}${child.name}${marker}`);
      walk(child, `${prefix}${last ? '    ' : '│   '}`);
    });
  };

  walk(node, '');
  if (truncated) lines.push('… (tree truncated)');
  return lines;
}

/** Count the leaf files in a tree. */
export function countFiles(node: TreeNode): number {
  if (node.file) return 1;
  return node.children.reduce((sum, child) => sum + countFiles(child), 0);
}
