import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  decodeDataUri,
  findSourceMappingAnnotation,
  loadSourcemap,
  originalPosition,
  writeRecoveredSources,
} from '../src/extract/sourcemaps.js';
import { fixture } from './helpers.js';

describe('sourceMappingURL discovery', () => {
  it('finds the trailing comment form', () => {
    const annotation = findSourceMappingAnnotation('var a=1;\n//# sourceMappingURL=app.min.js.map\n');
    assert.equal(annotation?.url, 'app.min.js.map');
    assert.equal(annotation?.inline, false);
  });

  it('accepts the deprecated //@ spelling and the block-comment form', () => {
    assert.equal(findSourceMappingAnnotation('//@ sourceMappingURL=a.map')?.url, 'a.map');
    assert.equal(findSourceMappingAnnotation('/*# sourceMappingURL=b.map */')?.url, 'b.map');
  });

  it('prefers the last annotation, as browsers do', () => {
    const annotation = findSourceMappingAnnotation(
      '//# sourceMappingURL=first.map\n//# sourceMappingURL=second.map\n',
    );
    assert.equal(annotation?.url, 'second.map');
  });

  it('recognises an inline data URI', () => {
    const annotation = findSourceMappingAnnotation(
      '//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==',
    );
    assert.equal(annotation?.inline, true);
  });

  it('returns null when there is no annotation', () => {
    assert.equal(findSourceMappingAnnotation('var a = 1;'), null);
  });

  it('decodes both base64 and percent-encoded data URIs', () => {
    assert.equal(
      decodeDataUri('data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=='),
      '{"version":3}',
    );
    assert.equal(decodeDataUri('data:application/json,%7B%22version%22%3A3%7D'), '{"version":3}');
    assert.equal(decodeDataUri('not-a-data-uri'), null);
  });
});

describe('source map recovery', () => {
  const raw = fs.readFileSync(fixture('bundle', 'app.min.js.map'), 'utf8');

  it('recovers original paths and normalises the bundler prefix', async () => {
    const loaded = await loadSourcemap(raw, { asset: 'app.min.js', discovery: 'comment' });
    assert.deepEqual(loaded.finding.sources, [
      'src/admin/panel.tsx',
      'src/api/client.js',
      'src/config/flags.ts',
    ]);
    assert.equal(loaded.finding.sourceCount, 3);
    assert.equal(loaded.finding.withContent, 2);
    loaded.consumer.destroy();
  });

  it('rebuilds the directory tree and marks files with no content', async () => {
    const loaded = await loadSourcemap(raw, { asset: 'app.min.js', discovery: 'comment' });
    const src = loaded.finding.tree.children.find((node) => node.name === 'src');
    assert.ok(src);
    const admin = src.children.find((node) => node.name === 'admin');
    assert.equal(admin?.children[0]?.name, 'panel.tsx');
    assert.equal(admin?.children[0]?.hasContent, false);
    loaded.consumer.destroy();
  });

  it('highlights paths a tester cares about', async () => {
    const loaded = await loadSourcemap(raw, { asset: 'app.min.js', discovery: 'comment' });
    assert.ok(loaded.finding.highlights.includes('src/api/client.js'));
    assert.ok(loaded.finding.highlights.includes('src/config/flags.ts'));
    loaded.consumer.destroy();
  });

  it('maps a generated position back to the original file', async () => {
    const loaded = await loadSourcemap(raw, { asset: 'app.min.js', discovery: 'comment' });
    const bundle = fs.readFileSync(fixture('bundle', 'app.min.js'), 'utf8');
    const column = bundle.indexOf('fetch(`/api/v2/users/') + 1;
    const mapped = originalPosition(loaded.consumer, 1, column);
    assert.equal(mapped?.source, 'src/api/client.js');
    assert.equal(mapped?.line, 4);
    loaded.consumer.destroy();
  });

  it('rejects a map that is not a JSON object', async () => {
    await assert.rejects(() => loadSourcemap('[]', { asset: 'x', discovery: 'direct' }));
    await assert.rejects(() => loadSourcemap('not json', { asset: 'x', discovery: 'direct' }));
  });

  it('writes recovered sources inside the output directory only', async () => {
    const outDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'bundle-recon-test-'));
    try {
      const written = await writeRecoveredSources(
        new Map([
          ['src/api/client.js', 'export const a = 1;'],
          ['../../../../etc/cron.d/evil', 'malicious'],
        ]),
        outDir,
        'app.min.js',
      );
      assert.equal(written.length, 2);
      for (const file of written) {
        assert.ok(!file.startsWith('..'), `${file} escaped the output directory`);
      }
      const escaped = path.resolve(outDir, '..', '..', '..', '..', 'etc', 'cron.d', 'evil');
      assert.equal(fs.existsSync(escaped), false, 'traversal must not write outside --out');
      const recovered = await fsp.readFile(
        path.join(outDir, 'app.min.js', 'src', 'api', 'client.js'),
        'utf8',
      );
      assert.equal(recovered, 'export const a = 1;');
    } finally {
      await fsp.rm(outDir, { recursive: true, force: true });
    }
  });
});
