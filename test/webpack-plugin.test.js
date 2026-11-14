// SPDX-License-Identifier: MIT
// The webpack/Rspack plugin's bookkeeping, with stand-in compilers: what it writes for one configuration and for
// several, and that a compiler that has shut down is not written into a later build's file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { temporaryFolder } from './lib/temporary.js';

const { VexproofPlugin } = createRequire(import.meta.url)('../src/webpack.cjs');

/** A compiler with the two hooks the plugin taps, and ways to fire them. */
function standInCompiler(context, outputFolder) {
  const callbacks = {};
  const hook = (name) => ({
    tap: (_pluginName, callback) => {
      callbacks[name] = callback;
    },
  });

  const compiler = {
    context,
    outputPath: join(context, outputFolder),
    webpack: { version: '5.99.0' },
    hooks: { done: hook('done'), shutdown: hook('shutdown') },
  };
  new VexproofPlugin().apply(compiler);

  return {
    finishBuild: (stats) => callbacks.done({ toJson: () => structuredClone(stats) }),
    shutDown: () => callbacks.shutdown(),
  };
}

const writtenFile = (root) => JSON.parse(readFileSync(join(root, 'vexproof-modules.json'), 'utf8'));

test('webpack plugin: one configuration writes its stats; several write one child each', (testContext) => {
  const root = temporaryFolder(testContext);
  const app = standInCompiler(root, 'dist/app');
  const admin = standInCompiler(root, 'dist/admin');

  app.finishBuild({ modules: [{ name: './src/app.js' }] });
  assert.equal(writtenFile(root).vexproofOutDir, 'dist/app');
  assert.equal(writtenFile(root).children, undefined);

  admin.finishBuild({ modules: [{ name: './src/admin.js' }] });
  const both = writtenFile(root);
  assert.equal(both.vexproofConfigurations, 2);
  assert.deepEqual(both.children.map((child) => child.outputPath), ['dist/app', 'dist/admin']);
});

test('webpack plugin: a later build in the same process does not carry a shut-down compiler\'s stats', (testContext) => {
  const root = temporaryFolder(testContext);
  const first = standInCompiler(root, 'dist');
  first.finishBuild({ modules: [{ name: './src/old.js' }] });
  first.shutDown();

  const second = standInCompiler(root, 'dist');
  second.finishBuild({ modules: [{ name: './src/new.js' }] });

  const written = writtenFile(root);
  assert.equal(written.children, undefined);
  assert.deepEqual(written.modules, [{ name: './src/new.js' }]);
});
