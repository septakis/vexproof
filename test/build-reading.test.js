// SPDX-License-Identifier: MIT
// Reading what a build shipped from its module map and output folder: ways a shipped package looked absent, found
// by the code audit of 1.0.0-beta.9. Each case gave not_affected for a package that ships.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { symlinkSync, unlinkSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { project, write, pkg, lockfile, metafile, run, git, idOf } from './lib/project.js';
import { readModuleMap, attachVersions, packageOfSpecifier, webpackStatsGaps } from '../src/modules.js';
import { strayOutputs, accountFor } from '../src/coverage.js';
import { installedDirs } from '../src/content-check.js';
import { readPackageJson } from '../src/package-json.js';
import vexproof from '../src/vite.js';

// A small package with a sentence of its own, which a minifier would keep; and an app that ships clsx.
const VENDLIB = 'export function parse(v){if(typeof v!=="string")throw new TypeError("vendlib expected the input value to be a string");return v}\n';
function app(testContext, files = {}) {
  const root = project(testContext, {
    'node_modules/vendlib/package.json': pkg('vendlib', '1.2.3'),
    'node_modules/vendlib/dist/lib.js': VENDLIB,
    'node_modules/clsx/package.json': pkg('clsx', '2.1.1'),
    'node_modules/clsx/index.js': 'module.exports=function clsx(){};\n',
    'src/main.js': 'import clsx from "clsx"; clsx();\n',
    'dist/app.js': '(()=>{function clsx(){}clsx()})();\n',
    ...files,
  });
  lockfile(root, [['vendlib', '1.2.3'], ['clsx', '2.1.1']]);
  metafile(root, { 'dist/app.js': ['src/main.js', 'node_modules/clsx/index.js'] });

  return root;
}

test('a copy of a package file checked out with CRLF line endings is still that package', (testContext) => {
  const root = app(testContext, { 'dist/vendor/lib.js': VENDLIB.replace(/\n/g, '\r\n') });

  const result = run(root, ['--modules', 'meta.json']);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.verdicts[idOf('vendlib')], 'in_triage');
  assert.match(result.stderr, /1 copied from installed packages/);
});

test("a git-tracked file that is a near copy of a package can't explain away that package's strings", (testContext) => {
  const patched = `/* vendored and patched */\n${VENDLIB}`;
  const root = app(testContext, { 'public/vendor/lib.js': patched, 'dist/vendor/lib.js': patched });
  assert.equal(git(root, 'init', '-q').status, 0);
  assert.equal(git(root, 'add', 'public/vendor/lib.js').status, 0);

  const result = run(root, ['--modules', 'meta.json']);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /1 the project's own/); // accepted as the project's own file...
  assert.equal(result.verdicts[idOf('vendlib')], 'in_triage'); // ...but its strings still count against vendlib
  assert.match(result.stderr, /vendlib is not in the build's records, but 1 string/);
});

test('files in a linked folder of the build output are checked like the rest', (testContext) => {
  const root = app(testContext);
  try {
    symlinkSync(join(root, 'node_modules/vendlib/dist'), join(root, 'dist/vendor'), 'junction');
  } catch (error) {
    // only a system that won't make the link skips; any other error is a failure
    if (!['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) {
      throw error;
    }

    testContext.skip(`can't make a link here: ${error.code}`);
    return;
  }
  testContext.after(() => {
    try {
      unlinkSync(join(root, 'dist/vendor'));
    } catch {
      /* removed already */
    }
  });

  const result = run(root, ['--modules', 'meta.json']);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.verdicts[idOf('vendlib')], 'in_triage');
});

test('output files are found whatever the case of their extension', (testContext) => {
  const root = app(testContext, { 'dist/vendor/B.JS': VENDLIB, 'dist/vendor/c.Mjs': VENDLIB });
  const meta = JSON.parse(readFileSync(join(root, 'meta.json'), 'utf8'));

  const { stray } = strayOutputs(meta, { root, file: join(root, 'meta.json') });

  assert.deepEqual(stray.map((file) => file.slice(root.length + 1).replace(/\\/g, '/')), ['dist/vendor/B.JS', 'dist/vendor/c.Mjs']);
});

test('a file accounted for by its source map keeps the packages it loads by name', (testContext) => {
  const root = app(testContext, {
    'src/worker.js': 'import "lodash/template.js";\n',
    // code of its own, so it is not glue: only its source map can account for it
    'dist/worker.js': 'import "lodash/template.js";\nexport function work(x){return x*2}\n//# sourceMappingURL=worker.js.map\n',
    'dist/worker.js.map': { version: 3, sources: ['../src/worker.js'], names: [], mappings: '' },
  });

  const { accounted, unknown } = accountFor([join(root, 'dist/worker.js')], { root, outDirs: [join(root, 'dist')] });

  assert.deepEqual(unknown, []);
  assert.equal(accounted[0].kind, 'mapped');
  assert.deepEqual(accounted[0].loads, ['lodash']);
});

test('externals count as shipped, whole: webpack (also from a global), esbuild, and the Vite plugin', () => {
  // externals: { react: 'React' } reads a global; the stats name the module after it, and the reason says react
  const webpackMap = readModuleMap({ modules: [
    { name: './src/a.js', chunks: [1] },
    { name: 'external "React"', chunks: [1], reasons: [{ moduleName: './src/a.js', userRequest: 'react' }] },
    { name: 'external commonjs "fs"', chunks: [1], reasons: [{ userRequest: 'fs' }] },
  ] });

  assert.ok(webpackMap.packages.has('react') && webpackMap.whole.has('react'));
  assert.ok(!webpackMap.packages.has('fs') && !webpackMap.own.has('external "React"'));
  // without reasons the package is unknown: that is a gap, and the stats are refused
  assert.match(webpackStatsGaps({ modules: [{ name: 'external "React"', chunks: [1] }] })[0], /does not say which package/);

  const esbuildMap = readModuleMap({ inputs: { 'src/a.js': { imports: [{ path: '@scope/ui/button', kind: 'import-statement', external: true }] } },
    outputs: { 'dist/a.js': { inputs: { 'src/a.js': { bytesInOutput: 9 } }, imports: [{ path: 'react', kind: 'import-statement', external: true }] } } });

  assert.deepEqual([...esbuildMap.whole].sort(), ['@scope/ui', 'react']);

  // the Vite plugin marks an import Rollup kept external (also for iife/umd output, where it reads a global)
  const plugin = vexproof({ root: '/proj' });
  plugin.configResolved({ root: '/proj', build: { outDir: 'dist' } });
  const ids = ['/proj/src/a.js', 'react'];
  plugin.generateBundle.call({
    getModuleIds: () => ids,
    getModuleInfo: (id) => (id === 'react' ? { isExternal: true } : { importedIds: ['react'], dynamicallyImportedIds: [] }),
  }, { dir: '/proj/dist' }, { 'a.js': { type: 'chunk', fileName: 'a.js', modules: { '/proj/src/a.js': { renderedLength: 9 } } } });

  const record = globalThis[Symbol.for('vexproof.vite.registry')].get(resolve('/proj', 'vexproof-modules.json'));

  assert.deepEqual(record.inputs['src/a.js'].imports, [{ path: 'react', external: true }]);
  assert.ok(readModuleMap(record).whole.has('react'));
  assert.equal(packageOfSpecifier('react/jsx-runtime'), 'react');
  assert.equal(packageOfSpecifier('node:fs'), null);
  assert.equal(packageOfSpecifier('./x.js'), null);
  assert.equal(packageOfSpecifier('fs/promises'), null);
});

test('a nested package whose package.json starts with a byte order mark is still its own package', (testContext) => {
  const root = project(testContext, {
    'node_modules/a/package.json': pkg('a', '1.0.0'),
    'node_modules/a/index.js': 'module.exports = require("b");\n',
    'node_modules/a/node_modules/b/package.json': `﻿${JSON.stringify(pkg('b', '2.0.0'))}`,
    'node_modules/a/node_modules/b/index.js': 'module.exports = 1;\n',
    'node_modules/c/package.json': '{ "name": "c", broken',
    'node_modules/c/index.js': 'module.exports = 3;\n',
  });

  assert.equal(readPackageJson(join(root, 'node_modules/a/node_modules/b')).pkg.name, 'b');
  assert.ok(readPackageJson(join(root, 'node_modules/c')).error);
  assert.ok(readPackageJson(join(root, 'node_modules/none')).missing);

  const moduleMap = attachVersions(readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: {
    'node_modules/a/index.js': { bytesInOutput: 9 },
    'node_modules/a/node_modules/b/index.js': { bytesInOutput: 9 },
    'node_modules/c/index.js': { bytesInOutput: 9 },
  } } } }), { cwd: root });

  assert.deepEqual([...moduleMap.packages.get('b').files], ['index.js']);
  assert.deepEqual([...moduleMap.packages.get('a').files], ['index.js']);
  // a package.json that can't be read leaves the folder's name standing, and says so
  assert.deepEqual([...moduleMap.packages.get('c').files], ['index.js']);
  assert.deepEqual(moduleMap.unverified.map((unverified) => unverified.name), ['c']);
});

test('the content check finds a package spelled in another case than the lockfile spells it', (testContext) => {
  const root = project(testContext, {
    'node_modules/JSONStream/package.json': pkg('JSONStream', '1.3.5'),
    'node_modules/.pnpm/Some-Pkg@1.0.0/node_modules/Some-Pkg/package.json': pkg('Some-Pkg'),
  });

  assert.equal(installedDirs('jsonstream', [root]).length, 1);
  assert.equal(installedDirs('some-pkg', [root]).length, 1);
});
