// SPDX-License-Identifier: MIT
// Vite 7 (Rollup), Vite 8 (Rolldown), Rollup and Rspack module maps from real builds, and the guards
// that stop an incomplete module map from making shipped code look absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import vexproof, { cleanModuleId } from '../src/vite.js';
import { readModuleMap, webpackStatsGaps, bundleSbomFromModules } from '../src/modules.js';
import { strayOutputs, recordedOutputs } from '../src/coverage.js';
import { temporaryFolder } from './lib/temporary.js';
import { triage } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { fromNpmAudit } from '../src/sources.js';

const fixture = (fileName) => JSON.parse(readFileSync(new URL(`./fixtures/${fileName}`, import.meta.url)));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const files = (moduleMap, packageName) => [...(moduleMap.packages.get(packageName)?.files ?? [])].sort();

test('cleanModuleId folds Rollup/Vite virtual ids onto the real file', () => {
  assert.equal(cleanModuleId('\0/app/node_modules/lodash/omit.js?commonjs-es-import', '/app'), 'node_modules/lodash/omit.js');
  assert.equal(cleanModuleId('/app/node_modules/lodash/omit.js?commonjs-module', '/app'), 'node_modules/lodash/omit.js');
  assert.equal(cleanModuleId('src/main.jsx', '/app'), 'src/main.jsx');
});

test('recharts demo: Vite 7, Vite 8 and esbuild ship the same lodash files', () => {
  const esbuild = files(readModuleMap(fixture('recharts.metafile.json')), 'lodash');

  for (const viteMajor of ['7', '8']) {
    const moduleMap = readModuleMap(fixture(`recharts.vite${viteMajor}.json`));

    assert.match(moduleMap.format, viteMajor === '8' ? /rolldown/ : /rollup/);
    assert.deepEqual(files(moduleMap, 'lodash'), esbuild, `vite ${viteMajor}`);
  }
});

test('recharts demo on Vite: same verdicts, bundle taken from the module map', () => {
  const lock = fixture('recharts.bom.lockfile.json');

  for (const viteMajor of ['7', '8']) {
    const moduleMap = readModuleMap(fixture(`recharts.vite${viteMajor}.json`));
    const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom: lock, cwd: '/nonexistent' });
    const findings = fromNpmAudit(fixture('recharts.audit.json'), lock);

    const results = triage({ lockfileSbom: lock, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings });

    assert.deepEqual(
      Object.fromEntries(results.map((result) => [result.id, result.state])),
      { 'GHSA-r5fr-rjxr-66jc': 'not_affected', 'GHSA-f23m-r3pf-42rh': 'in_triage', 'GHSA-xxjr-mmjv-4gpg': 'in_triage' },
      `vite ${viteMajor}`,
    );
  }
});

test('lodash-es (ES modules) on Vite 7 and 8: the same 21 files as the Angular/esbuild build; all five settle', () => {
  const angular = files(readModuleMap(fixture('angular-capitalize.metafile.json')), 'lodash-es');
  const lock = fixture('lodash-es.bom.lockfile.json');

  for (const viteMajor of ['7', '8']) {
    const moduleMap = readModuleMap(fixture(`lodash-es.vite${viteMajor}.json`));

    assert.deepEqual(files(moduleMap, 'lodash-es'), angular, `vite ${viteMajor}`);

    const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom: lock, cwd: '/nonexistent' });
    const findings = fromNpmAudit(fixture('lodash-es.audit.json'), lock);

    const results = triage({ lockfileSbom: lock, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings });

    assert.equal(results.length, 5);
    assert.ok(results.every((result) => result.state === 'not_affected' && result.level === 'module'), `vite ${viteMajor}`);
  }
});

test('Rspack: `rspack build --json` output is refused (it hides concatenated modules); the plugin output is complete', () => {
  assert.throws(
    () => readModuleMap(fixture('recharts.rspack-cli-incomplete.json')),
    /leaves modules out.*lists 0 of its 191 concatenated modules/s,
  );

  const moduleMap = readModuleMap(fixture('recharts.rspack-plugin.json'));

  assert.equal(moduleMap.packages.size, 25);
  assert.deepEqual(files(moduleMap, 'recharts'), files(readModuleMap(fixture('recharts.metafile.json')), 'recharts'));
});

test('stats guard ignores the bundler runtime but not filtered modules', () => {
  assert.deepEqual(webpackStatsGaps({ modules: [{ type: 'runtime modules', filteredChildren: 6 }] }), []);
  assert.equal(webpackStatsGaps({ filteredModules: 3, modules: [] }).length, 1);
  assert.equal(webpackStatsGaps({ modules: [{ type: 'orphan modules', filteredChildren: 9 }] }).length, 1);
});

test('coverage check: a JS file in the output folder that no plugin recorded is reported', (testContext) => {
  const root = temporaryFolder(testContext, 'vxp-');
  mkdirSync(join(root, 'dist/assets'), { recursive: true });
  writeFileSync(join(root, 'dist/assets/index-abc.js'), '');
  writeFileSync(join(root, 'dist/assets/index-abc.css'), '');
  const moduleMap = { vexproof: 1, outDirs: ['dist'], outputs: { 'dist/assets/index-abc.js': { inputs: {} } } };

  assert.deepEqual(strayOutputs(moduleMap, { root }).stray, []);

  writeFileSync(join(root, 'dist/assets/worker-xyz.js'), '');

  assert.deepEqual(strayOutputs(moduleMap, { root }).stray, [join(root, 'dist/assets/worker-xyz.js')]);
});

test('plugin: several builds in one process (main, worker, nested) merge into one file', (testContext) => {
  const root = temporaryFolder(testContext, 'vxp-');
  const chunk = (fileName, modules) => ({ [fileName]: { type: 'chunk', fileName, modules } });
  const context = { meta: { viteVersion: '8.0.0', rolldownVersion: '1.0.0' } };
  const main = vexproof({ root, output: 'mm.json' });
  const worker = vexproof({ root, output: 'mm.json' });
  for (const plugin of [main, worker]) {
    plugin.configResolved({ root, build: { outDir: 'dist' } });
    plugin.buildStart.call(context);
  }

  main.generateBundle.call(context, { dir: join(root, 'dist') }, chunk('assets/index.js', {
    [join(root, 'node_modules/a/x.js')]: { renderedLength: 10 },
    [join(root, 'node_modules/a/y.js')]: { renderedLength: 0 },
  }));
  main.closeBundle();
  worker.generateBundle.call(context, { dir: join(root, 'dist') }, chunk('assets/worker.js', {
    ['\0' + join(root, 'node_modules/b/z.js') + '?commonjs-module']: { renderedLength: 5 },
  }));
  worker.closeBundle();

  const out = JSON.parse(readFileSync(join(root, 'mm.json'), 'utf8'));
  assert.deepEqual(Object.keys(out.outputs).sort(), ['dist/assets/index.js', 'dist/assets/worker.js']);
  const moduleMap = readModuleMap(out);
  assert.deepEqual(files(moduleMap, 'a'), ['x.js']); // y.js rendered nothing
  assert.deepEqual(files(moduleMap, 'b'), ['z.js']);
});

test('plugin: each output file\'s size is recorded when the build is done, and a file changed since is refused', (testContext) => {
  const root = temporaryFolder(testContext);
  mkdirSync(join(root, 'dist/assets'), { recursive: true });
  writeFileSync(join(root, 'src.js'), '');
  writeFileSync(join(root, 'dist/assets/index.js'), 'console.log(1);');
  const plugin = vexproof({ root, output: 'sized.json' });
  const bundle = {
    'assets/index.js': { type: 'chunk', fileName: 'assets/index.js', modules: { [join(root, 'src.js')]: { renderedLength: 15 } } },
  };

  plugin.configResolved({ root, build: { outDir: 'dist' } });
  plugin.buildStart.call({ meta: { viteVersion: '8.0.0', rolldownVersion: '1.0.0' } });
  plugin.generateBundle.call({}, { dir: join(root, 'dist') }, bundle);
  plugin.closeBundle();

  const recorded = JSON.parse(readFileSync(join(root, 'sized.json'), 'utf8'));
  assert.equal(recorded.outputs['dist/assets/index.js'].bytes, 15);
  assert.doesNotThrow(() => recordedOutputs(recorded, { root }));

  // another build, one without the plugin, writes a file of the same name
  writeFileSync(join(root, 'dist/assets/index.js'), 'console.log("something else");');
  assert.throws(() => recordedOutputs(recorded, { root }), /dist\/assets\/index\.js is 30 bytes, and the bundler wrote 15/);
});

test('plugin: a worker\'s record moves to where the main build puts its file, and only a worker\'s record moves', (testContext) => {
  const root = temporaryFolder(testContext);
  const context = { meta: { viteVersion: '8.0.0', rolldownVersion: '1.0.0' } };
  const chunk = (fileName, modulePath) => ({
    [fileName]: { type: 'chunk', fileName, modules: { [join(root, modulePath)]: { renderedLength: 5 } } },
  });
  const asset = (fileName) => ({ [fileName]: { type: 'asset', fileName } });

  const worker = vexproof({ root, output: 'moved.json' });
  const library = vexproof({ root, output: 'moved.json' });
  const main = vexproof({ root, output: 'moved.json' });
  worker.configResolved({ root, isWorker: true, build: { outDir: 'dist' } });
  library.configResolved({ root, build: { outDir: 'lib' } });
  main.configResolved({ root, build: { outDir: 'out' } });
  for (const plugin of [worker, library, main]) {
    plugin.buildStart.call(context);
  }

  worker.generateBundle.call(context, { dir: join(root, 'dist') }, chunk('assets/worker.js', 'node_modules/b/z.js'));
  library.generateBundle.call(context, { dir: join(root, 'lib') }, chunk('assets/helper.js', 'node_modules/c/q.js'));
  // the main build is handed the worker's file, and has a file of its own that shares a name with the library's
  main.generateBundle.call(context, { dir: join(root, 'out') }, { ...asset('assets/worker.js'), ...asset('assets/helper.js') });
  for (const plugin of [worker, library, main]) {
    plugin.closeBundle();
  }

  const recorded = JSON.parse(readFileSync(join(root, 'moved.json'), 'utf8'));
  assert.deepEqual(Object.keys(recorded.outputs).sort(), ['lib/assets/helper.js', 'out/assets/worker.js']);
});

test('plugin: a worker recorded where the main build writes it gets its size from the main build', (testContext) => {
  const root = temporaryFolder(testContext);
  const context = { meta: { viteVersion: '8.0.0', rolldownVersion: '1.0.0' } };
  const worker = vexproof({ root, output: 'sized-worker.json' });
  const main = vexproof({ root, output: 'sized-worker.json' });
  worker.configResolved({ root, isWorker: true, build: { outDir: 'out' } });
  main.configResolved({ root, build: { outDir: 'out' } });
  for (const plugin of [worker, main]) {
    plugin.buildStart.call(context);
  }

  // the worker's build closes before the main build writes the worker's file
  worker.generateBundle.call(context, { dir: join(root, 'out') }, {
    'workers/w.js': { type: 'chunk', fileName: 'workers/w.js', modules: { [join(root, 'node_modules/b/z.js')]: { renderedLength: 5 } } },
  });
  worker.closeBundle();
  main.generateBundle.call(context, { dir: join(root, 'out') }, { 'workers/w.js': { type: 'asset', fileName: 'workers/w.js' } });
  mkdirSync(join(root, 'out/workers'), { recursive: true });
  writeFileSync(join(root, 'out/workers/w.js'), 'postMessage(1);');
  main.closeBundle();

  const recorded = JSON.parse(readFileSync(join(root, 'sized-worker.json'), 'utf8'));
  assert.equal(recorded.outputs['out/workers/w.js'].bytes, 15);
});

test('plugin: when two worker records share the file\'s name, neither moves', (testContext) => {
  const root = temporaryFolder(testContext);
  const context = { meta: { viteVersion: '8.0.0', rolldownVersion: '1.0.0' } };
  const chunk = (fileName, modulePath) => ({
    [fileName]: { type: 'chunk', fileName, modules: { [join(root, modulePath)]: { renderedLength: 5 } } },
  });

  const firstWorker = vexproof({ root, output: 'ambiguous.json' });
  const secondWorker = vexproof({ root, output: 'ambiguous.json' });
  const main = vexproof({ root, output: 'ambiguous.json' });
  firstWorker.configResolved({ root, isWorker: true, build: { outDir: 'dist/one' } });
  secondWorker.configResolved({ root, isWorker: true, build: { outDir: 'dist/two' } });
  main.configResolved({ root, build: { outDir: 'out' } });
  for (const plugin of [firstWorker, secondWorker, main]) {
    plugin.buildStart.call(context);
  }

  firstWorker.generateBundle.call(context, { dir: join(root, 'dist/one') }, chunk('worker.js', 'node_modules/b/z.js'));
  secondWorker.generateBundle.call(context, { dir: join(root, 'dist/two') }, chunk('worker.js', 'node_modules/c/q.js'));
  main.generateBundle.call(context, { dir: join(root, 'out') }, { 'worker.js': { type: 'asset', fileName: 'worker.js' } });
  for (const plugin of [firstWorker, secondWorker, main]) {
    plugin.closeBundle();
  }

  // which of the two the file holds can't be told, so the file stays unrecorded and the CLI checks it
  const recorded = JSON.parse(readFileSync(join(root, 'ambiguous.json'), 'utf8'));
  assert.deepEqual(Object.keys(recorded.outputs).sort(), ['dist/one/worker.js', 'dist/two/worker.js']);
});

test('plugin: server builds are skipped unless asked for', (testContext) => {
  const root = temporaryFolder(testContext, 'vxp-');
  const plugin = vexproof({ root, output: 'ssr.json' });
  plugin.configResolved({ root, build: { outDir: 'dist' } });
  const serverContext = { environment: { config: { consumer: 'server' } } };
  const bundle = { 'x.js': { type: 'chunk', fileName: 'x.js', modules: { [join(root, 'node_modules/a/i.js')]: { renderedLength: 3 } } } };

  plugin.generateBundle.call(serverContext, { dir: join(root, 'dist') }, bundle);
  plugin.closeBundle();

  assert.equal(existsSync(join(root, 'ssr.json')), false);
});
