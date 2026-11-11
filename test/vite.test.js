// SPDX-License-Identifier: MIT
// Vite 7 (Rollup), Vite 8 (Rolldown), Rollup and Rspack module maps from real builds, and the guards
// that stop an incomplete module map from making shipped code look absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vexproof, { cleanModuleId } from '../src/vite.js';
import { readModuleMap, webpackStatsGaps, bundleSbomFromModules } from '../src/modules.js';
import { strayOutputs } from '../src/coverage.js';
import { triage } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { fromNpmAudit } from '../src/sources.js';

const fx = (f) => JSON.parse(readFileSync(new URL(`./fixtures/${f}`, import.meta.url)));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const files = (mm, pkg) => [...(mm.packages.get(pkg)?.files ?? [])].sort();

test('cleanModuleId folds Rollup/Vite virtual ids onto the real file', () => {
  assert.equal(cleanModuleId('\0/app/node_modules/lodash/omit.js?commonjs-es-import', '/app'), 'node_modules/lodash/omit.js');
  assert.equal(cleanModuleId('/app/node_modules/lodash/omit.js?commonjs-module', '/app'), 'node_modules/lodash/omit.js');
  assert.equal(cleanModuleId('src/main.jsx', '/app'), 'src/main.jsx');
});

test('recharts demo: Vite 7, Vite 8 and esbuild ship the same lodash files', () => {
  const esb = files(readModuleMap(fx('recharts.metafile.json')), 'lodash');
  for (const v of ['7', '8']) {
    const mm = readModuleMap(fx(`recharts.vite${v}.json`));
    assert.match(mm.format, v === '8' ? /rolldown/ : /rollup/);
    assert.deepEqual(files(mm, 'lodash'), esb, `vite ${v}`);
  }
});

test('recharts demo on Vite: same verdicts, bundle taken from the module map', () => {
  const lock = fx('recharts.bom.lockfile.json');
  for (const v of ['7', '8']) {
    const moduleMap = readModuleMap(fx(`recharts.vite${v}.json`));
    const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom: lock, cwd: '/nonexistent' });
    const rs = triage({ lockfileSbom: lock, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings: fromNpmAudit(fx('recharts.audit.json'), lock) });
    assert.deepEqual(Object.fromEntries(rs.map((r) => [r.id, r.state])), { 'GHSA-r5fr-rjxr-66jc': 'not_affected', 'GHSA-f23m-r3pf-42rh': 'in_triage', 'GHSA-xxjr-mmjv-4gpg': 'in_triage' }, `vite ${v}`);
  }
});

test('lodash-es (ES modules) on Vite 7 and 8: the same 21 files as the Angular/esbuild build; all five settle', () => {
  const angular = files(readModuleMap(fx('angular-capitalize.metafile.json')), 'lodash-es');
  const lock = fx('lodash-es.bom.lockfile.json');
  for (const v of ['7', '8']) {
    const moduleMap = readModuleMap(fx(`lodash-es.vite${v}.json`));
    assert.deepEqual(files(moduleMap, 'lodash-es'), angular, `vite ${v}`);
    const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom: lock, cwd: '/nonexistent' });
    const rs = triage({ lockfileSbom: lock, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings: fromNpmAudit(fx('lodash-es.audit.json'), lock) });
    assert.equal(rs.length, 5);
    assert.ok(rs.every((r) => r.state === 'not_affected' && r.level === 'module'), `vite ${v}`);
  }
});

test('Rspack: `rspack build --json` output is refused (it hides concatenated modules); the plugin output is complete', () => {
  assert.throws(() => readModuleMap(fx('recharts.rspack-cli-incomplete.json')), /leaves modules out.*lists 0 of its 190 concatenated modules/s);
  const mm = readModuleMap(fx('recharts.rspack-plugin.json'));
  assert.equal(mm.packages.size, 25);
  assert.deepEqual(files(mm, 'recharts'), files(readModuleMap(fx('recharts.metafile.json')), 'recharts'));
});

test('stats guard ignores the bundler runtime but not filtered modules', () => {
  assert.deepEqual(webpackStatsGaps({ modules: [{ type: 'runtime modules', filteredChildren: 6 }] }), []);
  assert.equal(webpackStatsGaps({ filteredModules: 3, modules: [] }).length, 1);
  assert.equal(webpackStatsGaps({ modules: [{ type: 'orphan modules', filteredChildren: 9 }] }).length, 1);
});

test('coverage check: a JS file in the output folder that no plugin recorded is reported', () => {
  const root = mkdtempSync(join(tmpdir(), 'vxp-'));
  mkdirSync(join(root, 'dist/assets'), { recursive: true });
  writeFileSync(join(root, 'dist/assets/index-abc.js'), '');
  writeFileSync(join(root, 'dist/assets/index-abc.css'), '');
  const mm = { vexproof: 1, outDirs: ['dist'], outputs: { 'dist/assets/index-abc.js': { inputs: {} } } };
  assert.deepEqual(strayOutputs(mm, { root }).stray, []);
  writeFileSync(join(root, 'dist/assets/worker-xyz.js'), '');
  assert.deepEqual(strayOutputs(mm, { root }).stray, [join(root, 'dist/assets/worker-xyz.js')]);
});

test('plugin: several builds in one process (main, worker, nested) merge into one file', () => {
  const root = mkdtempSync(join(tmpdir(), 'vxp-'));
  const chunk = (fileName, mods) => ({ [fileName]: { type: 'chunk', fileName, modules: mods } });
  const ctx = { meta: { viteVersion: '8.0.0', rolldownVersion: '1.0.0' } };
  const main = vexproof({ root, output: 'mm.json' }), worker = vexproof({ root, output: 'mm.json' });
  for (const p of [main, worker]) { p.configResolved({ root, build: { outDir: 'dist' } }); p.buildStart.call(ctx); }
  main.generateBundle.call(ctx, { dir: join(root, 'dist') }, chunk('assets/index.js', { [join(root, 'node_modules/a/x.js')]: { renderedLength: 10 }, [join(root, 'node_modules/a/y.js')]: { renderedLength: 0 } }));
  main.closeBundle();
  worker.generateBundle.call(ctx, { dir: join(root, 'dist') }, chunk('assets/worker.js', { ['\0' + join(root, 'node_modules/b/z.js') + '?commonjs-module']: { renderedLength: 5 } }));
  worker.closeBundle();
  const out = JSON.parse(readFileSync(join(root, 'mm.json'), 'utf8'));
  assert.deepEqual(Object.keys(out.outputs).sort(), ['dist/assets/index.js', 'dist/assets/worker.js']);
  const mm = readModuleMap(out);
  assert.deepEqual(files(mm, 'a'), ['x.js']); // y.js rendered nothing
  assert.deepEqual(files(mm, 'b'), ['z.js']);
});

test('plugin: server builds are skipped unless asked for', () => {
  const root = mkdtempSync(join(tmpdir(), 'vxp-'));
  const p = vexproof({ root, output: 'ssr.json' });
  p.configResolved({ root, build: { outDir: 'dist' } });
  p.generateBundle.call({ environment: { config: { consumer: 'server' } } }, { dir: join(root, 'dist') }, { 'x.js': { type: 'chunk', fileName: 'x.js', modules: { [join(root, 'node_modules/a/i.js')]: { renderedLength: 3 } } } });
  p.closeBundle();
  assert.equal(existsSync(join(root, 'ssr.json')), false);
});
