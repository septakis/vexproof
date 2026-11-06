// SPDX-License-Identifier: MIT
// Deployment folders as evidence: files copied into the deployment, plus the source maps of bundled code.
// Each case builds a small deployment on disk; the rules were found on real Next.js 16 and Nuxt 4 builds.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readDeployment, mergeModuleMaps, loadedSpecifiers, runtimeImports, usesNodeBuiltins, isGlue } from '../src/deploy.js';
import { readModuleMap } from '../src/modules.js';
import { triage } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const put = (root, files) => { for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), c); } };
const map = (sources) => JSON.stringify({ version: 3, sources, mappings: '' });

function app(extra = {}) {
  const root = mkdtempSync(join(tmpdir(), 'vxp-deploy-'));
  put(root, {
    // installed packages
    'node_modules/lodash/package.json': '{"name":"lodash","version":"4.17.21"}',
    'node_modules/lodash/debounce.js': 'module.exports = function debounce() {};',
    'node_modules/lodash/template.js': 'module.exports = function template() {};',
    'node_modules/marked/package.json': '{"name":"marked","version":"4.0.9"}',
    'node_modules/marked/lib/marked.cjs': 'exports.parse = function () {};',
    // the deployment: a server chunk bundling lodash/debounce, the server's own node_modules with marked
    'out/server/chunks/page.js': 'const m = require("marked"); function page() {}\n//# sourceMappingURL=page.js.map',
    'out/server/chunks/page.js.map': map(['../../../node_modules/lodash/debounce.js', '../../../src/page.js']),
    'out/server/node_modules/marked/package.json': '{"name":"marked","version":"4.0.9"}',
    'out/server/node_modules/marked/lib/marked.cjs': 'exports.parse = function () {};',
    'out/server/index.mjs': 'import "node:http"; import "./chunks/page.js";',
    'out/server/manifest.js': 'self.__BUILD_MANIFEST = {"pages":{"/":[]}};',
    ...extra,
  });
  return root;
}
const lock = (names) => new Set(names);

test('deployed files and source-mapped bundles make the module map', () => {
  const d = readDeployment(['out'], { root: app(), lockNames: lock(['lodash', 'marked']) });
  assert.deepEqual([...d.packages.get('lodash').files], ['debounce.js']);
  assert.deepEqual([...d.packages.get('marked').roots], ['out/server/node_modules/marked']);
  assert.equal(d.hasServer, true);
  assert.deepEqual([d.unmapped, d.missingRuntime, d.unattributed], [[], [], []]);
});

test('a bundled file with no source map is refused unless it is glue or an exact copy of an installed file', () => {
  const root = app({ 'out/server/chunks/vendor.js': 'function a(){} function b(){}', 'out/server/chunks/polyfill.js': 'module.exports = function template() {};' });
  const d = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked']) });
  assert.deepEqual(d.unmapped, ['out/server/chunks/vendor.js']); // manifest.js is glue; polyfill.js is lodash/template.js
  assert.ok(d.packages.get('lodash').files.has('template.js'));
  assert.ok(isGlue("const p = require('path'); startServer({ dir }).catch((err) => { process.exit(1) })"));
  assert.ok(!isGlue('function x(){}'));
});

test('runtime loads of lockfile packages must be satisfied inside the deployment; comments and strings do not count', () => {
  const root = app({ 'out/server/chunks/api.js': '/* import x from "js-yaml" */ const s = "require(\'axios\')"; const y = require("js-yaml"); function f(){}\n//# sourceMappingURL=api.js.map', 'out/server/chunks/api.js.map': map([]) });
  const d = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked', 'js-yaml', 'axios']) });
  assert.deepEqual(d.missingRuntime.map((m) => m.name), ['js-yaml']);
  const specs = loadedSpecifiers('import a from "a"; export * from "b"; import("c"); require("d/sub"); // import "e"\nconst t = "import f from \'f\'"');
  assert.deepEqual([...runtimeImports(specs)].sort(), ['a', 'b', 'c', 'd']);
  assert.ok(usesNodeBuiltins(loadedSpecifiers('require("node:fs")')) && !usesNodeBuiltins(loadedSpecifiers('import "react"')));
});

test('externals linked under hashed names resolve to the real package, and must land inside the deployment', (t) => {
  const root = app({ 'out/server/chunks/ext.js': 'module.exports = require("marked-77b6df11dc860fde"); function f(){}\n//# sourceMappingURL=ext.js.map', 'out/server/chunks/ext.js.map': map([]) });
  mkdirSync(join(root, 'out/server/.next/node_modules'), { recursive: true });
  try { symlinkSync('../../node_modules/marked', join(root, 'out/server/.next/node_modules/marked-77b6df11dc860fde')); } catch (e) {
    if (e.code === 'EPERM') return t.skip('this account cannot create symlinks; Next.js writes real ones, so Windows needs Developer Mode'); // eslint-disable-line consistent-return
    throw e;
  }
  assert.deepEqual(readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked']) }).missingRuntime, []);
  // the same link pointing outside the deployment
  const root2 = app({ 'out/server/chunks/ext.js': 'module.exports = require("marked-77b6df11dc860fde"); function f(){}\n//# sourceMappingURL=ext.js.map', 'out/server/chunks/ext.js.map': map([]) });
  mkdirSync(join(root2, 'out/server/.next/node_modules'), { recursive: true });
  symlinkSync(join(root2, 'node_modules/marked'), join(root2, 'out/server/.next/node_modules/marked-77b6df11dc860fde'));
  assert.deepEqual(readDeployment(['out'], { root: root2, lockNames: lock(['lodash', 'marked']) }).missingRuntime.map((m) => m.name), ['marked']);
});

test('sources reached through a package\'s own source maps are traced back to it, and the package is taken whole', () => {
  const root = app({
    'node_modules/fast-equals/package.json': '{"name":"fast-equals","version":"5.2.2"}',
    'node_modules/fast-equals/dist/es/index.mjs': 'export function equals(){}\n//# sourceMappingURL=index.mjs.map',
    'node_modules/fast-equals/dist/es/index.mjs.map': map(['../../../src/comparator.ts']), // resolves to node_modules/src/comparator.ts
    'out/app.js': 'function a(){}\n//# sourceMappingURL=app.js.map',
    'out/app.js.map': map(['../node_modules/src/comparator.ts', '../node_modules/ghost/src/x.ts']),
  });
  const d = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked', 'fast-equals']) });
  assert.ok(d.packages.has('fast-equals') && d.whole.has('fast-equals'));
  assert.ok(!d.packages.has('src'));
  assert.deepEqual(d.unattributed, ['node_modules/ghost/src/x.ts (in out/app.js)']);
});

test('a whole package gets no file-level claims', () => {
  const d = readDeployment(['out'], { root: app(), lockNames: lock(['lodash', 'marked']) });
  d.whole.add('lodash');
  const findings = [{ purl: 'pkg:npm/lodash@4.17.21', ids: ['GHSA-r5fr-rjxr-66jc'] }];
  const sbom = { components: [{ purl: 'pkg:npm/lodash@4.17.21' }] };
  const [r] = triage({ lockfileSbom: sbom, bundleSbom: sbom, findings, moduleMap: d, rules, moduleCheck: evaluateModuleRule, pro: true });
  assert.equal(r.state, 'in_triage');
  assert.match(r.moduleReason, /publishes its own source maps/);
});

test('several module maps merge; the import graph survives only if every map has one', () => {
  const a = readModuleMap({ inputs: { 'src/a.js': { imports: [{ path: 'node_modules/x/i.js' }] } }, outputs: { 'o.js': { inputs: { 'src/a.js': { bytesInOutput: 1 }, 'node_modules/x/i.js': { bytesInOutput: 1 } } } } });
  const b = readModuleMap({ inputs: {}, outputs: { 'p.js': { inputs: { 'node_modules/y/j.js': { bytesInOutput: 1 } } } } });
  const m = mergeModuleMaps([a, b]);
  assert.deepEqual([...m.packages.keys()].sort(), ['x', 'y']);
  assert.equal(m.graph, null);
  assert.ok(mergeModuleMaps([a, a]).graph);
});

test('CLI: a whole-app deployment satisfies the server check; a browser-only folder does not', () => {
  const root = app({ 'out/static/app.js': 'function a(){}\n//# sourceMappingURL=app.js.map', 'out/static/app.js.map': map(['../../node_modules/lodash/debounce.js']) });
  const sbom = { serialNumber: 'urn:uuid:11111111-2222-3333-4444-555555555555', version: 1, components: ['next@16.0.0', 'lodash@4.17.21', 'marked@4.0.9'].map((c) => ({ purl: `pkg:npm/${c}`, 'bom-ref': c })) };
  writeFileSync(join(root, 'bom.json'), JSON.stringify(sbom));
  writeFileSync(join(root, 'findings.json'), JSON.stringify([{ purl: 'pkg:npm/marked@4.0.9', ids: ['GHSA-rrrm-qjm4-v8hf'] }]));
  const run = (...a) => spawnSync(process.execPath, [CLI, '--lockfile', 'bom.json', '--findings', 'findings.json', '--out', 'vex.json', '--quiet', ...a], { cwd: root, encoding: 'utf8' });
  const browser = run('--deploy', 'out/static');
  assert.equal(browser.status, 2);
  assert.match(browser.stderr, /also runs JavaScript on a server/);
  const whole = run('--deploy', 'out/server', '--deploy', 'out/static');
  assert.equal(whole.status, 0, whole.stderr);
  assert.match(whole.stdout, /in_triage\s+GHSA-rrrm-qjm4-v8hf/); // marked is deployed on the server
});
