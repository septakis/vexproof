// SPDX-License-Identifier: MIT
// The CLI's own decisions about what shipped, end to end: every route by which a package counts as shipped, and
// every refusal that stops a run. A mutation test of 1.0.0-beta.9 turned each of these off in src/cli.js and the
// whole suite still passed, so each case here is the only evidence for its route. Each one is set up so that
// breaking the route gives not_affected (or a VEX where there should be none).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statSync } from 'node:fs';
import { join } from 'node:path';
import { project, write, pkg, lockfile, metafile, run, idOf } from './lib/project.js';
import { proCopy } from './lib/pro-copy.js';

// An app that ships clsx (so the bundle shares a package with the lockfile) and has a finding on victim.
function app(t, files = {}, { pkgs = [['victim', '1.0.0'], ['clsx', '2.1.1']], inputs = ['src/main.js', 'node_modules/clsx/index.js'], imports } = {}) {
  const root = project(t, {
    'node_modules/victim/package.json': pkg('victim'),
    'node_modules/victim/index.js': 'module.exports = function victim(){};\n',
    'node_modules/clsx/package.json': pkg('clsx', '2.1.1'),
    'node_modules/clsx/index.js': 'module.exports = function clsx(){};\n',
    'src/main.js': 'import clsx from "clsx"; clsx();\n',
    'dist/app.js': '(()=>{function clsx(){}clsx()})();\n',
    ...files,
  });
  lockfile(root, pkgs);
  metafile(root, { 'dist/app.js': inputs }, { imports });
  return root;
}
const shipsVictim = (r) => {
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.verdicts[idOf('victim')], 'in_triage', r.stderr);
};
const refuses = (r, message) => {
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, message);
  assert.deepEqual(r.verdicts, {}, 'no VEX is written');
};

// ---------- routes by which a package counts as shipped ----------

test('--bundle with --modules: a package only the module map names ships', (t) => {
  const root = app(t, {}, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/victim/index.js'] });
  write(root, { 'bundle.json': { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ type: 'library', name: 'clsx', version: '2.1.1', purl: 'pkg:npm/clsx@2.1.1' }] } });
  const r = run(root, ['--bundle', 'bundle.json', '--modules', 'meta.json']);
  shipsVictim(r);
  assert.match(r.stderr, /in the module map and not in the bundle SBOM/);
});

test('a package a recorded output loads by name when it runs ships', (t) => {
  const root = app(t, { 'dist/app.js': 'import "victim";\n(()=>{function clsx(){}clsx()})();\n' });
  const r = run(root, ['--modules', 'meta.json']);
  shipsVictim(r);
  assert.match(r.stderr, /loads 1 package\(s\) by name when it runs/);
});

test('a package an unrecorded output file loads by name ships', (t) => {
  const root = app(t, { 'dist/loader.js': 'import "victim";\n' });
  shipsVictim(run(root, ['--modules', 'meta.json']));
});

test("a file webpack says it copied from a package counts for that package", (t) => {
  const root = project(t, {
    'node_modules/victim/package.json': pkg('victim'), 'node_modules/victim/dist/v.js': 'function victim(a){return a}\n',
    'node_modules/clsx/package.json': pkg('clsx', '2.1.1'), 'node_modules/clsx/index.js': 'module.exports=1;\n',
    'src/a.js': 'x', 'dist/main.js': 'console.log(1);\n', 'dist/vendor/v.js': 'function v(a){return a}\n',
  });
  lockfile(root, [['victim', '1.0.0'], ['clsx', '2.1.1']]);
  const size = (p) => statSync(join(root, p)).size;
  write(root, { 'stats.json': {
    vexproofBundler: 'webpack 5.0.0', vexproofOutDir: 'dist',
    modules: [{ name: './src/a.js', chunks: [1] }, { name: './node_modules/clsx/index.js', chunks: [1] }, { name: 'webpack/runtime/x', moduleType: 'runtime', chunks: [1] }],
    chunks: [], assets: [
      { name: 'main.js', size: size('dist/main.js'), chunks: [1] },
      { name: 'vendor/v.js', size: size('dist/vendor/v.js'), chunks: [], info: { copied: true, sourceFilename: 'node_modules/victim/dist/v.js' } },
    ], children: [],
  } });
  shipsVictim(run(root, ['--modules', 'stats.json']));
});

test('compiled code copied into the output (.wasm, .node) counts for the package it came from', (t) => {
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 7]);
  const root = app(t, { 'node_modules/victim/v.wasm': wasm, 'dist/assets/v-1a2b.wasm': wasm });
  shipsVictim(run(root, ['--modules', 'meta.json']));
});

test('--deploy --browser-only: a package the browser code loads by name ships, though nothing supplies it', (t) => {
  const root = project(t, {
    'node_modules/victim/package.json': pkg('victim'), 'node_modules/victim/index.js': 'module.exports = 1;\n',
    'node_modules/clsx/package.json': pkg('clsx', '2.1.1'), 'node_modules/clsx/index.js': 'module.exports = 1;\n',
    'src/app.js': 'x',
    'out/app.js': 'import v from "victim"; export function run(){ return v; }\n//# sourceMappingURL=app.js.map',
    // clsx is bundled in, so what shipped shares a package with the lockfile and can vouch for absence at all
    'out/app.js.map': { version: 3, sources: ['../src/app.js', '../node_modules/clsx/index.js'], names: [], mappings: '' },
  });
  lockfile(root, [['victim', '1.0.0'], ['clsx', '2.1.1']]);
  // without --browser-only the deployment can't run, and the run says so
  refuses(run(root, ['--deploy', 'out']), /loads victim at runtime, but it is not in the deployment folders/);
  shipsVictim(run(root, ['--deploy', 'out', '--browser-only']));
});

test('the content check keeps a package open when its own strings are in what ships', (t) => {
  const sentence = 'victim expected the input value to be a string';
  const root = app(t, {
    'node_modules/victim/index.js': `module.exports = function victim(v){ if (typeof v !== "string") throw new TypeError("${sentence}"); };\n`,
    // the module map does not list victim, but its message is in the bundle
    'dist/app.js': `(()=>{function clsx(){}clsx();throw new TypeError("${sentence}")})();\n`,
  });
  const r = run(root, ['--modules', 'meta.json']);
  shipsVictim(r);
  assert.match(r.stderr, /victim is not in the build's records, but 1 string/);
});

// ---------- refusals ----------

test('refused: a --deploy folder that does not exist', (t) => {
  const root = app(t);
  refuses(run(root, ['--deploy', 'nowhere']), /no such folder/);
});

test("refused: a framework's server half without its browser half", (t) => {
  const root = app(t, { '.output/server/index.mjs': 'export default 1;\n', '.output/public/app.js': 'console.log(1);\n' });
  refuses(run(root, ['--deploy', '.output/server']), /server half of this build but not the browser half: \.output\/public/);
});

test('refused: deployed code with no source map', (t) => {
  const root = app(t, { 'out/app.js': 'function victimish(a){return a*2} console.log(victimish(1));\n' });
  refuses(run(root, ['--deploy', 'out']), /have no source map/);
});

test("refused: a source map naming package code that can't be traced to an installed package", (t) => {
  const root = app(t, {
    'out/app.js': 'function g(a){return a} console.log(g(1));\n//# sourceMappingURL=app.js.map',
    'out/app.js.map': { version: 3, sources: ['webpack://app/./node_modules/.cache/ghost/index.js'], names: [], mappings: '' },
  });
  refuses(run(root, ['--deploy', 'out']), /can't be traced to an installed package/);
});

test('refused: deployed code that loads a file from outside the deployment', (t) => {
  const root = app(t, {
    'generated/client.js': 'module.exports = require("victim");\n',
    'out/server.js': 'const c = require("../generated/client.js"); console.log(c);\n//# sourceMappingURL=server.js.map',
    'out/server.js.map': { version: 3, sources: ['../src/main.js'], names: [], mappings: '' },
  });
  refuses(run(root, ['--deploy', 'out']), /loads 1 file\(s\) from outside the deployment folders \(e\.g\. generated\/client\.js/);
});

test("refused: a shipped folder that has no readable package.json and a name the lockfile doesn't have", (t) => {
  const root = app(t, { 'node_modules/tiny/index.js': 'module.exports = 1;\n' }, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/tiny/index.js'] });
  refuses(run(root, ['--modules', 'meta.json']), /can't be read here and the lockfile SBOM has no package of that name/);
});

test("refused: code from Vite's prebundled dependencies (node_modules/.vite)", (t) => {
  const root = app(t, { 'node_modules/.vite/deps/react.js': 'export default 1;\n' }, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/.vite/deps/react.js'] });
  refuses(run(root, ['--modules', 'meta.json']), /where Vite keeps dependencies it bundled ahead of time/);
});

test('refused: a browser module map for an app with a server build the plugin skipped', (t) => {
  const root = app(t);
  write(root, { 'vexproof-modules.json': { vexproof: 1, bundler: 'vite 7.0.0 (rollup 4.0.0)', inputs: {}, outDirs: ['dist'], serverBuildsSkipped: 1,
    outputs: { 'dist/app.js': { inputs: { 'src/main.js': { bytesInOutput: 10 }, 'node_modules/clsx/index.js': { bytesInOutput: 10 } } } } } });
  refuses(run(root, ['--modules', 'vexproof-modules.json']), /also runs JavaScript on a server \(the build includes a server \(SSR\) build\)/);
  // --browser-only says the VEX is for the browser bundle alone
  assert.equal(run(root, ['--modules', 'vexproof-modules.json', '--browser-only']).status, 0);
});

test('refused: a browser module map for an app whose own dependencies include a server framework', (t) => {
  const root = app(t, { 'package.json': { name: 'app', version: '1.0.0', dependencies: { express: '^4.0.0', clsx: '^2.0.0' } } },
    { pkgs: [['victim', '1.0.0'], ['clsx', '2.1.1'], ['express', '4.21.0']] });
  refuses(run(root, ['--modules', 'meta.json']), /express is a dependency of this package/);
});

// ---------- Pro decisions ----------

test('Pro: a derived rule only suggests a verdict until --accept-derived', (t) => {
  const pro = proCopy(t);
  const root = app(t, { 'node_modules/victim/lib/other.js': 'x' }, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/victim/index.js'] });
  write(root, { 'rules.json': { schema: 1, origin: 'derived', packages: { victim: { advisories: {
    [`${idOf('victim')}@1.0.0`]: { id: idOf('victim'), versions: ['1.0.0'], files: ['lib/parse.js'], affects: 'parse bug', origin: 'derived', derivedFrom: { installed: '1.0.0', fixed: '1.0.1' } },
  } } } } });
  const base = ['--lockfile', 'bom.json', '--findings', 'findings.json', '--modules', 'meta.json', '--rules', 'rules.json', '--quiet'];
  let r = pro.run([...base, '--out', 'a.json'], { cwd: root });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, new RegExp(`in_triage\\s+${idOf('victim')}.*derived rule suggests not affected`));
  r = pro.run([...base, '--out', 'b.json', '--accept-derived'], { cwd: root });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, new RegExp(`not_affected \\(module\\)\\s+${idOf('victim')}`));
});

test('Pro: --baseline carries forward, and --fail-on new trips only on new open findings', (t) => {
  const pro = proCopy(t);
  const root = app(t, {}, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/victim/index.js'] });
  const base = ['--lockfile', 'bom.json', '--modules', 'meta.json', '--quiet'];
  write(root, { 'one.json': [{ purl: 'pkg:npm/victim@1.0.0', ids: ['GHSA-base-0001'] }] });
  assert.equal(pro.run([...base, '--findings', 'one.json', '--out', 'v1.json'], { cwd: root }).status, 0);
  // nothing new against itself
  let r = pro.run([...base, '--findings', 'one.json', '--out', 'v2.json', '--baseline', 'v1.json', '--fail-on', 'new'], { cwd: root });
  assert.equal(r.status, 0, r.stderr);
  // a second advisory on a shipped package is new and open
  write(root, { 'two.json': [{ purl: 'pkg:npm/victim@1.0.0', ids: ['GHSA-base-0001', 'GHSA-base-0002'] }] });
  r = pro.run([...base, '--findings', 'two.json', '--out', 'v3.json', '--baseline', 'v1.json', '--fail-on', 'new'], { cwd: root });
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /gate failed — 1 new open finding\(s\): GHSA-base-0002/);
});
