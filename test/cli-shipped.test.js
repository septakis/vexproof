// SPDX-License-Identifier: MIT
// The CLI's own decisions about what shipped, end to end: every route by which a package counts as shipped, and
// every refusal that stops a run. A mutation test of 1.0.0-beta.9 turned each of these off in src/cli.js and the
// whole suite still passed, so each case here is the only evidence for its route. Each one is set up so that
// breaking the route gives not_affected (or a VEX where there should be none).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { project, write, pkg, lockfile, metafile, run, idOf } from './lib/project.js';
import { proCopy } from './lib/pro-copy.js';

// An app that ships clsx (so the bundle shares a package with the lockfile) and has a finding on victim.
function app(testContext, files = {}, { pkgs = [['victim', '1.0.0'], ['clsx', '2.1.1']], inputs = ['src/main.js', 'node_modules/clsx/index.js'], imports } = {}) {
  const root = project(testContext, {
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
const shipsVictim = (result) => {
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.verdicts[idOf('victim')], 'in_triage', result.stderr);
};
const refuses = (result, message) => {
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, message);
  assert.deepEqual(result.verdicts, {}, 'no VEX is written');
};

// ---------- routes by which a package counts as shipped ----------

test('--bundle with --modules: a package only the module map names ships', (testContext) => {
  const root = app(testContext, {}, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/victim/index.js'] });
  write(root, { 'bundle.json': { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ type: 'library', name: 'clsx', version: '2.1.1', purl: 'pkg:npm/clsx@2.1.1' }] } });

  const result = run(root, ['--bundle', 'bundle.json', '--modules', 'meta.json']);

  shipsVictim(result);
  assert.match(result.stderr, /in the module map and not in the bundle SBOM/);
});

test('a package a recorded output loads by name when it runs ships', (testContext) => {
  const root = app(testContext, { 'dist/app.js': 'import "victim";\n(()=>{function clsx(){}clsx()})();\n' });

  const result = run(root, ['--modules', 'meta.json']);

  shipsVictim(result);
  assert.match(result.stderr, /loads 1 package\(s\) by name when it runs/);
});

test('a package an unrecorded output file loads by name ships', (testContext) => {
  const root = app(testContext, { 'dist/loader.js': 'import "victim";\n' });

  shipsVictim(run(root, ['--modules', 'meta.json']));
});

test("a file webpack says it copied from a package counts for that package", (testContext) => {
  const root = project(testContext, {
    'node_modules/victim/package.json': pkg('victim'), 'node_modules/victim/dist/v.js': 'function victim(a){return a}\n',
    'node_modules/clsx/package.json': pkg('clsx', '2.1.1'), 'node_modules/clsx/index.js': 'module.exports=1;\n',
    'src/a.js': 'x', 'dist/main.js': 'console.log(1);\n', 'dist/vendor/v.js': 'function v(a){return a}\n',
  });
  lockfile(root, [['victim', '1.0.0'], ['clsx', '2.1.1']]);
  const size = (filePath) => statSync(join(root, filePath)).size;
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

test('compiled code copied into the output (.wasm, .node) counts for the package it came from', (testContext) => {
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 7]);
  const root = app(testContext, { 'node_modules/victim/v.wasm': wasm, 'dist/assets/v-1a2b.wasm': wasm });

  shipsVictim(run(root, ['--modules', 'meta.json']));
});

test('--deploy --browser-only: a package the browser code loads by name ships, though nothing supplies it', (testContext) => {
  const root = project(testContext, {
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

test('the content check keeps a package open when its own strings are in what ships', (testContext) => {
  const sentence = 'victim expected the input value to be a string';
  const root = app(testContext, {
    'node_modules/victim/index.js': `module.exports = function victim(v){ if (typeof v !== "string") throw new TypeError("${sentence}"); };\n`,
    // the module map does not list victim, but its message is in the bundle
    'dist/app.js': `(()=>{function clsx(){}clsx();throw new TypeError("${sentence}")})();\n`,
  });

  const result = run(root, ['--modules', 'meta.json']);

  shipsVictim(result);
  assert.match(result.stderr, /victim is not in the build's records, but 1 string/);
});

// ---------- refusals ----------

test('refused: a --deploy folder that does not exist', (testContext) => {
  const root = app(testContext);

  refuses(run(root, ['--deploy', 'nowhere']), /no such folder/);
});

test("refused: a framework's server half without its browser half", (testContext) => {
  const root = app(testContext, { '.output/server/index.mjs': 'export default 1;\n', '.output/public/app.js': 'console.log(1);\n' });

  refuses(run(root, ['--deploy', '.output/server']), /server half of this build but not the browser half: \.output\/public/);
});

test('refused: deployed code with no source map', (testContext) => {
  const root = app(testContext, { 'out/app.js': 'function victimish(a){return a*2} console.log(victimish(1));\n' });

  refuses(run(root, ['--deploy', 'out']), /have no source map/);
});

test("refused: a source map naming package code that can't be traced to an installed package", (testContext) => {
  const root = app(testContext, {
    'out/app.js': 'function g(a){return a} console.log(g(1));\n//# sourceMappingURL=app.js.map',
    'out/app.js.map': { version: 3, sources: ['webpack://app/./node_modules/.cache/ghost/index.js'], names: [], mappings: '' },
  });

  refuses(run(root, ['--deploy', 'out']), /can't be traced to an installed package/);
});

test('refused: deployed code that loads a file from outside the deployment', (testContext) => {
  const root = app(testContext, {
    'generated/client.js': 'module.exports = require("victim");\n',
    'out/server.js': 'const c = require("../generated/client.js"); console.log(c);\n//# sourceMappingURL=server.js.map',
    'out/server.js.map': { version: 3, sources: ['../src/main.js'], names: [], mappings: '' },
  });

  refuses(run(root, ['--deploy', 'out']), /loads 1 file\(s\) from outside the deployment folders \(e\.g\. generated\/client\.js/);
});

test("refused: a shipped folder that has no readable package.json and a name the lockfile doesn't have", (testContext) => {
  const root = app(testContext, { 'node_modules/tiny/index.js': 'module.exports = 1;\n' }, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/tiny/index.js'] });

  refuses(run(root, ['--modules', 'meta.json']), /can't be read here and the lockfile SBOM has no package of that name/);
});

test("refused: code from Vite's prebundled dependencies (node_modules/.vite)", (testContext) => {
  const root = app(testContext, { 'node_modules/.vite/deps/react.js': 'export default 1;\n' }, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/.vite/deps/react.js'] });

  refuses(run(root, ['--modules', 'meta.json']), /where Vite keeps dependencies it bundled ahead of time/);
});

test('refused: a browser module map for an app with a server build the plugin skipped', (testContext) => {
  const root = app(testContext);
  write(root, { 'vexproof-modules.json': { vexproof: 1, bundler: 'vite 7.0.0 (rollup 4.0.0)', inputs: {}, outDirs: ['dist'], serverBuildsSkipped: 1,
    outputs: { 'dist/app.js': { inputs: { 'src/main.js': { bytesInOutput: 10 }, 'node_modules/clsx/index.js': { bytesInOutput: 10 } } } } } });

  refuses(run(root, ['--modules', 'vexproof-modules.json']), /also runs JavaScript on a server \(the build includes a server \(SSR\) build\)/);
  // --browser-only says the VEX is for the browser bundle alone
  assert.equal(run(root, ['--modules', 'vexproof-modules.json', '--browser-only']).status, 0);
});

test('refused: a browser module map for an app whose own dependencies include a server framework', (testContext) => {
  const root = app(testContext, { 'package.json': { name: 'app', version: '1.0.0', dependencies: { express: '^4.0.0', clsx: '^2.0.0' } } },
    { pkgs: [['victim', '1.0.0'], ['clsx', '2.1.1'], ['express', '4.21.0']] });

  refuses(run(root, ['--modules', 'meta.json']), /express is a dependency of this package/);
});

// ---------- Pro decisions ----------

test('Pro: a derived rule only suggests a verdict until --accept-derived', (testContext) => {
  const pro = proCopy(testContext);
  const root = app(testContext, { 'node_modules/victim/lib/other.js': 'x' }, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/victim/index.js'] });
  write(root, { 'rules.json': { schema: 1, origin: 'derived', packages: { victim: { advisories: {
    [`${idOf('victim')}@1.0.0`]: { id: idOf('victim'), versions: ['1.0.0'], files: ['lib/parse.js'], affects: 'parse bug', origin: 'derived', derivedFrom: { installed: '1.0.0', fixed: '1.0.1' } },
  } } } } });
  const base = ['--lockfile', 'bom.json', '--findings', 'findings.json', '--modules', 'meta.json', '--rules', 'rules.json', '--quiet'];

  let result = pro.run([...base, '--out', 'a.json'], { cwd: root });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, new RegExp(`in_triage\\s+${idOf('victim')}.*derived rule suggests not affected`));

  result = pro.run([...base, '--out', 'b.json', '--accept-derived'], { cwd: root });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, new RegExp(`not_affected \\(module\\)\\s+${idOf('victim')}`));
});

test('Pro: --baseline carries forward, and --fail-on new trips only on new open findings', (testContext) => {
  const pro = proCopy(testContext);
  const root = app(testContext, {}, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/victim/index.js'] });
  const base = ['--lockfile', 'bom.json', '--modules', 'meta.json', '--quiet'];
  write(root, { 'one.json': [{ purl: 'pkg:npm/victim@1.0.0', ids: ['GHSA-base-0001'] }] });

  assert.equal(pro.run([...base, '--findings', 'one.json', '--out', 'v1.json'], { cwd: root }).status, 0);

  // nothing new against itself
  let result = pro.run([...base, '--findings', 'one.json', '--out', 'v2.json', '--baseline', 'v1.json', '--fail-on', 'new'], { cwd: root });

  assert.equal(result.status, 0, result.stderr);

  // a second advisory on a shipped package is new and open
  write(root, { 'two.json': [{ purl: 'pkg:npm/victim@1.0.0', ids: ['GHSA-base-0001', 'GHSA-base-0002'] }] });

  result = pro.run([...base, '--findings', 'two.json', '--out', 'v3.json', '--baseline', 'v1.json', '--fail-on', 'new'], { cwd: root });

  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /gate failed — 1 new open finding\(s\): GHSA-base-0002/);
});

test('Pro: a finding reviewed exploitable trips both gates, however long it has been known', (testContext) => {
  const pro = proCopy(testContext);
  const root = app(testContext, {}, { inputs: ['src/main.js', 'node_modules/clsx/index.js', 'node_modules/victim/index.js'] });
  const base = ['--lockfile', 'bom.json', '--modules', 'meta.json', '--quiet'];
  write(root, { 'one.json': [{ purl: 'pkg:npm/victim@1.0.0', ids: ['GHSA-base-0001'] }] });
  assert.equal(pro.run([...base, '--findings', 'one.json', '--out', 'v1.json'], { cwd: root }).status, 0);

  const review = pro.run([
    'review', '--vex', 'v1.json', '--id', 'GHSA-base-0001', '--state', 'exploitable',
    '--detail', 'reachable from the upload form', '--by', 'Jane Doe',
  ], { cwd: root });
  assert.equal(review.status, 0, review.stderr);

  for (const gate of ['new', 'in_triage']) {
    const result = pro.run([...base, '--findings', 'one.json', '--out', `v2-${gate}.json`, '--baseline', 'v1.json', '--fail-on', gate], { cwd: root });

    assert.equal(result.status, 1, `${gate}: ${result.stderr}`);
    assert.match(result.stderr, /gate failed — 1 exploitable finding\(s\): GHSA-base-0001/, gate);
  }

  // with a new open finding beside it, the message counts both
  write(root, { 'two.json': [{ purl: 'pkg:npm/victim@1.0.0', ids: ['GHSA-base-0001', 'GHSA-base-0002'] }] });
  const both = pro.run([...base, '--findings', 'two.json', '--out', 'v3.json', '--baseline', 'v1.json', '--fail-on', 'new'], { cwd: root });

  assert.equal(both.status, 1, both.stderr);
  assert.match(both.stderr, /gate failed — 1 new open and 1 exploitable finding\(s\): GHSA-base-000[12], GHSA-base-000[12]/);
});

test('each module map is an input of its own in the VEX: module-map, module-map-2, as the contract names them', (testContext) => {
  const root = app(testContext);
  write(root, { 'meta2.json': JSON.parse(readFileSync(join(root, 'meta.json'), 'utf8')) });

  const result = run(root, ['--modules', 'meta.json', '--modules', 'meta2.json']);

  assert.equal(result.status, 0, result.stderr);

  const vex = JSON.parse(readFileSync(join(root, 'vex.json'), 'utf8'));
  const roles = vex.metadata.properties.map((property) => property.name).filter((name) => name.startsWith('vexproof:input:module-map'));

  assert.deepEqual(roles, ['vexproof:input:module-map:sha256', 'vexproof:input:module-map-2:sha256']);
});

// ---------- one build's output inside another's (found on authentik: esbuild into dist, Rollup into dist/sfe) ----------

const SECOND_BUNDLE = '(()=>{function victim(value){return String(value).trim()}victim(" x ")})();\n';

/**
 * The app, plus a second bundle that a build of its own wrote inside the first build's output folder. Only the
 * second bundle holds `victim`. `secondMap` is that build's esbuild metafile, written as second.meta.json.
 */
function twoBuilds(testContext, { files = {}, secondMap = {} } = {}) {
  const root = app(testContext, {
    'src/second.js': 'import victim from "victim"; victim();\n',
    'dist/sub/second.js': SECOND_BUNDLE,
    ...files,
  });
  const inputs = { 'src/second.js': { bytesInOutput: 10 }, 'node_modules/victim/index.js': { bytesInOutput: 10 } };
  write(root, { 'second.meta.json': {
    inputs: { 'src/second.js': { bytes: 10, imports: [] }, 'node_modules/victim/index.js': { bytes: 10, imports: [] } },
    outputs: { 'dist/sub/second.js': { bytes: Buffer.byteLength(SECOND_BUNDLE), inputs, imports: [] } },
    ...secondMap,
  } });

  return root;
}

test('a second build inside the first one\'s output folder is accounted for by its own module map', (testContext) => {
  const root = twoBuilds(testContext);

  // the first map alone: the second bundle is a file nothing accounts for, and the refusal names the way out
  refuses(run(root, ['--modules', 'meta.json']), /dist\/sub\/second\.js[^]*pass that map too: --modules, once for each map/);

  // with both maps the run goes through, in either order, and the package only the second bundle holds ships
  shipsVictim(run(root, ['--modules', 'meta.json', '--modules', 'second.meta.json']));
  shipsVictim(run(root, ['--modules', 'second.meta.json', '--modules', 'meta.json']));
});

test('refused: the second map does not record the file, or records another size for it', (testContext) => {
  // a map that records some other file in that folder says nothing about second.js
  const other = '(()=>{function other(value){return String(value).length}other("x")})();\n';
  const elsewhere = twoBuilds(testContext, {
    files: { 'dist/sub/other.js': other },
    secondMap: { outputs: { 'dist/sub/other.js': { bytes: Buffer.byteLength(other), inputs: { 'src/second.js': { bytesInOutput: 10 } }, imports: [] } } },
  });

  refuses(run(elsewhere, ['--modules', 'meta.json', '--modules', 'second.meta.json']), /dist\/sub\/second\.js: no bundler recorded it/);

  // a map that records the file at another size describes another build's file: its own check stops the run
  const stale = twoBuilds(testContext, {
    secondMap: { outputs: { 'dist/sub/second.js': { bytes: 5, inputs: { 'node_modules/victim/index.js': { bytesInOutput: 5 } }, imports: [] } } },
  });

  refuses(run(stale, ['--modules', 'meta.json', '--modules', 'second.meta.json']), /second\.meta\.json: [^]*not the ones this module map describes/);
});

test('a plugin map from a build in another folder: refused with what to set, and read once it names files from here', (testContext) => {
  const bytes = Buffer.byteLength(SECOND_BUNDLE);
  const pluginMap = (outDir, prefix) => ({
    vexproof: 1,
    bundler: 'rollup 4.62.2',
    inputs: {},
    outDirs: [outDir],
    outputs: { [`${outDir}/second.js`]: { bytes, inputs: { [`${prefix}node_modules/victim/index.js`]: { bytesInOutput: 10 }, [`${prefix}packages/second/src/index.js`]: { bytesInOutput: 10 } } } },
  });
  const root = twoBuilds(testContext, {
    files: {
      'packages/second/src/index.js': 'import victim from "victim"; victim();\n',
      // as the plugin writes it when the second build runs in packages/second: paths from that folder
      'packages/second/vexproof-modules.json': pluginMap('../../dist/sub', '../../'),
      // and with the plugin's root option set to the app's folder: paths from here
      'second.modules.json': pluginMap('dist/sub', ''),
    },
  });

  const misplaced = run(root, ['--modules', 'meta.json', '--modules', 'packages/second/vexproof-modules.json']);
  refuses(misplaced, /records build output in "\.\.\/\.\.\/dist\/sub"[^]*With several --modules files, each must name its files from the folder vexproof runs in[^]*vexproof\(\{ root:/);

  // alone, the same map gets the plain advice: there is no other build to line it up with
  const alone = run(root, ['--modules', 'packages/second/vexproof-modules.json']);
  refuses(alone, /records build output in "\.\.\/\.\.\/dist\/sub"/);
  assert.doesNotMatch(alone.stderr, /With several --modules files/);

  shipsVictim(run(root, ['--modules', 'meta.json', '--modules', 'second.modules.json']));
});
