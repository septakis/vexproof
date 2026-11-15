// SPDX-License-Identifier: MIT
// Deployment folders as evidence: files copied into the deployment, plus the source maps of bundled code.
// Each case builds a small deployment on disk; the rules were found on real Next.js 16 and Nuxt 4 builds.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, symlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  readDeployment, mergeModuleMaps, loadedSpecifiers, runtimeImports, usesNodeBuiltins, isGlue, defaultMapDirs, installBases,
} from '../src/deploy.js';
import { readModuleMap } from '../src/modules.js';
import { triage } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { temporaryFolder, temporaryFolderForFile } from './lib/temporary.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const put = (root, files) => {
  for (const [filePath, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, filePath)), { recursive: true });
    writeFileSync(join(root, filePath), content);
  }
};
const sourceMap = (sources) => JSON.stringify({ version: 3, sources, mappings: '' });

function app(extra = {}) {
  const root = temporaryFolderForFile('vxp-deploy-');
  put(root, {
    'package-lock.json': '{}', // a project of its own, whatever lies above the temp folder
    // installed packages
    'node_modules/lodash/package.json': '{"name":"lodash","version":"4.17.21"}',
    'node_modules/lodash/debounce.js': 'module.exports = function debounce() {};',
    'node_modules/lodash/template.js': 'module.exports = function template() {};',
    'node_modules/marked/package.json': '{"name":"marked","version":"4.0.9"}',
    'node_modules/marked/lib/marked.cjs': 'exports.parse = function () {};',
    // the deployment: a server chunk bundling lodash/debounce, the server's own node_modules with marked
    'out/server/chunks/page.js': 'const m = require("marked"); function page() {}\n//# sourceMappingURL=page.js.map',
    'out/server/chunks/page.js.map': sourceMap(['../../../node_modules/lodash/debounce.js', '../../../src/page.js']),
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
  const root = app();

  const deployment = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked']) });

  assert.deepEqual([...deployment.packages.get('lodash').files], ['debounce.js']);
  assert.deepEqual([...deployment.packages.get('marked').roots], ['out/server/node_modules/marked']);
  assert.equal(deployment.hasServer, true);
  assert.deepEqual([deployment.unmapped, deployment.missingRuntime, deployment.unattributed], [[], [], []]);
});

test('a bundled file with no source map is refused unless it is glue or an exact copy of an installed file', () => {
  const root = app({
    'out/server/chunks/vendor.js': 'function a(){ return 1 } function b(){ return 2 }',
    'out/server/chunks/polyfill.js': 'module.exports = function template() {};',
  });

  const deployment = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked']) });

  assert.deepEqual(deployment.unmapped, ['out/server/chunks/vendor.js']); // manifest.js is glue; polyfill.js is lodash/template.js
  assert.ok(deployment.packages.get('lodash').files.has('template.js'));

  assert.ok(isGlue("const p = require('path'); startServer({ dir }).catch((err) => { process.exit(1) })"));
  assert.ok(!isGlue('function x(){ return 1 }'));
  assert.ok(isGlue('function x(){}')); // a function with nothing in it does nothing
});

test('runtime loads of lockfile packages must be satisfied inside the deployment; comments and strings do not count', () => {
  const root = app({
    'out/server/chunks/api.js': '/* import x from "js-yaml" */ const s = "require(\'axios\')"; const y = require("js-yaml"); function f(){}\n//# sourceMappingURL=api.js.map',
    'out/server/chunks/api.js.map': sourceMap([]),
  });

  const deployment = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked', 'js-yaml', 'axios']) });

  assert.deepEqual(deployment.missingRuntime.map((missing) => missing.name), ['js-yaml']);

  const specifiers = loadedSpecifiers('import a from "a"; export * from "b"; import("c"); require("d/sub"); // import "e"\nconst t = "import f from \'f\'"');

  assert.deepEqual([...runtimeImports(specifiers)].sort(), ['a', 'b', 'c', 'd']);
  assert.ok(usesNodeBuiltins(loadedSpecifiers('require("node:fs")')) && !usesNodeBuiltins(loadedSpecifiers('import "react"')));
});

test('externals linked under hashed names resolve to the real package, and must land inside the deployment', (testContext) => {
  const hashedExternal = {
    'out/server/chunks/ext.js': 'module.exports = require("marked-77b6df11dc860fde"); function f(){}\n//# sourceMappingURL=ext.js.map',
    'out/server/chunks/ext.js.map': sourceMap([]),
  };
  const root = app(hashedExternal);
  mkdirSync(join(root, 'out/server/.next/node_modules'), { recursive: true });
  try {
    symlinkSync('../../node_modules/marked', join(root, 'out/server/.next/node_modules/marked-77b6df11dc860fde'));
  } catch (error) {
    if (error.code === 'EPERM') {
      return testContext.skip('this account cannot create symlinks; Next.js writes real ones, so Windows needs Developer Mode'); // eslint-disable-line consistent-return
    }
    throw error;
  }

  const inside = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked']) });

  assert.deepEqual(inside.missingRuntime, []);

  // the same link pointing outside the deployment
  const outsideRoot = app(hashedExternal);
  mkdirSync(join(outsideRoot, 'out/server/.next/node_modules'), { recursive: true });
  symlinkSync(join(outsideRoot, 'node_modules/marked'), join(outsideRoot, 'out/server/.next/node_modules/marked-77b6df11dc860fde'));

  const outside = readDeployment(['out'], { root: outsideRoot, lockNames: lock(['lodash', 'marked']) });

  assert.deepEqual(outside.missingRuntime.map((missing) => missing.name), ['marked']);
});

test('sources reached through a package\'s own source maps are traced back to it, and the package is taken whole', () => {
  const root = app({
    'node_modules/fast-equals/package.json': '{"name":"fast-equals","version":"5.2.2"}',
    'node_modules/fast-equals/dist/es/index.mjs': 'export function equals(){}\n//# sourceMappingURL=index.mjs.map',
    'node_modules/fast-equals/dist/es/index.mjs.map': sourceMap(['../../../src/comparator.ts']), // resolves to node_modules/src/comparator.ts
    'out/app.js': 'function a(){}\n//# sourceMappingURL=app.js.map',
    'out/app.js.map': sourceMap(['../node_modules/src/comparator.ts', '../node_modules/ghost/src/x.ts']),
  });

  const deployment = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked', 'fast-equals']) });

  assert.ok(deployment.packages.has('fast-equals') && deployment.whole.has('fast-equals'));
  assert.ok(!deployment.packages.has('src'));
  assert.deepEqual(deployment.unattributed, ['node_modules/ghost/src/x.ts (in out/app.js)']);
});

// The next four were found on ZITADEL's login app: Next.js 16 with Turbopack, in a pnpm workspace.
test('a Next.js client-reference proxy counts as the file it stands for', () => {
  const root = app({
    'out/server/chunks/ssr.js': 'function a(){}\n//# sourceMappingURL=ssr.js.map',
    'out/server/chunks/ssr.js.map': sourceMap([
      'turbopack:///[project]/node_modules/lodash/debounce.js/__nextjs-internal-proxy.cjs { server => "[project]/node_modules/lodash/debounce.js" }',
      'turbopack:///[project]/node_modules/marked/lib/marked.cjs/__nextjs-internal-proxy.mjs',
    ]),
  });

  const deployment = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked']) });

  assert.deepEqual(deployment.unattributed, []);
  assert.deepEqual([...deployment.packages.get('lodash').files], ['debounce.js']);
  assert.ok(deployment.packages.get('marked').roots.has('node_modules/marked'));
  assert.ok(!deployment.whole.has('lodash') && !deployment.whole.has('marked'));
});

test('a source that a package\'s own map names under an unpublished node_modules folder is traced back to it', () => {
  const root = app({
    'node_modules/@formatjs/icu-skeleton-parser/package.json': '{"name":"@formatjs/icu-skeleton-parser","version":"2.1.11"}',
    'node_modules/@formatjs/icu-skeleton-parser/index.js': 'export function parse(){}\n//# sourceMappingURL=index.js.map',
    // the package's build tool kept generated files here; the folder was never published
    'node_modules/@formatjs/icu-skeleton-parser/index.js.map': sourceMap(['../../.aspect_rules_js/gen@0.0.0/node_modules/gen/regex.js']),
    'out/app.js': 'function a(){}\n//# sourceMappingURL=app.js.map',
    'out/app.js.map': sourceMap(['turbopack:///[project]/node_modules/.aspect_rules_js/gen@0.0.0/node_modules/gen/regex.js']),
  });

  const deployment = readDeployment(['out'], { root, lockNames: lock(['lodash', 'marked', '@formatjs/icu-skeleton-parser']) });

  assert.deepEqual(deployment.unattributed, []);
  assert.ok(deployment.whole.has('@formatjs/icu-skeleton-parser'));
  assert.ok(!deployment.packages.has('gen'));
});

test('server source maps are looked for in the .next that each deployment folder sits in', () => {
  const root = app({ 'apps/web/.next/standalone/server.js': '', 'apps/web/.next/static/a.js': '' });

  assert.deepEqual(defaultMapDirs(['apps/web/.next/standalone', 'apps\\web\\.next\\static', 'out'], root), ['apps/web/.next']);

  put(root, { '.next/BUILD_ID': 'x' });

  assert.deepEqual(defaultMapDirs(['.next/standalone'], root), ['.next']);
  assert.deepEqual(defaultMapDirs(['out'], app()), []);
});

test('an app inside a workspace finds its packages in the workspace\'s node_modules', (testContext) => {
  const workspace = temporaryFolder(testContext, 'vxp-ws-');
  const next = 'node_modules/.pnpm/next@16.0.0/node_modules/next';
  put(workspace, {
    'pnpm-lock.yaml': '',
    [`${next}/package.json`]: '{"name":"next","version":"16.0.0"}',
    [`${next}/dist/polyfill.js`]: 'function polyfill(){} function more(){}',
    [`${next}/dist/server.js`]: 'function serve(){}',
    'apps/web/package.json': '{"name":"web"}',
    // Turbopack writes sources against the workspace root, where the app's own node_modules holds only links
    'apps/web/out/chunks/page.js': 'function page(){}\n//# sourceMappingURL=page.js.map',
    'apps/web/out/chunks/page.js.map': sourceMap([`turbopack:///[project]/${next}/dist/server.js`, `turbopack:///[project]/${next}/src/gone.ts`]),
    'apps/web/out/chunks/polyfill.js': 'function polyfill(){} function more(){}', // no map: a copy of an installed file
  });
  const root = join(workspace, 'apps/web');

  assert.deepEqual(installBases(root), [root, join(workspace, 'apps'), workspace]);
  assert.deepEqual(installBases(workspace), [workspace]); // the folder with the lockfile stands alone

  const deployment = readDeployment(['out'], { root, lockNames: lock(['next']) });

  assert.deepEqual([deployment.unmapped, deployment.unattributed], [[], []]);
  assert.deepEqual([...deployment.packages.get('next').roots], [`../../${next}`]);
  assert.deepEqual([...deployment.packages.get('next').files].sort(), ['dist/polyfill.js', 'dist/server.js', 'src/gone.ts']);
});

test('a whole package gets no file-level claims', () => {
  const deployment = readDeployment(['out'], { root: app(), lockNames: lock(['lodash', 'marked']) });
  deployment.whole.add('lodash');
  const findings = [{ purl: 'pkg:npm/lodash@4.17.21', ids: ['GHSA-r5fr-rjxr-66jc'] }];
  const sbom = { components: [{ purl: 'pkg:npm/lodash@4.17.21' }] };

  const [result] = triage({
    lockfileSbom: sbom, bundleSbom: sbom, findings, moduleMap: deployment, rules, moduleCheck: evaluateModuleRule, pro: true,
  });

  assert.equal(result.state, 'in_triage');
  assert.match(result.moduleReason, /its own source maps name its original sources/);
});

test('several module maps merge; the import graph survives only if every map has one', () => {
  const withGraph = readModuleMap({
    inputs: { 'src/a.js': { imports: [{ path: 'node_modules/x/i.js' }] } },
    outputs: { 'o.js': { inputs: { 'src/a.js': { bytesInOutput: 1 }, 'node_modules/x/i.js': { bytesInOutput: 1 } } } },
  });
  const withoutGraph = readModuleMap({ inputs: {}, outputs: { 'p.js': { inputs: { 'node_modules/y/j.js': { bytesInOutput: 1 } } } } });

  const merged = mergeModuleMaps([withGraph, withoutGraph]);

  assert.deepEqual([...merged.packages.keys()].sort(), ['x', 'y']);
  assert.equal(merged.graph, null);
  assert.ok(mergeModuleMaps([withGraph, withGraph]).graph);
});

test('CLI: a whole-app deployment satisfies the server check; a browser-only folder does not', () => {
  const root = app({
    'out/static/app.js': 'function a(){}\n//# sourceMappingURL=app.js.map',
    'out/static/app.js.map': sourceMap(['../../node_modules/lodash/debounce.js']),
  });
  const sbom = {
    serialNumber: 'urn:uuid:11111111-2222-3333-4444-555555555555',
    version: 1,
    components: ['next@16.0.0', 'lodash@4.17.21', 'marked@4.0.9']
      .map((component) => ({ purl: `pkg:npm/${component}`, 'bom-ref': component })),
  };
  writeFileSync(join(root, 'bom.json'), JSON.stringify(sbom));
  writeFileSync(join(root, 'findings.json'), JSON.stringify([{ purl: 'pkg:npm/marked@4.0.9', ids: ['GHSA-rrrm-qjm4-v8hf'] }]));
  const run = (...args) => spawnSync(
    process.execPath,
    [CLI, '--lockfile', 'bom.json', '--findings', 'findings.json', '--out', 'vex.json', '--quiet', ...args],
    { cwd: root, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '' } }, // free, whatever this machine holds
  );

  const browser = run('--deploy', 'out/static');

  assert.equal(browser.status, 2);
  assert.match(browser.stderr, /also runs JavaScript on a server/);

  const whole = run('--deploy', 'out/server', '--deploy', 'out/static');

  assert.equal(whole.status, 0, whole.stderr);
  assert.match(whole.stdout, /in_triage\s+GHSA-rrrm-qjm4-v8hf/); // marked is deployed on the server
});

test('CLI: a package absent from a deployment is said to be absent from the deployment, not from a bundle SBOM', () => {
  const root = app();
  const sbom = {
    serialNumber: 'urn:uuid:11111111-2222-3333-4444-555555555555',
    version: 1,
    components: ['lodash@4.17.21', 'marked@4.0.9', 'left-pad@1.3.0'].map((component) => ({ purl: `pkg:npm/${component}`, 'bom-ref': component })),
  };
  writeFileSync(join(root, 'bom.json'), JSON.stringify(sbom));
  writeFileSync(join(root, 'findings.json'), JSON.stringify([{ purl: 'pkg:npm/left-pad@1.3.0', ids: ['GHSA-left-0001'] }]));

  const result = spawnSync(
    process.execPath,
    [CLI, '--lockfile', 'bom.json', '--findings', 'findings.json', '--out', 'vex.json', '--quiet', '--deploy', 'out/server'],
    { cwd: root, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '' } },
  );

  assert.equal(result.status, 0, result.stderr);
  const vex = JSON.parse(readFileSync(join(root, 'vex.json'), 'utf8'));
  const statement = vex.vulnerabilities.find((vulnerability) => vulnerability.id === 'GHSA-left-0001');
  assert.equal(statement.analysis.state, 'not_affected');
  assert.match(statement.analysis.detail, /^left-pad@1\.3\.0 is in the lockfile SBOM, but the deployment holds no file of left-pad, and its source maps name none\./);
  assert.ok(!vex.metadata.properties.some((property) => property.name === 'vexproof:bundleSbomSerial'));
});

test('CLI: the VEX records a deployment digest that covers the source maps read from a --maps folder', () => {
  const root = app({
    'out/static/app.js': 'function a(){}\n//# sourceMappingURL=app.js.map',
    'maps/app.js.map': sourceMap(['../node_modules/lodash/debounce.js']),
  });
  const sbom = {
    serialNumber: 'urn:uuid:11111111-2222-3333-4444-555555555555',
    version: 1,
    components: ['lodash@4.17.21', 'marked@4.0.9'].map((component) => ({ purl: `pkg:npm/${component}`, 'bom-ref': component })),
  };
  writeFileSync(join(root, 'bom.json'), JSON.stringify(sbom));
  writeFileSync(join(root, 'findings.json'), JSON.stringify([{ purl: 'pkg:npm/marked@4.0.9', ids: ['GHSA-rrrm-qjm4-v8hf'] }]));
  const deploymentDigest = () => {
    const result = spawnSync(
      process.execPath,
      [CLI, '--lockfile', 'bom.json', '--findings', 'findings.json', '--out', 'vex.json', '--quiet',
        '--deploy', 'out/server', '--deploy', 'out/static', '--maps', 'maps'],
      { cwd: root, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '' } },
    );
    assert.equal(result.status, 0, result.stderr);
    const vex = JSON.parse(readFileSync(join(root, 'vex.json'), 'utf8'));

    return vex.metadata.properties.find((property) => property.name === 'vexproof:input:deployment:sha256').value;
  };

  const before = deploymentDigest();
  writeFileSync(join(root, 'maps/app.js.map'), sourceMap(['../node_modules/lodash/template.js']));

  assert.notEqual(deploymentDigest(), before);
});
