// SPDX-License-Identifier: MIT
// The hand-checked vite rules: Vite writes helpers into a production build (module preload, dynamic import,
// WebAssembly loading), and its dev-server advisories are settled only when nothing of Vite but those helpers
// is in the bundle.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mergeRules, validateRules, evaluateModuleRule } from '../src/pro/module-check.js';
import { triage } from '../src/index.js';
import { readModuleMap, bundleSbomFromModules, attachVersions, ruleFilesShipped } from '../src/modules.js';
import { attachFingerprints } from '../src/evidence.js';

const shipped = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const viteRules = shipped.packages.vite;

// the DOM clobbering advisory is about code Vite writes into cjs/iife/umd output: it must never get a rule
const GENERATED_OUTPUT_ADVISORY = 'GHSA-64vr-g452-qvp3';

/** A Vite plugin map whose one output holds the app's code plus the given inputs. */
const viteMap = (inputs) => readModuleMap({
  vexproof: 1,
  bundler: 'vite 5.4.21',
  inputs: {},
  outputs: {
    'build/assets/index.js': {
      inputs: {
        'src/main.js': { bytesInOutput: 900 },
        ...Object.fromEntries(inputs.map((input) => [input, { bytesInOutput: 300 }])),
      },
    },
  },
});

const HELPERS_ONLY = ['vite/preload-helper.js', 'vite/dynamic-import-helper.js'];

const check = (moduleMap, id, { rules = shipped, version = '5.4.19' } = {}) => evaluateModuleRule({
  key: 'npm/vite',
  parsed: { type: 'npm', name: 'vite', version },
  id,
  bundleVersions: new Set([version]),
  moduleMap: attachVersions(moduleMap, { cwd: '/nonexistent' }),
  rules,
});

test('the vite rules are well formed: dev and preview server advisories only, each with its source', () => {
  validateRules(shipped);

  const ids = Object.keys(viteRules.advisories);
  assert.equal(ids.length, 22);
  assert.ok(!ids.includes(GENERATED_OUTPUT_ADVISORY));
  assert.deepEqual(viteRules.injected, ['preload-helper.js', 'dynamic-import-helper.js', 'modulepreload-polyfill.js', 'wasm-helper.js']);

  for (const [id, rule] of Object.entries(viteRules.advisories)) {
    assert.deepEqual(rule.files, ['dist/node/'], id);
    assert.equal(rule.source, `https://github.com/advisories/${id}`, id);
    assert.match(rule.affects, /dev server|dev and preview servers|launch-editor/, id);
    assert.ok(rule.aliases.length >= 1 && rule.aliases.every((alias) => /^CVE-\d{4}-\d+$/.test(alias)), id);
    assert.equal(rule.versions, undefined, `${id}: the reasoning holds for every version`);
  }
});

test('a bundle with only the helpers Vite writes into it settles every dev-server advisory at module level', () => {
  const moduleMap = viteMap(HELPERS_ONLY);

  for (const id of Object.keys(viteRules.advisories)) {
    const result = check(moduleMap, id);

    assert.equal(result.ok, true, `${id}: ${result.reason}`);
    assert.match(result.detail, /is in the bundle only as the helper code it writes into a build: dynamic-import-helper\.js, preload-helper\.js/, id);
    assert.match(result.detail, /lives in dist\/node\/; nothing from there is in the shipped output\.$/, id);
    assert.deepEqual(result.evidence.survivingFiles, ['dynamic-import-helper.js', 'preload-helper.js'], id);
  }
});

test('any other file of vite in the bundle keeps every vite advisory open', () => {
  const others = [
    'node_modules/vite/dist/client/env.mjs',
    'node_modules/vite/dist/node/chunks/dep-BK3b2jBa.js',
    'node_modules/vite/package.json',
    'node_modules/vite/misc/true.js',
  ];

  for (const other of others) {
    const result = check(viteMap([...HELPERS_ONLY, other]), 'GHSA-vg6x-rcgg-rjx6');

    assert.equal(result.ok, false, other);
    assert.match(result.reason, /the bundle has more of vite than the helpers it writes into a build \(/, other);
  }
});

test('the advisory about code Vite generates into the output stays open, whatever a derived rule says', () => {
  const moduleMap = viteMap(HELPERS_ONLY);

  assert.match(check(moduleMap, GENERATED_OUTPUT_ADVISORY).reason, /no module rule for GHSA-64vr-g452-qvp3/);

  // rules derive would name the files its fix changed (in dist/node/), none of which ship: that proves nothing here
  const derived = validateRules({ origin: 'derived', packages: { vite: { advisories: {
    [`${GENERATED_OUTPUT_ADVISORY}@5.4.5`]: {
      id: GENERATED_OUTPUT_ADVISORY,
      versions: ['5.4.5'],
      files: ['dist/node/chunks/dep-abc.js'],
      affects: 'DOM Clobbering gadget found in vite bundled scripts that leads to XSS',
      derivedFrom: { installed: '5.4.5', fixed: '5.4.6' },
    },
  } } } });
  const result = check(moduleMap, GENERATED_OUTPUT_ADVISORY, { rules: mergeRules(shipped, derived), version: '5.4.5' });

  assert.equal(result.ok, false);
  assert.match(result.reason, /vite writes code into the build that no file list shows, so only hand-checked rules apply to it, and GHSA-64vr-g452-qvp3 has none/);
});

test('a rules file can narrow the helpers vite may ship with, never widen them', () => {
  const extra = validateRules({ packages: { vite: { injected: ['preload-helper.js', 'dev-server.js'], advisories: {} } } });
  const merged = mergeRules(shipped, extra);

  assert.deepEqual(merged.packages.vite.injected, ['preload-helper.js']);
  assert.equal(check(viteMap(['vite/preload-helper.js']), 'GHSA-vg6x-rcgg-rjx6', { rules: merged }).ok, true);

  // dev-server.js is not one of the helpers the hand-checked rules allow, dynamic-import-helper.js no longer is,
  // and a helper's name matches only as Vite spells it
  for (const input of ['vite/dev-server.js', 'vite/dynamic-import-helper.js', 'vite/Preload-Helper.js']) {
    const result = check(viteMap(['vite/preload-helper.js', input]), 'GHSA-vg6x-rcgg-rjx6', { rules: merged });

    assert.equal(result.ok, false, input);
  }

  assert.throws(() => validateRules({ packages: { vite: { injected: 'preload-helper.js', advisories: {} } } }), /vite\.injected must be a list/);
});

test('vite loaded at runtime by name (an external import) is shipped whole: no module-level claim', () => {
  const moduleMap = readModuleMap({
    inputs: { 'src/plugin.js': { imports: [{ path: 'vite', external: true }] } },
    outputs: { 'dist/plugin.js': { inputs: { 'src/plugin.js': { bytesInOutput: 400 }, 'vite/preload-helper.js': { bytesInOutput: 300 } } } },
  });

  const result = check(moduleMap, 'GHSA-vg6x-rcgg-rjx6');

  assert.equal(result.ok, false);
  assert.match(result.reason, /vite counts as shipped whole/);
});

test('through triage: Pro settles a dev-server advisory, the free tier keeps it open, the generated-output one stays open', () => {
  const purl = 'pkg:npm/vite@5.4.19';
  const lockfileSbom = { components: [{ 'bom-ref': purl, name: 'vite', version: '5.4.19', purl }] };
  const moduleMap = attachVersions(viteMap(HELPERS_ONLY), { cwd: '/nonexistent' });
  const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom, cwd: '/nonexistent' });
  const findings = [
    { purl, ids: ['GHSA-vg6x-rcgg-rjx6'] },
    { purl, ids: [GENERATED_OUTPUT_ADVISORY] },
  ];
  const stateOf = (results) => Object.fromEntries(results.map((result) => [result.id, `${result.state}/${result.level}`]));

  const pro = triage({ lockfileSbom, bundleSbom, findings, moduleMap, rules: shipped, moduleCheck: evaluateModuleRule, pro: true });

  assert.deepEqual(stateOf(pro), { 'GHSA-vg6x-rcgg-rjx6': 'not_affected/module', [GENERATED_OUTPUT_ADVISORY]: 'in_triage/null' });
  assert.equal(pro.find((result) => result.id === 'GHSA-vg6x-rcgg-rjx6').justification, 'code_not_present');

  const free = triage({ lockfileSbom, bundleSbom, findings, moduleMap });

  assert.deepEqual(stateOf(free), { 'GHSA-vg6x-rcgg-rjx6': 'in_triage/null', [GENERATED_OUTPUT_ADVISORY]: 'in_triage/null' });
});

test("a rule's folder entry covers every file under it, without regard to case", () => {
  assert.deepEqual(ruleFilesShipped(['dist/node/'], ['dist/node/chunks/dep.js', 'Dist/Node/index.js', 'dist/client/env.mjs']), ['dist/node/chunks/dep.js', 'Dist/Node/index.js']);
  assert.deepEqual(ruleFilesShipped(['template.js', 'omit.js'], ['Template.js', 'map.js']), ['template.js']);
  assert.deepEqual(ruleFilesShipped(['dist/node/'], ['dist/nodejs.js']), []);

  // in any package's rule, a shipped file under a folder entry keeps the finding open
  const rules = mergeRules(shipped, validateRules({ packages: { 'chart-kit': { advisories: {
    'GHSA-aaaa-bbbb-cccc': { files: ['lib/tooltip/'], affects: 'tooltip XSS' },
  } } } }));
  const chartKit = readModuleMap({ inputs: {}, outputs: { 'dist/a.js': { inputs: {
    'node_modules/chart-kit/lib/axis.js': { bytesInOutput: 9 },
    'node_modules/chart-kit/lib/tooltip/render.js': { bytesInOutput: 9 },
  } } } });
  const verdict = evaluateModuleRule({
    key: 'npm/chart-kit', parsed: { type: 'npm', name: 'chart-kit', version: '2.0.0' }, id: 'GHSA-aaaa-bbbb-cccc', bundleVersions: new Set(['2.0.0']), moduleMap: chartKit, rules,
  });

  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /are bundled: lib\/tooltip\/render\.js$/); // a --rules file counts as derived

  // an open vite finding's fingerprint names the shipped files the folder covers
  const purl = 'pkg:npm/vite@5.4.19';
  const moduleMap = attachVersions(viteMap([...HELPERS_ONLY, 'node_modules/vite/dist/node/chunks/dep-BK3b2jBa.js']), { cwd: '/nonexistent' });
  const results = [{ id: 'GHSA-vg6x-rcgg-rjx6', purl, state: 'in_triage' }];

  attachFingerprints(results, { moduleMap, rules: shipped, cwd: '/x', readFile: () => Buffer.from('code') });

  assert.deepEqual(results[0].fingerprint.vulnerableFiles, ['dist/node/chunks/dep-BK3b2jBa.js']);
});
