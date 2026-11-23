// SPDX-License-Identifier: MIT
// Advisories about what a build tool writes into the output (a bundler's runtime code, a compiler's output):
// the tool's own files say nothing about them, so no absence and no rule may settle one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { triage, applyRuleAliases, normalizeFindings, GENERATED_CODE } from '../src/index.js';
import { diffForRule } from '../src/derive.js';
import { temporaryFolder } from './lib/temporary.js';

const handRules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));

const component = (name, version) => ({ 'bom-ref': `pkg:npm/${name}@${version}`, name, version, purl: `pkg:npm/${name}@${version}` });
const stateOf = (results) => Object.fromEntries(results.map((result) => [result.id, `${result.state}/${result.level}`]));

// an app that ships lodash; its build tools are in the lockfile only
const lockfileSbom = { components: [
  component('lodash', '4.17.20'),
  component('rollup', '4.20.0'),
  component('@angular/compiler', '19.2.10'),
  component('@babel/helpers', '7.26.0'),
  component('svelte', '5.40.0'),
] };
const withoutTools = { components: [component('lodash', '4.17.20')] };

test('the list is well formed: each advisory names what is written and where it was read', () => {
  assert.equal(GENERATED_CODE.schema, 1);
  assert.match(GENERATED_CODE.version, /^\d{4}-\d{2}-\d{2}$/);

  for (const [packageName, entry] of Object.entries(GENERATED_CODE.packages)) {
    assert.ok(typeof entry.writes === 'string' && entry.writes, packageName);

    for (const [advisoryId, advisory] of Object.entries(entry.advisories)) {
      assert.match(advisoryId, /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/, `${packageName} ${advisoryId}`);
      assert.equal(advisory.source, `https://github.com/advisories/${advisoryId}`, advisoryId);
      assert.ok(typeof advisory.affects === 'string' && advisory.affects, advisoryId);
      assert.ok(advisory.aliases.every((alias) => /^(CVE-\d{4}-\d+|GHSA(-[a-z0-9]{4}){3})$/.test(alias)), advisoryId);
    }
  }

  for (const expected of ['vite', 'rollup', 'webpack', '@rspack/core', 'tsup', '@babel/helpers', '@angular/compiler', 'svelte', '@sveltejs/kit']) {
    assert.ok(GENERATED_CODE.packages[expected], expected);
  }
});

test('no hand-checked module rule covers a listed advisory', () => {
  for (const [packageName, entry] of Object.entries(GENERATED_CODE.packages)) {
    const ruleNames = Object.entries(handRules.packages[packageName]?.advisories ?? {})
      .flatMap(([ruleKey, rule]) => [ruleKey, rule.id, ...(rule.aliases ?? [])]);

    for (const [advisoryId, advisory] of Object.entries(entry.advisories)) {
      for (const name of [advisoryId, ...advisory.aliases]) {
        assert.ok(!ruleNames.includes(name), `${packageName} ${name} has a module rule`);
      }
    }
  }
});

test('a build tool that is not in the bundle: its generated-code advisory stays open, its others settle', () => {
  const findings = [
    { purl: 'pkg:npm/rollup@4.20.0', ids: ['GHSA-gcx4-mw62-g8wm'] }, // code Rollup writes into cjs/umd/iife output
    { purl: 'pkg:npm/rollup@4.20.0', ids: ['GHSA-mw96-cpmx-2vgc'] }, // a file write while Rollup itself runs
    { purl: 'pkg:npm/@angular/compiler@19.2.10', ids: ['GHSA-v4hv-rgfq-gp49'] },
    { purl: 'pkg:npm/@babel/helpers@7.26.0', ids: ['GHSA-968p-4wvh-cqc8'] },
  ];

  const results = triage({ lockfileSbom, bundleSbom: withoutTools, findings });

  assert.deepEqual(stateOf(results), {
    'GHSA-gcx4-mw62-g8wm': 'in_triage/null',
    'GHSA-mw96-cpmx-2vgc': 'not_affected/package',
    'GHSA-v4hv-rgfq-gp49': 'in_triage/null',
    'GHSA-968p-4wvh-cqc8': 'in_triage/null',
  });

  const rollup = results.find((result) => result.id === 'GHSA-gcx4-mw62-g8wm');

  assert.equal(rollup.generatedCode, 'GHSA-gcx4-mw62-g8wm');
  assert.equal(rollup.justification, undefined);
  assert.match(rollup.detail, /^GHSA-gcx4-mw62-g8wm is about what rollup writes into a build's output \(a DOM clobbering gadget in the code Rollup writes into cjs, umd and iife output\), so whether rollup's own files shipped says nothing about it; requires manual review\.$/);
  assert.match(rollup.moduleReason, /is about what rollup writes into a build/);
  assert.equal(results.find((result) => result.id === 'GHSA-mw96-cpmx-2vgc').generatedCode, null);
});

test('a scanner that reports only the CVE is matched through the alias', () => {
  const findings = [
    { purl: 'pkg:npm/rollup@4.20.0', ids: ['CVE-2024-47068'] },
    { purl: 'pkg:npm/@angular/compiler@19.2.10', ids: ['CVE-2026-22610'] },
  ];

  const results = triage({ lockfileSbom, bundleSbom: withoutTools, findings });

  assert.deepEqual(stateOf(results), { 'CVE-2024-47068': 'in_triage/null', 'CVE-2026-22610': 'in_triage/null' });
  assert.equal(results[0].generatedCode, 'GHSA-gcx4-mw62-g8wm');
});

test('the same advisory id on a package that is not listed for it settles as before', () => {
  // lodash is not a listed package, whatever id a scanner gives its finding
  const lockfile = { components: [component('lodash', '4.17.20'), component('left-pad', '1.3.0')] };
  const findings = [{ purl: 'pkg:npm/left-pad@1.3.0', ids: ['GHSA-gcx4-mw62-g8wm'] }];

  assert.deepEqual(stateOf(triage({ lockfileSbom: lockfile, bundleSbom: withoutTools, findings })), { 'GHSA-gcx4-mw62-g8wm': 'not_affected/package' });
});

test('no module rule settles a listed advisory, even an accepted one, when the package is in the bundle', () => {
  const bundleSbom = { components: [component('lodash', '4.17.20'), component('@angular/compiler', '19.2.10')] };
  const findings = [{ purl: 'pkg:npm/@angular/compiler@19.2.10', ids: ['GHSA-v4hv-rgfq-gp49'] }];
  const settles = () => ({ ok: true, detail: 'the files are not there', evidence: {} });
  const settlesByDerivedRule = () => ({ ok: true, derived: true, detail: 'the files the fix changed are not there', evidence: {} });

  for (const moduleCheck of [settles, settlesByDerivedRule]) {
    const results = triage({ lockfileSbom, bundleSbom, findings, moduleMap: {}, moduleCheck, pro: true, acceptDerived: true });

    assert.deepEqual(stateOf(results), { 'GHSA-v4hv-rgfq-gp49': 'in_triage/null' });
    assert.equal(results[0].proWouldSettle, false);
  }

  // the free tier must not count it as something Pro would settle either
  const free = triage({ lockfileSbom, bundleSbom, findings, moduleMap: {}, moduleCheck: settles });

  assert.equal(free[0].proWouldSettle, false);
});

test('a derived rule never applies to a package that writes code into builds; a hand-checked one does', () => {
  const bundleSbom = { components: [component('lodash', '4.17.20'), component('svelte', '5.40.0')] };
  const findings = [{ purl: 'pkg:npm/svelte@5.40.0', ids: ['GHSA-phwv-c562-gvmh'] }];
  const derived = () => ({ ok: true, derived: true, detail: 'the files the fix changed are not there', evidence: {} });
  const handChecked = () => ({ ok: true, detail: 'the vulnerable files are not there', evidence: {} });

  const refused = triage({ lockfileSbom, bundleSbom, findings, moduleMap: {}, moduleCheck: derived, pro: true, acceptDerived: true });

  assert.deepEqual(stateOf(refused), { 'GHSA-phwv-c562-gvmh': 'in_triage/null' });
  assert.match(refused[0].moduleReason, /^svelte writes code into the build that no file list shows, so only hand-checked rules apply to it, and GHSA-phwv-c562-gvmh has none$/);
  assert.equal(refused[0].generatedCode, null);

  // not offered as a suggestion, and not counted for the free tier's hint
  const suggested = triage({ lockfileSbom, bundleSbom, findings, moduleMap: {}, moduleCheck: derived, pro: true });
  const free = triage({ lockfileSbom, bundleSbom, findings, moduleMap: {}, moduleCheck: derived });

  assert.doesNotMatch(suggested[0].detail, /Suggested by a derived rule/);
  assert.equal(free[0].proWouldSettle, false);

  const settled = triage({ lockfileSbom, bundleSbom, findings, moduleMap: {}, moduleCheck: handChecked, pro: true });

  assert.deepEqual(stateOf(settled), { 'GHSA-phwv-c562-gvmh': 'not_affected/module' });

  // a package that is not listed takes an accepted derived rule as before
  const lodash = triage({
    lockfileSbom, bundleSbom, findings: [{ purl: 'pkg:npm/lodash@4.17.20', ids: ['GHSA-35jh-r3h4-6jhm'] }], moduleMap: {}, moduleCheck: derived, pro: true, acceptDerived: true,
  });

  assert.deepEqual(stateOf(lodash), { 'GHSA-35jh-r3h4-6jhm': 'not_affected/module' });
});

test('a caller can pass its own list, or none', () => {
  const findings = [{ purl: 'pkg:npm/rollup@4.20.0', ids: ['GHSA-gcx4-mw62-g8wm'] }];

  assert.deepEqual(stateOf(triage({ lockfileSbom, bundleSbom: withoutTools, findings, generatedCode: null })), { 'GHSA-gcx4-mw62-g8wm': 'not_affected/package' });
});

test('rules derive counts a rule\'s files against the JavaScript files they were taken from', () => {
  const bytes = (text) => Buffer.from(text);
  // the fix changed the one runtime file and three spec files: 4 files, of 5 JavaScript files
  const installedFiles = new Map([
    ['index.js', bytes('a')], ['lib/keep.js', bytes('k')],
    ['spec/one.js', bytes('1')], ['spec/two.js', bytes('2')], ['spec/three.js', bytes('3')],
  ]);
  const fixedFiles = new Map([
    ['index.js', bytes('A')], ['lib/keep.js', bytes('k')],
    ['spec/one.js', bytes('I')], ['spec/two.js', bytes('II')], ['spec/three.js', bytes('III')],
  ]);

  const diff = diffForRule({ installedFiles, fixedFiles });

  assert.deepEqual(diff, { files: ['index.js', 'spec/one.js', 'spec/three.js', 'spec/two.js'], javascriptFiles: 5 });
  assert.ok(diff.files.length <= diff.javascriptFiles);
});

test('the command says why such a finding stays open, with no module map, and writes no claim for it', (testContext) => {
  const folder = temporaryFolder(testContext, 'vxp-generated-');
  const application = { type: 'application', name: 'app', version: '1.0.0', purl: 'pkg:npm/app@1.0.0', 'bom-ref': 'app' };

  writeFileSync(join(folder, 'lock.json'), JSON.stringify({
    bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:11111111-1111-4111-8111-111111111111',
    metadata: { component: application },
    components: lockfileSbom.components.map((entry) => ({ type: 'library', ...entry })),
  }));
  writeFileSync(join(folder, 'bundle.json'), JSON.stringify({
    bomFormat: 'CycloneDX', specVersion: '1.6', components: withoutTools.components.map((entry) => ({ type: 'library', ...entry })),
  }));
  writeFileSync(join(folder, 'findings.json'), JSON.stringify([
    { purl: 'pkg:npm/rollup@4.20.0', ids: ['GHSA-gcx4-mw62-g8wm'] },
    { purl: 'pkg:npm/rollup@4.20.0', ids: ['GHSA-mw96-cpmx-2vgc'] },
  ]));

  const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
  const run = spawnSync(process.execPath, [cli, '--lockfile', 'lock.json', '--bundle', 'bundle.json', '--findings', 'findings.json', '--out', 'vex.json'], {
    cwd: folder, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '' },
  });

  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /2 finding\(s\) → 1 not_affected, 1 in_triage/);
  assert.match(run.stdout, /in_triage +GHSA-gcx4-mw62-g8wm +pkg:npm\/rollup@4\.20\.0 {2}← GHSA-gcx4-mw62-g8wm is about what rollup writes into a build, which its own files don't show/);

  const statements = JSON.parse(readFileSync(join(folder, 'vex.json'), 'utf8')).vulnerabilities;
  const generated = statements.find((statement) => statement.id === 'GHSA-gcx4-mw62-g8wm');

  assert.equal(generated.analysis.state, 'in_triage');
  assert.equal(generated.analysis.justification, undefined);
  assert.match(generated.analysis.detail, /is about what rollup writes into a build's output/);
  assert.equal(statements.find((statement) => statement.id === 'GHSA-mw96-cpmx-2vgc').analysis.state, 'not_affected');
});

test('a derived rule adds the advisory\'s other names to a finding, never its own key', () => {
  const derivedRules = { packages: { nanoid: { advisories: {
    'GHSA-mwcw-c2x4-8c55@3.3.3': { id: 'GHSA-mwcw-c2x4-8c55', versions: ['3.3.3'], files: ['index.browser.js'], aliases: ['CVE-2024-55565'], origin: 'derived' },
    'GHSA-mwcw-c2x4-8c55@4.0.2': { id: 'GHSA-mwcw-c2x4-8c55', versions: ['4.0.2'], files: ['index.browser.js'], aliases: ['CVE-2024-55565'], origin: 'derived' },
  } } } };
  const findings = applyRuleAliases(normalizeFindings([{ purl: 'pkg:npm/nanoid@3.3.3', ids: ['GHSA-mwcw-c2x4-8c55'] }]), derivedRules);

  assert.deepEqual(findings, [{ purl: 'pkg:npm/nanoid@3.3.3', id: 'GHSA-mwcw-c2x4-8c55', aliases: ['CVE-2024-55565'] }]);

  // a hand-checked rule is keyed by the advisory itself, and still links a CVE to its GHSA
  const handChecked = { packages: { lodash: { advisories: { 'GHSA-35jh-r3h4-6jhm': { files: ['template.js'], aliases: ['CVE-2021-23337'] } } } } };
  const byCve = applyRuleAliases(normalizeFindings([{ purl: 'pkg:npm/lodash@4.17.20', ids: ['CVE-2021-23337'] }]), handChecked);

  assert.deepEqual(byCve[0].aliases, ['GHSA-35jh-r3h4-6jhm']);
});
