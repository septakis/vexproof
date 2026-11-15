// SPDX-License-Identifier: MIT
// Yarn Classic, Yarn 4 (node-modules and Plug'n'Play) and Bun (hoisted and isolated): real audit output and
// module maps from the recharts demo installed with each. Every one must reach the same verdicts as npm.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readModuleMap, attachVersions, versionFromStorePath, bundleSbomFromModules } from '../src/modules.js';
import { triage } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { readFindingsText, inAdvisoryRange, fromBunAudit } from '../src/sources.js';

const raw = (fileName) => readFileSync(new URL(`./fixtures/${fileName}`, import.meta.url), 'utf8');
const fixture = (fileName) => JSON.parse(raw(fileName));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const files = (moduleMap, packageName) => [...(moduleMap.packages.get(packageName)?.files ?? [])].sort();
const EXPECTED = { 'GHSA-r5fr-rjxr-66jc': 'not_affected', 'GHSA-f23m-r3pf-42rh': 'in_triage', 'GHSA-xxjr-mmjv-4gpg': 'in_triage' };
const LODASH = ['GHSA-f23m-r3pf-42rh', 'GHSA-r5fr-rjxr-66jc', 'GHSA-xxjr-mmjv-4gpg'];

test('store paths give the copy version: pnpm, Bun isolated, Yarn zip cache', () => {
  assert.equal(versionFromStorePath('node_modules/.bun/lodash@4.17.21/node_modules/lodash', 'lodash'), '4.17.21');
  assert.equal(versionFromStorePath('node_modules/.bun/@babel+runtime@7.26.0/node_modules/@babel/runtime', '@babel/runtime'), '7.26.0');
  assert.equal(versionFromStorePath('node_modules/.bun/react-dom@18.3.1+b1ab299f0a400331/node_modules/react-dom', 'react-dom'), '18.3.1');
  assert.equal(versionFromStorePath('yarn-cache/lodash-npm-4.17.21-6382451519-10c0.zip/node_modules/lodash', 'lodash'), '4.17.21');
  assert.equal(
    versionFromStorePath('yarn-cache/@babel-runtime-npm-7.26.0-0123456789-10c0.zip/node_modules/@babel/runtime', '@babel/runtime'),
    '7.26.0',
  );
  assert.equal(versionFromStorePath('yarn-cache/lodash-es-npm-4.17.21-0123456789-10c0.zip/node_modules/lodash-es', 'lodash'), undefined);
});

test('yarn audit (Classic NDJSON) and yarn npm audit --recursive (Yarn 4 NDJSON) are read', () => {
  const lock = fixture('recharts.bom.lockfile.json');

  const classic = readFindingsText(raw('recharts.yarn-classic.audit.ndjson'), lock);

  assert.equal(classic.format, 'yarn-audit');

  const berry = readFindingsText(raw('recharts.yarn-berry.audit.ndjson'), lock);

  assert.equal(berry.format, 'yarn-berry-audit');
  for (const parsed of [classic, berry]) {
    assert.deepEqual(parsed.findings.map((finding) => finding.id).sort(), LODASH);
    assert.ok(parsed.findings.every((finding) => finding.purl === 'pkg:npm/lodash@4.17.21'));
  }

  assert.throws(() => readFindingsText('not json\n{"type":"info"}\n'), /Unrecognised findings file/);
});

test('bun audit --json: versions come from the lockfile SBOM, filtered by each advisory range', () => {
  const lock = fixture('recharts.bom.lockfile.json');

  const parsed = readFindingsText(raw('recharts.bun.audit.json'), lock);

  assert.equal(parsed.format, 'bun-audit');
  assert.deepEqual(parsed.findings.map((finding) => finding.id).sort(), LODASH);
  assert.ok(parsed.findings.every((finding) => finding.purl === 'pkg:npm/lodash@4.17.21'));

  const twoCopies = { components: [{ purl: 'pkg:npm/lodash@4.17.21' }, { purl: 'pkg:npm/lodash@4.18.1' }] };
  const audit = { lodash: [{ url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', vulnerable_versions: '>=4.0.0 <=4.17.23' }] };

  const one = fromBunAudit(audit, twoCopies);

  assert.deepEqual(one.map((finding) => finding.purl), ['pkg:npm/lodash@4.17.21']);
});

test('advisory ranges', () => {
  assert.ok(inAdvisoryRange('4.17.21', '>=4.0.0 <=4.17.22'));
  assert.ok(!inAdvisoryRange('4.17.23', '>=4.0.0 <=4.17.22'));
  assert.ok(inAdvisoryRange('1.0.0', '<0.5.0 || >=1.0.0 <1.0.1'));
  assert.ok(!inAdvisoryRange('0.7.0', '<0.5.0 || >=1.0.0 <1.0.1'));
  assert.ok(!inAdvisoryRange('2.0.0-rc.1', '>=2.0.0'));
  assert.ok(inAdvisoryRange('1.2.3', 'garbage'), 'unparseable ranges keep the finding');
});

test('Yarn 4 Plug\'n\'Play (Vite 8): zip-cache ids fold to one copy with a known version; same files and verdicts as npm', () => {
  const lock = fixture('recharts.bom.lockfile.json');
  const npm = files(readModuleMap(fixture('recharts.metafile.json')), 'lodash');

  const moduleMap = attachVersions(readModuleMap(fixture('recharts.yarn-pnp.vite8.json')), { cwd: '/nonexistent' });

  const entry = moduleMap.packages.get('lodash');
  assert.equal(entry.roots.size, 1);
  assert.deepEqual([...entry.versionByRoot.values()], ['4.17.21']);
  assert.deepEqual(files(moduleMap, 'lodash'), npm);
  assert.equal(moduleMap.packages.size, 26); // 25 bundled packages, and vite for the module preload polyfill it writes into the output
  assert.deepEqual(files(moduleMap, 'vite'), ['modulepreload-polyfill.js']);
  for (const packageEntry of moduleMap.packages.values()) {
    assert.equal(packageEntry.roots.size, 1, 'no phantom copies from __virtual__ ids');
  }

  const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom: lock, cwd: '/nonexistent' });
  const findings = readFindingsText(raw('recharts.yarn-berry.audit.ndjson'), lock).findings;

  const results = triage({ lockfileSbom: lock, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings });

  assert.deepEqual(Object.fromEntries(results.map((result) => [result.id, result.state])), EXPECTED);
});

test('Bun isolated linker: Vite 8 plugin and `bun build --metafile` give the same files and verdicts as npm', () => {
  const lock = fixture('recharts.bom.lockfile.json');
  const npm = files(readModuleMap(fixture('recharts.metafile.json')), 'lodash');
  const findings = readFindingsText(raw('recharts.bun.audit.json'), lock).findings;

  for (const fileName of ['recharts.bun-isolated.vite8.json', 'recharts.bun-build.metafile.json']) {
    const moduleMap = attachVersions(readModuleMap(fixture(fileName)), { cwd: '/nonexistent' });

    const entry = moduleMap.packages.get('lodash');
    assert.deepEqual([...entry.roots], ['node_modules/.bun/lodash@4.17.21/node_modules/lodash'], fileName);
    assert.deepEqual([...entry.versionByRoot.values()], ['4.17.21'], fileName);
    assert.deepEqual(files(moduleMap, 'lodash'), npm, fileName);

    const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom: lock, cwd: '/nonexistent' });
    const results = triage({ lockfileSbom: lock, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings });

    assert.deepEqual(Object.fromEntries(results.map((result) => [result.id, result.state])), EXPECTED, fileName);
  }
});
