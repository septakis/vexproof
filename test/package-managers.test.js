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

const raw = (f) => readFileSync(new URL(`./fixtures/${f}`, import.meta.url), 'utf8');
const fx = (f) => JSON.parse(raw(f));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const files = (mm, pkg) => [...(mm.packages.get(pkg)?.files ?? [])].sort();
const EXPECTED = { 'GHSA-r5fr-rjxr-66jc': 'not_affected', 'GHSA-f23m-r3pf-42rh': 'in_triage', 'GHSA-xxjr-mmjv-4gpg': 'in_triage' };
const LODASH = ['GHSA-f23m-r3pf-42rh', 'GHSA-r5fr-rjxr-66jc', 'GHSA-xxjr-mmjv-4gpg'];

test('store paths give the copy version: pnpm, Bun isolated, Yarn zip cache', () => {
  assert.equal(versionFromStorePath('node_modules/.bun/lodash@4.17.21/node_modules/lodash', 'lodash'), '4.17.21');
  assert.equal(versionFromStorePath('node_modules/.bun/@babel+runtime@7.26.0/node_modules/@babel/runtime', '@babel/runtime'), '7.26.0');
  assert.equal(versionFromStorePath('node_modules/.bun/react-dom@18.3.1+b1ab299f0a400331/node_modules/react-dom', 'react-dom'), '18.3.1');
  assert.equal(versionFromStorePath('yarn-cache/lodash-npm-4.17.21-6382451519-10c0.zip/node_modules/lodash', 'lodash'), '4.17.21');
  assert.equal(versionFromStorePath('yarn-cache/@babel-runtime-npm-7.26.0-0123456789-10c0.zip/node_modules/@babel/runtime', '@babel/runtime'), '7.26.0');
  assert.equal(versionFromStorePath('yarn-cache/lodash-es-npm-4.17.21-0123456789-10c0.zip/node_modules/lodash-es', 'lodash'), undefined);
});

test('yarn audit (Classic NDJSON) and yarn npm audit --recursive (Yarn 4 NDJSON) are read', () => {
  const lock = fx('recharts.bom.lockfile.json');
  const c = readFindingsText(raw('recharts.yarn-classic.audit.ndjson'), lock);
  assert.equal(c.format, 'yarn-audit');
  const b = readFindingsText(raw('recharts.yarn-berry.audit.ndjson'), lock);
  assert.equal(b.format, 'yarn-berry-audit');
  for (const r of [c, b]) {
    assert.deepEqual(r.findings.map((f) => f.id).sort(), LODASH);
    assert.ok(r.findings.every((f) => f.purl === 'pkg:npm/lodash@4.17.21'));
  }
  assert.throws(() => readFindingsText('not json\n{"type":"info"}\n'), /Unrecognised findings file/);
});

test('bun audit --json: versions come from the lockfile SBOM, filtered by each advisory range', () => {
  const lock = fx('recharts.bom.lockfile.json');
  const r = readFindingsText(raw('recharts.bun.audit.json'), lock);
  assert.equal(r.format, 'bun-audit');
  assert.deepEqual(r.findings.map((f) => f.id).sort(), LODASH);
  assert.ok(r.findings.every((f) => f.purl === 'pkg:npm/lodash@4.17.21'));

  const twoCopies = { components: [{ purl: 'pkg:npm/lodash@4.17.21' }, { purl: 'pkg:npm/lodash@4.18.1' }] };
  const one = fromBunAudit({ lodash: [{ url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', vulnerable_versions: '>=4.0.0 <=4.17.23' }] }, twoCopies);
  assert.deepEqual(one.map((f) => f.purl), ['pkg:npm/lodash@4.17.21']);
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
  const lock = fx('recharts.bom.lockfile.json');
  const npm = files(readModuleMap(fx('recharts.metafile.json')), 'lodash');
  const mm = attachVersions(readModuleMap(fx('recharts.yarn-pnp.vite8.json')), { cwd: '/nonexistent' });
  const entry = mm.packages.get('lodash');
  assert.equal(entry.roots.size, 1);
  assert.deepEqual([...entry.versionByRoot.values()], ['4.17.21']);
  assert.deepEqual(files(mm, 'lodash'), npm);
  assert.equal(mm.packages.size, 25);
  for (const pkg of mm.packages.values()) assert.equal(pkg.roots.size, 1, 'no phantom copies from __virtual__ ids');
  const bundleSbom = bundleSbomFromModules(mm, { lockfileSbom: lock, cwd: '/nonexistent' });
  const findings = readFindingsText(raw('recharts.yarn-berry.audit.ndjson'), lock).findings;
  const rs = triage({ lockfileSbom: lock, bundleSbom, moduleMap: mm, rules, moduleCheck: evaluateModuleRule, pro: true, findings });
  assert.deepEqual(Object.fromEntries(rs.map((r) => [r.id, r.state])), EXPECTED);
});

test('Bun isolated linker: Vite 8 plugin and `bun build --metafile` give the same files and verdicts as npm', () => {
  const lock = fx('recharts.bom.lockfile.json');
  const npm = files(readModuleMap(fx('recharts.metafile.json')), 'lodash');
  const findings = readFindingsText(raw('recharts.bun.audit.json'), lock).findings;
  for (const f of ['recharts.bun-isolated.vite8.json', 'recharts.bun-build.metafile.json']) {
    const mm = attachVersions(readModuleMap(fx(f)), { cwd: '/nonexistent' });
    const entry = mm.packages.get('lodash');
    assert.deepEqual([...entry.roots], ['node_modules/.bun/lodash@4.17.21/node_modules/lodash'], f);
    assert.deepEqual([...entry.versionByRoot.values()], ['4.17.21'], f);
    assert.deepEqual(files(mm, 'lodash'), npm, f);
    const bundleSbom = bundleSbomFromModules(mm, { lockfileSbom: lock, cwd: '/nonexistent' });
    const rs = triage({ lockfileSbom: lock, bundleSbom, moduleMap: mm, rules, moduleCheck: evaluateModuleRule, pro: true, findings });
    assert.deepEqual(Object.fromEntries(rs.map((r) => [r.id, r.state])), EXPECTED, f);
  }
});
