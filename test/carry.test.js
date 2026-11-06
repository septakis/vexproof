// SPDX-License-Identifier: MIT
// Reviewed decisions carry into later releases while their evidence holds: the shipped vulnerable files are
// byte-identical and the same code imports them. Fixtures are real esbuild graphs of a small app using
// lodash-es omit(), before and after a new module starts calling omit() with URL input.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { triage, toCycloneDxVex } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { readModuleMap, bundleSbomFromModules } from '../src/modules.js';
import { attachFingerprints } from '../src/evidence.js';
import { readBaseline, applyBaseline } from '../src/pro/baseline.js';
import { recordReview, sameCause } from '../src/review.js';
import vexproof from '../src/vite.js';

const fx = (f) => JSON.parse(readFileSync(new URL(`./fixtures/${f}`, import.meta.url)));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const F23M = 'GHSA-f23m-r3pf-42rh', XXJR = 'GHSA-xxjr-mmjv-4gpg';
// Real content hashes: _baseUnset.js and omit.js are byte-identical in lodash-es 4.17.22 and 4.17.23.
const REAL = { '_baseUnset.js': '7773e16762af23ca', 'omit.js': 'de577fc677627a13' };

function run({ meta = 'carry.metafile.json', version = '4.17.23', ids = [F23M], baseline = null, files = REAL, now = new Date('2026-10-01'), maxAgeDays = 365 } = {}) {
  const purl = `pkg:npm/lodash-es@${version}`;
  const lockfileSbom = { serialNumber: 'urn:uuid:11111111-2222-3333-4444-555555555555', version: 1, components: [{ 'bom-ref': purl, name: 'lodash-es', version, purl }] };
  const moduleMap = readModuleMap(fx(meta));
  const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom, cwd: '/nonexistent' });
  const results = triage({ lockfileSbom, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings: [{ purl, ids }] });
  attachFingerprints(results, { moduleMap, rules, cwd: '/x', readFile: (p) => Buffer.from(files[p.split(/[\\/]/).at(-1)] ?? 'other') });
  if (baseline) applyBaseline(results, readBaseline(baseline), { now, maxAgeDays });
  return { results, vex: toCycloneDxVex({ results, bundleSbom, lockfileSbom, productPurl: 'pkg:npm/settings-panel@1.0.0', now }) };
}
const review = (vex, extra = {}) => {
  recordReview(vex, { id: F23M, state: 'not_affected', justification: 'code_not_reachable', detail: 'omit() only receives a fixed key list', by: 'Jane Doe', now: new Date('2026-09-27'), ...extra });
  return vex;
};

test('open findings record their evidence: vulnerable files with hashes, and the code importing them', () => {
  const [r] = run({ version: '4.17.22' }).results;
  assert.deepEqual(r.fingerprint.vulnerableFiles, ['_baseUnset.js', 'omit.js']);
  assert.deepEqual(r.fingerprint.importers, ['src/main.js']); // through the lodash-es barrel, which is inside the package
  assert.ok(r.fingerprint.filesDigest);
});

test('a version bump that leaves the vulnerable files and their importers alone carries the review', () => {
  const reviewed = review(run({ version: '4.17.22' }).vex);
  const { results, vex } = run({ version: '4.17.23', baseline: reviewed });
  assert.equal(results[0].state, 'not_affected');
  assert.equal(results[0].isNew, false);
  assert.deepEqual(results[0].carriedFrom, { purl: 'pkg:npm/lodash-es@4.17.22', reviewedAt: '2026-09-27' });
  assert.match(results[0].detail, /Carried forward from the review by Jane Doe on 2026-09-27 for 4\.17\.22/);
  // carried again on the next release: the note is replaced, not stacked
  const again = run({ version: '4.17.23', baseline: vex }).results[0];
  assert.equal(again.detail.match(/Carried forward/g).length, 1);
  assert.equal(vex.vulnerabilities.find((v) => v.id === F23M).properties.find((p) => p.name === 'vexproof:reviewed-at').value, '2026-09-27T00:00:00.000Z');
});

test('changed vulnerable code sends it back, naming the file', () => {
  const reviewed = review(run({ version: '4.17.22' }).vex);
  const [r] = run({ version: '4.17.23', baseline: reviewed, files: { ...REAL, '_baseUnset.js': 'patched' } }).results;
  assert.equal(r.state, 'in_triage');
  assert.equal(r.isNew, true);
  assert.match(r.moduleReason, /the review by Jane Doe on 2026-09-27 needs re-confirming: vulnerable files changed: _baseUnset\.js/);
});

test('new code calling the vulnerable file sends it back, even at the same version', () => {
  const reviewed = review(run().vex);
  const [r] = run({ meta: 'carry-filters.metafile.json', baseline: reviewed }).results;
  assert.equal(r.state, 'in_triage');
  assert.deepEqual(r.reReview.changes, ['new importer: src/filters.js']);
});

test('reviews expire after the age limit', () => {
  const reviewed = review(run().vex);
  const [r] = run({ baseline: reviewed, now: new Date('2027-11-01') }).results;
  assert.match(r.moduleReason, /older than 365 days/);
  assert.equal(run({ baseline: reviewed, now: new Date('2027-11-01'), maxAgeDays: null }).results[0].state, 'not_affected');
});

test('decisions resting on things vexproof cannot see stay tied to the version', () => {
  const reviewed = review(run({ version: '4.17.22' }).vex, { justification: 'protected_at_perimeter' });
  assert.match(run({ version: '4.17.23', baseline: reviewed }).results[0].moduleReason, /only kept for the same version \(4\.17\.22\)/);
  assert.equal(run({ version: '4.17.22', baseline: reviewed }).results[0].state, 'not_affected');
});

test('reviews recorded without evidence carry only within the same version', () => {
  const reviewed = review(run({ version: '4.17.22' }).vex);
  for (const v of reviewed.vulnerabilities) v.properties = v.properties.filter((p) => !/evidence|importers|vulnerable-files/.test(p.name));
  assert.match(run({ version: '4.17.23', baseline: reviewed }).results[0].moduleReason, /evidence to carry it forward wasn't recorded/);
  assert.equal(run({ version: '4.17.22', baseline: reviewed }).results[0].state, 'not_affected');
});

test('one review covers every open finding on the same vulnerable files', () => {
  const { vex } = run({ version: '4.17.22', ids: [F23M, XXJR] });
  const v = recordReview(vex, { id: F23M, state: 'not_affected', justification: 'code_not_reachable', detail: 'fixed keys', by: 'Jane Doe' });
  assert.deepEqual(sameCause(vex, v).map((o) => o.id), [XXJR]);
});

test('the Vite plugin records imports for modules that no chunk contains (re-export barrels)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-graph-'));
  const p = vexproof({ root: dir });
  p.configResolved({ root: dir, build: { outDir: 'dist' } });
  const graph = { [join(dir, 'src/main.js')]: [join(dir, 'node_modules/lodash-es/lodash.js')], [join(dir, 'node_modules/lodash-es/lodash.js')]: [join(dir, 'node_modules/lodash-es/omit.js')], [join(dir, 'node_modules/lodash-es/omit.js')]: [] };
  const ctx = { getModuleIds: () => Object.keys(graph), getModuleInfo: (id) => ({ importedIds: graph[id] ?? [] }) };
  p.generateBundle.call(ctx, { dir: join(dir, 'dist') }, { 'a.js': { type: 'chunk', fileName: 'a.js', modules: { [join(dir, 'src/main.js')]: { renderedLength: 50 }, [join(dir, 'node_modules/lodash-es/omit.js')]: { renderedLength: 90 } } } });
  p.closeBundle();
  const rec = JSON.parse(readFileSync(join(dir, 'vexproof-modules.json'), 'utf8'));
  assert.deepEqual(rec.inputs['node_modules/lodash-es/lodash.js'].imports, [{ path: 'node_modules/lodash-es/omit.js' }]);
});
