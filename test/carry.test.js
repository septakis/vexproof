// SPDX-License-Identifier: MIT
// Reviewed decisions carry into later releases while their evidence holds: the shipped vulnerable files are
// byte-identical and the same code imports them. Fixtures are real esbuild graphs of a small app using
// lodash-es omit(), before and after a new module starts calling omit() with URL input.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { triage, toCycloneDxVex } from '../src/index.js';
import { evaluateModuleRule } from '../src/pro/module-check.js';
import { readModuleMap, bundleSbomFromModules } from '../src/modules.js';
import { attachFingerprints, fingerprintProperties, fingerprintFromProperties } from '../src/evidence.js';
import { readBaseline, applyBaseline } from '../src/pro/baseline.js';
import { recordReview, sameCause } from '../src/review.js';
import vexproof from '../src/vite.js';
import { temporaryFolder } from './lib/temporary.js';

const readFixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url)));
const rules = JSON.parse(readFileSync(new URL('../src/pro/rules/module-rules.json', import.meta.url)));
const F23M = 'GHSA-f23m-r3pf-42rh';
const XXJR = 'GHSA-xxjr-mmjv-4gpg';
// Real content hashes: _baseUnset.js and omit.js are byte-identical in lodash-es 4.17.22 and 4.17.23.
const REAL = { '_baseUnset.js': '7773e16762af23ca', 'omit.js': 'de577fc677627a13' };

function run({
  meta = 'carry.metafile.json',
  version = '4.17.23',
  ids = [F23M],
  baseline = null,
  files = REAL,
  now = new Date('2026-10-01'),
  maxAgeDays = 365,
} = {}) {
  const purl = `pkg:npm/lodash-es@${version}`;
  const lockfileSbom = {
    serialNumber: 'urn:uuid:11111111-2222-3333-4444-555555555555',
    version: 1,
    components: [{ 'bom-ref': purl, name: 'lodash-es', version, purl }],
  };
  const moduleMap = readModuleMap(readFixture(meta));
  const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom, cwd: '/nonexistent' });
  const results = triage({
    lockfileSbom, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings: [{ purl, ids }],
  });
  attachFingerprints(results, {
    moduleMap,
    rules,
    cwd: '/x',
    readFile: (path) => Buffer.from(files[path.split(/[\\/]/).at(-1)] ?? 'other'),
  });
  if (baseline) applyBaseline(results, readBaseline(baseline), { now, maxAgeDays });

  return {
    results,
    vex: toCycloneDxVex({ results, bundleSbom, lockfileSbom, productPurl: 'pkg:npm/settings-panel@1.0.0', now }),
  };
}
const review = (vex, extra = {}) => {
  recordReview(vex, {
    id: F23M,
    state: 'not_affected',
    justification: 'code_not_reachable',
    detail: 'omit() only receives a fixed key list',
    by: 'Jane Doe',
    now: new Date('2026-09-27'),
    ...extra,
  });
  return vex;
};

test('open findings record their evidence: vulnerable files with hashes, and the code importing them', () => {
  const [result] = run({ version: '4.17.22' }).results;

  assert.deepEqual(result.fingerprint.vulnerableFiles, ['_baseUnset.js', 'omit.js']);
  assert.deepEqual(result.fingerprint.importers, ['src/main.js']); // through the lodash-es barrel, which is inside the package
  assert.ok(result.fingerprint.filesDigest);
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
  const statement = vex.vulnerabilities.find((vulnerability) => vulnerability.id === F23M);
  assert.equal(statement.properties.find((property) => property.name === 'vexproof:reviewed-at').value, '2026-09-27T00:00:00.000Z');
});

test('changed vulnerable code sends it back, naming the file', () => {
  const reviewed = review(run({ version: '4.17.22' }).vex);

  const [result] = run({ version: '4.17.23', baseline: reviewed, files: { ...REAL, '_baseUnset.js': 'patched' } }).results;

  assert.equal(result.state, 'in_triage');
  assert.equal(result.isNew, true);
  assert.match(result.moduleReason, /the review by Jane Doe on 2026-09-27 needs re-confirming: vulnerable files changed: _baseUnset\.js/);
});

test('new code calling the vulnerable file sends it back, even at the same version', () => {
  const reviewed = review(run().vex);

  const [result] = run({ meta: 'carry-filters.metafile.json', baseline: reviewed }).results;

  assert.equal(result.state, 'in_triage');
  assert.deepEqual(result.reReview.changes, ['new importer: src/filters.js']);
});

test('reviews expire after the age limit', () => {
  const reviewed = review(run().vex);

  const [result] = run({ baseline: reviewed, now: new Date('2027-11-01') }).results;
  assert.match(result.moduleReason, /older than 365 days/);

  assert.equal(run({ baseline: reviewed, now: new Date('2027-11-01'), maxAgeDays: null }).results[0].state, 'not_affected');
});

test('decisions resting on things vexproof cannot see stay tied to the version', () => {
  const reviewed = review(run({ version: '4.17.22' }).vex, { justification: 'protected_at_perimeter' });

  assert.match(run({ version: '4.17.23', baseline: reviewed }).results[0].moduleReason, /only kept for the same version \(4\.17\.22\)/);
  assert.equal(run({ version: '4.17.22', baseline: reviewed }).results[0].state, 'not_affected');
});

test('reviews recorded without evidence carry only within the same version', () => {
  const reviewed = review(run({ version: '4.17.22' }).vex);
  for (const statement of reviewed.vulnerabilities) {
    statement.properties = statement.properties.filter((property) => !/evidence|importers|vulnerable-files/.test(property.name));
  }

  assert.match(run({ version: '4.17.23', baseline: reviewed }).results[0].moduleReason, /evidence to carry it forward wasn't recorded/);
  assert.equal(run({ version: '4.17.22', baseline: reviewed }).results[0].state, 'not_affected');
});

test('one review covers every open finding on the same vulnerable files', () => {
  const { vex } = run({ version: '4.17.22', ids: [F23M, XXJR] });

  const reviewedStatement = recordReview(vex, {
    id: F23M, state: 'not_affected', justification: 'code_not_reachable', detail: 'fixed keys', by: 'Jane Doe',
  });

  assert.deepEqual(sameCause(vex, reviewedStatement).map((other) => other.id), [XXJR]);
});

test('the Vite plugin records imports for modules that no chunk contains (re-export barrels)', (testContext) => {
  const dir = temporaryFolder(testContext, 'vxp-graph-');
  const plugin = vexproof({ root: dir });
  plugin.configResolved({ root: dir, build: { outDir: 'dist' } });
  const graph = {
    [join(dir, 'src/main.js')]: [join(dir, 'node_modules/lodash-es/lodash.js')],
    [join(dir, 'node_modules/lodash-es/lodash.js')]: [join(dir, 'node_modules/lodash-es/omit.js')],
    [join(dir, 'node_modules/lodash-es/omit.js')]: [],
  };
  const context = { getModuleIds: () => Object.keys(graph), getModuleInfo: (id) => ({ importedIds: graph[id] ?? [] }) };
  const bundle = {
    'a.js': {
      type: 'chunk',
      fileName: 'a.js',
      modules: {
        [join(dir, 'src/main.js')]: { renderedLength: 50 },
        [join(dir, 'node_modules/lodash-es/omit.js')]: { renderedLength: 90 },
      },
    },
  };

  plugin.generateBundle.call(context, { dir: join(dir, 'dist') }, bundle);
  plugin.closeBundle();

  const recorded = JSON.parse(readFileSync(join(dir, 'vexproof-modules.json'), 'utf8'));
  assert.deepEqual(recorded.inputs['node_modules/lodash-es/lodash.js'].imports, [{ path: 'node_modules/lodash-es/omit.js' }]);
});

// A deployment (--deploy) has no import graph, so who imports the vulnerable files is unknown on both sides.
// That neither confirms nor contradicts a review: the same version carries it, another version doesn't.
// (Before, every such review went back for re-confirming, and --fail-on new tripped on each one.)
test('without an import graph a review carries for the same version, and only for it', () => {
  const withoutGraph = (fixtureName) => {
    const meta = readFixture(fixtureName);
    for (const input of Object.values(meta.inputs ?? {})) delete input.imports;

    return meta;
  };

  const decide = ({ version, baseline }) => {
    const purl = `pkg:npm/lodash-es@${version}`;
    const lockfileSbom = {
      serialNumber: 'urn:uuid:11111111-2222-3333-4444-555555555555',
      version: 1,
      components: [{ 'bom-ref': purl, name: 'lodash-es', version, purl }],
    };
    const moduleMap = readModuleMap(withoutGraph('carry.metafile.json'));
    assert.equal(moduleMap.graph, null);

    const bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom, cwd: '/nonexistent' });
    const results = triage({
      lockfileSbom, bundleSbom, moduleMap, rules, moduleCheck: evaluateModuleRule, pro: true, findings: [{ purl, ids: [F23M] }],
    });
    attachFingerprints(results, {
      moduleMap,
      rules,
      cwd: '/x',
      readFile: (path) => Buffer.from(REAL[path.split(/[\\/]/).at(-1)] ?? 'other'),
    });
    if (baseline) applyBaseline(results, readBaseline(baseline), { now: new Date('2026-10-01'), maxAgeDays: 365 });

    const vex = toCycloneDxVex({
      results, bundleSbom, lockfileSbom, productPurl: 'pkg:npm/settings-panel@1.0.0', now: new Date('2026-10-01'),
    });
    return { result: results[0], vex };
  };

  const reviewed = review(decide({ version: '4.17.22' }).vex);
  const sameVersion = decide({ version: '4.17.22', baseline: reviewed }).result;
  assert.equal(sameVersion.state, 'not_affected');
  assert.equal(sameVersion.isNew, false);

  const nextVersion = decide({ version: '4.17.23', baseline: reviewed }).result;
  assert.equal(nextVersion.state, 'in_triage');
  assert.match(nextVersion.moduleReason, /it was for 4\.17\.22, and the code importing them could not be compared/);
});

test('a review whose date cannot be read counts as too old', () => {
  const reviewed = review(run().vex);
  for (const statement of reviewed.vulnerabilities) {
    for (const property of statement.properties) if (property.name === 'vexproof:reviewed-at') property.value = 'yesterday';
  }

  const [result] = run({ baseline: reviewed }).results;
  assert.equal(result.state, 'in_triage');
  assert.match(result.moduleReason, /its date could not be read/);
});

test('two installed copies of the same version: a change to either copy shows, identical copies are no change', () => {
  const fingerprintWith = (contentByRoot) => {
    const roots = Object.keys(contentByRoot);
    const moduleMap = {
      graph: null,
      packages: new Map([['lodash-es', {
        roots: new Set(roots),
        byRoot: new Map(roots.map((root) => [root, new Set(['_baseUnset.js', 'omit.js'])])),
        versionByRoot: new Map(roots.map((root) => [root, '4.17.22'])),
      }]]),
    };
    const results = [{ state: 'in_triage', purl: 'pkg:npm/lodash-es@4.17.22', id: F23M, aliases: [] }];

    attachFingerprints(results, {
      moduleMap,
      rules,
      cwd: '/x',
      readFile: (path) => {
        const root = roots.find((candidate) => path.replace(/\\/g, '/').startsWith(`/x/${candidate}/`));

        return Buffer.from(`${contentByRoot[root]}:${path.split(/[\\/]/).at(-1)}`);
      },
    });

    return results[0].fingerprint;
  };

  const oneCopy = fingerprintWith({ 'node_modules/lodash-es': 'original' });
  const twoIdentical = fingerprintWith({ 'node_modules/lodash-es': 'original', 'node_modules/app/node_modules/lodash-es': 'original' });
  const onePatched = fingerprintWith({ 'node_modules/lodash-es': 'original', 'node_modules/app/node_modules/lodash-es': 'patched' });
  const otherPatched = fingerprintWith({ 'node_modules/lodash-es': 'patched', 'node_modules/app/node_modules/lodash-es': 'original' });

  assert.deepEqual(twoIdentical.vulnerableFiles, ['_baseUnset.js', 'omit.js']);
  assert.equal(twoIdentical.fileCount, 2);
  assert.equal(twoIdentical.filesDigest, oneCopy.filesDigest);
  // one copy is hashed as before this change, so reviews recorded by an earlier vexproof still carry
  const contentHash = (text) => createHash('sha256').update(text).digest('hex').slice(0, 16);
  assert.equal(oneCopy.files['omit.js'], contentHash('original:omit.js'));
  assert.equal(twoIdentical.files['omit.js'], contentHash('original:omit.js'));

  assert.notEqual(onePatched.filesDigest, oneCopy.filesDigest);
  assert.notEqual(otherPatched.filesDigest, oneCopy.filesDigest);
});

test('paths holding spaces or "=" read back whole from the VEX properties', () => {
  const fingerprint = {
    vulnerableFiles: ['lib/my file.js', 'omit.js'],
    files: { 'lib/my file.js': '0123456789abcdef', 'a=b%20.js': 'fedcba9876543210' },
    fileCount: 2,
    filesDigest: '1111222233334444',
    importers: ['src/settings panel.js', 'src/main.js'],
  };

  const readBack = fingerprintFromProperties(fingerprintProperties(fingerprint));

  assert.deepEqual(readBack, fingerprint);

  // a path with none of those characters is written as before, so older VEX files read the same
  const plain = fingerprintProperties({ ...fingerprint, vulnerableFiles: ['omit.js'], importers: ['src/main.js'] });
  assert.equal(plain.find((property) => property.name === 'vexproof:vulnerable-files').value, 'omit.js');
  assert.equal(plain.find((property) => property.name === 'vexproof:importers').value, 'src/main.js');
});

test('a review that names no reviewer says so, rather than "undefined"', () => {
  const reviewed = review(run({ version: '4.17.22' }).vex);
  for (const statement of reviewed.vulnerabilities) {
    statement.properties = statement.properties.filter((property) => property.name !== 'vexproof:reviewed-by');
  }

  const carried = run({ version: '4.17.23', baseline: reviewed }).results[0];
  assert.match(carried.detail, /Carried forward from the review by an unnamed reviewer on 2026-09-27 for 4\.17\.22/);

  const changed = run({ version: '4.17.23', baseline: reviewed, files: { ...REAL, '_baseUnset.js': 'patched' } }).results[0];
  assert.match(changed.moduleReason, /the review by an unnamed reviewer on 2026-09-27 needs re-confirming/);
  assert.doesNotMatch(`${carried.detail} ${changed.moduleReason} ${changed.detail}`, /undefined/);
});

test('a review leaves no automatic evidence behind, renews the serial number, and removes a signature it broke', async () => {
  const { finishReview } = await import('../src/review.js');
  const vex = run().vex;
  const statement = vex.vulnerabilities.find((entry) => entry.id === F23M);
  statement.properties.push({ name: 'vexproof:rule-origin', value: 'derived: files changed between 4.17.22 and the fixed 4.17.23' });
  vex.signature = { algorithm: 'Ed25519', value: 'x' };
  const serialBefore = vex.serialNumber;

  review(vex);
  const { wasSigned } = finishReview(vex, { now: new Date('2026-09-28') });

  assert.equal(wasSigned, true);
  assert.equal(vex.signature, undefined);
  assert.ok(!statement.properties.some((entry) => entry.name === 'vexproof:rule-origin'));
  assert.notEqual(vex.serialNumber, serialBefore);
  assert.match(vex.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  assert.equal(vex.metadata.timestamp, '2026-09-28T00:00:00.000Z');
});
