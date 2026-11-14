// SPDX-License-Identifier: MIT
// Rollup (Pro): one CycloneDX VEX for an organization from each application's VEX.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { triage, toCycloneDxVex } from '../src/index.js';
import { fromNpmAudit } from '../src/sources.js';
import { recordReview } from '../src/review.js';
import { readApplication, rollup } from '../src/pro/rollup.js';
import { verifyCycloneDx } from '../src/pro/sign.js';
import { proCopy, fixture } from './lib/pro-copy.js';

const require = createRequire(import.meta.url);
const readFixture = (name) => JSON.parse(readFileSync(fixture(name)));
const lockfileSbom = readFixture('recharts.bom.lockfile.json');
const withLodash = readFixture('recharts.bom.bundle.json');
const withoutLodash = { ...withLodash, components: withLodash.components.filter((component) => !/lodash/.test(component.purl ?? '')) };
const findings = () => fromNpmAudit(readFixture('recharts.audit.json'), lockfileSbom);
const propertyValue = (statement, name) => statement.properties?.find((property) => property.name === name)?.value;

/** Two applications: A ships lodash (open findings, one reviewed), B does not (settled at package level). */
function twoApps() {
  const appA = toCycloneDxVex({
    results: triage({ lockfileSbom, bundleSbom: withLodash, findings: findings() }),
    lockfileSbom,
    bundleSbom: withLodash,
    productPurl: 'pkg:npm/app-a@1.0.0',
  });
  recordReview(appA, {
    id: appA.vulnerabilities[0].id,
    state: 'not_affected',
    justification: 'code_not_reachable',
    detail: 'Never called with user input.',
    by: 'Jane Doe',
  });
  const appB = toCycloneDxVex({
    results: triage({ lockfileSbom, bundleSbom: withoutLodash, findings: findings() }),
    lockfileSbom,
    bundleSbom: withoutLodash,
    productPurl: 'pkg:npm/app-b@2.0.0',
  });
  return { appA, appB };
}

test('statements keep their evidence, name their application, and settled ones come first', async () => {
  const { appA, appB } = twoApps();
  const apps = [{ file: 'b.json', vex: appB, sha256: 'bb' }, { file: 'a.json', vex: appA, sha256: 'aa' }].map(readApplication);

  const { vex, summary } = rollup({ apps, productPurl: 'pkg:generic/acme-platform@2026.11', licensee: 'Acme GmbH', version: '1.0.0' });

  assert.deepEqual(vex.components.map((component) => component['bom-ref']), ['pkg:npm/app-a@1.0.0', 'pkg:npm/app-b@2.0.0']);
  assert.equal(vex.vulnerabilities.length, appA.vulnerabilities.length + appB.vulnerabilities.length);
  for (const statement of vex.vulnerabilities) {
    assert.ok(propertyValue(statement, 'vexproof:package'));
    assert.ok(['pkg:npm/app-a@1.0.0', 'pkg:npm/app-b@2.0.0'].includes(propertyValue(statement, 'vexproof:application')));
    assert.deepEqual(statement.affects, [{ ref: propertyValue(statement, 'vexproof:application') }]);
  }
  const states = vex.vulnerabilities.map((statement) => (statement.analysis.state === 'in_triage' ? 1 : 0));
  assert.deepEqual(states, [...states].sort());
  const reviewed = vex.vulnerabilities.find((statement) => propertyValue(statement, 'vexproof:reviewed-by'));
  assert.equal(reviewed.analysis.state, 'not_affected');
  assert.equal(propertyValue(reviewed, 'vexproof:application'), 'pkg:npm/app-a@1.0.0');
  assert.deepEqual(
    summary.applications.map((application) => [application.purl, application.not_affected, application.in_triage, application.reviewed]),
    [['pkg:npm/app-a@1.0.0', 1, 2, 1], ['pkg:npm/app-b@2.0.0', 3, 0, 0]],
  );

  // the two open ones on app A are settled on app B: those are the disagreements
  assert.equal(summary.disagreements.length, 2);
  assert.ok(summary.disagreements.every((disagreement) => disagreement.applications.length === 2));
  assert.equal(vex.metadata.properties.find((property) => property.name === 'vexproof:rollup').value, '2');
  assert.equal(vex.metadata.properties.find((property) => property.name === 'vexproof:licensee').value, 'Acme GmbH');
  const { Validation, Spec } = require('@cyclonedx/cyclonedx-library');
  assert.equal(await new Validation.JsonStrictValidator(Spec.Version.v1dot6).validate(JSON.stringify(vex)), null);

  // deterministic
  const again = rollup({
    apps: [...apps].reverse(),
    productPurl: 'pkg:generic/acme-platform@2026.11',
    licensee: 'Acme GmbH',
    version: '1.0.0',
    now: new Date(vex.metadata.timestamp),
  });
  assert.deepEqual(again.vex, vex);
});

test('inputs that are not vexproof VEX, duplicates, and a missing product are refused', () => {
  const { appA } = twoApps();

  assert.throws(() => readApplication({ file: 'x.json', vex: { foo: 1 }, sha256: '' }), /not a CycloneDX VEX/);

  const stripped = JSON.parse(JSON.stringify(appA));
  for (const statement of stripped.vulnerabilities) statement.properties = [];
  assert.throws(() => readApplication({ file: 'x.json', vex: stripped, sha256: '' }), /only vexproof's own VEX/);

  const app = readApplication({ file: 'a.json', vex: appA, sha256: 'aa' });
  assert.throws(() => rollup({ apps: [app, app], productPurl: 'pkg:generic/x@1' }), /two VEX files describe/);
  assert.throws(() => rollup({ apps: [app] }), /--product/);
});

test('CLI: rollup is gated, writes a signed document, and reports disagreements on stderr', (context) => {
  const { dir, run } = proCopy(context);
  const { appA, appB } = twoApps();
  writeFileSync(join(dir, 'a.json'), JSON.stringify(appA));
  writeFileSync(join(dir, 'b.json'), JSON.stringify(appB));

  const free = run([
    'rollup',
    '--vex', join(dir, 'a.json'),
    '--vex', join(dir, 'b.json'),
    '--product', 'pkg:generic/acme@1',
    '--out', join(dir, 'r.json'),
  ], { license: null });
  assert.equal(free.status, 2);
  assert.match(free.stderr, /Pro feature/);
  assert.ok(!existsSync(join(dir, 'r.json')));
  assert.equal(run(['rollup', '--product', 'pkg:generic/acme@1']).status, 2, 'needs --vex');

  run(['keygen', '--out', join(dir, 'k')], { license: null });
  const result = run([
    'rollup',
    '--vex', join(dir, 'a.json'),
    '--vex', join(dir, 'b.json'),
    '--product', 'pkg:generic/acme@1',
    '--out', join(dir, 'r.json'),
    '--sign', join(dir, 'k.pem'),
    '--signer', 'Acme',
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /2 application\(s\), 6 statement\(s\)/);
  assert.match(result.stdout, /signed by Acme/);
  assert.match(result.stderr, /differs between applications/);
  const doc = JSON.parse(readFileSync(join(dir, 'r.json'), 'utf8'));
  assert.equal(verifyCycloneDx(doc).ok, true);
  assert.equal(run(['verify', join(dir, 'r.json')], { license: null }).status, 0);
});

test('a disagreement is found when the applications name the advisory by different ids', () => {
  const pkg = 'pkg:npm/lodash@4.17.20';
  const statement = (id, references, state) => ({
    id, ...(references.length ? { references: references.map((ref) => ({ id: ref, source: { name: 'NVD' } })) } : {}),
    analysis: { state }, affects: [{ ref: 'x' }], properties: [{ name: 'vexproof:package', value: pkg }],
  });
  const app = (purl, statements) => readApplication({
    file: `${purl}.json`,
    sha256: 'x',
    vex: { bomFormat: 'CycloneDX', metadata: { component: { purl, name: purl } }, vulnerabilities: statements },
  });

  // app A scanned with GHSA ids (the CVE is a reference), app B with CVE ids (the GHSA is a reference)
  const apps = [
    app('pkg:npm/a@1', [statement('GHSA-35jh-r3h4-6jhm', ['CVE-2021-23337'], 'not_affected')]),
    app('pkg:npm/b@1', [statement('CVE-2021-23337', ['GHSA-35jh-r3h4-6jhm'], 'in_triage')]),
  ];
  const { summary } = rollup({ apps, productPurl: 'pkg:generic/acme@2026' });

  assert.equal(summary.disagreements.length, 1);
  assert.equal(summary.disagreements[0].id, 'GHSA-35jh-r3h4-6jhm');
  assert.deepEqual(summary.disagreements[0].applications.map((entry) => entry.state).sort(), ['in_triage', 'not_affected']);
});
