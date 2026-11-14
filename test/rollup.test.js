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
const fx = (f) => JSON.parse(readFileSync(fixture(f)));
const lockfileSbom = fx('recharts.bom.lockfile.json');
const withLodash = fx('recharts.bom.bundle.json');
const withoutLodash = { ...withLodash, components: withLodash.components.filter((c) => !/lodash/.test(c.purl ?? '')) };
const findings = () => fromNpmAudit(fx('recharts.audit.json'), lockfileSbom);
const prop = (v, name) => v.properties?.find((p) => p.name === name)?.value;

/** Two applications: A ships lodash (open findings, one reviewed), B does not (settled at package level). */
function twoApps() {
  const a = toCycloneDxVex({ results: triage({ lockfileSbom, bundleSbom: withLodash, findings: findings() }), lockfileSbom, bundleSbom: withLodash, productPurl: 'pkg:npm/app-a@1.0.0' });
  recordReview(a, { id: a.vulnerabilities[0].id, state: 'not_affected', justification: 'code_not_reachable', detail: 'Never called with user input.', by: 'Jane Doe' });
  const b = toCycloneDxVex({ results: triage({ lockfileSbom, bundleSbom: withoutLodash, findings: findings() }), lockfileSbom, bundleSbom: withoutLodash, productPurl: 'pkg:npm/app-b@2.0.0' });
  return { a, b };
}

test('statements keep their evidence, name their application, and settled ones come first', async () => {
  const { a, b } = twoApps();
  const apps = [{ file: 'b.json', vex: b, sha256: 'bb' }, { file: 'a.json', vex: a, sha256: 'aa' }].map(readApplication);
  const { vex, summary } = rollup({ apps, productPurl: 'pkg:generic/acme-platform@2026.11', licensee: 'Acme GmbH', version: '1.0.0' });
  assert.deepEqual(vex.components.map((c) => c['bom-ref']), ['pkg:npm/app-a@1.0.0', 'pkg:npm/app-b@2.0.0']);
  assert.equal(vex.vulnerabilities.length, a.vulnerabilities.length + b.vulnerabilities.length);
  for (const v of vex.vulnerabilities) {
    assert.ok(prop(v, 'vexproof:package'));
    assert.ok(['pkg:npm/app-a@1.0.0', 'pkg:npm/app-b@2.0.0'].includes(prop(v, 'vexproof:application')));
    assert.deepEqual(v.affects, [{ ref: prop(v, 'vexproof:application') }]);
  }
  const states = vex.vulnerabilities.map((v) => (v.analysis.state === 'in_triage' ? 1 : 0));
  assert.deepEqual(states, [...states].sort());
  const reviewed = vex.vulnerabilities.find((v) => prop(v, 'vexproof:reviewed-by'));
  assert.equal(reviewed.analysis.state, 'not_affected');
  assert.equal(prop(reviewed, 'vexproof:application'), 'pkg:npm/app-a@1.0.0');
  assert.deepEqual(summary.applications.map((s) => [s.purl, s.not_affected, s.in_triage, s.reviewed]), [['pkg:npm/app-a@1.0.0', 1, 2, 1], ['pkg:npm/app-b@2.0.0', 3, 0, 0]]);
  // the two open ones on app A are settled on app B: those are the disagreements
  assert.equal(summary.disagreements.length, 2);
  assert.ok(summary.disagreements.every((d) => d.applications.length === 2));
  assert.equal(vex.metadata.properties.find((p) => p.name === 'vexproof:rollup').value, '2');
  assert.equal(vex.metadata.properties.find((p) => p.name === 'vexproof:licensee').value, 'Acme GmbH');
  const { Validation, Spec } = require('@cyclonedx/cyclonedx-library');
  assert.equal(await new Validation.JsonStrictValidator(Spec.Version.v1dot6).validate(JSON.stringify(vex)), null);
  // deterministic
  const again = rollup({ apps: [...apps].reverse(), productPurl: 'pkg:generic/acme-platform@2026.11', licensee: 'Acme GmbH', version: '1.0.0', now: new Date(vex.metadata.timestamp) });
  assert.deepEqual(again.vex, vex);
});

test('inputs that are not vexproof VEX, duplicates, and a missing product are refused', () => {
  const { a } = twoApps();
  assert.throws(() => readApplication({ file: 'x.json', vex: { foo: 1 }, sha256: '' }), /not a CycloneDX VEX/);
  const stripped = JSON.parse(JSON.stringify(a));
  for (const v of stripped.vulnerabilities) v.properties = [];
  assert.throws(() => readApplication({ file: 'x.json', vex: stripped, sha256: '' }), /only vexproof's own VEX/);
  const app = readApplication({ file: 'a.json', vex: a, sha256: 'aa' });
  assert.throws(() => rollup({ apps: [app, app], productPurl: 'pkg:generic/x@1' }), /two VEX files describe/);
  assert.throws(() => rollup({ apps: [app] }), /--product/);
});

test('CLI: rollup is gated, writes a signed document, and reports disagreements on stderr', (t) => {
  const { dir, run } = proCopy(t);
  const { a, b } = twoApps();
  writeFileSync(join(dir, 'a.json'), JSON.stringify(a));
  writeFileSync(join(dir, 'b.json'), JSON.stringify(b));
  const free = run(['rollup', '--vex', join(dir, 'a.json'), '--vex', join(dir, 'b.json'), '--product', 'pkg:generic/acme@1', '--out', join(dir, 'r.json')], { license: null });
  assert.equal(free.status, 2);
  assert.match(free.stderr, /Pro feature/);
  assert.ok(!existsSync(join(dir, 'r.json')));
  assert.equal(run(['rollup', '--product', 'pkg:generic/acme@1']).status, 2, 'needs --vex');

  run(['keygen', '--out', join(dir, 'k')], { license: null });
  const r = run(['rollup', '--vex', join(dir, 'a.json'), '--vex', join(dir, 'b.json'), '--product', 'pkg:generic/acme@1', '--out', join(dir, 'r.json'), '--sign', join(dir, 'k.pem'), '--signer', 'Acme']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /2 application\(s\), 6 statement\(s\)/);
  assert.match(r.stdout, /signed by Acme/);
  assert.match(r.stderr, /differs between applications/);
  const doc = JSON.parse(readFileSync(join(dir, 'r.json'), 'utf8'));
  assert.equal(verifyCycloneDx(doc).ok, true);
  assert.equal(run(['verify', join(dir, 'r.json')], { license: null }).status, 0);
});
