// SPDX-License-Identifier: MIT
// CSAF 2.0 VEX (Pro): checked with BSI's validator (schema, every mandatory test, the optional ones that apply).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import validate from '@secvisogram/csaf-validator-lib/validate.js';
import { csaf_2_0_strict } from '@secvisogram/csaf-validator-lib/schemaTests.js';
import * as mandatory from '@secvisogram/csaf-validator-lib/mandatoryTests.js';
import * as optional from '@secvisogram/csaf-validator-lib/optionalTests.js';
import { triage } from '../src/index.js';
import { fromNpmAudit } from '../src/sources.js';
import { toCsaf, csafFileName, defaultTrackingId, sortKeys } from '../src/pro/csaf.js';
import { proCopy, fixture } from './lib/pro-copy.js';

const fx = (f) => JSON.parse(readFileSync(fixture(f)));
const lockfileSbom = fx('recharts.bom.lockfile.json');
const bundleSbom = fx('recharts.bom.bundle.json');
const APP = 'pkg:npm/my-app@1.4.0';
const publisher = { namespace: 'https://acme.example' };
const now = new Date('2026-11-05T12:00:00Z');

/** Results covering every CycloneDX state, so every CSAF mapping is exercised. */
function mixedResults() {
  const rs = triage({ lockfileSbom, bundleSbom, findings: fromNpmAudit(fx('recharts.audit.json'), lockfileSbom) });
  assert.ok(rs.length >= 3);
  rs[0] = { ...rs[0], state: 'exploitable', origin: 'reviewed', response: 'will_not_fix', detail: 'Reviewed: reachable from the upload form.' };
  rs[1] = { ...rs[1], state: 'not_affected', justification: 'code_not_present', level: 'module', detail: 'Vulnerable file _baseUnset.js not bundled.' };
  rs.push({ ...rs[2], id: 'GHSA-pkg1-pkg1-pkg1', aliases: [], purl: 'pkg:npm/moment@2.29.1', state: 'not_affected', justification: 'code_not_present', level: 'package', detail: 'moment is not in the bundle.' });
  rs.push({ ...rs[2], id: 'GHSA-zzzz-zzzz-zzzz', aliases: ['CVE-2026-9999'], purl: 'pkg:npm/moment@2.29.1', state: 'false_positive', origin: 'reviewed', detail: 'Not this code path.' });
  rs.push({ ...rs[2], id: 'CVE-2026-9999', aliases: [], purl: 'pkg:npm/dompurify@3.0.0', state: 'resolved', origin: 'reviewed', detail: 'Patched in our fork.' });
  rs.push({ ...rs[2], id: 'GHSA-rrrr-rrrr-rrrr', aliases: [], purl: 'pkg:npm/dompurify@3.0.0', state: 'not_affected', justification: 'requires_configuration', origin: 'reviewed', detail: 'Only with SAFE_FOR_TEMPLATES, which we never set.' });
  return rs;
}

const validateAll = (doc) => validate([csaf_2_0_strict, ...Object.values(mandatory), ...Object.values(optional)], doc);
const problems = (r) => r.tests.filter((t) => t.errors?.length || t.warnings?.length).map((t) => `${t.name}: ${[...(t.errors ?? []), ...(t.warnings ?? [])].map((e) => e.message).join('; ')}`);

test('a mixed document passes the schema and every mandatory test; only the known optional notes remain', async () => {
  const doc = toCsaf({ results: mixedResults(), productPurl: APP, publisher, licensee: 'Acme GmbH', version: '1.0.0', url: 'https://acme.example/csaf/my-app-1_4_0-vex.json', now });
  const r = await validateAll(doc);
  assert.equal(r.isValid, true, JSON.stringify(problems(r)));
  // 6.2.2 (no remediation while under investigation) and 6.2.3 (no CVSS) are deliberate: nothing is decided, and
  // vexproof has no scores of its own.
  assert.deepEqual(problems(r).map((p) => p.split(':')[0]).sort(), ['optionalTest_6_2_2', 'optionalTest_6_2_3']);
});

test('every CycloneDX state lands in the right CSAF status, flag and remediation', () => {
  const doc = toCsaf({ results: mixedResults(), productPurl: APP, publisher, licensee: 'Acme GmbH', now });
  assert.equal(doc.document.category, 'csaf_vex');
  assert.equal(doc.document.publisher.name, 'Acme GmbH');
  const by = Object.fromEntries(doc.vulnerabilities.map((v) => [v.cve ?? v.ids[0].text, v]));
  const rel = (purl) => `REL-${purl.replace(/^pkg:/, '').replace(/[^A-Za-z0-9.-]+/g, '_')}`;
  // exploitable → known_affected with a remediation from the response
  const affected = Object.values(by).find((v) => v.product_status.known_affected);
  assert.equal(affected.remediations[0].category, 'no_fix_planned');
  // module-level not_affected → vulnerable_code_not_present; package-level → component_not_present
  const moduleLevel = Object.values(by).find((v) => v.flags?.some((f) => f.label === 'vulnerable_code_not_present'));
  assert.ok(moduleLevel);
  assert.deepEqual(by['GHSA-pkg1-pkg1-pkg1'].flags.map((f) => f.label), ['component_not_present']);
  assert.deepEqual(by['GHSA-pkg1-pkg1-pkg1'].product_status, { known_not_affected: [rel('pkg:npm/moment@2.29.1')] });
  // a reviewed justification maps to its CSAF flag
  assert.deepEqual(by['GHSA-rrrr-rrrr-rrrr'].flags.map((f) => f.label), ['vulnerable_code_cannot_be_controlled_by_adversary']);
  // GHSA-zzzz (alias CVE-2026-9999, false positive on moment) and CVE-2026-9999 (resolved on dompurify) merge into
  // one entry, since CSAF allows one entry per CVE
  const merged = by['CVE-2026-9999'];
  assert.deepEqual(merged.ids.map((i) => i.text), ['GHSA-zzzz-zzzz-zzzz']);
  assert.deepEqual(merged.product_status, { fixed: [rel('pkg:npm/dompurify@3.0.0')], known_not_affected: [rel('pkg:npm/moment@2.29.1')] });
  assert.ok(merged.threats.some((t) => t.details.startsWith('False positive')));
  // every product id in a status exists in the tree
  const ids = new Set(doc.product_tree.relationships.map((r) => r.full_product_name.product_id));
  for (const v of doc.vulnerabilities) for (const list of Object.values(v.product_status)) for (const id of list) assert.ok(ids.has(id), id);
});

test('tracking: default id and file name, versions, drafts, and revisions that carry history forward', async () => {
  assert.equal(defaultTrackingId('pkg:npm/%40acme/web-app@2.0.0-rc.1'), 'ACME-WEB-APP-2.0.0-RC.1-VEX');
  assert.equal(csafFileName('ACME-WEB-APP-2.0.0-RC.1-VEX'), 'acme-web-app-2_0_0-rc_1-vex.json');
  const results = mixedResults();
  const v1 = toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', now });
  assert.equal(v1.document.tracking.version, '1');
  assert.equal(v1.document.tracking.revision_history.length, 1);
  const v2 = toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', previous: v1, now: new Date(now.getTime() + 86400e3) });
  assert.equal(v2.document.tracking.version, '2');
  assert.equal(v2.document.tracking.initial_release_date, v1.document.tracking.initial_release_date);
  assert.deepEqual(v2.document.tracking.revision_history.map((h) => h.number), ['1', '2']);
  assert.equal((await validate([csaf_2_0_strict, ...Object.values(mandatory)], v2)).isValid, true);
  const draft = toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', status: 'draft', now });
  assert.equal(draft.document.tracking.version, '0');
  assert.equal((await validate([csaf_2_0_strict, ...Object.values(mandatory)], draft)).isValid, true);
  assert.throws(() => toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', previous: v1, trackingId: 'OTHER-ID' }), /tracking id/);
});

test('what the spec needs and vexproof cannot infer is an error, not a guess', () => {
  const results = mixedResults();
  assert.throws(() => toCsaf({ results, productPurl: APP, publisher: {}, licensee: 'Acme' }), /--csaf-namespace/);
  assert.throws(() => toCsaf({ results, productPurl: APP, publisher: { namespace: 'acme.example' }, licensee: 'Acme' }), /namespace URL/);
  assert.throws(() => toCsaf({ results, productPurl: APP, publisher }), /--csaf-publisher/);
  assert.throws(() => toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', tlp: 'CLEAR' }), /--csaf-tlp/);
  assert.throws(() => toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', status: 'published' }), /--csaf-status/);
  assert.throws(() => toCsaf({ results: [], productPurl: APP, publisher, licensee: 'Acme' }), /nothing to say/);
});

test('the document is written with sorted keys and is the same for the same input', () => {
  const results = mixedResults();
  const a = toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', now });
  const b = toCsaf({ results: [...results].reverse(), productPurl: APP, publisher, licensee: 'Acme', now });
  assert.deepEqual(a, b);
  assert.equal(JSON.stringify(a), JSON.stringify(sortKeys(a)));
});

test('CLI: --csaf writes the document next to the VEX, needs a namespace, and is skipped without a license', () => {
  const { dir, run } = proCopy();
  const base = ['--lockfile', fixture('recharts.bom.lockfile.json'), '--findings', fixture('recharts.audit.json'), '--bundle', fixture('recharts.bom.bundle.json'), '--product', APP, '--out', join(dir, 'vex.cdx.json')];
  const ok = run([...base, '--csaf', join(dir, 'vex.csaf.json'), '--csaf-namespace', 'https://acme.example', '--csaf-url', 'https://acme.example/csaf/other-name.json']);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stderr, /publish it as my-app-1_4_0-vex\.json/);
  const doc = JSON.parse(readFileSync(join(dir, 'vex.csaf.json'), 'utf8'));
  assert.equal(doc.document.publisher.name, 'Acme GmbH');
  assert.equal(doc.document.references[0].url, 'https://acme.example/csaf/other-name.json');
  assert.match(ok.stderr, /--csaf-url should end with my-app-1_4_0-vex\.json/);

  const noNs = run([...base, '--csaf', join(dir, 'c2.json')]);
  assert.equal(noNs.status, 2);
  assert.match(noNs.stderr, /--csaf-namespace/);
  assert.ok(!existsSync(join(dir, 'c2.json')));

  const free = run([...base, '--csaf', join(dir, 'c3.json'), '--csaf-namespace', 'https://acme.example'], { license: null });
  assert.equal(free.status, 0, free.stderr);
  assert.match(free.stderr, /--csaf is a Pro feature; skipped/);
  assert.ok(!existsSync(join(dir, 'c3.json')));
});
