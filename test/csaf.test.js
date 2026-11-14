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

const readFixture = (name) => JSON.parse(readFileSync(fixture(name)));
const lockfileSbom = readFixture('recharts.bom.lockfile.json');
const bundleSbom = readFixture('recharts.bom.bundle.json');
const APP = 'pkg:npm/my-app@1.4.0';
const publisher = { namespace: 'https://acme.example' };
const now = new Date('2026-11-05T12:00:00Z');

/** Results covering every CycloneDX state, so every CSAF mapping is exercised. */
function mixedResults() {
  const results = triage({ lockfileSbom, bundleSbom, findings: fromNpmAudit(readFixture('recharts.audit.json'), lockfileSbom) });
  assert.ok(results.length >= 3);
  results[0] = { ...results[0], state: 'exploitable', origin: 'reviewed', response: 'will_not_fix', detail: 'Reviewed: reachable from the upload form.' };
  results[1] = { ...results[1], state: 'not_affected', justification: 'code_not_present', level: 'module', detail: 'Vulnerable file _baseUnset.js not bundled.' };
  results.push({ ...results[2], id: 'GHSA-pkg1-pkg1-pkg1', aliases: [], purl: 'pkg:npm/moment@2.29.1', state: 'not_affected', justification: 'code_not_present', level: 'package', detail: 'moment is not in the bundle.' });
  results.push({ ...results[2], id: 'GHSA-zzzz-zzzz-zzzz', aliases: ['CVE-2026-9999'], purl: 'pkg:npm/moment@2.29.1', state: 'false_positive', origin: 'reviewed', detail: 'Not this code path.' });
  results.push({ ...results[2], id: 'CVE-2026-9999', aliases: [], purl: 'pkg:npm/dompurify@3.0.0', state: 'resolved', origin: 'reviewed', detail: 'Patched in our fork.' });
  results.push({ ...results[2], id: 'GHSA-rrrr-rrrr-rrrr', aliases: [], purl: 'pkg:npm/dompurify@3.0.0', state: 'not_affected', justification: 'requires_configuration', origin: 'reviewed', detail: 'Only with SAFE_FOR_TEMPLATES, which we never set.' });
  return results;
}

const validateAll = (doc) => validate([csaf_2_0_strict, ...Object.values(mandatory), ...Object.values(optional)], doc);
const problems = (report) => report.tests
  .filter((check) => check.errors?.length || check.warnings?.length)
  .map((check) => `${check.name}: ${[...(check.errors ?? []), ...(check.warnings ?? [])].map((issue) => issue.message).join('; ')}`);

test('a mixed document passes the schema and every mandatory test; only the known optional notes remain', async () => {
  const doc = toCsaf({
    results: mixedResults(),
    productPurl: APP,
    publisher,
    licensee: 'Acme GmbH',
    version: '1.0.0',
    url: 'https://acme.example/csaf/my-app-1_4_0-vex.json',
    now,
  });

  const report = await validateAll(doc);

  assert.equal(report.isValid, true, JSON.stringify(problems(report)));
  // 6.2.2 (no remediation while under investigation) and 6.2.3 (no CVSS) are deliberate: nothing is decided, and
  // vexproof has no scores of its own.
  assert.deepEqual(problems(report).map((problem) => problem.split(':')[0]).sort(), ['optionalTest_6_2_2', 'optionalTest_6_2_3']);
});

test('every CycloneDX state lands in the right CSAF status, flag and remediation', () => {
  const doc = toCsaf({ results: mixedResults(), productPurl: APP, publisher, licensee: 'Acme GmbH', now });
  assert.equal(doc.document.category, 'csaf_vex');
  assert.equal(doc.document.publisher.name, 'Acme GmbH');

  const byId = Object.fromEntries(doc.vulnerabilities.map((vulnerability) => [vulnerability.cve ?? vulnerability.ids[0].text, vulnerability]));
  const relationshipId = (purl) => `REL-${purl.replace(/^pkg:/, '').replace(/[^A-Za-z0-9.-]+/g, '_')}`;

  // exploitable → known_affected with a remediation from the response
  const affected = Object.values(byId).find((vulnerability) => vulnerability.product_status.known_affected);
  assert.equal(affected.remediations[0].category, 'no_fix_planned');

  // module-level not_affected → vulnerable_code_not_present; package-level → component_not_present
  const moduleLevel = Object.values(byId).find(
    (vulnerability) => vulnerability.flags?.some((flag) => flag.label === 'vulnerable_code_not_present'),
  );
  assert.ok(moduleLevel);
  assert.deepEqual(byId['GHSA-pkg1-pkg1-pkg1'].flags.map((flag) => flag.label), ['component_not_present']);
  assert.deepEqual(byId['GHSA-pkg1-pkg1-pkg1'].product_status, { known_not_affected: [relationshipId('pkg:npm/moment@2.29.1')] });

  // a reviewed justification maps to its CSAF flag
  assert.deepEqual(byId['GHSA-rrrr-rrrr-rrrr'].flags.map((flag) => flag.label), ['vulnerable_code_cannot_be_controlled_by_adversary']);

  // GHSA-zzzz (alias CVE-2026-9999, false positive on moment) and CVE-2026-9999 (resolved on dompurify) merge into
  // one entry, since CSAF allows one entry per CVE
  const merged = byId['CVE-2026-9999'];
  assert.deepEqual(merged.ids.map((identifier) => identifier.text), ['GHSA-zzzz-zzzz-zzzz']);
  assert.deepEqual(merged.product_status, {
    fixed: [relationshipId('pkg:npm/dompurify@3.0.0')],
    known_not_affected: [relationshipId('pkg:npm/moment@2.29.1')],
  });
  assert.ok(merged.threats.some((threat) => threat.details.startsWith('False positive')));

  // every product id in a status exists in the tree
  const ids = new Set(doc.product_tree.relationships.map((relationship) => relationship.full_product_name.product_id));
  for (const vulnerability of doc.vulnerabilities) {
    for (const list of Object.values(vulnerability.product_status)) {
      for (const id of list) assert.ok(ids.has(id), id);
    }
  }
});

test('tracking: default id and file name, versions, drafts, and revisions that carry history forward', async () => {
  assert.equal(defaultTrackingId('pkg:npm/%40acme/web-app@2.0.0-rc.1'), 'ACME-WEB-APP-2.0.0-RC.1-VEX');
  assert.equal(csafFileName('ACME-WEB-APP-2.0.0-RC.1-VEX'), 'acme-web-app-2_0_0-rc_1-vex.json');

  const results = mixedResults();
  const firstVersion = toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', now });
  assert.equal(firstVersion.document.tracking.version, '1');
  assert.equal(firstVersion.document.tracking.revision_history.length, 1);

  const secondVersion = toCsaf({
    results,
    productPurl: APP,
    publisher,
    licensee: 'Acme',
    previous: firstVersion,
    now: new Date(now.getTime() + 86400e3),
  });
  assert.equal(secondVersion.document.tracking.version, '2');
  assert.equal(secondVersion.document.tracking.initial_release_date, firstVersion.document.tracking.initial_release_date);
  assert.deepEqual(secondVersion.document.tracking.revision_history.map((revision) => revision.number), ['1', '2']);
  assert.equal((await validate([csaf_2_0_strict, ...Object.values(mandatory)], secondVersion)).isValid, true);

  const draft = toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', status: 'draft', now });
  assert.equal(draft.document.tracking.version, '0');
  assert.equal((await validate([csaf_2_0_strict, ...Object.values(mandatory)], draft)).isValid, true);

  assert.throws(
    () => toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', previous: firstVersion, trackingId: 'OTHER-ID' }),
    /tracking id/,
  );
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

test('the document\'s keys are in sorted order, and it is the same for the same input', () => {
  const results = mixedResults();

  const forward = toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', now });
  const reversed = toCsaf({ results: [...results].reverse(), productPurl: APP, publisher, licensee: 'Acme', now });

  assert.deepEqual(forward, reversed);
  assert.equal(JSON.stringify(forward), JSON.stringify(sortKeys(forward)));
});

test('CLI: --csaf writes the document next to the VEX, needs a namespace, and is skipped without a license', (context) => {
  const { dir, run } = proCopy(context);
  const base = [
    '--lockfile', fixture('recharts.bom.lockfile.json'),
    '--findings', fixture('recharts.audit.json'),
    '--bundle', fixture('recharts.bom.bundle.json'),
    '--product', APP,
    '--out', join(dir, 'vex.cdx.json'),
  ];

  const ok = run([
    ...base,
    '--csaf', join(dir, 'vex.csaf.json'),
    '--csaf-namespace', 'https://acme.example',
    '--csaf-url', 'https://acme.example/csaf/other-name.json',
  ]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stderr, /publish it as my-app-1_4_0-vex\.json/);
  const written = readFileSync(join(dir, 'vex.csaf.json'), 'utf8');
  const doc = JSON.parse(written);
  assert.equal(written, JSON.stringify(sortKeys(doc), null, 2)); // the file, as written, has its keys sorted
  assert.equal(doc.document.publisher.name, 'Acme GmbH');
  assert.equal(doc.document.references[0].url, 'https://acme.example/csaf/other-name.json');
  assert.match(ok.stderr, /--csaf-url should end with my-app-1_4_0-vex\.json/);

  const noNamespace = run([...base, '--csaf', join(dir, 'c2.json')]);
  assert.equal(noNamespace.status, 2);
  assert.match(noNamespace.stderr, /--csaf-namespace/);
  assert.ok(!existsSync(join(dir, 'c2.json')));

  const free = run([...base, '--csaf', join(dir, 'c3.json'), '--csaf-namespace', 'https://acme.example'], { license: null });
  assert.equal(free.status, 0, free.stderr);
  assert.match(free.stderr, /--csaf is a Pro feature; skipped/);
  assert.ok(!existsSync(join(dir, 'c3.json')));
});

// ---------- found by the code audit of 1.0.0-beta.9 ----------

const strict = (doc) => validate([csaf_2_0_strict, ...Object.values(mandatory)], doc);

test('a draft can be revised as a draft, and released; a released document does not go back to draft', async () => {
  const results = mixedResults();
  const later = (days) => new Date(now.getTime() + days * 86400e3);
  const draft = toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', status: 'draft', now });

  const draftAgain = toCsaf({
    results, productPurl: APP, publisher, licensee: 'Acme', status: 'draft', previous: draft, now: later(1),
  });
  assert.equal(draftAgain.document.tracking.version, '0');
  assert.deepEqual(draftAgain.document.tracking.revision_history.map((entry) => entry.number), ['0']);
  assert.equal((await strict(draftAgain)).isValid, true);

  const released = toCsaf({
    results, productPurl: APP, publisher, licensee: 'Acme', status: 'final', previous: draftAgain, now: later(2),
  });
  assert.equal(released.document.tracking.version, '1');
  assert.deepEqual(released.document.tracking.revision_history.map((entry) => entry.number), ['1']);
  assert.equal(released.document.tracking.initial_release_date, later(2).toISOString());
  assert.equal((await strict(released)).isValid, true);

  assert.throws(
    () => toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', status: 'draft', previous: released, now: later(3) }),
    /can't become a draft again/,
  );
});

test('no findings: no CSAF document, whatever its status', () => {
  for (const status of ['draft', 'interim', 'final']) {
    assert.throws(() => toCsaf({ results: [], productPurl: APP, publisher, licensee: 'Acme', status, now }), /nothing to say/, status);
  }
});

test('product ids are unique: names that read alike get a hash, and a package is listed once per status', async () => {
  const base = mixedResults()[2];
  const results = [
    { ...base, id: 'GHSA-aaaa-aaaa-aaaa', aliases: [], purl: 'pkg:npm/%40a/b_c@1.0.0', state: 'not_affected', justification: 'code_not_present', level: 'package', detail: 'absent' },
    { ...base, id: 'GHSA-bbbb-bbbb-bbbb', aliases: [], purl: 'pkg:npm/%40a_b/c@1.0.0', state: 'not_affected', justification: 'code_not_present', level: 'package', detail: 'absent' },
    // one advisory reported under both its ids, on one package
    { ...base, id: 'GHSA-cccc-cccc-cccc', aliases: ['CVE-2026-1111'], purl: 'pkg:npm/x@1.0.0', state: 'not_affected', justification: 'code_not_present', level: 'package', detail: 'absent' },
    { ...base, id: 'CVE-2026-1111', aliases: [], purl: 'pkg:npm/x@1.0.0', state: 'not_affected', justification: 'code_not_present', level: 'package', detail: 'absent' },
  ];

  const doc = toCsaf({ results, productPurl: APP, publisher, licensee: 'Acme', now });

  const ids = doc.product_tree.full_product_names.map((entry) => entry.product_id);
  assert.equal(new Set(ids).size, ids.length);
  const cve = doc.vulnerabilities.find((entry) => entry.cve === 'CVE-2026-1111');
  assert.equal(cve.product_status.known_not_affected.length, 1);
  assert.equal((await strict(doc)).isValid, true);
});
