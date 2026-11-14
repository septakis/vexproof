// SPDX-License-Identifier: MIT
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fetchOsvFindings, fromNpmAudit, detectFormat } from '../src/sources.js';
import { triage } from '../src/index.js';

const lockfile = { components: [
  { type: 'library', purl: 'pkg:npm/lodash@4.17.20' },
  { type: 'library', purl: 'pkg:npm/qs@6.5.2' },
  { type: 'library', purl: 'pkg:npm/ms@2.1.3' },
]};

test('fetchOsvFindings batches lockfile packages into a querybatch call', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) });
    return { ok: true, json: async () => ({ results: [
      { vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }, { id: 'GHSA-29mw-wpgm-hmr9' }] },
      { vulns: [{ id: 'GHSA-hrpp-h998-j3pp' }] },
      {},
    ]}) };
  };

  const findings = await fetchOsvFindings(lockfile, { fetchImpl });

  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].body.queries[0], { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' });
  assert.deepEqual(findings, [
    { purl: 'pkg:npm/lodash@4.17.20', ids: ['GHSA-35jh-r3h4-6jhm', 'GHSA-29mw-wpgm-hmr9'] },
    { purl: 'pkg:npm/qs@6.5.2', ids: ['GHSA-hrpp-h998-j3pp'] },
  ]);
});

test('fetchOsvFindings surfaces HTTP failures instead of returning empty findings', async () => {
  await assert.rejects(fetchOsvFindings(lockfile, { fetchImpl: async () => ({ ok: false, status: 403 }) }), /HTTP 403/);
});

test('fromNpmAudit reads a real `npm audit --json` and feeds triage', () => {
  const audit = JSON.parse(readFileSync(new URL('./fixtures/npm-audit.json', import.meta.url)));
  assert.equal(detectFormat(audit), 'npm-audit');

  const findings = fromNpmAudit(audit, lockfile);
  const names = [...new Set(findings.map((finding) => finding.purl))].sort();
  assert.deepEqual(names, ['pkg:npm/lodash@4.17.20', 'pkg:npm/qs@6.5.2']);
  assert.ok(findings.every((finding) => finding.id.startsWith('GHSA-')));

  const bundle = { components: [{ type: 'library', purl: 'pkg:npm/ms@2.1.3' }] };
  const results = triage({ lockfileSbom: lockfile, bundleSbom: bundle, findings });
  assert.ok(results.length >= 2 && results.every((result) => result.state === 'not_affected'));
});

test('npm audit: each advisory lands on the installed versions inside its range', () => {
  const lock = { components: [{ purl: 'pkg:npm/postcss@8.5.23' }, { purl: 'pkg:npm/postcss@8.4.30' }] };
  const audit = { auditReportVersion: 2, vulnerabilities: { postcss: { via: [
    { url: 'https://github.com/advisories/GHSA-7fh5-64p2-3v2j', range: '<8.4.31' },
    { url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', range: '<9.0.0' },
  ] } } };

  const pairs = fromNpmAudit(audit, lock).map((finding) => `${finding.id} ${finding.purl}`).sort();

  assert.deepEqual(pairs, [
    'GHSA-7fh5-64p2-3v2j pkg:npm/postcss@8.4.30',
    'GHSA-aaaa-bbbb-cccc pkg:npm/postcss@8.4.30',
    'GHSA-aaaa-bbbb-cccc pkg:npm/postcss@8.5.23',
  ]);
});

// ---------- found by the code audit of 1.0.0-beta.9 ----------

test('OSV results that come back in pages are all read', async () => {
  const bodies = [];
  const fetchImpl = async (url, options) => {
    const body = JSON.parse(options.body);
    bodies.push(body);
    const reply = (results) => ({ ok: true, status: 200, json: async () => ({ results }) });
    // first call: lodash has more on a second page, qs and ms are done
    if (bodies.length === 1) {
      return reply([{ vulns: [{ id: 'GHSA-page-one-0001' }], next_page_token: 'more' }, { vulns: [{ id: 'GHSA-qsqs-qsqs-qsqs' }] }, {}]);
    }
    return reply([{ vulns: [{ id: 'GHSA-page-two-0002' }] }]);
  };
  const found = await fetchOsvFindings(lockfile, { fetchImpl });

  assert.equal(bodies.length, 2);
  assert.deepEqual(bodies[1].queries, [{ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20', page_token: 'more' }]);
  assert.deepEqual(found, [
    { purl: 'pkg:npm/lodash@4.17.20', ids: ['GHSA-page-one-0001', 'GHSA-page-two-0002'] },
    { purl: 'pkg:npm/qs@6.5.2', ids: ['GHSA-qsqs-qsqs-qsqs'] },
  ]);
});

test('a clean yarn audit is zero findings; an empty file or {} is refused with the way out', async () => {
  const { readFindingsText } = await import('../src/sources.js');
  const summary = (counts) => `${JSON.stringify({ type: 'auditSummary', data: { vulnerabilities: counts, dependencies: 44 } })}\n`;

  assert.deepEqual(
    readFindingsText(summary({ info: 0, low: 0, moderate: 0, high: 0, critical: 0 })),
    { format: 'yarn-audit', findings: [] },
  );
  assert.throws(
    () => readFindingsText(summary({ info: 0, low: 0, moderate: 2, high: 0, critical: 0 })),
    /counts 2 vulnerabilities, but the file holds no advisory/,
  );
  assert.throws(() => readFindingsText(''), /the findings file is empty/);
  assert.throws(() => readFindingsText('{}'), /an empty JSON object/);
});

test('alias lookups say how many ids OSV could not be reached for', async () => {
  const { enrichAliases } = await import('../src/sources.js');
  const { normalizeFindings } = await import('../src/index.js');
  const findings = normalizeFindings([{ purl: 'pkg:npm/x@1', ids: ['GHSA-down-0001'] }, { purl: 'pkg:npm/y@1', ids: ['GHSA-gone-0002'] }]);
  const fetchImpl = async (url) => (url.includes('down')
    ? { ok: false, status: 503, headers: { get: () => null } }
    : { ok: false, status: 404 });
  const result = await enrichAliases(findings, { fetchImpl, sleep: async () => {} });

  assert.deepEqual(
    { looked: result.looked, resolved: result.resolved, unreachable: result.unreachable },
    { looked: 2, resolved: 0, unreachable: 1 },
  );
});
