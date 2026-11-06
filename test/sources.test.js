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
  const fetchImpl = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body) });
    return { ok: true, json: async () => ({ results: [
      { vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }, { id: 'GHSA-29mw-wpgm-hmr9' }] },
      { vulns: [{ id: 'GHSA-hrpp-h998-j3pp' }] },
      {},
    ]}) };
  };
  const f = await fetchOsvFindings(lockfile, { fetchImpl });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].body.queries[0], { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' });
  assert.deepEqual(f, [
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
  const f = fromNpmAudit(audit, lockfile);
  const names = [...new Set(f.map((x) => x.purl))].sort();
  assert.deepEqual(names, ['pkg:npm/lodash@4.17.20', 'pkg:npm/qs@6.5.2']);
  assert.ok(f.every((x) => x.id.startsWith('GHSA-')));
  const bundle = { components: [{ type: 'library', purl: 'pkg:npm/ms@2.1.3' }] };
  const results = triage({ lockfileSbom: lockfile, bundleSbom: bundle, findings: f });
  assert.ok(results.length >= 2 && results.every((r) => r.state === 'not_affected'));
});

test('npm audit: each advisory lands on the installed versions inside its range', () => {
  const lock = { components: [{ purl: 'pkg:npm/postcss@8.5.23' }, { purl: 'pkg:npm/postcss@8.4.30' }] };
  const audit = { auditReportVersion: 2, vulnerabilities: { postcss: { via: [
    { url: 'https://github.com/advisories/GHSA-7fh5-64p2-3v2j', range: '<8.4.31' },
    { url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', range: '<9.0.0' },
  ] } } };
  const f = fromNpmAudit(audit, lock).map((x) => `${x.id} ${x.purl}`).sort();
  assert.deepEqual(f, ['GHSA-7fh5-64p2-3v2j pkg:npm/postcss@8.4.30', 'GHSA-aaaa-bbbb-cccc pkg:npm/postcss@8.4.30', 'GHSA-aaaa-bbbb-cccc pkg:npm/postcss@8.5.23']);
});
