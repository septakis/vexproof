// SPDX-License-Identifier: MIT
// The same input writes the same VEX, byte for byte, so VEX files diff cleanly in git.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { triage, toCycloneDxVex, contentUuid, outputTime } from '../src/index.js';
import { toOpenVex } from '../src/openvex.js';
import { temporaryFolder } from './lib/temporary.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const fixture = (fileName) => fileURLToPath(new URL(`./fixtures/${fileName}`, import.meta.url));
const UUID_V5 = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const sbom = (purls) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
  components: purls.map((purl) => ({ type: 'library', purl, 'bom-ref': purl })),
});
const lockfile = sbom(['pkg:npm/a@1.0.0', 'pkg:npm/b@1.0.0', 'pkg:npm/c@1.0.0', 'pkg:npm/d@1.0.0']);
const bundle = sbom(['pkg:npm/b@1.0.0', 'pkg:npm/d@1.0.0']);
const findings = [
  { purl: 'pkg:npm/d@1.0.0', ids: ['GHSA-dddd'] },
  { purl: 'pkg:npm/a@1.0.0', ids: ['GHSA-zzzz'], aliases: ['CVE-2026-0002'] },
  { purl: 'pkg:npm/c@1.0.0', ids: ['GHSA-aaaa'] },
  { purl: 'pkg:npm/b@1.0.0', ids: ['GHSA-bbbb'] },
];
const now = new Date('2026-01-02T03:04:05Z');

test('input order does not change either file, and settled statements still come first', () => {
  const write = (findingsInOrder) => {
    const results = triage({ findings: findingsInOrder, bundleSbom: bundle, lockfileSbom: lockfile });
    return [
      toCycloneDxVex({ results, bundleSbom: bundle, lockfileSbom: lockfile, productPurl: 'pkg:npm/app@1.0.0', now }),
      toOpenVex({ results, productPurl: 'pkg:npm/app@1.0.0', now }),
    ];
  };

  const [cycloneDx, openVex] = write(findings);
  const [reversedCycloneDx, reversedOpenVex] = write([...findings].reverse());

  assert.deepEqual(reversedCycloneDx, cycloneDx);
  assert.deepEqual(reversedOpenVex, openVex);
  assert.match(cycloneDx.serialNumber, UUID_V5);
  assert.match(openVex['@id'], UUID_V5);

  const states = cycloneDx.vulnerabilities.map((vulnerability) => vulnerability.analysis.state);
  const settledFirst = (left, right) => (left === 'not_affected' ? 0 : 1) - (right === 'not_affected' ? 0 : 1);
  assert.deepEqual(states, [...states].sort(settledFirst));

  const settled = cycloneDx.vulnerabilities
    .filter((vulnerability) => vulnerability.analysis.state === 'not_affected')
    .map((vulnerability) => vulnerability.id);
  assert.deepEqual(settled, [...settled].sort());
  assert.equal(openVex.statements.at(-1).status, 'under_investigation');
});

test('a different document gets a different serial number', () => {
  assert.notEqual(contentUuid({ a: 1 }), contentUuid({ a: 2 }));
  assert.equal(contentUuid({ a: 1 }), contentUuid({ a: 1 }));
});

test('SOURCE_DATE_EPOCH pins the timestamp; anything but whole seconds is refused', () => {
  assert.equal(outputTime({ SOURCE_DATE_EPOCH: '1767225600' }).toISOString(), '2026-01-01T00:00:00.000Z');
  assert.ok(Math.abs(outputTime({}) - Date.now()) < 5000);
  assert.throws(() => outputTime({ SOURCE_DATE_EPOCH: '2026-01-01' }), /whole seconds/);
});

test('the CLI writes identical files on two runs with SOURCE_DATE_EPOCH set', (testContext) => {
  const dir = temporaryFolder(testContext, 'vexproof-det-');
  const run = (runNumber, env) => spawnSync(process.execPath, [
    CLI,
    '--lockfile', fixture('recharts.bom.lockfile.json'),
    '--findings', fixture('recharts.audit.json'),
    '--bundle', fixture('recharts.bom.bundle.json'),
    '--out', join(dir, `${runNumber}.cdx.json`),
    '--openvex', join(dir, `${runNumber}.openvex.json`),
    '--quiet',
  ], { encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '', ...env } });

  for (const runNumber of [1, 2]) {
    assert.equal(run(runNumber, { SOURCE_DATE_EPOCH: '1767225600' }).status, 0);
  }

  for (const extension of ['cdx.json', 'openvex.json']) {
    assert.equal(readFileSync(join(dir, `2.${extension}`), 'utf8'), readFileSync(join(dir, `1.${extension}`), 'utf8'), extension);
  }
  assert.match(readFileSync(join(dir, '1.cdx.json'), 'utf8'), /"timestamp": "2026-01-01T00:00:00.000Z"/);

  const bad = run(3, { SOURCE_DATE_EPOCH: 'yesterday' });

  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /SOURCE_DATE_EPOCH/);
});
