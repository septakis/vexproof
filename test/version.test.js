// SPDX-License-Identifier: MIT
// 1.0.0-beta.4 shipped reporting itself as 1.0.0-beta.3, because the version was a constant nobody bumped.
// VERSION now comes from package.json; these tests keep the CLI, the library and the VEX metadata in step with it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { VERSION, toCycloneDxVex, triage } from '../src/index.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('VERSION is package.json\'s version', () => {
  assert.equal(VERSION, pkg.version);
  assert.match(VERSION, /^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/);
});

test('vexproof --version prints package.json\'s version', () => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL('../src/cli.js', import.meta.url)), '--version'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), pkg.version);
});

test('the VEX names the version that wrote it', () => {
  const sbom = { bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:test', components: [{ type: 'library', purl: 'pkg:npm/left@1.0.0' }] };
  const results = triage({ lockfileSbom: sbom, bundleSbom: { ...sbom, components: [] }, findings: [{ purl: 'pkg:npm/left@1.0.0', ids: ['GHSA-test-0000-0000'] }] });
  const vex = toCycloneDxVex({ results, lockfileSbom: sbom, bundleSbom: { ...sbom, components: [] }, now: new Date(0) });
  const tool = (vex.metadata.tools.components ?? vex.metadata.tools).find((t) => t.name === 'vexproof');
  assert.equal(tool.version, pkg.version);
});
