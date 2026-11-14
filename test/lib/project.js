// SPDX-License-Identifier: MIT
// A small project on disk for tests that run the CLI end to end: its files, a lockfile SBOM, findings, a module
// map, and a CLI run that reads them. Each project is removed when its test ends.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const CLI = fileURLToPath(new URL('../../src/cli.js', import.meta.url));
const NO_NETWORK = fileURLToPath(new URL('../fixtures/no-network.cjs', import.meta.url));

/** Write `files` (path → text, or an object written as JSON) under `root`. */
export function write(root, files) {
  for (const [filePath, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, filePath)), { recursive: true });
    writeFileSync(join(root, filePath), typeof content === 'string' || Buffer.isBuffer(content) ? content : JSON.stringify(content));
  }
}

/** A fresh folder with a package.json, a lockfile and `files`, removed when the test of `testContext` ends. */
export function project(testContext, files = {}) {
  const root = mkdtempSync(join(tmpdir(), 'vxp-proj-'));
  testContext?.after?.(() => rmSync(root, { recursive: true, force: true }));

  write(root, { 'package.json': { name: 'app', version: '1.0.0' }, 'package-lock.json': '{}', ...files });

  return root;
}

export const pkg = (name, version = '1.0.0', extra = {}) => ({ name, version, ...extra });
const purl = (name, version) => `pkg:npm/${name.replace('@', '%40')}@${version}`;
/** The id of the one finding `lockfile` writes for a package: GHSA-test-<name without punctuation>. */
export const idOf = (name) => `GHSA-test-${name.replace(/\W/g, '')}`;

/** bom.json (a lockfile SBOM listing `pkgs`, [[name, version]]) and findings.json (one finding per package). */
export function lockfile(root, pkgs) {
  write(root, {
    'bom.json': {
      bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79', version: 1,
      metadata: { component: { type: 'application', name: 'app', 'bom-ref': 'app', purl: 'pkg:npm/app@1.0.0' } },
      components: pkgs.map(([name, version]) => ({ type: 'library', name, version, 'bom-ref': `${name}@${version}`, purl: purl(name, version) })),
    },
    'findings.json': pkgs.map(([name, version]) => ({ purl: purl(name, version), ids: [idOf(name)] })),
  });
}

/**
 * An esbuild metafile at meta.json for outputs already on disk: { 'dist/app.js': ['src/main.js', ...] }. Each
 * output's size is taken from its file, as esbuild records it; `imports` adds an output's imports.
 */
export function metafile(root, outputs, { imports = {} } = {}) {
  const meta = { inputs: {}, outputs: {} };

  for (const [outputPath, inputs] of Object.entries(outputs)) {
    meta.outputs[outputPath] = {
      bytes: statSync(join(root, outputPath)).size,
      inputs: Object.fromEntries(inputs.map((input) => [input, { bytesInOutput: 10 }])),
      imports: imports[outputPath] ?? [],
    };
    for (const input of inputs) {
      meta.inputs[input] ??= { bytes: 10, imports: [] };
    }
  }

  write(root, { 'meta.json': meta });

  return 'meta.json';
}

/**
 * Run the CLI in `root` on bom.json and findings.json, with no license and no network. Returns
 * { status, stdout, stderr, verdicts: { id: state } } (verdicts empty when no VEX was written).
 */
export function run(root, args, { env = {} } = {}) {
  const result = spawnSync(process.execPath, ['--require', NO_NETWORK, CLI, '--lockfile', 'bom.json', '--findings', 'findings.json', '--out', 'vex.json', '--quiet', ...args],
    { cwd: root, encoding: 'utf8', env: { ...process.env, VEXPROOF_LICENSE: '', ...env } });

  const vexFile = join(root, 'vex.json');
  const verdicts = existsSync(vexFile)
    ? Object.fromEntries(JSON.parse(readFileSync(vexFile, 'utf8')).vulnerabilities.map((vulnerability) => [vulnerability.id, vulnerability.analysis.state]))
    : {};

  return { status: result.status, stdout: result.stdout, stderr: result.stderr, verdicts };
}

/** git in `root`; asserts nothing, returns spawnSync's result. */
export const git = (root, ...args) => spawnSync('git', args, { cwd: root, encoding: 'utf8' });
