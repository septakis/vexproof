// SPDX-License-Identifier: MIT
// Lookups on public sources time out, back off and retry, and a lookup that never happens stops the run
// with a nonzero exit instead of writing an empty VEX.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { fetchRetrying, fetchOsvFindings, enrichAliases } from '../src/sources.js';
import { normalizeFindings } from '../src/index.js';
import { temporaryFolder } from './lib/temporary.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const fixture = (fileName) => fileURLToPath(new URL(`./fixtures/${fileName}`, import.meta.url));
const noSleep = async () => {};
const reply = (status, body = {}, headers = {}) => ({
  ok: status < 400,
  status,
  headers: { get: (name) => headers[name.toLowerCase()] ?? null },
  json: async () => body,
});

test('429 and 5xx are retried with backoff, honouring Retry-After, then succeed', async () => {
  const seen = [];
  const waits = [];
  const fetchImpl = async () => {
    seen.push(1);
    return [reply(503), reply(429, {}, { 'retry-after': '2' }), reply(200, { ok: 1 })][seen.length - 1];
  };

  const response = await fetchRetrying('https://x', {}, { fetchImpl, sleep: async (milliseconds) => { waits.push(milliseconds); } });

  assert.equal(response.status, 200);
  assert.equal(seen.length, 3);
  assert.deepEqual(waits, [500, 2000]);
});

test('a network error is retried; after the retries it is reported with the attempt count', async () => {
  let attempts = 0;
  const fetchImpl = async () => {
    attempts++;
    throw new Error('ECONNRESET');
  };

  await assert.rejects(
    fetchRetrying('https://x', {}, { fetchImpl, retries: 2, sleep: noSleep }),
    /ECONNRESET \(gave up after 3 attempts\)/,
  );

  assert.equal(attempts, 3);
});

test('each attempt has a timeout, and a 4xx other than 429 is returned without retrying', async () => {
  let signal;
  const recordSignal = async (_url, init) => {
    signal = init.signal;
    return reply(404);
  };

  const response = await fetchRetrying('https://x', {}, { fetchImpl: recordSignal, sleep: noSleep });

  assert.equal(response.status, 404);
  assert.ok(signal instanceof AbortSignal);

  // A real fetch holds a socket open; this fake holds a timer instead, since AbortSignal.timeout's own timer is
  // unref'd and on Node 22 would let the event loop drain before the signal fires.
  const neverAnswer = async (_url, init) => new Promise((_resolve, reject) => {
    const hold = setTimeout(() => {}, 5000);
    init.signal.addEventListener('abort', () => {
      clearTimeout(hold);
      reject(init.signal.reason);
    });
  });

  await assert.rejects(
    fetchRetrying('https://x', {}, { fetchImpl: neverAnswer, timeoutMs: 20, retries: 0 }),
    /no response within 0.02s/,
  );
});

test('OSV findings: a lookup that keeps failing is an error that names the way out', async () => {
  const sbom = { components: [{ type: 'library', purl: 'pkg:npm/lodash@4.17.20' }] };

  await assert.rejects(
    fetchOsvFindings(sbom, { fetchImpl: async () => reply(500), sleep: noSleep }),
    /OSV lookup failed: .*HTTP 500 \(gave up after 4 attempts\).*--findings/,
  );

  const found = await fetchOsvFindings(sbom, { fetchImpl: async () => reply(200, { results: [{ vulns: [{ id: 'GHSA-x' }] }] }) });

  assert.deepEqual(found, [{ purl: 'pkg:npm/lodash@4.17.20', ids: ['GHSA-x'] }]);
});

test('alias enrichment retries too, and still leaves findings alone when the source stays down', async () => {
  let attempts = 0;
  const findings = normalizeFindings([{ purl: 'pkg:npm/x@1', ids: ['GHSA-x'] }]);
  const fetchImpl = async () => {
    attempts++;
    return reply(503);
  };

  const result = await enrichAliases(findings, { fetchImpl, sleep: noSleep });

  assert.equal(result.resolved, 0);
  assert.equal(attempts, 4);
  assert.deepEqual(findings[0].aliases, []);
});

test('the CLI exits 2 and writes no VEX when OSV cannot be reached', (testContext) => {
  const dir = temporaryFolder(testContext, 'vexproof-net-');
  const out = join(dir, 'vex.cdx.json');
  const noNetwork = fileURLToPath(new URL('./fixtures/no-network.cjs', import.meta.url));

  // Preloading test/fixtures/no-network.cjs replaces globalThis.fetch with one that fails at once, so every
  // request fails fast without touching the network.
  const args = ['--lockfile', fixture('recharts.bom.lockfile.json'), '--bundle', fixture('recharts.bom.bundle.json'), '--out', out];
  const run = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8', timeout: 120_000,
    env: { ...process.env, VEXPROOF_LICENSE: '', NODE_OPTIONS: `--require ${noNetwork}` },
  });

  assert.equal(run.status, 2, run.stderr);
  assert.match(run.stderr, /OSV lookup failed/);
  assert.ok(!existsSync(out));
});
