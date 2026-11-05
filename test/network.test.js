// SPDX-License-Identifier: MIT
// Lookups on public sources time out, back off and retry, and a lookup that never happens stops the run
// with a nonzero exit instead of writing an empty VEX.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { fetchRetrying, fetchOsvFindings, enrichAliases } from '../src/sources.js';
import { normalizeFindings } from '../src/index.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const fx = (f) => fileURLToPath(new URL(`./fixtures/${f}`, import.meta.url));
const noSleep = async () => {};
const reply = (status, body = {}, headers = {}) => ({ ok: status < 400, status, headers: { get: (k) => headers[k.toLowerCase()] ?? null }, json: async () => body });

test('429 and 5xx are retried with backoff, honouring Retry-After, then succeed', async () => {
  const seen = [];
  const waits = [];
  const fetchImpl = async () => { seen.push(1); return [reply(503), reply(429, {}, { 'retry-after': '2' }), reply(200, { ok: 1 })][seen.length - 1]; };
  const res = await fetchRetrying('https://x', {}, { fetchImpl, sleep: async (ms) => { waits.push(ms); } });
  assert.equal(res.status, 200);
  assert.equal(seen.length, 3);
  assert.deepEqual(waits, [500, 2000]);
});

test('a network error is retried; after the retries it is reported with the attempt count', async () => {
  let n = 0;
  await assert.rejects(
    fetchRetrying('https://x', {}, { fetchImpl: async () => { n++; throw new Error('ECONNRESET'); }, retries: 2, sleep: noSleep }),
    /ECONNRESET \(gave up after 3 attempts\)/,
  );
  assert.equal(n, 3);
});

test('each attempt has a timeout, and a 4xx other than 429 is returned without retrying', async () => {
  let signal;
  const res = await fetchRetrying('https://x', {}, { fetchImpl: async (_u, init) => { signal = init.signal; return reply(404); }, sleep: noSleep });
  assert.equal(res.status, 404);
  assert.ok(signal instanceof AbortSignal);
  await assert.rejects(
    fetchRetrying('https://x', {}, { fetchImpl: async (_u, init) => new Promise((_r, rej) => init.signal.addEventListener('abort', () => rej(init.signal.reason))), timeoutMs: 20, retries: 0 }),
    /no response within 0.02s/,
  );
});

test('OSV findings: a lookup that keeps failing is an error that names the way out', async () => {
  const sbom = { components: [{ type: 'library', purl: 'pkg:npm/lodash@4.17.20' }] };
  await assert.rejects(fetchOsvFindings(sbom, { fetchImpl: async () => reply(500), sleep: noSleep }), /OSV lookup failed: .*HTTP 500 \(gave up after 4 attempts\).*--findings/);
  const found = await fetchOsvFindings(sbom, { fetchImpl: async () => reply(200, { results: [{ vulns: [{ id: 'GHSA-x' }] }] }) });
  assert.deepEqual(found, [{ purl: 'pkg:npm/lodash@4.17.20', ids: ['GHSA-x'] }]);
});

test('alias enrichment retries too, and still leaves findings alone when the source stays down', async () => {
  let n = 0;
  const f = normalizeFindings([{ purl: 'pkg:npm/x@1', ids: ['GHSA-x'] }]);
  const r = await enrichAliases(f, { fetchImpl: async () => { n++; return reply(503); }, sleep: noSleep });
  assert.equal(r.resolved, 0);
  assert.equal(n, 4);
  assert.deepEqual(f[0].aliases, []);
});

test('the CLI exits 2 and writes no VEX when OSV cannot be reached', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vexproof-net-'));
  const out = join(dir, 'vex.cdx.json');
  // An unroutable proxy makes every request fail fast without touching the network.
  const r = spawnSync(process.execPath, [CLI, '--lockfile', fx('recharts.bom.lockfile.json'), '--bundle', fx('recharts.bom.bundle.json'), '--out', out], {
    encoding: 'utf8', timeout: 120_000,
    env: { ...process.env, VEXPROOF_LICENSE: '', NODE_OPTIONS: `--require ${fileURLToPath(new URL('./fixtures/no-network.cjs', import.meta.url))}` },
  });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /OSV lookup failed/);
  assert.ok(!existsSync(out));
});
