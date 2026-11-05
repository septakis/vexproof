// SPDX-License-Identifier: MIT
// docs/CONTRACT.md is the 1.0 public API. These tests keep it and the code in step: a flag, property, exit
// code or environment variable that one has and the other does not fails the build.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const contract = readFileSync(join(ROOT, 'docs/CONTRACT.md'), 'utf8');
const walk = (dir) => readdirSync(dir).flatMap((f) => { const p = join(dir, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
const sources = walk(join(ROOT, 'src')).filter((f) => /\.(js|cjs)$/.test(f)).map((f) => readFileSync(f, 'utf8'));
const cli = readFileSync(join(ROOT, 'src/cli.js'), 'utf8');

const same = (a, b, what) => {
  const A = new Set(a), B = new Set(b);
  assert.deepEqual([...A].filter((x) => !B.has(x)).sort(), [], `${what} in the code but not in docs/CONTRACT.md`);
  assert.deepEqual([...B].filter((x) => !A.has(x)).sort(), [], `${what} in docs/CONTRACT.md but not in the code`);
};

test('every flag the CLI reads is in the contract, and every flag in the contract is read', () => {
  const read = [...cli.matchAll(/args\.([a-z]+)\b|args\['([a-z-]+)'\]|(?:need|every)\('([a-z-]+)'\)/g)].map((m) => m[1] ?? m[2] ?? m[3]);
  const listed = [...contract.matchAll(/`--([a-z-]+)/g)].map((m) => m[1]);
  same(read, listed, 'flags');
});

test('every vexproof:* property the code writes is in the contract', () => {
  const written = sources.flatMap((s) => [...s.matchAll(/['`]vexproof:([a-zA-Z-]+)/g)].map((m) => m[1]));
  const evidence = ['bundleSbomSerial', 'lockfileSbomSerial', 'bundleComponentCount', 'lockfileComponentCount']; // built from an object's keys
  const listed = [...contract.matchAll(/`vexproof:([a-zA-Z-]+)/g)].map((m) => m[1]);
  same([...written, ...evidence], listed, 'properties');
});

test('the exit codes are 0, 1 and 2, and the contract lists exactly those', () => {
  const used = [...cli.matchAll(/process\.exit\((\d)\)/g)].map((m) => m[1]);
  const listed = [...contract.matchAll(/^\| (\d) \|/gm)].map((m) => m[1]);
  same(used, listed, 'exit codes');
  assert.deepEqual([...new Set(used)].sort(), ['0', '1', '2']);
});

test('every VEXPROOF_* variable and SOURCE_DATE_EPOCH the code reads is in the contract', () => {
  const read = sources.flatMap((s) => [...s.matchAll(/\b(VEXPROOF_[A-Z_]+|SOURCE_DATE_EPOCH)\b/g)].map((m) => m[1]));
  const listed = [...contract.matchAll(/`(VEXPROOF_[A-Z_]+|SOURCE_DATE_EPOCH)`/g)].map((m) => m[1]);
  same(read, listed, 'environment variables');
});
