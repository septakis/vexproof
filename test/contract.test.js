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
const walk = (dir) => readdirSync(dir).flatMap((name) => {
  const path = join(dir, name);
  return statSync(path).isDirectory() ? walk(path) : [path];
});
const sources = walk(join(ROOT, 'src')).filter((file) => /\.(js|cjs)$/.test(file)).map((file) => readFileSync(file, 'utf8'));
// the CLI's own tables: every option of every command, and every exit code
const { OPTIONS } = await import('../src/cli/args.js');
const { EXIT } = await import('../src/stop.js');
const cliFiles = walk(join(ROOT, 'src')).filter((file) => /[\\/]cli(\.js$|[\\/])/.test(file)).map((file) => readFileSync(file, 'utf8'));

const same = (inCode, inContract, what) => {
  const codeSet = new Set(inCode);
  const contractSet = new Set(inContract);
  assert.deepEqual([...codeSet].filter((item) => !contractSet.has(item)).sort(), [], `${what} in the code but not in docs/CONTRACT.md`);
  assert.deepEqual([...contractSet].filter((item) => !codeSet.has(item)).sort(), [], `${what} in docs/CONTRACT.md but not in the code`);
};

test('every option a command takes is in the contract, and every option in the contract is taken', () => {
  const taken = Object.values(OPTIONS).flatMap((table) => Object.keys(table)).filter((name) => !['help', 'version'].includes(name));
  const listed = [...contract.matchAll(/`--([a-z-]+)/g)].map((match) => match[1]).filter((name) => !['help', 'version'].includes(name));

  same(taken, listed, 'flags');
});

test('every vexproof:* property the code writes is in the contract', () => {
  const written = sources.flatMap((source) => [...source.matchAll(/['`]vexproof:([a-zA-Z-]+)/g)].map((match) => match[1]));
  const evidence = ['bundleSbomSerial', 'lockfileSbomSerial', 'bundleComponentCount', 'lockfileComponentCount']; // built from an object's keys
  const listed = [...contract.matchAll(/`vexproof:([a-zA-Z-]+)/g)].map((match) => match[1]);

  same([...written, ...evidence], listed, 'properties');
});

test('the exit codes are 0, 1 and 2, and the contract lists exactly those', () => {
  const used = Object.values(EXIT).map(String);
  const listed = [...contract.matchAll(/^\| (\d) \|/gm)].map((match) => match[1]);

  same(used, listed, 'exit codes');
  assert.deepEqual([...new Set(used)].sort(), ['0', '1', '2']);

  // and no command exits on its own: each returns one of those, or throws a Stop that src/cli.js reports
  for (const source of cliFiles) {
    const afterNodeCheck = source.replace(/^[\s\S]*?MINIMUM_NODE\) \{[\s\S]*?\n\}\n/, '');
    assert.doesNotMatch(afterNodeCheck, /process\.exit\((?!error\?\.code)/);
  }
});

test('every VEXPROOF_* variable and SOURCE_DATE_EPOCH the code reads is in the contract', () => {
  const read = sources.flatMap((source) => [...source.matchAll(/\b(VEXPROOF_[A-Z_]+|SOURCE_DATE_EPOCH)\b/g)].map((match) => match[1]));
  const listed = [...contract.matchAll(/`(VEXPROOF_[A-Z_]+|SOURCE_DATE_EPOCH)`/g)].map((match) => match[1]);

  same(read, listed, 'environment variables');
});
