// SPDX-License-Identifier: MIT
// `vexproof --help` fits on one screen, every page fits in 80 columns, and every flag the CLI reads is on a page.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const help = (...a) => {
  const r = spawnSync(process.execPath, [CLI, ...a, '--help'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout;
};
const PAGES = [[], ['all'], ['review'], ['dependabot'], ['rules', 'derive'], ['rollup'], ['verify'], ['keygen']];

test('the overview fits on a 24-line screen and every page fits in 80 columns', () => {
  assert.ok(help().trimEnd().split('\n').length <= 24);
  for (const p of PAGES) for (const line of help(...p).split('\n')) assert.ok(line.length <= 80, `${p.join(' ') || 'overview'}: ${line}`);
});

test('each command has its own page, and an unknown one gets the overview', () => {
  assert.match(help('review'), /^vexproof review:/);
  assert.match(help('dependabot'), /^vexproof dependabot \(Pro\):/);
  assert.match(help('rules', 'derive'), /^vexproof rules derive:/);
  assert.match(help('rollup'), /^vexproof rollup \(Pro\):/);
  assert.match(help('verify'), /^vexproof verify:/);
  assert.match(help('keygen'), /^vexproof keygen:/);
  assert.equal(help('nonsense'), help());
});

test('every flag the CLI reads is documented on some help page', () => {
  const src = readFileSync(CLI, 'utf8');
  const read = new Set([...src.matchAll(/args\.([a-z]+)\b|args\['([a-z-]+)'\]|(?:need|every)\('([a-z-]+)'\)/g)].map((m) => m[1] ?? m[2] ?? m[3]));
  for (const k of ['help', 'version']) read.delete(k);
  const all = PAGES.map((p) => help(...p)).join('\n');
  for (const flag of read) assert.match(all, new RegExp(`--${flag}(?![\\w-])`), `--${flag} is not in any help page`);
});
