// SPDX-License-Identifier: MIT
// `vexproof --help` fits on one screen, every page fits in 80 columns, and every flag the CLI reads is on a page.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const help = (...args) => {
  const result = spawnSync(process.execPath, [CLI, ...args, '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
};
const PAGES = [[], ['all'], ['review'], ['dependabot'], ['rules', 'derive'], ['rollup'], ['verify'], ['keygen']];

test('the overview fits on a 24-line screen and every page fits in 80 columns', () => {
  assert.ok(help().trimEnd().split('\n').length <= 24);

  for (const page of PAGES) {
    for (const line of help(...page).split('\n')) assert.ok(line.length <= 80, `${page.join(' ') || 'overview'}: ${line}`);
  }
});

test('each command has its own page, and an unknown one is refused', () => {
  assert.match(help('review'), /^vexproof review:/);
  assert.match(help('dependabot'), /^vexproof dependabot \(Pro\):/);
  assert.match(help('rules', 'derive'), /^vexproof rules derive:/);
  assert.match(help('rollup'), /^vexproof rollup \(Pro\):/);
  assert.match(help('verify'), /^vexproof verify:/);
  assert.match(help('keygen'), /^vexproof keygen:/);

  const unknown = spawnSync(process.execPath, [CLI, 'nonsense', '--help'], { encoding: 'utf8' });
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /unknown command "nonsense"/);
});

test("every command's every option is on that command's help page", async () => {
  const { OPTIONS } = await import('../src/cli/args.js');
  const pageOf = {
    vex: ['all'], review: ['review'], verify: ['verify'], keygen: ['keygen'],
    rollup: ['rollup'], 'rules-derive': ['rules', 'derive'], dependabot: ['dependabot'],
  };

  for (const [command, table] of Object.entries(OPTIONS)) {
    const page = help(...pageOf[command]);
    for (const name of Object.keys(table)) {
      if (['help', 'version'].includes(name)) continue;
      assert.match(page, new RegExp(`--${name}(?![\\w-])`), `--${name} is not on the help page of ${command}`);
    }
  }
});
