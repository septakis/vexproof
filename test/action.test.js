// SPDX-License-Identifier: MIT
// action.yml is parsed by GitHub, not by anything in this repository, so a broken file only shows up in a user's
// workflow run. These checks catch the breakage that happened once: a line inside a `run: |` block that started at
// column 0 ended the block and made the rest of the file unparseable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const lines = readFileSync(new URL('../action.yml', import.meta.url), 'utf8').split('\n');

test('every top-level line of action.yml is a key or a comment', () => {
  const bad = lines.map((l, i) => [i + 1, l]).filter(([, l]) => l.length && !l.startsWith(' ') && !l.startsWith('#') && !/^[a-z][a-z-]*:/.test(l));
  assert.deepEqual(bad, [], 'lines at column 0 that are neither a key nor a comment');
});

test('the shell in action.yml spells newlines as \\n, never as a line break inside a quoted string', () => {
  const text = lines.join('\n');
  assert.doesNotMatch(text, /printf '[^'\n]*\n/, "a printf format string must not contain a literal line break");
  assert.match(text, /printf '%s\\n' "\$IN_SIGNING_KEY"/);
});

test('action.yml declares the inputs the README documents', () => {
  for (const input of ['lockfile', 'bundle', 'findings', 'modules', 'deploy', 'out', 'openvex', 'license', 'version', 'fail-on', 'dependabot']) {
    assert.ok(lines.some((l) => l === `  ${input}:`), `input ${input}`);
  }
});
