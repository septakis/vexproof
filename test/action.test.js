// SPDX-License-Identifier: MIT
// action.yml is parsed by GitHub, not by anything in this repository, so a broken file only shows up in a user's
// workflow run. These checks catch the breakage that happened once (a line inside a `run: |` block that started at
// column 0 ended the block and made the rest of the file unparseable), inputs the README documents that the
// action lacks, and inputs the action declares but never passes on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// CRLF too: a Windows checkout may write the file that way, and GitHub reads it either way
const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const lines = read('../action.yml').split(/\r?\n/);
const action = lines.join('\n');

/** The input names action.yml declares: the keys indented two spaces under `inputs:`. */
function declaredInputs() {
  const start = lines.indexOf('inputs:');
  const names = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break; // the next top-level key
    const key = /^ {2}([a-z][a-z-]*):\s*$/.exec(line);
    if (key) names.push(key[1]);
  }

  return names;
}

/** The inputs the README's examples pass: the keys under `with:` after each `uses: septakis/vexproof@…`. */
function documentedInputs() {
  const readme = read('../README.md').split(/\r?\n/);
  const names = new Set();
  readme.forEach((line, index) => {
    if (!/uses: septakis\/vexproof@/.test(line)) return;

    const indent = /^(\s*)/.exec(readme[index + 1] ?? '')[1];
    if (!readme[index + 1]?.trim().startsWith('with:')) return;
    for (const next of readme.slice(index + 2)) {
      const key = new RegExp(`^${indent}  ([a-z][a-z-]*):`).exec(next);
      if (!key) break;
      names.add(key[1]);
    }
  });

  return [...names];
}

test('every top-level line of action.yml is a key or a comment', () => {
  const bad = lines.map((line, index) => [index + 1, line]).filter(([, line]) => line.length && !line.startsWith(' ') && !line.startsWith('#') && !/^[a-z][a-z-]*:/.test(line));
  assert.deepEqual(bad, [], 'lines at column 0 that are neither a key nor a comment');
});

test('the shell in action.yml spells newlines as \\n, never as a line break inside a quoted string', () => {
  assert.doesNotMatch(action, /printf '[^'\n]*\n/, 'a printf format string must not contain a literal line break');
  assert.match(action, /printf '%s\\n' "\$IN_SIGNING_KEY"/);
});

test('action.yml declares every input the README passes it', () => {
  const documented = documentedInputs();
  assert.ok(documented.length >= 5, `the README's examples name ${documented.length} inputs`);
  const declared = declaredInputs();
  assert.deepEqual(documented.filter((name) => !declared.includes(name)), []);
});

test('every input action.yml declares is passed on to vexproof', () => {
  const unused = declaredInputs().filter((name) => !new RegExp(String.raw`inputs\.${name}(?![\w-])`).test(action));
  assert.deepEqual(unused, []);
});
