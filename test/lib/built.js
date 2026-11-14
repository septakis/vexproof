// SPDX-License-Identifier: MIT
// The CLI refuses a module map whose build it can't find: the output files it lists, and the project's own
// source files it names. built() copies a fixture into a fresh folder beside a stand-in file for each of them
// and returns the copy's path; modulesArgs() gives the CLI arguments that read it from that folder. The
// stand-in outputs are recorded outputs, so the coverage check passes them unread.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';

export function built(fixture) {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-built-'));
  const text = readFileSync(fixture, 'utf8');
  const json = JSON.parse(text);
  const put = (p, c) => { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), c); };
  // of the size the bundler recorded: a file of another size is not the one the map describes
  const standIn = (bytes) => { const text = '/* stand-in for a build output */\n'; return typeof bytes === 'number' && bytes > text.length ? text + ' '.repeat(bytes - text.length) : typeof bytes === 'number' ? ' '.repeat(bytes) : text; };
  for (const [out, o] of Object.entries(json.outputs ?? {})) put(out, standIn(o?.bytes));
  for (const out of Object.values(json.outputs ?? {})) {
    for (const input of Object.keys(out?.inputs ?? {})) {
      if (!/(^|\/)node_modules\//.test(input) && !/^[a-z][a-z0-9+.-]+:|^</i.test(input) && !input.startsWith('..')) put(input, '// stand-in for a source file\n');
    }
  }
  const copy = join(dir, basename(fixture));
  writeFileSync(copy, text);
  return copy;
}

/** `--modules <copy of the fixture> --root <its folder>`: the build "ran" in the folder the copy sits in. */
export function modulesArgs(fixture) {
  const map = built(fixture);
  return ['--modules', map, '--root', dirname(map)];
}
