// SPDX-License-Identifier: MIT
// The CLI refuses a module map whose build it can't find: the output files it lists, and the project's own
// source files it names. built() copies a fixture into a fresh folder beside a stand-in file for each of them
// and returns the copy's path; modulesArgs() gives the CLI arguments that read it from that folder. The
// stand-in outputs are recorded outputs, so the coverage check passes them unread.
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { temporaryFolderForFile } from './temporary.js';

export function built(fixture) {
  const dir = temporaryFolderForFile('vxp-built-');
  const text = readFileSync(fixture, 'utf8');
  const json = JSON.parse(text);
  const put = (path, contents) => {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), contents);
  };
  // of the size the bundler recorded: a file of another size is not the one the map describes
  const standIn = (bytes) => {
    const banner = '/* stand-in for a build output */\n';
    if (typeof bytes === 'number' && bytes > banner.length) {
      return banner + ' '.repeat(bytes - banner.length);
    }
    if (typeof bytes === 'number') {
      return ' '.repeat(bytes);
    }

    return banner;
  };

  for (const [outputPath, output] of Object.entries(json.outputs ?? {})) put(outputPath, standIn(output?.bytes));
  for (const output of Object.values(json.outputs ?? {})) {
    for (const input of Object.keys(output?.inputs ?? {})) {
      const ownSource = !/(^|\/)node_modules\//.test(input) && !/^[a-z][a-z0-9+.-]+:|^</i.test(input) && !input.startsWith('..');
      if (ownSource) put(input, '// stand-in for a source file\n');
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
