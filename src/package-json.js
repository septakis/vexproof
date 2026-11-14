// SPDX-License-Identifier: MIT
// Reading an installed package's package.json the way Node and npm do, in one place.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The package.json in `dir`, as one of:
 *   { pkg }            it was read
 *   { missing: true }  there is none
 *   { error }          there is one, and it can't be read
 *
 * Node and npm accept a UTF-8 byte order mark at the start of the file; JSON.parse does not, so it is removed
 * first. Callers must not treat an unreadable file like a missing one: a folder that has a package.json is a
 * package, even when vexproof can't read its name, and filing its code under some other package would make it
 * look absent.
 */
export function readPackageJson(dir) {
  let text;
  try {
    text = readFileSync(join(dir, 'package.json'), 'utf8');
  } catch (e) {
    return e.code === 'ENOENT' || e.code === 'ENOTDIR' ? { missing: true } : { error: e };
  }
  try {
    return { pkg: JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text) };
  } catch (e) {
    return { error: e };
  }
}
