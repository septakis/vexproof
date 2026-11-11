// SPDX-License-Identifier: MIT
// The CLI refuses a module map whose build output it can't find, so a fixture map needs its outputs on disk.
// built() copies a fixture into a fresh folder beside a stand-in file for every output the map lists, and
// returns the copy's path. The stand-ins are recorded outputs, so the coverage check passes them unread.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';

export function built(fixture) {
  const dir = mkdtempSync(join(tmpdir(), 'vxp-built-'));
  const text = readFileSync(fixture, 'utf8');
  for (const out of Object.keys(JSON.parse(text).outputs ?? {})) {
    mkdirSync(dirname(join(dir, out)), { recursive: true });
    writeFileSync(join(dir, out), '/* stand-in for a build output */\n');
  }
  const copy = join(dir, basename(fixture));
  writeFileSync(copy, text);
  return copy;
}
