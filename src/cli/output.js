// SPDX-License-Identifier: MIT
// Writing what a command produces, all or nothing. Every file is built in memory first; then each is written
// beside its place and renamed into it. If one can't be written, the ones written so far are removed and the
// run stops: exit 2 means nothing was written (docs/CONTRACT.md).
import { writeFileSync, renameSync, rmSync } from 'node:fs';
import { Stop } from '../stop.js';

/**
 * Write `files` ([{ path, text, mode? }]) as one step. A file that already exists is replaced only once every
 * new file is in place beside it.
 */
export function writeAll(files) {
  const staged = [];
  const temporary = (path) => `${path}.vexproof-${process.pid}.tmp`;

  try {
    for (const file of files) {
      writeFileSync(temporary(file.path), file.text, file.mode ? { mode: file.mode } : undefined);
      staged.push(file);
    }
  } catch (error) {
    for (const file of staged) rmSync(temporary(file.path), { force: true });
    const failed = files[staged.length];
    throw new Stop(`can't write ${failed.path}: ${error.code === 'ENOENT' ? 'its folder does not exist' : error.message}. Nothing was written.`);
  }

  for (const file of staged) renameSync(temporary(file.path), file.path);
}
