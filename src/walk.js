// SPDX-License-Identifier: MIT
// Listing the files under a folder of shipped output, one way for every check that looks at it.
import { readdirSync, statSync, realpathSync } from 'node:fs';
import { join } from 'node:path';

/** A folder that had to be read could not be. A check that can't look at every file must not pass. */
export class UnreadableFolder extends Error {
  constructor(dir, cause) {
    super(`${dir} could not be read (${cause?.code ?? cause?.message ?? 'unknown error'})`);
    this.dir = dir;
  }
}

/**
 * Every file under `dir` (paths joined from `dir`).
 *
 * A link to a file is listed. A link to a folder is followed, each real folder once, so a cycle ends: a server
 * serves the files of a linked folder like any other, and a check that skipped them would miss what ships.
 * `enter(name, path)` decides whether to go into a subfolder, `recurse: false` lists `dir` alone, and with
 * `strict` a folder that can't be read throws UnreadableFolder (a missing `dir` itself is an empty list).
 */
export function listFiles(dir, { enter = () => true, recurse = true, strict = false } = {}) {
  const files = [];
  const seen = new Set();

  const visit = (folder, isTop) => {
    let real = folder;
    try {
      real = realpathSync(folder);
    } catch {
      /* listed below, or reported */
    }
    if (seen.has(real)) {
      return;
    }
    seen.add(real);

    let entries;
    try {
      entries = readdirSync(folder, { withFileTypes: true });
    } catch (error) {
      if (strict && !(isTop && error.code === 'ENOENT')) {
        throw new UnreadableFolder(folder, error);
      }

      return;
    }

    for (const entry of entries) {
      const path = join(folder, entry.name);
      let isFile = entry.isFile();
      let isDir = entry.isDirectory();
      if (entry.isSymbolicLink()) {
        try {
          const stats = statSync(path);
          isFile = stats.isFile();
          isDir = stats.isDirectory();
        } catch {
          continue; // dangling
        }
      }

      if (isFile) files.push(path);
      else if (isDir && recurse && enter(entry.name, path)) visit(path, false);
    }
  };

  visit(dir, true);

  return files;
}
