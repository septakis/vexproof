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
  const out = [];
  const seen = new Set();
  const visit = (d, top) => {
    let real = d;
    try { real = realpathSync(d); } catch { /* listed below, or reported */ }
    if (seen.has(real)) return;
    seen.add(real);
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch (e) {
      if (strict && !(top && e.code === 'ENOENT')) throw new UnreadableFolder(d, e);
      return;
    }
    for (const e of entries) {
      const p = join(d, e.name);
      let isFile = e.isFile(), isDir = e.isDirectory();
      if (e.isSymbolicLink()) {
        try { const st = statSync(p); isFile = st.isFile(); isDir = st.isDirectory(); } catch { continue; } // dangling
      }
      if (isFile) out.push(p);
      else if (isDir && recurse && enter(e.name, p)) visit(p, false);
    }
  };
  visit(dir, true);
  return out;
}
