// SPDX-License-Identifier: MIT
// Byte-identical copies: is a file in the build output an installed package file, or one of the project's own?
//
// Files are indexed by size first and hashed only when a size matches, so a few stray files don't cost a hash
// of every installed file.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const JS = /\.(m|c)?js$/;
const sha = (buf) => createHash('sha256').update(buf).digest('hex');

/**
 * { installed(buf), project(buf) }: each returns the absolute path of an identical file, or undefined.
 *
 * `installed` looks in node_modules under each of `bases` (installBases). `project` looks only at files git
 * tracks under the outermost base, outside `outDirs`: a tracked file is something the project wrote or vendored,
 * while an untracked one may be another build's output, a bundle with packages inside that nothing recorded.
 * Outside a git checkout no file counts as the project's own.
 */
export function copyFinder({ root, bases, outDirs = [] }) {
  const hashes = new Map();
  const hashOf = (f) => { if (!hashes.has(f)) { try { hashes.set(f, sha(readFileSync(f))); } catch { hashes.set(f, null); } } return hashes.get(f); };
  const bySizeOf = (files) => {
    const bySize = new Map();
    for (const p of files) {
      let size; try { size = statSync(p).size; } catch { continue; }
      if (!bySize.has(size)) bySize.set(size, []);
      bySize.get(size).push(p);
    }
    return bySize;
  };
  const match = (bySize, buf) => { const h = sha(buf); return (bySize.get(buf.length) ?? []).find((f) => hashOf(f) === h); };

  // node_modules also holds tool folders (.cache, .vite, .bin): only the package stores among them hold packages
  const notPackages = (name, p) => name.startsWith('.') && !['.pnpm', '.bun', '.store'].includes(name) && dirname(p).endsWith('node_modules');
  const installedFiles = () => {
    const out = [];
    const walk = (dir) => {
      let entries;
      try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        const p = join(dir, e.name);
        if (e.isDirectory()) { if (!notPackages(e.name, p)) walk(p); } else if (JS.test(e.name)) out.push(p);
      }
    };
    for (const b of bases) walk(join(b, 'node_modules'));
    return out;
  };

  const outs = outDirs.map((d) => resolve(d));
  const trackedFiles = () => {
    const top = bases.at(-1) ?? root;
    const r = spawnSync('git', ['ls-files', '-z'], { cwd: top, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
    if (r.status !== 0 || typeof r.stdout !== 'string') return [];
    return r.stdout.split('\0').filter((f) => JS.test(f) && !/(^|\/)node_modules\//.test(f)).map((f) => resolve(top, f))
      .filter((p) => !outs.some((o) => p === o || p.startsWith(o + '/') || p.startsWith(o + '\\')));
  };

  let installed = null, project = null;
  return {
    installed: (buf) => match(installed ??= bySizeOf(installedFiles()), buf),
    project: (buf) => match(project ??= bySizeOf(trackedFiles()), buf),
  };
}
