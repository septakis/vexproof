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
const BINARY = /\.(node|wasm)$/; // compiled code a bundler copies as it is
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
  const matches = (bySize, buf) => { const h = sha(buf); return (bySize.get(buf.length) ?? []).filter((f) => hashOf(f) === h); };

  // node_modules also holds tool folders (.cache, .vite, .bin): only the package stores among them hold packages
  const notPackages = (name, p) => name.startsWith('.') && !['.pnpm', '.bun', '.store'].includes(name) && dirname(p).endsWith('node_modules');
  const installedFiles = () => {
    const out = [];
    const walk = (dir) => {
      let entries;
      try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        const p = join(dir, e.name);
        if (e.isDirectory()) { if (!notPackages(e.name, p)) walk(p); } else if (JS.test(e.name) || BINARY.test(e.name)) out.push(p);
      }
    };
    for (const b of bases) walk(join(b, 'node_modules'));
    return out;
  };

  const outs = outDirs.map((d) => resolve(d));
  // What git has for each tracked file: the id of its content as committed or staged, not what is in the
  // working tree now. A build that overwrites a tracked file does not make its output the project's own.
  const trackedBlobs = () => {
    const top = bases.at(-1) ?? root;
    const blobs = new Map(); // blob id -> path
    const r = spawnSync('git', ['ls-files', '-s', '-z'], { cwd: top, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
    if (r.status !== 0 || typeof r.stdout !== 'string') return blobs;
    for (const line of r.stdout.split('\0')) {
      const m = /^\d+ ([0-9a-f]+) \d+\t(.+)$/.exec(line);
      if (!m || !JS.test(m[2]) || /(^|\/)node_modules\//.test(m[2])) continue;
      const p = resolve(top, m[2]);
      if (outs.some((o) => p === o || p.startsWith(o + '/') || p.startsWith(o + '\\'))) continue;
      if (!blobs.has(m[1])) blobs.set(m[1], p);
    }
    return blobs;
  };
  const blobId = (buf, algo) => createHash(algo).update(`blob ${buf.length}\0`).update(buf).digest('hex');

  let installed = null, project = null, list = null;
  const files = () => (list ??= installedFiles());
  const installedAll = (buf) => matches(installed ??= bySizeOf(files()), buf);
  return {
    installedAll,
    /** Installed files whose path ends with the given one ("base/worker/workerMain.js"): where a copy may have come from. */
    installedEndingWith: (tail) => { const t = `/${String(tail).replace(/\\/g, '/').replace(/^\.?\/+/, '')}`; return files().filter((f) => f.replace(/\\/g, '/').endsWith(t)); },
    installed: (buf) => installedAll(buf)[0],
    project: (buf) => {
      project ??= trackedBlobs();
      if (!project.size) return undefined;
      const algo = [...project.keys()][0].length === 64 ? 'sha256' : 'sha1';
      // git may store line endings as LF and check them out as CRLF: the same file either way
      const lf = buf.includes(13) ? Buffer.from(buf.toString('latin1').replace(/\r\n/g, '\n'), 'latin1') : null;
      return project.get(blobId(buf, algo)) ?? (lf ? project.get(blobId(lf, algo)) : undefined);
    },
  };
}
