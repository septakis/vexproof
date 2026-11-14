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
/** The same bytes with CRLF line endings turned into LF. */
const toLf = (buf) => Buffer.from(buf.toString('latin1').replace(/\r\n/g, '\n'), 'latin1');

/**
 * { installedAll(buf), installedEndingWith(tail), project(buf) }: installedAll returns every installed file with
 * the same content (line endings aside), project the tracked project file with it, or undefined.
 *
 * `installedAll` looks in node_modules under each of `bases` (installBases). `project` looks only at files git
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

  // compared without case on Windows, where a stats file may spell the output folder differently from --root
  const fold = process.platform === 'win32' ? (p) => p.toLowerCase() : (p) => p;
  const outs = outDirs.map((d) => fold(resolve(d)));
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
      const p = resolve(top, m[2]), f = fold(p);
      if (outs.some((o) => f === o || f.startsWith(o + '/') || f.startsWith(o + '\\'))) continue;
      if (!blobs.has(m[1])) blobs.set(m[1], p);
    }
    return blobs;
  };
  const blobId = (buf, algo) => createHash(algo).update(`blob ${buf.length}\0`).update(buf).digest('hex');

  let installed = null, project = null, list = null;
  const files = () => (list ??= installedFiles());
  // git may check a vendored copy out with CRLF line endings (core.autocrlf): it is still that package's file
  const installedAll = (buf) => {
    const exact = matches(installed ??= bySizeOf(files()), buf);
    return exact.length || !buf.includes(13) ? exact : matches(installed, toLf(buf));
  };
  return {
    installedAll,
    /** Installed files whose path ends with the given one ("base/worker/workerMain.js"): where a copy may have come from. */
    installedEndingWith: (tail) => { const t = `/${String(tail).replace(/\\/g, '/').replace(/^\.?\/+/, '')}`; return files().filter((f) => f.replace(/\\/g, '/').endsWith(t)); },
    project: (buf) => {
      project ??= trackedBlobs();
      if (!project.size) return undefined;
      const algo = [...project.keys()][0].length === 64 ? 'sha256' : 'sha1';
      // git may store line endings as LF and check them out as CRLF: the same file either way
      const lf = buf.includes(13) ? toLf(buf) : null;
      return project.get(blobId(buf, algo)) ?? (lf ? project.get(blobId(lf, algo)) : undefined);
    },
  };
}
