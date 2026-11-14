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
const sha = (buffer) => createHash('sha256').update(buffer).digest('hex');
/** The same bytes with CRLF line endings turned into LF. */
const toLf = (buffer) => Buffer.from(buffer.toString('latin1').replace(/\r\n/g, '\n'), 'latin1');

/**
 * { installedAll(buffer), installedEndingWith(tail), project(buffer) }: installedAll returns every installed file with
 * the same content (line endings aside), project the tracked project file with it, or undefined.
 *
 * `installedAll` looks in node_modules under each of `bases` (installBases). `project` looks only at files git
 * tracks under the outermost base, outside `outDirs`: a tracked file is something the project wrote or vendored,
 * while an untracked one may be another build's output, a bundle with packages inside that nothing recorded.
 * Outside a git checkout no file counts as the project's own.
 */
export function copyFinder({ root, bases, outDirs = [] }) {
  const hashes = new Map();
  const hashOf = (file) => {
    if (!hashes.has(file)) {
      try {
        hashes.set(file, sha(readFileSync(file)));
      } catch {
        hashes.set(file, null);
      }
    }

    return hashes.get(file);
  };
  const bySizeOf = (files) => {
    const bySize = new Map();
    for (const file of files) {
      let size;
      try {
        size = statSync(file).size;
      } catch {
        continue;
      }
      if (!bySize.has(size)) bySize.set(size, []);
      bySize.get(size).push(file);
    }

    return bySize;
  };
  const matches = (bySize, buffer) => {
    const hash = sha(buffer);

    return (bySize.get(buffer.length) ?? []).filter((file) => hashOf(file) === hash);
  };

  // node_modules also holds tool folders (.cache, .vite, .bin): only the package stores among them hold packages
  const notPackages = (name, path) => name.startsWith('.')
    && !['.pnpm', '.bun', '.store'].includes(name)
    && dirname(path).endsWith('node_modules');
  const installedFiles = () => {
    const found = [];
    const walk = (dir) => {
      let entries;
      try {
        entries = readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!notPackages(entry.name, path)) walk(path);
        } else if (JS.test(entry.name) || BINARY.test(entry.name)) {
          found.push(path);
        }
      }
    };

    for (const base of bases) walk(join(base, 'node_modules'));

    return found;
  };

  // compared without case on Windows, where a stats file may spell the output folder differently from --root
  const fold = process.platform === 'win32' ? (path) => path.toLowerCase() : (path) => path;
  const foldedOutDirs = outDirs.map((outDir) => fold(resolve(outDir)));
  // What git has for each tracked file: the id of its content as committed or staged, not what is in the
  // working tree now. A build that overwrites a tracked file does not make its output the project's own.
  const trackedBlobs = () => {
    const top = bases.at(-1) ?? root;
    const blobs = new Map(); // blob id -> path
    const git = spawnSync('git', ['ls-files', '-s', '-z'], { cwd: top, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
    if (git.status !== 0 || typeof git.stdout !== 'string') {
      return blobs;
    }

    for (const line of git.stdout.split('\0')) {
      const match = /^\d+ ([0-9a-f]+) \d+\t(.+)$/.exec(line);
      if (!match || !JS.test(match[2]) || /(^|\/)node_modules\//.test(match[2])) continue;

      const path = resolve(top, match[2]);
      const folded = fold(path);
      const inOutDir = foldedOutDirs.some((outDir) => folded === outDir
        || folded.startsWith(outDir + '/')
        || folded.startsWith(outDir + '\\'));
      if (inOutDir) continue;
      if (!blobs.has(match[1])) blobs.set(match[1], path);
    }

    return blobs;
  };
  const blobId = (buffer, algorithm) => createHash(algorithm).update(`blob ${buffer.length}\0`).update(buffer).digest('hex');

  let installedBySize = null;
  let projectBlobs = null;
  let installedList = null;
  const files = () => (installedList ??= installedFiles());
  // git may check a vendored copy out with CRLF line endings (core.autocrlf): it is still that package's file
  const installedAll = (buffer) => {
    installedBySize ??= bySizeOf(files());
    const exact = matches(installedBySize, buffer);

    return exact.length || !buffer.includes(13) ? exact : matches(installedBySize, toLf(buffer));
  };

  return {
    installedAll,
    /** Installed files whose path ends with the given one ("base/worker/workerMain.js"): where a copy may have come from. */
    installedEndingWith: (tail) => {
      const suffix = `/${String(tail).replace(/\\/g, '/').replace(/^\.?\/+/, '')}`;

      return files().filter((file) => file.replace(/\\/g, '/').endsWith(suffix));
    },
    project: (buffer) => {
      projectBlobs ??= trackedBlobs();
      if (!projectBlobs.size) {
        return undefined;
      }

      const algorithm = [...projectBlobs.keys()][0].length === 64 ? 'sha256' : 'sha1';
      // git may store line endings as LF and check them out as CRLF: the same file either way
      const lfBuffer = buffer.includes(13) ? toLf(buffer) : null;

      return projectBlobs.get(blobId(buffer, algorithm))
        ?? (lfBuffer ? projectBlobs.get(blobId(lfBuffer, algorithm)) : undefined);
    },
  };
}
