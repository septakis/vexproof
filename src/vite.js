// SPDX-License-Identifier: MIT
// vexproof module map for Vite (7 with Rollup, 8 with Rolldown) and plain Rollup.
//
//   // vite.config.js
//   import vexproof from 'vexproof/vite';
//   export default { plugins: [vexproof()], worker: { plugins: () => [vexproof()] } };
//
// After `vite build`, vexproof-modules.json (in the project root, not the deployed output) lists every
// source file with code in each output chunk. Pass it to `vexproof --modules vexproof-modules.json`.
//
// Every build that ships code needs the plugin: the main build, web workers (worker.plugins) and any
// nested build() calls. Instances in one process write one merged file, and vexproof checks that every
// .js file in the recorded output folders is covered, so a build without the plugin is caught, not missed.
import { writeFileSync, rmSync, existsSync, statSync } from 'node:fs';
import { relative, resolve, isAbsolute, join } from 'node:path';

const REGISTRY = Symbol.for('vexproof.vite.registry');
const registry = (globalThis[REGISTRY] ??= new Map()); // output path → merged record, per process
// The outputs a worker build recorded, kept on the merged record under a symbol so they are not written out.
// A worker build guesses where its file will land; only these records may be moved to where it really does.
const WORKER_OUTPUTS = Symbol.for('vexproof.vite.workerOutputs');

/**
 * Rollup's CommonJS support and Vite add virtual ids for the same file:
 *   "\0/app/node_modules/lodash/omit.js?commonjs-es-import". Strip the marker and query so they
 * count toward the real file. A file counts as shipped if any id for it rendered code, which can
 * only keep findings open, never close one.
 */
export function cleanModuleId(id, root) {
  let modulePath = String(id).replace(/^\0+/, '').split('?')[0];
  if (isAbsolute(modulePath)) modulePath = relative(root, modulePath);

  return modulePath.replace(/\\/g, '/');
}

const toPosix = (filePath) => filePath.replace(/\\/g, '/');

export default function vexproof({ output = 'vexproof-modules.json', includeServer = false, root: rootOption } = {}) {
  let root = rootOption ?? process.cwd();
  let outDir = null;
  let bundler = 'rollup';
  let ssrBuild = false;
  let workerBuild = false; // Vite builds web workers as builds of their own, and says so (config.isWorker)
  let watching = false;
  let mine = new Set(); // output files this instance recorded in the build that is running
  let stale = new Set(); // ones it recorded in an earlier build of this watch and has not written again

  const mergedRecord = () => {
    const file = resolve(root, output);
    if (!registry.has(file)) {
      registry.set(file, { vexproof: 1, bundler, inputs: {}, outputs: {}, outDirs: [] });
      // A map left by an earlier build describes that build. If this one records nothing (the plugin is on
      // a pass that ships no code), the old file must not stand in for it.
      try {
        rmSync(file, { force: true });
      } catch {
        /* not ours to remove, or already gone */
      }
    }

    return { file, record: registry.get(file) };
  };

  return {
    name: 'vexproof-modules',
    apply: 'build',
    configResolved(config) {
      if (!rootOption) root = config.root ?? root;
      if (config.build?.outDir) outDir = resolve(root, config.build.outDir);
      ssrBuild = Boolean(config.build?.ssr);
      workerBuild = Boolean(config.isWorker);
    },
    buildStart() {
      const meta = this.meta ?? {};
      watching = Boolean(meta.watchMode);
      stale = new Set([...stale, ...mine]);
      mine = new Set();

      if (meta.viteVersion) {
        const engine = meta.rolldownVersion ? `rolldown ${meta.rolldownVersion}` : `rollup ${meta.rollupVersion}`;
        bundler = `vite ${meta.viteVersion} (${engine})`;
      } else if (meta.rolldownVersion) {
        bundler = `rolldown ${meta.rolldownVersion}`;
      } else {
        bundler = `rollup ${meta.rollupVersion ?? '?'}`;
      }
    },
    generateBundle(options, bundle) {
      const consumer = this.environment?.config?.consumer;
      if ((consumer === 'server' || (!consumer && ssrBuild)) && !includeServer) {
        // not shipped to browsers, but part of the product: the CLI refuses to treat the browser bundle as the whole app
        const { record } = mergedRecord();
        record.serverBuildsSkipped = (record.serverBuildsSkipped ?? 0) + 1;

        return;
      }

      let dir;
      if (options.dir) {
        dir = resolve(root, options.dir);
      } else if (options.file) {
        dir = resolve(root, options.file, '..');
      } else {
        dir = outDir;
      }

      const { record } = mergedRecord();
      record.bundler = bundler;
      if (dir) {
        const outDirName = toPosix(relative(root, dir)) || '.';
        if (!record.outDirs.includes(outDirName)) record.outDirs.push(outDirName);
      }

      // who imports whom, in the metafile's shape: lets a reviewed decision tell when new code starts using a file.
      // Every module in the build's graph, not only those in chunks: re-export barrels (lodash-es/lodash.js) are
      // often dropped from chunks entirely, and the chain from your code to a vulnerable file runs through them.
      for (const id of this.getModuleIds?.() ?? []) {
        const info = this.getModuleInfo?.(id);
        if (!info) continue;
        const moduleKey = cleanModuleId(id, root);
        // an external (Rollup `external`, iife/umd `globals`) is marked: the output loads it at runtime, so it ships
        const imports = [...(info.importedIds ?? []), ...(info.dynamicallyImportedIds ?? [])]
          .map((importedId) => (this.getModuleInfo?.(importedId)?.isExternal
            ? { path: importedId, external: true }
            : { path: cleanModuleId(importedId, root) }))
          .filter((imported) => imported.path !== moduleKey);
        if (imports.length) {
          const known = record.inputs[moduleKey]?.imports ?? [];
          const byPath = new Map([...known, ...imports].map((imported) => [imported.path, imported]));
          record.inputs[moduleKey] = { imports: [...byPath.values()] };
        }
      }

      // A worker imported with ?worker or ?sharedworker is bundled by a build of its own, and that build runs
      // this plugin only if it is in worker.plugins. Each build notes its entry files; a worker whose file no
      // build entered was bundled unseen. Inlined (?worker&inline) it is not even a file of its own, so the
      // check for unrecorded output files can't catch it. The CLI stops on what is listed here.
      record.entries ??= [];
      for (const chunk of Object.values(bundle)) {
        if (chunk.type === 'chunk' && chunk.isEntry && chunk.facadeModuleId) {
          const entryId = cleanModuleId(chunk.facadeModuleId, root);
          if (!record.entries.includes(entryId)) record.entries.push(entryId);
        }
      }
      const unseen = new Set(record.unrecordedWorkers ?? []);
      for (const id of this.getModuleIds?.() ?? []) {
        if (!/[?&](worker|sharedworker)(&|=|$)/.test(String(id))) continue;
        const entry = cleanModuleId(id, root);
        if (!record.entries.includes(entry)) unseen.add(entry);
      }
      record.unrecordedWorkers = [...unseen].filter((entry) => !record.entries.includes(entry));

      record[WORKER_OUTPUTS] ??= new Set();
      for (const chunk of Object.values(bundle)) {
        if (chunk.type !== 'chunk') {
          continue;
        }

        const key = dir ? toPosix(relative(root, join(dir, chunk.fileName))) : chunk.fileName;
        const inputs = (record.outputs[key] ??= { inputs: {} }).inputs;
        mine.add(key);
        stale.delete(key);
        if (workerBuild) {
          record[WORKER_OUTPUTS].add(key);
        }

        for (const [id, info] of Object.entries(chunk.modules ?? {})) {
          const bytes = info?.renderedLength ?? 0;
          if (bytes <= 0) continue;
          const moduleKey = cleanModuleId(id, root);
          inputs[moduleKey] = { bytesInOutput: (inputs[moduleKey]?.bytesInOutput ?? 0) + bytes };
        }
      }

      // A worker is bundled on its own and handed to this build as a finished file. The worker's build can't
      // know where that file will land (SvelteKit writes elsewhere than build.outDir), so it was recorded
      // under a guess. This build knows: move the record to where it puts the file. Only a record a worker
      // build made can move, and only when exactly one has the file's name: a record that moved to the wrong
      // file would vouch for code it does not describe. A worker whose record stays put leaves its file
      // unrecorded, and the CLI checks unrecorded files.
      for (const item of Object.values(bundle)) {
        if (item.type !== 'asset' || !/\.(m|c)?js$/.test(item.fileName)) {
          continue;
        }

        const key = dir ? toPosix(relative(root, join(dir, item.fileName))) : item.fileName;
        if (record.outputs[key]) {
          // Already recorded where this build writes the file (the worker's build guessed right). This build
          // writes it, after the worker's build closed, so this build takes its size when it is done.
          mine.add(key);
          stale.delete(key);
          continue;
        }

        const candidates = [...record[WORKER_OUTPUTS]]
          .filter((outputKey) => record.outputs[outputKey])
          .filter((outputKey) => outputKey === item.fileName || outputKey.endsWith(`/${item.fileName}`));
        if (candidates.length !== 1) {
          continue;
        }

        const [from] = candidates;
        record.outputs[key] = record.outputs[from];
        delete record.outputs[from];
        record[WORKER_OUTPUTS].delete(from);
        mine.add(key);
        stale.delete(key);
      }
    },
    closeBundle() {
      const { file, record } = mergedRecord();

      // A rebuild in watch mode writes chunks under new hashed names and removes the old files (emptyOutDir),
      // but this process still holds their records. Drop the ones this instance wrote in an earlier build, did
      // not write again, and whose file is gone, so the map describes what is on disk.
      if (watching) {
        for (const outputKey of stale) {
          if (!existsSync(resolve(root, outputKey))) {
            delete record.outputs[outputKey];
            stale.delete(outputKey);
          }
        }
      }

      if (Object.keys(record.outputs).length === 0) {
        return; // e.g. only a server pass so far
      }

      // The size of each file this instance recorded, as it is now that the build is done. The CLI compares it
      // with the file on disk: one of another size was written since, by a build this map knows nothing about.
      for (const outputKey of mine) {
        const recorded = record.outputs[outputKey];
        if (!recorded) {
          continue;
        }

        try {
          recorded.bytes = statSync(resolve(root, outputKey)).size;
        } catch {
          delete recorded.bytes; // not where it was recorded: the CLI decides what that means
        }
      }

      writeFileSync(file, JSON.stringify(record, null, 1)); // rewritten by each build; the last write has everything
    },
  };
}

export { vexproof };
