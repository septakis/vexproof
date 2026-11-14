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
import { writeFileSync, rmSync, existsSync } from 'node:fs';
import { relative, resolve, isAbsolute, join } from 'node:path';

const REGISTRY = Symbol.for('vexproof.vite.registry');
const registry = (globalThis[REGISTRY] ??= new Map()); // output path → merged record, per process

/**
 * Rollup's CommonJS support and Vite add virtual ids for the same file:
 *   "\0/app/node_modules/lodash/omit.js?commonjs-es-import". Strip the marker and query so they
 * count toward the real file. A file counts as shipped if any id for it rendered code, which can
 * only keep findings open, never close one.
 */
export function cleanModuleId(id, root) {
  let p = String(id).replace(/^\0+/, '').split('?')[0];
  if (isAbsolute(p)) p = relative(root, p);
  return p.replace(/\\/g, '/');
}

const toPosix = (p) => p.replace(/\\/g, '/');

export default function vexproof({ output = 'vexproof-modules.json', includeServer = false, root: rootOption } = {}) {
  let root = rootOption ?? process.cwd();
  let outDir = null;
  let bundler = 'rollup';
  let ssrBuild = false;
  let watching = false;
  let mine = new Set(); // output files this instance recorded in the build that is running
  let stale = new Set(); // ones it recorded in an earlier build of this watch and has not written again

  const record = () => {
    const file = resolve(root, output);
    if (!registry.has(file)) {
      registry.set(file, { vexproof: 1, bundler, inputs: {}, outputs: {}, outDirs: [] });
      // A map left by an earlier build describes that build. If this one records nothing (the plugin is on
      // a pass that ships no code), the old file must not stand in for it.
      try { rmSync(file, { force: true }); } catch { /* not ours to remove, or already gone */ }
    }
    return { file, rec: registry.get(file) };
  };

  return {
    name: 'vexproof-modules',
    apply: 'build',
    configResolved(config) {
      if (!rootOption) root = config.root ?? root;
      if (config.build?.outDir) outDir = resolve(root, config.build.outDir);
      ssrBuild = Boolean(config.build?.ssr);
    },
    buildStart() {
      const m = this.meta ?? {};
      watching = Boolean(m.watchMode);
      stale = new Set([...stale, ...mine]);
      mine = new Set();
      bundler = m.viteVersion ? `vite ${m.viteVersion} (${m.rolldownVersion ? `rolldown ${m.rolldownVersion}` : `rollup ${m.rollupVersion}`})` : m.rolldownVersion ? `rolldown ${m.rolldownVersion}` : `rollup ${m.rollupVersion ?? '?'}`;
    },
    generateBundle(options, bundle) {
      const consumer = this.environment?.config?.consumer;
      if ((consumer === 'server' || (!consumer && ssrBuild)) && !includeServer) {
        // not shipped to browsers, but part of the product: the CLI refuses to treat the browser bundle as the whole app
        record().rec.serverBuildsSkipped = (record().rec.serverBuildsSkipped ?? 0) + 1;
        return;
      }
      const dir = options.dir ? resolve(root, options.dir) : options.file ? resolve(root, options.file, '..') : outDir;
      const { rec } = record();
      rec.bundler = bundler;
      if (dir) {
        const d = toPosix(relative(root, dir)) || '.';
        if (!rec.outDirs.includes(d)) rec.outDirs.push(d);
      }
      // who imports whom, in the metafile's shape: lets a reviewed decision tell when new code starts using a file.
      // Every module in the build's graph, not only those in chunks: re-export barrels (lodash-es/lodash.js) are
      // often dropped from chunks entirely, and the chain from your code to a vulnerable file runs through them.
      for (const id of this.getModuleIds?.() ?? []) {
        const info = this.getModuleInfo?.(id);
        if (!info) continue;
        const k = cleanModuleId(id, root);
        const imports = [...(info.importedIds ?? []), ...(info.dynamicallyImportedIds ?? [])].map((i) => ({ path: cleanModuleId(i, root) })).filter((i) => i.path !== k);
        if (imports.length) rec.inputs[k] = { imports: [...new Map([...(rec.inputs[k]?.imports ?? []), ...imports].map((i) => [i.path, i])).values()] };
      }
      // A worker imported with ?worker or ?sharedworker is bundled by a build of its own, and that build runs
      // this plugin only if it is in worker.plugins. Each build notes its entry files; a worker whose file no
      // build entered was bundled unseen. Inlined (?worker&inline) it is not even a file of its own, so the
      // check for unrecorded output files can't catch it. The CLI stops on what is listed here.
      rec.entries ??= [];
      for (const chunk of Object.values(bundle)) {
        if (chunk.type === 'chunk' && chunk.isEntry && chunk.facadeModuleId) { const e = cleanModuleId(chunk.facadeModuleId, root); if (!rec.entries.includes(e)) rec.entries.push(e); }
      }
      const unseen = new Set(rec.unrecordedWorkers ?? []);
      for (const id of this.getModuleIds?.() ?? []) {
        if (!/[?&](worker|sharedworker)(&|=|$)/.test(String(id))) continue;
        const entry = cleanModuleId(id, root);
        if (!rec.entries.includes(entry)) unseen.add(entry);
      }
      rec.unrecordedWorkers = [...unseen].filter((e) => !rec.entries.includes(e));
      for (const chunk of Object.values(bundle)) {
        if (chunk.type !== 'chunk') continue;
        const key = dir ? toPosix(relative(root, join(dir, chunk.fileName))) : chunk.fileName;
        const inputs = (rec.outputs[key] ??= { inputs: {} }).inputs;
        mine.add(key); stale.delete(key);
        for (const [id, info] of Object.entries(chunk.modules ?? {})) {
          const bytes = info?.renderedLength ?? 0;
          if (bytes <= 0) continue;
          const k = cleanModuleId(id, root);
          inputs[k] = { bytesInOutput: (inputs[k]?.bytesInOutput ?? 0) + bytes };
        }
      }
      // A worker is bundled on its own and handed to this build as a finished file. The worker's build can't
      // know where that file will land (SvelteKit writes elsewhere than build.outDir), so it was recorded
      // under a guess. This build knows: move the record to where it puts the file.
      for (const item of Object.values(bundle)) {
        if (item.type !== 'asset' || !/\.(m|c)?js$/.test(item.fileName)) continue;
        const key = dir ? toPosix(relative(root, join(dir, item.fileName))) : item.fileName;
        if (rec.outputs[key]) continue;
        const from = Object.keys(rec.outputs).find((k) => k === item.fileName || k.endsWith(`/${item.fileName}`));
        if (from) { rec.outputs[key] = rec.outputs[from]; delete rec.outputs[from]; mine.add(key); stale.delete(key); }
      }
    },
    closeBundle() {
      const { file, rec } = record();
      // A rebuild in watch mode writes chunks under new hashed names and removes the old files (emptyOutDir),
      // but this process still holds their records. Drop the ones this instance wrote in an earlier build, did
      // not write again, and whose file is gone, so the map describes what is on disk.
      if (watching) for (const k of stale) if (!existsSync(resolve(root, k))) { delete rec.outputs[k]; stale.delete(k); }
      if (Object.keys(rec.outputs).length === 0) return; // e.g. only a server pass so far
      writeFileSync(file, JSON.stringify(rec, null, 1)); // rewritten by each build; the last write has everything
    },
  };
}

export { vexproof };
