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
import { writeFileSync } from 'node:fs';
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

  const record = () => {
    const file = resolve(root, output);
    if (!registry.has(file)) registry.set(file, { vexproof: 1, bundler, inputs: {}, outputs: {}, outDirs: [] });
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
      for (const chunk of Object.values(bundle)) {
        if (chunk.type !== 'chunk') continue;
        const key = dir ? toPosix(relative(root, join(dir, chunk.fileName))) : chunk.fileName;
        const inputs = (rec.outputs[key] ??= { inputs: {} }).inputs;
        for (const [id, info] of Object.entries(chunk.modules ?? {})) {
          const bytes = info?.renderedLength ?? 0;
          if (bytes <= 0) continue;
          const k = cleanModuleId(id, root);
          inputs[k] = { bytesInOutput: (inputs[k]?.bytesInOutput ?? 0) + bytes };
        }
      }
    },
    closeBundle() {
      const { file, rec } = record();
      if (Object.keys(rec.outputs).length === 0) return; // e.g. only a server pass so far
      writeFileSync(file, JSON.stringify(rec, null, 1)); // rewritten by each build; the last write has everything
    },
  };
}

export { vexproof };
