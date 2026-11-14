// SPDX-License-Identifier: MIT
// vexproof module map for webpack 5 and Rspack.
//
//   // webpack.config.js or rspack.config.js
//   const { VexproofPlugin } = require('vexproof/webpack');
//   module.exports = { plugins: [new VexproofPlugin()] };
//
// Writes vexproof-modules.json (project root) with every module, including those concatenated into
// others. `webpack --json` usually does too, but `rspack build --json` ignores the config's stats options
// and leaves concatenated modules out, which is why this plugin exists.
const { writeFileSync } = require('node:fs');
const { resolve, relative } = require('node:path');

const STATS = {
  all: false,
  modules: true,
  nestedModules: true,
  orphanModules: true,
  runtimeModules: true, // so a chunk that holds only the runtime is not mistaken for one whose contents are unknown
  ids: true,
  reasons: true, // who imports each module: lets a reviewed decision tell when new code starts using a vulnerable file
  chunks: false,
  groupModulesByType: false,
  groupModulesByAttributes: false,
  groupModulesByPath: false,
  groupModulesByExtension: false,
  excludeModules: false,
  modulesSpace: Infinity,
  nestedModulesSpace: Infinity,
  // Which files the build emitted, and for which chunks: vexproof checks that every .js file in the output
  // folder is one of them. A file a plugin copied in belongs to no chunk, and is then accounted for on its own.
  assets: true,
  cachedAssets: true,
  assetsSpace: Infinity,
  // Child compilations (worker-loader, monaco's workers) ship code too; they take these same options.
  children: true,
};

// Every compiler in this process that writes to one file, by that file. A configuration array (webpack's
// multi-compiler) runs one compiler per configuration, each with its own plugin instance and often its own
// output folder. Written one after another, the last would replace the rest, and the packages only an earlier
// configuration shipped would look absent. Kept per compiler, so a rebuild in watch mode replaces its own record,
// and forgotten when the compiler shuts down: a later build in the same process, with compilers of its own,
// writes a file about its own output, not one that still holds a finished build's.
const written = new Map(); // output file → Map<compiler, stats>

class VexproofPlugin {
  constructor({ output = 'vexproof-modules.json' } = {}) {
    this.output = output;
  }

  apply(compiler) {
    const file = () => resolve(compiler.context, this.output);

    compiler.hooks.done.tap('VexproofPlugin', (stats) => {
      const json = stats.toJson(STATS);
      // relative to the project folder, like the module names, so the file means the same on another machine
      json.vexproofOutDir = relative(compiler.context, compiler.outputPath).replace(/\\/g, '/') || '.';
      json.vexproofBundler = compiler.webpack?.rspackVersion
        ? `rspack ${compiler.webpack.rspackVersion}`
        : `webpack ${compiler.webpack?.version ?? '?'}`;

      const outputFile = file();
      if (!written.has(outputFile)) {
        written.set(outputFile, new Map());
      }
      const mine = written.get(outputFile);
      mine.set(compiler, json);

      // One configuration: its stats, as before. Several: the shape `webpack --json` gives a configuration
      // array, one child per configuration, each with its own output folder.
      const all = [...mine.values()];
      const doc = all.length === 1
        ? json
        : {
          vexproofBundler: json.vexproofBundler,
          vexproofConfigurations: all.length,
          children: all.map((configurationStats) => ({ ...configurationStats, outputPath: configurationStats.vexproofOutDir })),
        };
      writeFileSync(outputFile, JSON.stringify(doc));
    });

    // the file on disk stays as written; only this process's memory of the compiler goes
    compiler.hooks.shutdown?.tap('VexproofPlugin', () => {
      const outputFile = file();
      const records = written.get(outputFile);
      records?.delete(compiler);
      if (records?.size === 0) {
        written.delete(outputFile);
      }
    });
  }
}

module.exports = { VexproofPlugin, STATS };
