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
const STATS = {
  all: false,
  modules: true,
  nestedModules: true,
  orphanModules: true,
  runtimeModules: false,
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

class VexproofPlugin {
  constructor({ output = 'vexproof-modules.json' } = {}) {
    this.output = output;
  }

  apply(compiler) {
    compiler.hooks.done.tap('VexproofPlugin', (stats) => {
      const { writeFileSync } = require('node:fs');
      const { resolve, relative } = require('node:path');
      const json = stats.toJson(STATS);
      // relative to the project folder, like the module names, so the file means the same on another machine
      json.vexproofOutDir = relative(compiler.context, compiler.outputPath).replace(/\\/g, '/') || '.';
      json.vexproofBundler = compiler.webpack?.rspackVersion ? `rspack ${compiler.webpack.rspackVersion}` : `webpack ${compiler.webpack?.version ?? '?'}`;
      writeFileSync(resolve(compiler.context, this.output), JSON.stringify(json));
    });
  }
}

module.exports = { VexproofPlugin, STATS };
