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
};

class VexproofPlugin {
  constructor({ output = 'vexproof-modules.json' } = {}) {
    this.output = output;
  }

  apply(compiler) {
    compiler.hooks.done.tap('VexproofPlugin', (stats) => {
      const { writeFileSync } = require('node:fs');
      const { resolve } = require('node:path');
      const json = stats.toJson(STATS);
      json.vexproofBundler = compiler.webpack?.rspackVersion ? `rspack ${compiler.webpack.rspackVersion}` : `webpack ${compiler.webpack?.version ?? '?'}`;
      writeFileSync(resolve(compiler.context, this.output), JSON.stringify(json));
    });
  }
}

module.exports = { VexproofPlugin, STATS };
