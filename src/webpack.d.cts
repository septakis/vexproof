// SPDX-License-Identifier: MIT
// Types for 'vexproof/webpack' and 'vexproof/rspack'. Written without importing webpack's or Rspack's types,
// so the package needs neither installed.

declare class VexproofPlugin {
  constructor(options?: {
    /** Where the module map is written, relative to the compiler's context. Default `vexproof-modules.json`. */
    output?: string;
  });
  output: string;
  apply(compiler: any): void;
}

/** The stats options the plugin asks the bundler for. */
declare const STATS: Record<string, unknown>;

export { VexproofPlugin, STATS };
