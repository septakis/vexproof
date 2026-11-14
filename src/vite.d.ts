// SPDX-License-Identifier: MIT
// Types for 'vexproof/vite' and 'vexproof/rollup'. Written without importing Vite's or Rollup's types, so
// the package needs neither installed; the plugin object fits both `Plugin` types.

export interface VexproofOptions {
  /** Where the module map is written, relative to the project root. Default `vexproof-modules.json`. */
  output?: string;
  /** Record server (SSR) builds too. By default they are counted and left out. */
  includeServer?: boolean;
  /** The project root. Default: Vite's `root`, or the current directory under plain Rollup. */
  root?: string;
}

export interface VexproofPlugin {
  name: 'vexproof-modules';
  apply: 'build';
  configResolved(config: any): void;
  buildStart(this: any): void;
  generateBundle(this: any, options: any, bundle: any): void;
  closeBundle(this: any): void;
}

/** Writes `vexproof-modules.json`: every source file with code in each output chunk. */
export default function vexproof(options?: VexproofOptions): VexproofPlugin;
export { vexproof };

/** A module id as the module map names it: no virtual-module marker or query, relative to `root`, `/` separators. */
export function cleanModuleId(id: string, root: string): string;
