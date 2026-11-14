// SPDX-License-Identifier: MIT
// How npm package names are compared, in one place. Every module that matches a name from one source (a purl, a
// module map, a require() call, a Dependabot alert) against a name from another uses these.

/**
 * The name vexproof compares npm packages by. The purl spec lowercases npm names, and SBOM tools follow it
 * (cyclonedx-npm writes pkg:npm/jsonstream for JSONStream), while bundlers and module maps keep the name from
 * package.json. The registry refuses names that differ only in case, so the two spellings are one package.
 */
export const npmName = (name) => String(name).toLowerCase();

/** A Set of npm package names whose `add`, `has` and `delete` ignore case (see npmName). */
export class NpmNameSet extends Set {
  add(name) { return super.add(npmName(name)); }
  has(name) { return super.has(npmName(name)); }
  delete(name) { return super.delete(npmName(name)); }
}
