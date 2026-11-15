// SPDX-License-Identifier: MIT
// What shipped: the packages a build or a deployment put in front of users, from module maps (--modules), a
// deployment folder (--deploy) and a bundle SBOM (--bundle), with every check that has to pass before vexproof
// may call a package absent. A check that fails stops the run with a Stop that says what to do; nothing here
// writes a file or exits.
import { resolve, dirname } from 'node:path';
import { readModuleMap, bundleSbomFromModules, attachVersions, addToMap, splitNodeModulesPath, unnamedStorePackages } from './modules.js';
import { strayOutputs, accountFor, addWorkspacePackages, runtimeLoads, binaryCopies, CoverageError } from './coverage.js';
import { readDeployment, mergeModuleMaps, defaultMapDirs, inlineMapPackages, deploymentDigest } from './deploy.js';
import { normalizeFindings, parsePurl, indexSbom, NpmNameSet } from './index.js';
import { readPackageJson } from './package-json.js';
import { Stop } from './stop.js';
import { NO_PROGRESS } from './progress.js';

// Frameworks whose apps also run code on a server. Their packages can be missing from the browser bundle and
// still run in production, so a browser module map cannot stand for the whole product.
const SERVER_FRAMEWORKS = ['next', 'nuxt', '@sveltejs/kit', '@remix-run/server-runtime', '@react-router/node', '@angular/ssr', 'vike', '@solidjs/start', '@tanstack/react-start', '@astrojs/node', '@analogjs/platform'];
// Servers a project writes beside its front end (an Express API, an Electron main process). These are in many
// lockfiles as someone's dependency, so only the project's own dependencies count.
const SERVERS = ['express', 'fastify', 'koa', '@hapi/hapi', '@nestjs/core', 'hono', 'restify', 'polka', 'h3', 'electron', 'socket.io', '@apollo/server', '@trpc/server'];

const MAX_LISTED = 8; // how many files or folders a message names before it says "and N more"
const listed = (items, show = (item) => item) => [
  ...items.slice(0, MAX_LISTED).map((item) => `  ${show(item)}`),
  ...(items.length > MAX_LISTED ? [`  … and ${items.length - MAX_LISTED} more`] : []),
];
const some = (names, count = 6) => `${names.slice(0, count).join(', ')}${names.length > count ? ', …' : ''}`;

/** Count a package as shipped by name: it runs, by a route vexproof can't follow to its files. */
function shipWhole(map, name) {
  addToMap(map.packages, `node_modules/${name}/package.json`);
  map.whole ??= new Set();
  map.whole.add(name);
}

/**
 * One module map, read and checked: every JavaScript file in the build output must be a chunk the map records,
 * or be accounted for on its own. Adds to `state` (shippedDirs, selfVouched, inputs). Returns the map.
 */
function readOneModuleMap(file, { root, lockNames, state, readJson, sha256, log }) {
  const mapJson = readJson(file, 'module map');
  let map;
  try {
    map = readModuleMap(mapJson);
  } catch (error) {
    throw new Stop(`${file}: ${error.message}`);
  }

  let coverage;
  try {
    coverage = strayOutputs(mapJson, { root, file });
  } catch (error) {
    if (!(error instanceof CoverageError)) throw error;
    throw new Stop(`${file}: ${error.message}`);
  }
  const { stray, copied, dirs: outDirs, recorded, hints } = coverage;

  // files the bundler says it copied from somewhere: that origin shipped
  for (const copy of copied) {
    if (splitNodeModulesPath(copy.from)) addToMap(map.packages, copy.from);
    else map.own.add(copy.from);
  }

  if (stray.length || copied.length) {
    const { accounted, unknown } = accountFor(stray, { root, outDirs, hints });
    if (unknown.length) {
      throw new Stop([
        `${unknown.length} JavaScript file(s) in the build output are not accounted for, so their packages could look absent:`,
        ...listed(unknown, (entry) => `${entry.file}: ${entry.why}`),
        'If a worker or a nested build() made them, add the vexproof plugin to that build (worker.plugins) and rebuild.',
        'A file that is copied in must be an unmodified copy of an installed or project file, or have a source map',
        'beside it. For an app that cannot meet that, use --deploy <output folder> with source maps on.',
      ]);
    }

    map.whole ??= new Set();
    for (const entry of accounted) {
      for (const path of entry.adds) {
        if (splitNodeModulesPath(path)) addToMap(map.packages, path);
        else map.own.add(path);
      }
      // a git-tracked original vouches for the output file, but is no record of what is in it (see the content check)
      if (entry.kind === 'own') for (const path of entry.adds) state.selfVouched.add(resolve(root, path));
      for (const name of entry.whole) map.whole.add(name);
      // loaded by name from a file that ships as it is: present, by a route vexproof can't follow to files
      for (const name of entry.loads) if (lockNames.has(name)) shipWhole(map, name);
    }

    const count = (kind) => accounted.filter((entry) => entry.kind === kind).length;
    const generated = count('generated') ? `, ${count('generated')} written by a build tool` : '';
    log(`vexproof: ${accounted.length + copied.length} output file(s) outside the module map accounted for: ${count('copy') + copied.length} copied from installed packages, ${count('mapped')} by their source maps, ${count('own')} the project's own, ${count('glue')} holding no package code${generated}`);
  }

  // a package the recorded output loads by name when it runs is used by the product, wherever it is loaded from
  const external = [...runtimeLoads(recorded)].filter((name) => lockNames.has(name));
  if (external.length) {
    for (const name of external) shipWhole(map, name);
    log(`vexproof: the build output loads ${external.length} package(s) by name when it runs, so they count as shipped: ${some(external)}`);
  }

  state.shippedDirs.push(...outDirs);
  // compiled code in the output (a .wasm or .node file a bundler copied): whose it is, where it is an exact copy
  for (const path of binaryCopies(outDirs, { root })) addToMap(map.packages, path);

  // An esbuild metafile doesn't say where the build's output folder is; the folder its outputs share is
  // checked. JavaScript beside that folder (dist/vendor next to dist/js) is in no record, so the content
  // check at least searches it.
  if (map.format === 'esbuild-metafile' && outDirs.length === 1) {
    const outDir = resolve(outDirs[0]);
    const parent = dirname(outDir);
    const here = resolve(root);
    const insideProject = parent !== here && parent.startsWith(here);
    if (insideProject && dirname(resolve(file)) !== outDir) state.shippedDirs.push(parent);
  }

  map.serverBuildsSkipped = mapJson.serverBuildsSkipped ?? 0;
  // the contract's role name; a second map and later ones are numbered, so every role names one input
  const mapsSoFar = state.inputs.filter((input) => input.role.startsWith('module-map')).length;
  state.inputs.push({ role: mapsSoFar ? `module-map-${mapsSoFar + 1}` : 'module-map', path: file, sha256: sha256(file) });

  return map;
}

/** The deployment folders, read and checked. Adds to `state`. Returns the deployment's module map. */
function readOneDeployment(dirs, { root, maps: mapOption, lockNames, browserOnly, state, log, progress }) {
  const mapDirs = mapOption ?? defaultMapDirs(dirs, root);
  const deployment = readDeployment(dirs, { root, mapDirs, lockNames, progress });

  if (deployment.missingDirs.length) {
    throw new Stop(`--deploy ${deployment.missingDirs.join(', ')}: no such folder under ${root}. A folder that is not read can't be vouched for.`);
  }
  if (deployment.missingHalves.length) {
    throw new Stop([
      `--deploy has the server half of this build but not the browser half: ${deployment.missingHalves.join(', ')}.`,
      'What the browser gets ships too, and holds packages the server half does not. Add it as another --deploy folder.',
    ]);
  }
  if (deployment.loadedFromOutside.length) {
    const loads = deployment.loadedFromOutside;
    log(`vexproof: ${loads.length} package(s) are loaded by deployed packages but are not in the deployment (e.g. ${loads[0].name}, by ${loads[0].from}).`);
    log(`They run only where Node can find them further up, and count as shipped: ${some(loads.map((load) => load.name))}`);
  }
  if (deployment.unplaced.length) {
    const example = deployment.unplaced[0];
    const source = example.source.length > 90 ? `${example.source.slice(0, 90)}…` : example.source;
    log(`vexproof: ${deployment.unplaced.length} source(s) named in the deployment's source maps are no file and no installed package's own map names them`);
    log(`(e.g. ${source} in ${example.file}); taken as modules the bundler made up`);
  }
  if (deployment.unmapped.length) {
    throw new Stop([
      `${deployment.unmapped.length} bundled file(s) in the deployment have no source map (or could not be parsed), so what they contain is unknown:`,
      ...listed(deployment.unmapped),
      'Turn on source maps for that build (Next.js: productionBrowserSourceMaps and experimental.serverSourceMaps;',
      "Nuxt: sourcemap: { server: true, client: 'hidden' }; Vite: build.sourcemap: 'hidden'), or pass --maps <folder>.",
      'A file whose source map names only modules the bundler made up says nothing about its contents either.',
    ]);
  }
  if (deployment.escapes.length) {
    // code the deployment loads from a file outside it: it runs, and nothing vexproof was shown can say what it holds
    const escape = deployment.escapes[0];
    throw new Stop([
      `code in the deployment loads ${deployment.escapes.length} file(s) from outside the deployment folders (e.g. ${escape.target}, from ${escape.from}),`,
      'so what those files hold, and load, is not checked. Add the folder that holds them as another --deploy folder.',
    ]);
  }
  if (deployment.unattributed.length) {
    throw new Stop([
      `${deployment.unattributed.length} source(s) named in the deployment's source maps can't be traced to an installed package:`,
      ...listed(deployment.unattributed),
      'Their code shipped, but vexproof can\'t tell whose it is. Run vexproof where the build ran, with node_modules installed.',
    ]);
  }

  const missing = [...new Set(deployment.missingRuntime.map((load) => load.name))];
  if (missing.length && browserOnly) {
    // Files for a browser can't load a package from node_modules: there is none where they run. Code written
    // for browsers and Node keeps such loads for its Node side (pdf.js asks for @napi-rs/canvas). Whether a
    // loader could still supply the package is not for vexproof to say, so it counts as shipped.
    for (const name of missing) shipWhole(deployment, name);
    log(`vexproof: code in the deployment loads ${missing.length} package(s) by name that the deployment does not hold; in a browser nothing supplies them,`);
    log(`but they count as shipped: ${some(missing)}`);
  } else if (missing.length) {
    throw new Stop([
      `code in the deployment loads ${missing.slice(0, 8).join(', ')} at runtime, but ${missing.length > 1 ? 'they are' : 'it is'} not in the deployment folders (e.g. ${deployment.missingRuntime[0].from}).`,
      'Point --deploy at the self-contained output (Next.js output: \'standalone\', Nuxt .output), or add the node_modules',
      'the server runs with (after npm prune --omit=dev) as another --deploy folder.',
    ]);
  }

  for (const path of deployment.selfVouched) state.selfVouched.add(resolve(root, path));
  for (const dir of dirs) state.shippedDirs.push(resolve(root, dir));
  const digest = deploymentDigest(dirs, root, { mapsRead: deployment.mapsRead, progress });
  state.inputs.push({ role: 'deployment', path: dirs.join(','), sha256: digest });

  return deployment;
}

/** The maps merged into one, with versions, and the checks that need all of them. Returns the module map. */
function mergeAndCheck(maps, { root, lockNames, findings, deployment, log }) {
  const merged = mergeModuleMaps(maps);

  // a workspace package bundled from source is named by its real path, not under node_modules
  const workspace = addWorkspacePackages(merged, root);
  if (workspace.length) log(`vexproof: ${workspace.length} workspace package(s) bundled from source: ${some(workspace)}`);

  const moduleMap = attachVersions(merged, { cwd: root });
  const unnamed = unnamedStorePackages(moduleMap);
  if (unnamed.length) {
    throw new Stop([
      `${unnamed.length} shipped package folder(s) in Yarn's node_modules/.store can't be named, so their packages could look absent:`,
      ...listed(unnamed),
      'Run vexproof from the folder the build ran in, with node_modules installed, or pass --root.',
    ]);
  }

  // read through source maps, a package with a map inlined in its files is taken whole, like one that publishes .map files
  if (deployment) {
    moduleMap.whole ??= new Set();
    const asked = new Set(normalizeFindings(findings).map((finding) => parsePurl(finding.purl)?.name).filter(Boolean));
    for (const name of inlineMapPackages(moduleMap, asked, root)) moduleMap.whole.add(name);
  }

  // a folder that can't be read is known by its folder name only; if the lockfile has no package of that name,
  // it may be another package installed under an alias, and nothing could then be said about that package
  const unverified = (moduleMap.unverified ?? []).filter((entry) => !lockNames.has(entry.name));
  if (unverified.length) {
    throw new Stop([
      `${unverified.length} shipped package folder(s) can't be read here and the lockfile SBOM has no package of that name, so each may be`,
      'another package installed under an alias:',
      ...listed(unverified, (entry) => entry.root),
      'Run vexproof from the folder the build ran in, with node_modules installed, or pass --root.',
    ]);
  }

  // .cache, .prisma and the like: said out loud, in case one of them is a package store vexproof doesn't know
  const dotFolders = [...moduleMap.packages].filter(([name]) => name.startsWith('.')).flatMap(([, entry]) => [...entry.roots]);
  // node_modules/.vite holds dependencies Vite bundled ahead of time: package code, under no package's name
  const prebundled = dotFolders.filter((folder) => folder === 'node_modules/.vite' || folder.endsWith('/node_modules/.vite'));
  if (prebundled.length) {
    throw new Stop([
      `the build ships code from ${prebundled[0]}, where Vite keeps dependencies it bundled ahead of time. Which packages those are`,
      'is not recorded, so they could look absent. Build without the dependency optimizer (optimizeDeps.noDiscovery with no include), or use --deploy.',
    ]);
  }
  if (dotFolders.length) log(`vexproof: shipped code under ${some(dotFolders, 4)} is counted for no package: a dot folder in node_modules is not one`);

  return moduleMap;
}

/** The project's own dependencies: from its package.json in `root`, and from the lockfile SBOM's dependency graph. */
function directDependencies(lockfileSbom, root) {
  const direct = new Set(Object.keys(readPackageJson(root).pkg?.dependencies ?? {}));

  // the lockfile SBOM says the same when it carries the dependency graph: what the application itself depends on
  const nameByRef = new Map();
  const walk = (components) => {
    for (const component of components ?? []) {
      const parsed = parsePurl(component.purl ?? '');
      if (parsed?.type === 'npm' && component['bom-ref']) nameByRef.set(component['bom-ref'], parsed.name);
      walk(component.components);
    }
  };
  walk(lockfileSbom?.components);

  const app = lockfileSbom?.metadata?.component?.['bom-ref'];
  const graph = (lockfileSbom?.dependencies ?? []).find((entry) => entry.ref === app);
  for (const ref of graph?.dependsOn ?? []) if (nameByRef.has(ref)) direct.add(nameByRef.get(ref));

  return direct;
}

/**
 * A browser module map cannot vouch for code that runs on a server. Stops the run when the app also has a
 * server that what was read does not cover, unless the VEX is for the browser bundle alone.
 */
function checkServer({ maps, deployment, lockfileSbom, root, browserOnly }) {
  const reasons = [];
  if (maps.some((map) => map.serverBuildsSkipped)) reasons.push('the build includes a server (SSR) build');

  const lockIndex = indexSbom(lockfileSbom);
  for (const name of SERVER_FRAMEWORKS) if (lockIndex.has(`npm/${name}`)) reasons.push(`${name} is a dependency`);

  const direct = directDependencies(lockfileSbom, root);
  for (const name of SERVERS) if (direct.has(name)) reasons.push(`${name} is a dependency of this package`);

  const serverCovered = Boolean(deployment?.hasServer); // the deployment includes what the server runs
  if (!reasons.length || serverCovered || browserOnly) {
    return;
  }

  throw new Stop([
    `this app also runs JavaScript on a server (${reasons.join('; ')}).`,
    'Packages used only on the server are missing from the browser bundle but still run in production, so',
    'vexproof cannot speak for the whole app. Pass --browser-only to write VEX for the browser bundle alone,',
    'and give that artifact its own identifier with --product.',
  ]);
}

/**
 * What shipped, and the checks it must pass. Takes the lockfile SBOM, the findings, the bundle SBOM (or null),
 * the --modules files, the --deploy folders (or null), --maps folders (or null), root and browserOnly, plus
 * readJson, sha256 and log from the caller. Returns { moduleMap, bundleSbom, shippedDirs, selfVouched, inputs }:
 * moduleMap is null when only a bundle SBOM was given; inputs are the module maps and deployment read, for the
 * VEX's evidence. Throws a Stop when a check fails.
 */
export function whatShipped({
  lockfileSbom, findings, bundleSbom, modules = [], deploy = null, maps: mapDirs = null, root, browserOnly = false, readJson, sha256, log,
  progress = NO_PROGRESS,
}) {
  // the lockfile's npm package names, matched without regard to case (see src/names.js)
  const lockNames = new NpmNameSet([...indexSbom(lockfileSbom).keys()].filter((key) => key.startsWith('npm/')).map((key) => key.slice(4)));
  // Project files that vouch for an output file only by being its git-tracked original (public/vendor/x.js). They
  // are not records of what a bundler put in: a vendored package's file passes this way too. So the content check
  // must not count their strings as explained, or the shipped copy would explain itself away.
  const state = { shippedDirs: [], selfVouched: new Set(), inputs: [] };
  const context = { root, lockNames, state, readJson, sha256, log, progress };

  const maps = modules.map((file) => readOneModuleMap(file, context));
  const deployment = deploy ? readOneDeployment(deploy, { ...context, maps: mapDirs, browserOnly }) : null;
  if (deployment) maps.push(deployment);

  let moduleMap = null;
  let shipped = bundleSbom;
  if (maps.length) {
    moduleMap = mergeAndCheck(maps, { ...context, findings, deployment });
    const fromMaps = bundleSbomFromModules(moduleMap, { lockfileSbom, cwd: root });
    if (!shipped) {
      shipped = fromMaps;
      log(`vexproof: ${deployment ? 'deployed' : 'bundle'} contents taken from the ${deployment ? 'deployment' : 'module map'} (${shipped.components.length} packages)`);
    } else {
      // --bundle with --modules or --deploy: the bundle SBOM is one account of what ships, the module map or the
      // deployment another (a server's packages are in no browser bundle SBOM). A package either one names ships.
      // Compared by package and version: the two write purls with different qualifiers.
      const key = (component) => `${String(component.name ?? '').toLowerCase()}@${component.version ?? ''}`;
      const have = new Set((shipped.components ?? []).map((component) => key({ name: parsePurl(component.purl ?? '')?.name ?? component.name, version: parsePurl(component.purl ?? '')?.version ?? component.version })));
      const extra = fromMaps.components.filter((component) => !have.has(key(component)));
      if (extra.length) {
        shipped = { ...shipped, components: [...(shipped.components ?? []), ...extra] };
        log(`vexproof: ${extra.length} package(s) are in the ${deployment ? 'deployment' : 'module map'} and not in the bundle SBOM; they count as shipped too`);
      }
    }
  }

  checkServer({ maps, deployment, lockfileSbom, root, browserOnly });

  return { moduleMap, bundleSbom: shipped, shippedDirs: state.shippedDirs, selfVouched: state.selfVouched, inputs: state.inputs };
}

