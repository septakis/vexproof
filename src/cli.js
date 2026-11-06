#!/usr/bin/env node
// SPDX-License-Identifier: MIT
import { readFileSync, writeFileSync, appendFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { triage, toCycloneDxVex, summarize, VERSION } from './index.js';
import { fetchOsvFindings, readFindingsText, enrichAliases } from './sources.js';
import { toOpenVex } from './openvex.js';
import { readModuleMap, bundleSbomFromModules, uncoveredOutputs, attachVersions } from './modules.js';
import { recordReview, sameCause } from './review.js';
import { attachFingerprints } from './evidence.js';
import { readDeployment, mergeModuleMaps } from './deploy.js';
import { normalizeFindings, parsePurl, indexSbom } from './index.js';
import { deriveRules } from './derive.js';

// Frameworks whose apps also run code on a server. Their packages can be missing from the browser bundle and
// still run in production, so a browser module map cannot stand for the whole product.
const SERVER_FRAMEWORKS = ['next', 'nuxt', '@sveltejs/kit', '@remix-run/server-runtime', '@react-router/node', '@angular/ssr', 'vike', '@solidjs/start', '@tanstack/react-start', '@astrojs/node', '@analogjs/platform'];

const PRO_URL = 'https://vexproof.dev/#pricing';

// vexproof Pro lives in src/pro/ under its own license (src/pro/LICENSE.md); everything else is MIT.
// A copy without that directory runs the MIT features only.
const proLib = await import('./pro/index.js').catch((e) => { if (e?.code === 'ERR_MODULE_NOT_FOUND') return null; throw e; });
const BOOLEAN = new Set(['dry-run', 'quiet', 'help', 'version', 'enrich-aliases', 'openvex-package-products', 'accept-derived', 'browser-only', 'same-cause']);

const MULTI = new Set(['modules', 'deploy', 'maps']); // may be given more than once, or comma-separated

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const k = a.slice(2);
    if (BOOLEAN.has(k)) out[k] = true;
    else if (MULTI.has(k)) out[k] = [...(out[k] ?? []), ...String(argv[++i]).split(',').filter(Boolean)];
    else out[k] = argv[++i];
  }
  return out;
}

// Exit 1 means only "the --fail-on gate tripped". Anything else that stops a run (unreadable or
// unrecognised input, a network failure) exits 2 with a one-line message.
const fatal = (e) => { console.error(`vexproof: ${e?.message ?? e}`); process.exit(2); };
process.on('uncaughtException', fatal);
process.on('unhandledRejection', fatal);

const args = parseArgs(process.argv.slice(2));
const log = (...m) => console.error(...m);
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const sha256 = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const need = (k) => { if (!args[k]) { log(`vexproof: missing --${k}`); process.exit(2); } return args[k]; };
const loadLicense = (opts) => {
  const token = proLib ? proLib.loadLicenseToken({ arg: args.license }) : (args.license ?? process.env.VEXPROOF_LICENSE ?? null);
  const license = proLib ? proLib.verifyLicense(token, opts) : { valid: false, features: [], reason: 'this copy of vexproof has no Pro files (src/pro/)' };
  if (token && !license.valid) log(`vexproof: ${license.reason}; running free features only`);
  if (license.warning) log(`vexproof: ${license.warning}`);
  return license;
};
const licensedFor = (license, f) => license.valid && license.features.includes(f);

const HELP = `vexproof ${VERSION}

  vexproof --lockfile <sbom> (--bundle <sbom> | --modules <stats>) [options]
    --findings <file>     npm, pnpm, yarn or bun audit, osv-scanner, Trivy, Grype or Snyk JSON, or [{purl, ids}]
                          (default: query OSV directly)
    --enrich-aliases      look up GHSA/CVE aliases on OSV (automatic when querying OSV)
    --bundle <file>       CycloneDX SBOM of the bundle; optional when --modules is given
    --modules <file>      vexproof-modules.json (vexproof/vite, vexproof/webpack), esbuild or bun build
                          metafile, Angular stats.json, or webpack stats JSON. Repeatable.
    --deploy <dir>        a deployment folder: its node_modules files, and the source maps of its bundled
                          code. Repeatable (Next.js: .next/standalone and .next/static; Nuxt: .output)
    --maps <dir>          extra folder to find source maps in (default: .next when present)
    --root <dir>          where node_modules lives, for package versions (default: cwd)
    --product <purl>      product identifier used in the VEX
    --out <file>          CycloneDX VEX output (default vex.cdx.json)
    --spec-version <v>    CycloneDX version of the VEX: 1.6 (default) or 1.7. Trivy reads 1.7 from
                          0.71, Dependency-Track from 4.14
    --openvex <file>      also write OpenVEX (what Trivy and Grype apply to any scan)
    --openvex-package-products
                          add package-as-product statements, which Grype needs for
                          directory and SBOM scans; use that file only for this app
    --rules <file>        extra module rules, e.g. from \`vexproof rules derive\`                  [Pro]
    --accept-derived      let derived rules settle findings instead of only suggesting     [Pro]
    --browser-only        the VEX covers the browser bundle only (required when the app
                          also has a server build; name that artifact with --product)
    --fail-on <mode>      in_triage | new   (exit 1 when the gate trips; "new" needs --baseline)
    --baseline <vex>      previous release's VEX; reviews carry forward while their evidence
                          (vulnerable files, code importing them) is unchanged           [Pro]
    --review-max-age <d>  reviews older than this many days need re-confirming (default 365)
    --report <file.html>  audit-ready evidence report                           [Pro]
    --license <token|file>  or VEXPROOF_LICENSE, or ./.vexproof-license
    --quiet               no Pro hints

  vexproof review --vex <file> --id <advisory> --state <state> --detail <text> --by <name>
                   [--justification <j>] [--package <purl>] [--same-cause]
    --same-cause          also apply the decision to open findings on the same vulnerable files
    Records a human decision in a VEX file. With --baseline, Pro carries it into later releases.

  vexproof dependabot --vex <file> --lockfile <sbom> [--repo owner/name] [--manifest <path>] [--dry-run]  [Pro]
    Applies the VEX to the repository's Dependabot npm alerts: dismisses those it settles (with the reason
    and a link as the comment) and reopens ones it dismissed earlier that it no longer settles. Alerts
    dismissed by people are never changed. Needs a token that can write Dependabot alerts (--token,
    VEXPROOF_DEPENDABOT_TOKEN, GH_TOKEN or GITHUB_TOKEN). --vex, --lockfile and --manifest repeat.
    --manifest        manifest file or folder whose alerts to change (default: the current folder)
    --link <url>      what the dismissal comment links to (default: this Actions run)
    --dry-run         print what would change

  vexproof rules derive --lockfile <sbom> --findings <file> [--modules <file>] [--out <file>]
    Writes rules from each advisory's fix: the files that changed between the installed version and the
    first fixed release (from the npm registry). Default output: vexproof-rules.derived.json.`;

if (args.help) { console.log(HELP); process.exit(0); }
if (args.version) { console.log(VERSION); process.exit(0); }

// ---------- review ----------
if (args._[0] === 'review') {
  const file = need('vex');
  const vex = readJson(file);
  try {
    const v = recordReview(vex, { id: need('id'), purl: args.package, state: need('state'), justification: args.justification, detail: args.detail, by: args.by });
    const also = args['same-cause'] ? sameCause(vex, v) : [];
    for (const o of also) recordReview(vex, { id: o.id, purl: o.properties.find((p) => p.name === 'vexproof:package').value, state: args.state, justification: args.justification, detail: args.detail, by: args.by });
    writeFileSync(file, JSON.stringify(vex, null, 2));
    console.log(`vexproof: ${v.id} → ${v.analysis.state} (reviewed by ${args.by}) in ${file}`);
    for (const o of also) console.log(`vexproof: ${o.id} → ${o.analysis.state} (same vulnerable files: ${o.properties.find((p) => p.name === 'vexproof:vulnerable-files').value})`);
    process.exit(0);
  } catch (e) { log(`vexproof: ${e.message}`); process.exit(2); }
}

// ---------- rules derive ----------
if (args._[0] === 'rules' && args._[1] === 'derive') {
  const lockfileSbom = readJson(need('lockfile'));
  const findings = normalizeFindings(readFindingsText(readFileSync(need('findings'), 'utf8'), lockfileSbom).findings);
  let only = null; // with a module map, derive only for packages that ship: the rest settle at package level
  if (args.modules) only = new Set(args.modules.flatMap((f) => [...readModuleMap(readJson(f)).packages.keys()]));
  const wanted = findings.map((f) => ({ ...parsePurl(f.purl), id: f.id, aliases: f.aliases }))
    .filter((f) => f.type === 'npm' && f.version && (!only || only.has(f.name)));
  log(`vexproof: deriving rules for ${wanted.length} finding(s) from the npm registry…`);
  const { rules, report } = await deriveRules(wanted);
  const out = args.out ?? 'vexproof-rules.derived.json';
  writeFileSync(out, JSON.stringify(rules, null, 2));
  for (const r of report) {
    const what = r.files ? `${r.files.length} of ${r.runtimeFiles} files changed by ${r.version} → ${r.fixed}` : `no rule: ${r.reason}`;
    console.log(`  ${String(r.id).padEnd(22)} ${`${r.name}@${r.version}`.padEnd(28)} ${what}`);
  }
  console.log(`vexproof: ${report.filter((r) => r.files).length} of ${report.length} rule(s) → ${out}`);
  process.exit(0);
}

// ---------- dependabot ----------
if (args._[0] === 'dependabot') {
  // An open-source key must cover the repository whose alerts change, not just the one this runs in.
  const host = (u) => { try { return new URL(u).host; } catch { return 'github.com'; } };
  const named = args.repo ? { repo: `${host(process.env.GITHUB_SERVER_URL)}/${args.repo}` } : undefined;
  if (!licensedFor(loadLicense(named), 'dependabot')) { log('vexproof dependabot is a Pro feature; no alerts changed'); process.exit(0); }
  const { readDocuments, github, syncDependabot, explain, summaryLine, markdownSummary, verb, scopeLabel } = proLib.dependabot;
  const argv = process.argv.slice(2);
  const every = (name) => argv.flatMap((a, i) => (a === `--${name}` && argv[i + 1] !== undefined ? String(argv[i + 1]).split(',').map((s) => s.trim()).filter(Boolean) : []));
  const env = process.env;
  const git = (...a) => { try { return execFileSync('git', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return null; } };
  const vexFiles = every('vex');
  const lockFiles = every('lockfile');
  if (!vexFiles.length || !lockFiles.length) { log('vexproof: dependabot needs --vex and the --lockfile SBOM each VEX was made from'); process.exit(2); }
  const token = args.token ?? env.VEXPROOF_DEPENDABOT_TOKEN ?? env.GH_TOKEN ?? env.GITHUB_TOKEN;
  if (!token) { log('vexproof: dependabot needs a GitHub token: --token, or VEXPROOF_DEPENDABOT_TOKEN, GH_TOKEN or GITHUB_TOKEN'); process.exit(2); }
  const origin = /github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?\/?$/.exec(git('config', '--get', 'remote.origin.url') ?? '')?.[1];
  const repo = args.repo ?? env.GITHUB_REPOSITORY ?? origin;
  if (!repo || !/^[^/\s]+\/[^/\s]+$/.test(repo)) { log('vexproof: pass --repo owner/name (the repository whose Dependabot alerts to change)'); process.exit(2); }
  const scopes = every('manifest');
  if (!scopes.length) scopes.push((git('rev-parse', '--show-prefix') ?? '').replace(/\/$/, ''));
  let dryRun = Boolean(args['dry-run']);
  if (!dryRun && env.GITHUB_ACTIONS === 'true' && env.GITHUB_EVENT_PATH) {
    // Dependabot alerts describe the default branch, so only a build of that branch may change them.
    let main = null;
    try { main = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, 'utf8')).repository?.default_branch ?? null; } catch { main = null; }
    if (main && env.GITHUB_REF !== `refs/heads/${main}`) {
      log(`vexproof: this run builds ${env.GITHUB_REF ?? 'another ref'}, but Dependabot alerts describe ${main}; previewing only`);
      dryRun = true;
    }
  }
  const link = args.link ?? (env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : null);
  try {
    const lockfiles = lockFiles.map((file) => ({ file, sbom: readJson(file), sha256: sha256(file) }));
    const docs = readDocuments(vexFiles.map((file) => ({ file, vex: readJson(file) })), lockfiles);
    const client = github({ token, repo, apiUrl: env.GITHUB_API_URL || 'https://api.github.com', userAgent: `vexproof/${VERSION}` });
    log(`vexproof: ${dryRun ? 'previewing' : 'applying'} ${vexFiles.join(', ')} to Dependabot's npm alerts in ${repo}, on manifests ${scopeLabel(scopes)}`);
    const { plan, elsewhere } = await syncDependabot({ client, docs, scopes, link, dryRun });
    const shown = plan.filter((i) => i.action !== 'kept');
    const w = Math.max(8, ...shown.map((i) => String(i.alert.dependency?.package?.name ?? '').length));
    for (const i of shown) {
      const a = i.alert;
      console.log(`  ${verb(i).padEnd(20)} #${String(a.number).padEnd(5)} ${String(a.security_advisory?.ghsa_id ?? '').padEnd(20)} ${String(a.dependency?.package?.name ?? '').padEnd(w)}  ${i.error ?? i.why}`);
    }
    console.log(`vexproof: ${summaryLine(plan, dryRun)}`);
    if (!plan.length && elsewhere.length) log(`vexproof: no npm alerts on manifests ${scopeLabel(scopes)}; there are alerts on ${elsewhere.slice(0, 5).join(', ')}. Pass --manifest to choose.`);
    if (env.GITHUB_STEP_SUMMARY) { try { appendFileSync(env.GITHUB_STEP_SUMMARY, markdownSummary({ repo, plan, dryRun })); } catch { /* summary is optional */ } }
    process.exit(plan.some((i) => i.result === 'failed' || i.result === 'unchanged') ? 2 : 0);
  } catch (e) {
    log(`vexproof: ${explain(e, repo)}`);
    process.exit(2);
  }
}

// ---------- run ----------
const quiet = args.quiet || process.env.VEXPROOF_QUIET === '1';
const lockPath = need('lockfile');
if (!args.bundle && !args.modules && !args.deploy) { log('vexproof: need --bundle, --modules or --deploy to know what ships'); process.exit(2); }
const bundlePath = args.bundle ?? null;
const lockfileSbom = readJson(lockPath);
let bundleSbom = bundlePath ? readJson(bundlePath) : null;
const productPurl = args.product ?? lockfileSbom?.metadata?.component?.purl ?? 'pkg:generic/app';
const inputs = [{ role: 'lockfile-sbom', path: lockPath, sha256: sha256(lockPath) }];
if (bundlePath) inputs.push({ role: 'bundle-sbom', path: bundlePath, sha256: sha256(bundlePath) });

const license = loadLicense();
const has = (f) => licensedFor(license, f);

let findings;
if (args.findings) {
  const r = readFindingsText(readFileSync(args.findings, 'utf8'), lockfileSbom);
  findings = r.findings;
  inputs.push({ role: `findings-${r.format}`, path: args.findings, sha256: sha256(args.findings) });
  log(`vexproof: findings from ${args.findings} (${r.format})`);
} else {
  log('vexproof: querying OSV for lockfile components…');
  findings = await fetchOsvFindings(lockfileSbom);
}
if (!args.findings || args['enrich-aliases']) {
  // scanners disagree on id schemes (Trivy: CVE, npm audit and Grype: GHSA); OSV links them
  findings = normalizeFindings(findings);
  const e = await enrichAliases(findings);
  log(`vexproof: aliases from OSV for ${e.resolved} of ${e.looked} advisories${e.resolved < e.looked ? ' (offline or unknown ids keep their own)' : ''}`);
}

let moduleMap = null;
const root = args.root ?? process.cwd();
const maps = [];
for (const file of args.modules ?? []) {
  const mmJson = readJson(file);
  let mm;
  try { mm = readModuleMap(mmJson); } catch (e) { log(`vexproof: ${file}: ${e.message}`); process.exit(2); }
  const gaps = uncoveredOutputs(mmJson, root);
  if (gaps.length) {
    log(`vexproof: ${gaps.length} shipped JavaScript file(s) are not in the module map, so their packages could look absent:`);
    for (const g of gaps.slice(0, 8)) log(`  ${g}`);
    log('Add the vexproof plugin to the build that produces them (worker.plugins, or a nested build() call), then rebuild.');
    process.exit(2);
  }
  mm.serverBuildsSkipped = mmJson.serverBuildsSkipped ?? 0;
  maps.push(mm);
  inputs.push({ role: `modules-${mm.format}`, path: file, sha256: sha256(file) });
}
let deployment = null;
if (args.deploy) {
  const lockNames = new Set([...indexSbom(lockfileSbom).keys()].filter((k) => k.startsWith('npm/')).map((k) => k.slice(4)));
  const mapDirs = args.maps ?? (existsSync(`${root}/.next`) ? ['.next'] : []);
  deployment = readDeployment(args.deploy, { root, mapDirs, lockNames });
  if (deployment.unmapped.length) {
    log(`vexproof: ${deployment.unmapped.length} bundled file(s) in the deployment have no source map (or could not be parsed), so what they contain is unknown:`);
    for (const f of deployment.unmapped.slice(0, 8)) log(`  ${f}`);
    log('Turn on source maps for that build (Next.js: productionBrowserSourceMaps and experimental.serverSourceMaps;');
    log("Nuxt: sourcemap: { server: true, client: 'hidden' }; Vite: build.sourcemap: 'hidden'), or pass --maps <folder>.");
    process.exit(2);
  }
  if (deployment.unattributed.length) {
    log(`vexproof: ${deployment.unattributed.length} source(s) named in the deployment's source maps can't be traced to an installed package:`);
    for (const f of deployment.unattributed.slice(0, 8)) log(`  ${f}`);
    log('Their code shipped, but vexproof can\'t tell whose it is. Run vexproof where the build ran, with node_modules installed.');
    process.exit(2);
  }
  if (deployment.missingRuntime.length) {
    const names = [...new Set(deployment.missingRuntime.map((m) => m.name))];
    log(`vexproof: code in the deployment loads ${names.slice(0, 8).join(', ')} at runtime, but ${names.length > 1 ? 'they are' : 'it is'} not in the deployment folders (e.g. ${deployment.missingRuntime[0].from}).`);
    log('Point --deploy at the self-contained output (Next.js output: \'standalone\', Nuxt .output), or add the node_modules');
    log('the server runs with (after npm prune --omit=dev) as another --deploy folder.');
    process.exit(2);
  }
  maps.push(deployment);
  inputs.push({ role: 'deployment', path: args.deploy.join(','), sha256: '-' });
}
if (maps.length) {
  moduleMap = attachVersions(mergeModuleMaps(maps), { cwd: root });
  if (!bundleSbom) {
    bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom, cwd: root });
    log(`vexproof: ${deployment ? 'deployed' : 'bundle'} contents taken from the ${deployment ? 'deployment' : 'module map'} (${bundleSbom.components.length} packages)`);
  }
}
let rules = proLib ? proLib.loadRules() : null;
if (args.rules) {
  if (has('modules')) {
    rules = proLib.mergeRules(rules, readJson(args.rules));
    inputs.push({ role: 'rules', path: args.rules, sha256: sha256(args.rules) });
  } else log('vexproof: --rules is a Pro feature; ignoring it');
}

// A browser module map cannot vouch for code that runs on a server.
const serverSide = [];
if (maps.some((m) => m.serverBuildsSkipped)) serverSide.push('the build includes a server (SSR) build');
const lockIndex = indexSbom(lockfileSbom);
for (const n of SERVER_FRAMEWORKS) if (lockIndex.has(`npm/${n}`)) serverSide.push(`${n} is a dependency`);
const serverCovered = Boolean(deployment?.hasServer); // the deployment includes what the server runs
if (serverSide.length && !serverCovered && !args['browser-only']) {
  log(`vexproof: this app also runs JavaScript on a server (${serverSide.join('; ')}).`);
  log('Packages used only on the server are missing from the browser bundle but still run in production, so');
  log('vexproof cannot speak for the whole app. Pass --browser-only to write VEX for the browser bundle alone,');
  log('and give that artifact its own identifier with --product.');
  process.exit(2);
}

const results = triage({ lockfileSbom, bundleSbom, findings, moduleMap, rules, moduleCheck: proLib?.evaluateModuleRule ?? null, pro: has('modules'), acceptDerived: Boolean(args['accept-derived']) && has('modules') });

attachFingerprints(results, { moduleMap, rules, cwd: args.root ?? process.cwd() });

let baselineApplied = false;
if (args.baseline) {
  if (has('baseline')) {
    const maxAgeDays = args['review-max-age'] === undefined ? 365 : Number(args['review-max-age']);
    proLib.applyBaseline(results, proLib.readBaseline(readJson(args.baseline)), { maxAgeDays: Number.isFinite(maxAgeDays) && maxAgeDays > 0 ? maxAgeDays : null });
    inputs.push({ role: 'baseline-vex', path: args.baseline, sha256: sha256(args.baseline) });
    baselineApplied = true;
  } else log('vexproof: --baseline is a Pro feature; ignoring it');
}

const out = args.out ?? 'vex.cdx.json';
if (!/^urn:uuid:[0-9a-f-]{36}$/i.test(String(lockfileSbom?.serialNumber ?? ''))) {
  log('vexproof: the lockfile SBOM has no serialNumber, so the CycloneDX VEX can\'t point into it with BOM-Links, and Trivy and');
  log('Dependency-Track will not apply it (OpenVEX is unaffected). Generate the SBOM without --output-reproducible.');
}
let vex;
try {
  vex = toCycloneDxVex({ results, bundleSbom, lockfileSbom, productPurl, inputs, licensee: license.valid ? license.org : null, scope: args['browser-only'] ? 'browser-bundle' : null, specVersion: args['spec-version'] ?? '1.6' });
} catch (e) { log(`vexproof: ${e.message}`); process.exit(2); }
writeFileSync(out, JSON.stringify(vex, null, 2));
if (args.openvex) {
  const ov = toOpenVex({ results, productPurl, author: license.valid ? license.org : 'vexproof', packageProducts: args['openvex-package-products'] });
  writeFileSync(args.openvex, JSON.stringify(ov, null, 2));
}

const s = summarize(results);
const parts = [`${s.not_affected} not_affected${s.module ? ` (${s.module} at module level)` : ''}`];
if (s.reviewed) parts.push(`${s.reviewed} reviewed`);
parts.push(`${s.in_triage} in_triage`);
console.log(`vexproof: ${results.length} finding(s) → ${parts.join(', ')} → ${out}${args.openvex ? ` + ${args.openvex}` : ''}`);
for (const r of results) {
  const tag = r.origin === 'reviewed' ? `${r.state} (${r.carriedFrom ? 'carried' : 'reviewed'})` : r.state + (r.level === 'module' ? ' (module)' : '');
  const why = r.state === 'in_triage' && r.moduleReason && (moduleMap || r.reReview) ? `  ← ${r.moduleReason}` : '';
  console.log(`  ${tag.padEnd(24)} ${String(r.id).padEnd(22)} ${r.purl}${r.isNew ? '  [new]' : ''}${why}`);
}

if (args.report) {
  if (has('report')) {
    const command = `vexproof ${process.argv.slice(2).filter((a, i, arr) => a !== '--license' && arr[i - 1] !== '--license').join(' ')}`;
    writeFileSync(args.report, proLib.renderReport({ results, summary: s, inputs, productPurl, license, command, version: VERSION }));
    console.log(`vexproof: report → ${args.report}`);
  } else log('vexproof: --report is a Pro feature; skipped');
}

// ---------- Pro hints (free users only; never more than two lines) ----------
if (!quiet && proLib && !has('modules')) {
  if (s.proWouldSettle > 0) {
    const byPkg = {};
    for (const r of results) if (r.proWouldSettle) byPkg[r.key.replace(/^npm\//, '')] = (byPkg[r.key.replace(/^npm\//, '')] ?? 0) + 1;
    const list = Object.entries(byPkg).map(([k, n]) => `${k} ${n}`).join(', ');
    log(`\nvexproof Pro would settle ${s.proWouldSettle} of your ${s.in_triage} open finding(s) by checking which files of each package shipped (${list}),`);
    log(`and write an audit-ready report with the evidence. $1,200/year per organization, free for open source: ${PRO_URL}`);
  } else if (!moduleMap && s.in_triage > 0) {
    log(`\nTip: add --modules <stats.json> to see how many of the ${s.in_triage} open finding(s) module-level analysis could settle.`);
  }
}

// ---------- gate ----------
if (args['fail-on']) {
  const mode = args['fail-on'];
  let tripped = [];
  if (mode === 'in_triage') tripped = results.filter((r) => r.state === 'in_triage');
  else if (mode === 'new') {
    if (baselineApplied) tripped = results.filter((r) => r.isNew);
    else log('vexproof: --fail-on new needs a Pro --baseline; gate not applied');
  } else { log(`vexproof: unknown --fail-on mode "${mode}"`); process.exit(2); }
  if (tripped.length) {
    log(`vexproof: gate failed — ${tripped.length} ${mode === 'new' ? 'new ' : ''}open finding(s): ${[...new Set(tripped.map((r) => r.id))].join(', ')}`);
    process.exit(1);
  }
}
