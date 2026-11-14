#!/usr/bin/env node
// SPDX-License-Identifier: MIT
import { readFileSync, writeFileSync, appendFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { triage, toCycloneDxVex, summarize, VERSION, outputTime } from './index.js';
import { fetchOsvFindings, readFindingsText, enrichAliases } from './sources.js';
import { toOpenVex } from './openvex.js';
import { readModuleMap, bundleSbomFromModules, attachVersions, addToMap, splitNodeModulesPath, unnamedStorePackages } from './modules.js';
import { strayOutputs, accountFor, addWorkspacePackages, runtimeLoads, binaryCopies, CoverageError } from './coverage.js';
import { recordReview, sameCause } from './review.js';
import { attachFingerprints } from './evidence.js';
import { readDeployment, mergeModuleMaps, defaultMapDirs, installBases, inlineMapPackages, deploymentDigest } from './deploy.js';
import { contentCheck } from './content-check.js';
import { normalizeFindings, parsePurl, indexSbom } from './index.js';
import { deriveRules } from './derive.js';

// Frameworks whose apps also run code on a server. Their packages can be missing from the browser bundle and
// still run in production, so a browser module map cannot stand for the whole product.
const SERVERS = ['express', 'fastify', 'koa', '@hapi/hapi', '@nestjs/core', 'hono', 'restify', 'polka', 'h3', 'electron', 'socket.io', '@apollo/server', '@trpc/server'];
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

// Help fits in 80 columns. `vexproof --help` fits on one screen; each command has its own page.
const HELP = {
  overview: `vexproof ${VERSION}: build-proven VEX for npm

Usage:
  vexproof --lockfile <sbom> --bundle <sbom> [options]   write VEX
           (or --modules <file> / --deploy <dir> in place of --bundle)
  vexproof review --vex <file> --id <advisory> ...       record a decision
  vexproof rules derive --lockfile <sbom> --findings <file>
  vexproof dependabot --vex <file> --lockfile <sbom>     (Pro) apply to alerts
  vexproof rollup --vex <file>... --product <purl>       (Pro) one VEX per org
  vexproof verify <file> [--key <pub.pem>]               check a signature

Common options:
  --findings <file>   scanner or audit JSON (default: query OSV)
  --product <purl>    product identifier in the VEX
  --out <file>        CycloneDX VEX (default vex.cdx.json)
  --openvex <file>    also write OpenVEX
  --fail-on <mode>    in_triage | new: exit 1 when the gate trips
  --csaf <file>       (Pro) also write CSAF 2.0 VEX; needs --csaf-namespace
  --sign <key.pem>    (Pro) sign every file written
  --license <key>     Pro license key or file (or VEXPROOF_LICENSE)

More: vexproof --help all (every option), vexproof <command> --help
      (review, rules derive, dependabot, rollup, verify, keygen),
      https://vexproof.dev/docs/`,

  all: `vexproof ${VERSION}

  vexproof --lockfile <sbom> [options]
           (--bundle <sbom> | --modules <file> | --deploy <dir>)

What ships (at least one):
  --bundle <file>         CycloneDX SBOM of the bundle; optional with --modules
  --modules <file>        vexproof-modules.json (vexproof/vite or /webpack),
                          esbuild or bun build metafile, Angular stats.json,
                          or webpack stats JSON. Repeatable.
  --deploy <dir>          deployment folder: its node_modules files and the
                          source maps of its bundled code. Repeatable (Next.js:
                          .next/standalone and .next/static; Nuxt: .output)
  --maps <dir>            extra source map folder (default: the build's .next)
  --root <dir>            the folder the build ran in: node_modules and the
                          build output are looked for there (default: cwd)

Findings:
  --findings <file>       npm, pnpm, yarn or bun audit, osv-scanner, Trivy,
                          Grype or Snyk JSON, or [{purl, ids}] (default:
                          query OSV)
  --enrich-aliases        look up GHSA/CVE aliases on OSV (automatic when
                          querying OSV)

Output:
  --product <purl>        product identifier used in the VEX
  --out <file>            CycloneDX VEX (default vex.cdx.json)
  --spec-version <v>      CycloneDX 1.6 (default) or 1.7. Trivy reads 1.7 from
                          0.71, Dependency-Track from 4.14
  --openvex <file>        also write OpenVEX (Trivy and Grype apply it to any
                          scan)
  --openvex-package-products
                          add package-as-product statements, which Grype needs
                          for directory and SBOM scans; use that file only for
                          this app
  --browser-only          the VEX covers the browser bundle only (required when
                          the app also has a server build; name that artifact
                          with --product)
  SOURCE_DATE_EPOCH       env var: pin every timestamp written (seconds since
                          1970)

CSAF (Pro; the document a supplier hands to customers and regulators):
  --csaf <file>           also write CSAF 2.0 VEX (profile csaf_vex)
  --csaf-namespace <url>  the publisher's namespace URL. Required with --csaf
  --csaf-publisher <name> publisher name (default: the license holder)
  --csaf-id <id>          tracking id (default <PRODUCT>-<VERSION>-VEX)
  --csaf-status <s>       draft | interim | final (default final)
  --csaf-tlp <label>      WHITE | GREEN | AMBER | RED (default WHITE)
  --csaf-url <url>        canonical URL of the document (its "self" reference)
  --csaf-previous <file>  the previous revision: carries its history forward
                          and bumps the version

Gates and reviews:
  --fail-on <mode>        in_triage | new: exit 1 when the gate trips ("new"
                          needs --baseline)
  --baseline <vex>        (Pro) previous release's VEX; reviews carry forward
                          while their evidence is unchanged
  --review-max-age <d>    reviews older than this many days need re-confirming
                          (default 365)

Pro:
  --license <token|file>  or VEXPROOF_LICENSE, or ./.vexproof-license
  --rules <file>          extra module rules, e.g. from \`vexproof rules derive\`
  --accept-derived        let derived rules settle findings, not only suggest
  --report <file.html>    audit-ready evidence report
  --sign <key.pem>        sign every file written (Ed25519 or ECDSA P-256 key,
                          see vexproof keygen): JSF signature inside the
                          CycloneDX VEX, <file>.sig beside OpenVEX and CSAF
  --signer <name>         name recorded with the signature (default: the key's
                          fingerprint)
  --quiet                 no Pro hints`,

  review: `vexproof review: record a human decision in a VEX file

  vexproof review --vex <file> --id <advisory> --state <state> --detail <text>
                  --by <name> [--justification <j>] [--package <purl>]
                  [--same-cause]

  --same-cause            also apply the decision to open findings on the same
                          vulnerable files

With --baseline, Pro carries the decision into later releases.`,

  dependabot: `vexproof dependabot (Pro): apply a VEX to Dependabot npm alerts

  vexproof dependabot --vex <file> --lockfile <sbom> [--repo owner/name]
                      [--manifest <path>] [--link <url>] [--dry-run]

Dismisses the alerts the VEX settles (with the reason and a link as the
comment) and reopens ones it dismissed earlier that it no longer settles.
Alerts dismissed by people are never changed. --vex, --lockfile and
--manifest repeat.

  --manifest <path>       manifest file or folder whose alerts to change
                          (default: the current folder)
  --repo owner/name       default: GITHUB_REPOSITORY, then the git remote
  --link <url>            what the dismissal comment links to (default: this
                          Actions run)
  --token <token>         a token that can write Dependabot alerts (or
                          VEXPROOF_DEPENDABOT_TOKEN, GH_TOKEN, GITHUB_TOKEN)
  --dry-run               print what would change`,

  rules: `vexproof rules derive: write module rules from each advisory's fix

  vexproof rules derive --lockfile <sbom> --findings <file> [--modules <file>]
                        [--out <file>]

The rules list the files that changed between the installed version and the
first fixed release, from the npm registry. With --modules, only packages that
ship get rules. Default output: vexproof-rules.derived.json.`,

  rollup: `vexproof rollup (Pro): one CycloneDX VEX for an organization

  vexproof rollup --vex <file> [--vex <file>...] --product <purl>
                  [--out <file>] [--sign <key.pem>] [--signer <name>]

Combines the VEX files vexproof wrote for each application into one document
about the product that contains them all. Every statement keeps its evidence
and names its application (vexproof:application). Settled statements come
first, then open ones; verdicts that differ between applications on the same
package version are listed on standard error.

  --vex <file>            an application's CycloneDX VEX. Repeat for each
  --product <purl>        what the rollup speaks for, e.g. pkg:generic/acme@2026
  --out <file>            default vex.rollup.cdx.json
  --sign <key.pem>        sign the rollup (JSF signature inside the document)
  --signer <name>         name recorded with the signature`,

  verify: `vexproof verify: check a signature vexproof wrote. Needs no license.

  vexproof verify <file> [--key <public.pem>]

A CycloneDX VEX carries its signature inside (JSF, the schema's "signature");
OpenVEX and CSAF have a detached <file>.sig beside them. Without --key the
public key embedded in the signature is used and printed, so you can compare
it with the one the publisher gave you; with --key the two must match.
Exit 0 when the signature checks, 1 when it does not, 2 on unreadable input.`,

  keygen: `vexproof keygen: make a signing key pair for --sign. Needs no license.

  vexproof keygen [--out <prefix>] [--type ed25519|p256]

Writes <prefix>.pem (the private key: keep it with your release secrets) and
<prefix>.pub.pem (the public key: publish it where customers can find it).
Default prefix vexproof-signing; nothing is overwritten. Any Ed25519 or ECDSA
P-256 key in PEM form works too, for example from openssl.`,
};

if (args.help) {
  const page = args._[0] === 'all' ? 'all' : (HELP[args._[0]] && args._[0] !== 'overview' ? args._[0] : 'overview');
  console.log(HELP[page]);
  process.exit(0);
}
if (args.version) { console.log(VERSION); process.exit(0); }

// Every timestamp vexproof writes. SOURCE_DATE_EPOCH pins it, so the same inputs write the same files.
const now = outputTime();

// ---------- review ----------
if (args._[0] === 'review') {
  const file = need('vex');
  const vex = readJson(file);
  try {
    const v = recordReview(vex, { id: need('id'), purl: args.package, state: need('state'), justification: args.justification, detail: args.detail, by: args.by, now });
    const also = args['same-cause'] ? sameCause(vex, v) : [];
    for (const o of also) recordReview(vex, { id: o.id, purl: o.properties.find((p) => p.name === 'vexproof:package').value, state: args.state, justification: args.justification, detail: args.detail, by: args.by, now });
    writeFileSync(file, JSON.stringify(vex, null, 2));
    console.log(`vexproof: ${v.id} → ${v.analysis.state} (reviewed by ${args.by}) in ${file}`);
    for (const o of also) console.log(`vexproof: ${o.id} → ${o.analysis.state} (same vulnerable files: ${o.properties.find((p) => p.name === 'vexproof:vulnerable-files').value})`);
    process.exit(0);
  } catch (e) { log(`vexproof: ${e.message}`); process.exit(2); }
}

// ---------- verify (no license needed: anyone can check a signature) ----------
if (args._[0] === 'verify') {
  const file = args._[1] ?? need('vex');
  if (!proLib) { log('vexproof: this copy of vexproof has no Pro files (src/pro/), which hold the signature code'); process.exit(2); }
  let publicKey = null;
  try { if (args.key) publicKey = proLib.sign.loadPublicKey(args.key); } catch (e) { log(`vexproof: cannot read --key: ${e.message}`); process.exit(2); }
  let bytes, doc = null;
  try { bytes = readFileSync(file); } catch (e) { log(`vexproof: cannot read ${file}: ${e.message}`); process.exit(2); }
  try { doc = JSON.parse(bytes.toString('utf8')); } catch { doc = null; }
  let r;
  if (doc?.bomFormat === 'CycloneDX' && doc.signature) r = proLib.sign.verifyCycloneDx(doc, { publicKey });
  else {
    let sig;
    try { sig = JSON.parse(readFileSync(`${file}.sig`, 'utf8')); } catch { log(`vexproof: ${file} carries no signature and there is no ${file}.sig beside it`); process.exit(2); }
    r = proLib.sign.verifyBytes(bytes, sig, { publicKey });
  }
  if (!r.ok) { log(`vexproof: signature on ${file} does not check: ${r.reason}`); process.exit(1); }
  console.log(`vexproof: ${file} is signed (${r.algorithm}) by ${r.keyId ?? 'an unnamed key'}; the public key is:`);
  console.log(r.publicKey.trim());
  process.exit(0);
}

// ---------- keygen (no license needed) ----------
if (args._[0] === 'keygen') {
  if (!proLib) { log('vexproof: this copy of vexproof has no Pro files (src/pro/), which hold the signature code'); process.exit(2); }
  const prefix = args.out ?? 'vexproof-signing';
  const type = args.type ?? 'ed25519';
  if (!['ed25519', 'p256'].includes(type)) { log('vexproof: --type must be ed25519 or p256'); process.exit(2); }
  const priv = `${prefix}.pem`, pub = `${prefix}.pub.pem`;
  if (existsSync(priv) || existsSync(pub)) { log(`vexproof: ${existsSync(priv) ? priv : pub} already exists; pass another --out`); process.exit(2); }
  const k = proLib.sign.generateSigningKey(type);
  writeFileSync(priv, k.privateKeyPem, { mode: 0o600 });
  writeFileSync(pub, k.publicKeyPem);
  console.log(`vexproof: wrote ${priv} (private: keep it with your release secrets) and ${pub} (public: publish it)`);
  console.log(`vexproof: key fingerprint ${k.fingerprint}`);
  process.exit(0);
}

// ---------- rollup (Pro) ----------
if (args._[0] === 'rollup') {
  const argv = process.argv.slice(2);
  const every = (name) => argv.flatMap((a, i) => (a === `--${name}` && argv[i + 1] !== undefined ? String(argv[i + 1]).split(',').map((s) => s.trim()).filter(Boolean) : []));
  const vexFiles = every('vex');
  if (!vexFiles.length) { log('vexproof: rollup needs at least one --vex'); process.exit(2); }
  const license = loadLicense();
  if (!licensedFor(license, 'rollup')) { log('vexproof rollup is a Pro feature; nothing written'); process.exit(2); }
  const out = args.out ?? 'vex.rollup.cdx.json';
  try {
    const apps = vexFiles.map((file) => proLib.rollup.readApplication({ file, vex: readJson(file), sha256: sha256(file) }));
    let { vex, summary } = proLib.rollup.rollup({ apps, productPurl: args.product, licensee: license.org, version: VERSION, now });
    let signedBy = null;
    if (args.sign) {
      if (!licensedFor(license, 'signing')) { log('vexproof: --sign is a Pro feature not covered by this license; the rollup is unsigned'); }
      else { const key = proLib.sign.loadPrivateKey(args.sign); vex = proLib.sign.signCycloneDx(vex, key, { keyId: args.signer ?? null }); signedBy = vex.signature.keyId; }
    }
    writeFileSync(out, JSON.stringify(vex, null, 2));
    for (const a of summary.applications) console.log(`  ${a.purl.padEnd(40)} ${a.statements} statement(s): ${a.not_affected} not_affected, ${a.in_triage} in_triage${a.reviewed ? `, ${a.reviewed} reviewed` : ''}`);
    console.log(`vexproof: ${summary.applications.length} application(s), ${vex.vulnerabilities.length} statement(s) → ${out}${signedBy ? ` (signed by ${signedBy})` : ''}`);
    for (const d of summary.disagreements) log(`vexproof: ${d.id} on ${d.package} differs between applications: ${d.applications.map((x) => `${x.purl} ${x.state}`).join(', ')}`);
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
  const { rules, report } = await deriveRules(wanted, { now });
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
  log(`vexproof: aliases from OSV for ${e.resolved} of ${e.looked} advisories${e.resolved < e.looked ? ' (ids OSV could not be reached for, or does not know, keep their own)' : ''}`);
}

let moduleMap = null;
const root = args.root ?? process.cwd();
const lockNames = new Set([...indexSbom(lockfileSbom).keys()].filter((k) => k.startsWith('npm/')).map((k) => k.slice(4)));
const maps = [];
const shippedDirs = []; // every folder of files that ship, for the content check
for (const file of args.modules ?? []) {
  const mmJson = readJson(file);
  let mm;
  try { mm = readModuleMap(mmJson); } catch (e) { log(`vexproof: ${file}: ${e.message}`); process.exit(2); }
  // every JavaScript file in the build output must be a recorded chunk, or be accounted for on its own
  let stray, copied, outDirs, recorded, hints;
  try { ({ stray, copied, dirs: outDirs, recorded, hints } = strayOutputs(mmJson, { root, file })); } catch (e) {
    if (!(e instanceof CoverageError)) throw e;
    log(`vexproof: ${file}: ${e.message}`);
    process.exit(2);
  }
  // files the bundler says it copied from somewhere: that origin shipped
  for (const c of copied) { if (splitNodeModulesPath(c.from)) addToMap(mm.packages, c.from); else mm.own.add(c.from); }
  if (stray.length || copied.length) {
    const { accounted, unknown } = accountFor(stray, { root, outDirs, hints });
    if (unknown.length) {
      log(`vexproof: ${unknown.length} JavaScript file(s) in the build output are not accounted for, so their packages could look absent:`);
      for (const u of unknown.slice(0, 8)) log(`  ${u.file}: ${u.why}`);
      if (unknown.length > 8) log(`  … and ${unknown.length - 8} more`);
      log('If a worker or a nested build() made them, add the vexproof plugin to that build (worker.plugins) and rebuild.');
      log('A file that is copied in must be an unmodified copy of an installed or project file, or have a source map');
      log('beside it. For an app that cannot meet that, use --deploy <output folder> with source maps on.');
      process.exit(2);
    }
    mm.whole ??= new Set();
    for (const a of accounted) {
      for (const p of a.adds) { if (splitNodeModulesPath(p)) addToMap(mm.packages, p); else mm.own.add(p); }
      for (const n of a.whole) mm.whole.add(n);
      // loaded by name from a file that ships as it is: present, by a route vexproof can't follow to files
      for (const n of a.loads) if (lockNames.has(n)) { addToMap(mm.packages, `node_modules/${n}/package.json`); mm.whole.add(n); }
    }
    const n = (k) => accounted.filter((a) => a.kind === k).length;
    log(`vexproof: ${accounted.length + copied.length} output file(s) outside the module map accounted for: ${n('copy') + copied.length} copied from installed packages, ${n('mapped')} by their source maps, ${n('own')} the project's own, ${n('glue')} holding no package code${n('generated') ? `, ${n('generated')} written by a build tool` : ''}`);
  }
  // a package the recorded output loads by name when it runs is used by the product, wherever it is loaded from
  const external = [...runtimeLoads(recorded)].filter((n) => lockNames.has(n));
  if (external.length) {
    mm.whole ??= new Set();
    for (const n of external) { addToMap(mm.packages, `node_modules/${n}/package.json`); mm.whole.add(n); }
    log(`vexproof: the build output loads ${external.length} package(s) by name when it runs, so they count as shipped: ${external.slice(0, 6).join(', ')}${external.length > 6 ? ', …' : ''}`);
  }
  shippedDirs.push(...outDirs);
  // compiled code in the output (a .wasm or .node file a bundler copied): whose it is, where it is an exact copy
  for (const p of binaryCopies(outDirs, { root })) addToMap(mm.packages, p);
  // An esbuild metafile doesn't say where the build's output folder is; the folder its outputs share is
  // checked. JavaScript beside that folder (dist/vendor next to dist/js) is in no record, so the content
  // check at least searches it.
  if (mm.format === 'esbuild-metafile' && outDirs.length === 1) {
    const at = resolve(outDirs[0]), up = dirname(at), here = resolve(root);
    if (up !== here && up.startsWith(here) && dirname(resolve(file)) !== at) shippedDirs.push(up);
  }
  mm.serverBuildsSkipped = mmJson.serverBuildsSkipped ?? 0;
  maps.push(mm);
  inputs.push({ role: `modules-${mm.format}`, path: file, sha256: sha256(file) });
}
let deployment = null;
if (args.deploy) {
  const mapDirs = args.maps ?? defaultMapDirs(args.deploy, root);
  deployment = readDeployment(args.deploy, { root, mapDirs, lockNames });
  if (deployment.missingDirs.length) {
    log(`vexproof: --deploy ${deployment.missingDirs.join(', ')}: no such folder under ${root}. A folder that is not read can't be vouched for.`);
    process.exit(2);
  }
  if (deployment.missingHalves.length) {
    log(`vexproof: --deploy has the server half of this build but not the browser half: ${deployment.missingHalves.join(', ')}.`);
    log('What the browser gets ships too, and holds packages the server half does not. Add it as another --deploy folder.');
    process.exit(2);
  }
  if (deployment.loadedFromOutside.length) {
    const l = deployment.loadedFromOutside;
    log(`vexproof: ${l.length} package(s) are loaded by deployed packages but are not in the deployment (e.g. ${l[0].name}, by ${l[0].from}).`);
    log(`They run only where Node can find them further up, and count as shipped: ${l.slice(0, 6).map((x) => x.name).join(', ')}${l.length > 6 ? ', …' : ''}`);
  }
  if (deployment.unplaced.length) {
    const eg = deployment.unplaced[0];
    log(`vexproof: ${deployment.unplaced.length} source(s) named in the deployment's source maps are no file and no installed package's own map names them`);
    log(`(e.g. ${eg.source.length > 90 ? `${eg.source.slice(0, 90)}…` : eg.source} in ${eg.file}); taken as modules the bundler made up`);
  }
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
  if (deployment.missingRuntime.length && args['browser-only']) {
    // Files for a browser can't load a package from node_modules: there is none where they run. Code written
    // for browsers and Node keeps such loads for its Node side (pdf.js asks for @napi-rs/canvas). Whether a
    // loader could still supply the package is not for vexproof to say, so it counts as shipped.
    const names = [...new Set(deployment.missingRuntime.map((m) => m.name))];
    for (const n of names) { addToMap(deployment.packages, `node_modules/${n}/package.json`); deployment.whole.add(n); }
    log(`vexproof: code in the deployment loads ${names.length} package(s) by name that the deployment does not hold; in a browser nothing supplies them,`);
    log(`but they count as shipped: ${names.slice(0, 6).join(', ')}${names.length > 6 ? ', …' : ''}`);
  } else if (deployment.missingRuntime.length) {
    const names = [...new Set(deployment.missingRuntime.map((m) => m.name))];
    log(`vexproof: code in the deployment loads ${names.slice(0, 8).join(', ')} at runtime, but ${names.length > 1 ? 'they are' : 'it is'} not in the deployment folders (e.g. ${deployment.missingRuntime[0].from}).`);
    log('Point --deploy at the self-contained output (Next.js output: \'standalone\', Nuxt .output), or add the node_modules');
    log('the server runs with (after npm prune --omit=dev) as another --deploy folder.');
    process.exit(2);
  }
  maps.push(deployment);
  for (const d of args.deploy) shippedDirs.push(resolve(root, d));
  inputs.push({ role: 'deployment', path: args.deploy.join(','), sha256: deploymentDigest(args.deploy, root) });
}
if (maps.length) {
  const merged = mergeModuleMaps(maps);
  // a workspace package bundled from source is named by its real path, not under node_modules
  const workspace = addWorkspacePackages(merged, root);
  if (workspace.length) log(`vexproof: ${workspace.length} workspace package(s) bundled from source: ${workspace.slice(0, 6).join(', ')}${workspace.length > 6 ? ', …' : ''}`);
  moduleMap = attachVersions(merged, { cwd: root });
  const unnamed = unnamedStorePackages(moduleMap);
  if (unnamed.length) {
    log(`vexproof: ${unnamed.length} shipped package folder(s) in Yarn's node_modules/.store can't be named, so their packages could look absent:`);
    for (const r of unnamed.slice(0, 8)) log(`  ${r}`);
    if (unnamed.length > 8) log(`  … and ${unnamed.length - 8} more`);
    log('Run vexproof from the folder the build ran in, with node_modules installed, or pass --root.');
    process.exit(2);
  }
  // read through source maps, a package with a map inlined in its files is taken whole, like one that publishes .map files
  if (deployment) {
    moduleMap.whole ??= new Set();
    const asked = new Set(normalizeFindings(findings).map((f) => parsePurl(f.purl)?.name).filter(Boolean));
    for (const n of inlineMapPackages(moduleMap, asked, root)) moduleMap.whole.add(n);
  }
  // a folder that can't be read is known by its folder name only; if the lockfile has no package of that name,
  // it may be another package installed under an alias, and nothing could then be said about that package
  const unverified = (moduleMap.unverified ?? []).filter((u) => !lockNames.has(u.name));
  if (unverified.length) {
    log(`vexproof: ${unverified.length} shipped package folder(s) can't be read here and the lockfile SBOM has no package of that name, so each may be`);
    log('another package installed under an alias:');
    for (const u of unverified.slice(0, 8)) log(`  ${u.root}`);
    if (unverified.length > 8) log(`  … and ${unverified.length - 8} more`);
    log('Run vexproof from the folder the build ran in, with node_modules installed, or pass --root.');
    process.exit(2);
  }
  if (!bundleSbom) {
    bundleSbom = bundleSbomFromModules(moduleMap, { lockfileSbom, cwd: root });
    log(`vexproof: ${deployment ? 'deployed' : 'bundle'} contents taken from the ${deployment ? 'deployment' : 'module map'} (${bundleSbom.components.length} packages)`);
  }
  else {
    // --bundle with --modules or --deploy: the bundle SBOM is one account of what ships, the module map or the
    // deployment another (a server's packages are in no browser bundle SBOM). A package either one names ships.
    const have = new Set(bundleSbom.components?.map((c) => c.purl) ?? []);
    const extra = bundleSbomFromModules(moduleMap, { lockfileSbom, cwd: root }).components.filter((c) => !have.has(c.purl));
    if (extra.length) {
      bundleSbom = { ...bundleSbom, components: [...(bundleSbom.components ?? []), ...extra] };
      log(`vexproof: ${extra.length} package(s) are in the ${deployment ? 'deployment' : 'module map'} and not in the bundle SBOM; they count as shipped too`);
    }
  }
  // .cache, .prisma and the like: said out loud, in case one of them is a package store vexproof doesn't know
  const dotFolders = [...moduleMap.packages].filter(([n]) => n.startsWith('.')).flatMap(([, e]) => [...e.roots]);
  // node_modules/.vite holds dependencies Vite bundled ahead of time: package code, under no package's name
  const prebundled = dotFolders.filter((r) => r === 'node_modules/.vite' || r.endsWith('/node_modules/.vite'));
  if (prebundled.length) {
    log(`vexproof: the build ships code from ${prebundled[0]}, where Vite keeps dependencies it bundled ahead of time. Which packages those are`);
    log('is not recorded, so they could look absent. Build without the dependency optimizer (optimizeDeps.noDiscovery with no include), or use --deploy.');
    process.exit(2);
  }
  if (dotFolders.length) log(`vexproof: shipped code under ${dotFolders.slice(0, 4).join(', ')}${dotFolders.length > 4 ? ', …' : ''} is counted for no package: a dot folder in node_modules is not one`);
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
// A server of the project's own beside the front end (an Express API, an Electron main process). These are in
// many lockfiles as someone's dependency, so only the project's own package.json counts.
const direct = new Set();
try { for (const n of Object.keys(JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')).dependencies ?? {})) direct.add(n); } catch { /* no package.json here */ }
{
  // the lockfile SBOM says the same when it carries the dependency graph: what the application itself depends on
  const names = new Map();
  const walk = (cs) => { for (const c of cs ?? []) { const p = parsePurl(c.purl ?? ''); if (p?.type === 'npm' && c['bom-ref']) names.set(c['bom-ref'], p.name); walk(c.components); } };
  walk(lockfileSbom?.components);
  const app = lockfileSbom?.metadata?.component?.['bom-ref'];
  for (const ref of (lockfileSbom?.dependencies ?? []).find((d) => d.ref === app)?.dependsOn ?? []) if (names.has(ref)) direct.add(names.get(ref));
}
for (const n of SERVERS) if (direct.has(n) && !serverSide.some((s) => s.startsWith(`${n} `))) serverSide.push(`${n} is a dependency of this package`);
const serverCovered = Boolean(deployment?.hasServer); // the deployment includes what the server runs
if (serverSide.length && !serverCovered && !args['browser-only']) {
  log(`vexproof: this app also runs JavaScript on a server (${serverSide.join('; ')}).`);
  log('Packages used only on the server are missing from the browser bundle but still run in production, so');
  log('vexproof cannot speak for the whole app. Pass --browser-only to write VEX for the browser bundle alone,');
  log('and give that artifact its own identifier with --product.');
  process.exit(2);
}

const results = triage({ lockfileSbom, bundleSbom, findings, moduleMap, rules, moduleCheck: proLib?.evaluateModuleRule ?? null, pro: has('modules'), acceptDerived: Boolean(args['accept-derived']) && has('modules') });

// Independent of the maps: a package about to be called absent must not have its own strings in what ships.
if (shippedDirs.length) {
  // what the records name as shipped: every recorded file of every package, and the project's own files
  const recorded = () => {
    const files = [];
    for (const e of moduleMap?.packages.values() ?? []) for (const [r, fs] of e.byRoot ?? []) for (const f of fs) files.push(resolve(root, r, f));
    for (const p of moduleMap?.own ?? []) files.push(resolve(root, p));
    return files;
  };
  const c = contentCheck(results, { root, bases: installBases(root), shippedDirs, recorded });
  for (const k of c.kept) log(`vexproof: ${k.name} is not in the build's records, but ${k.hits.length} string(s) from its own files are in the shipped output (e.g. "${k.hits[0].text}" in ${k.hits[0].file}): its findings stay open`);
  if (c.checked || c.uncheckable.length) log(`vexproof: content check: looked for ${c.checked} absent package(s) in the shipped files${c.kept.length ? `, found ${c.kept.length}` : ''}${c.uncheckable.length ? `; ${c.uncheckable.length} are not installed here and were not looked for` : ''}`);
}

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
  vex = toCycloneDxVex({ results, bundleSbom, lockfileSbom, productPurl, inputs, licensee: license.valid ? license.org : null, scope: args['browser-only'] ? 'browser-bundle' : null, specVersion: args['spec-version'] ?? '1.6', now });
} catch (e) { log(`vexproof: ${e.message}`); process.exit(2); }

// CSAF (Pro): built before anything is written, so a bad option stops the run with nothing half-done.
let csafDoc = null;
if (args.csaf) {
  if (has('csaf')) {
    try {
      csafDoc = proLib.csaf.toCsaf({
        results, productPurl, licensee: license.org, version: VERSION, now,
        publisher: { name: args['csaf-publisher'], namespace: args['csaf-namespace'] },
        trackingId: args['csaf-id'], status: args['csaf-status'] ?? 'final', tlp: args['csaf-tlp'] ?? 'WHITE', url: args['csaf-url'] ?? null,
        previous: args['csaf-previous'] ? readJson(args['csaf-previous']) : null,
      });
    } catch (e) { log(`vexproof: ${e.message}`); process.exit(2); }
  } else log('vexproof: --csaf is a Pro feature; skipped');
}

// Signing (Pro): the CycloneDX VEX carries its signature; the other files get a detached one beside them.
let signingKey = null;
if (args.sign) {
  if (has('signing')) {
    try { signingKey = proLib.sign.loadPrivateKey(args.sign); } catch (e) { log(`vexproof: cannot read --sign key: ${e.message}`); process.exit(2); }
    try { vex = proLib.sign.signCycloneDx(vex, signingKey, { keyId: args.signer ?? null }); } catch (e) { log(`vexproof: ${e.message}`); process.exit(2); }
  } else log('vexproof: --sign is a Pro feature; skipped');
}
const writeSigned = (file, text) => {
  writeFileSync(file, text);
  if (signingKey) writeFileSync(`${file}.sig`, JSON.stringify(proLib.sign.signBytes(Buffer.from(text), signingKey, { keyId: args.signer ?? null }), null, 2));
};
writeFileSync(out, JSON.stringify(vex, null, 2));
if (args.openvex) {
  const ov = toOpenVex({ results, productPurl, author: license.valid ? license.org : 'vexproof', packageProducts: args['openvex-package-products'], now });
  writeSigned(args.openvex, JSON.stringify(ov, null, 2));
}
if (csafDoc) writeSigned(args.csaf, JSON.stringify(csafDoc, null, 2));

const s = summarize(results);
const parts = [`${s.not_affected} not_affected${s.module ? ` (${s.module} at module level)` : ''}`];
if (s.reviewed) parts.push(`${s.reviewed} reviewed`);
parts.push(`${s.in_triage} in_triage`);
console.log(`vexproof: ${results.length} finding(s) → ${parts.join(', ')} → ${out}${args.openvex ? ` + ${args.openvex}` : ''}${csafDoc ? ` + ${args.csaf}` : ''}${signingKey ? ` (signed by ${vex.signature.keyId})` : ''}`);
if (csafDoc) {
  const fileName = proLib.csaf.csafFileName(csafDoc.document.tracking.id);
  log(`vexproof: CSAF tracking id ${csafDoc.document.tracking.id}, version ${csafDoc.document.tracking.version}; publish it as ${fileName}`);
  if (args['csaf-url'] && !args['csaf-url'].endsWith(`/${fileName}`)) log(`vexproof: --csaf-url should end with ${fileName} (CSAF section 5.1); validators flag the document otherwise`);
}
for (const r of results) {
  const tag = r.origin === 'reviewed' ? `${r.state} (${r.carriedFrom ? 'carried' : 'reviewed'})` : r.state + (r.level === 'module' ? ' (module)' : '');
  const why = r.state === 'in_triage' && r.moduleReason && (moduleMap || r.reReview) ? `  ← ${r.moduleReason}` : '';
  console.log(`  ${tag.padEnd(24)} ${String(r.id).padEnd(22)} ${r.purl}${r.isNew ? '  [new]' : ''}${why}`);
}

if (args.report) {
  if (has('report')) {
    const command = `vexproof ${process.argv.slice(2).filter((a, i, arr) => a !== '--license' && arr[i - 1] !== '--license').join(' ')}`;
    writeFileSync(args.report, proLib.renderReport({ results, summary: s, inputs, productPurl, license, command, version: VERSION, now }));
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
    log(`and write an audit-ready report with the evidence. One yearly price per organization, free for open source: ${PRO_URL} (hide this with --quiet)`);
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
