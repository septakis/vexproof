// SPDX-License-Identifier: MIT
// vexproof (the main command): write VEX from a lockfile SBOM, the findings, and what shipped.
import { resolve } from 'node:path';
import { triage, toCycloneDxVex, summarize, VERSION, normalizeFindings } from '../../index.js';
import { fetchOsvFindings, readFindingsText, enrichAliases } from '../../sources.js';
import { toOpenVex } from '../../openvex.js';
import { attachFingerprints } from '../../evidence.js';
import { installBases } from '../../deploy.js';
import { contentCheck } from '../../content-check.js';
import { whatShipped } from '../../shipped.js';
import { Stop, UsageError, EXIT } from '../../stop.js';
import { pro, readJson, readText, sha256, log, loadLicense, licensedFor } from '../common.js';
import { writeAll } from '../output.js';
import { progressReporter } from '../../progress.js';

const PRO_URL = 'https://vexproof.dev/#pricing';
const DEFAULT_REVIEW_MAX_AGE_DAYS = 365;

/** The findings: from --findings, or OSV; with aliases from OSV unless a scanner's file is used as it is. */
async function readFindings(options, lockfileSbom, inputs) {
  let findings;
  if (options.findings) {
    const read = readFindingsText(readText(options.findings, 'findings file'), lockfileSbom);
    findings = read.findings;
    inputs.push({ role: `findings-${read.format}`, path: options.findings, sha256: sha256(options.findings) });
    log(`vexproof: findings from ${options.findings} (${read.format})`);
  } else {
    log('vexproof: querying OSV for lockfile components…');
    findings = await fetchOsvFindings(lockfileSbom);
  }

  if (!options.findings || options['enrich-aliases']) {
    // scanners disagree on id schemes (Trivy: CVE, npm audit and Grype: GHSA); OSV links them
    findings = normalizeFindings(findings);
    const enrichment = await enrichAliases(findings);
    const unknown = enrichment.looked - enrichment.resolved - enrichment.unreachable;
    const kept = [unknown && `${unknown} OSV does not know`, enrichment.unreachable && `${enrichment.unreachable} OSV could not be reached for`].filter(Boolean);
    log(`vexproof: aliases from OSV for ${enrichment.resolved} of ${enrichment.looked} advisories${kept.length ? ` (${kept.join(', ')}: they keep their own id only)` : ''}`);
  }

  return findings;
}

/** Keep open every package-level verdict whose package has its own strings in what ships (see content-check.js). */
function checkContent(results, { moduleMap, shippedDirs, selfVouched, root, progress }) {
  if (!shippedDirs.length) {
    return;
  }

  // what the records name as shipped: every recorded file of every package, and the project's own files
  const recorded = () => {
    const files = [];
    for (const entry of moduleMap?.packages.values() ?? []) {
      for (const [packageRoot, packageFiles] of entry.byRoot ?? []) for (const file of packageFiles) files.push(resolve(root, packageRoot, file));
    }
    for (const path of moduleMap?.own ?? []) files.push(resolve(root, path));

    return files.filter((file) => !selfVouched.has(file));
  };

  const check = contentCheck(results, { root, bases: installBases(root), shippedDirs, recorded, progress });
  for (const kept of check.kept) {
    log(`vexproof: ${kept.name} is not in the build's records, but ${kept.hits.length} string(s) from its own files are in the shipped output (e.g. "${kept.hits[0].text}" in ${kept.hits[0].file}): its findings stay open`);
  }
  for (const loaded of check.loaded) {
    log(`vexproof: ${loaded.name} is not in the build's records, but ${loaded.file} loads it from a CDN (${loaded.url}): its findings stay open`);
  }
  if (check.checked || check.uncheckable.length) {
    const found = check.kept.length ? `, found ${check.kept.length}` : '';
    const uncheckable = check.uncheckable.length ? `; ${check.uncheckable.length} are not installed here and were not looked for` : '';
    log(`vexproof: content check: looked for ${check.checked} absent package(s) in the shipped files${found}${uncheckable}`);
  }
}

/** The run's summary line and one line per statement, on standard output. */
function printSummary(results, { summary, moduleMap, written, signedBy }) {
  const parts = [`${summary.not_affected} not_affected${summary.module ? ` (${summary.module} at module level)` : ''}`];
  if (summary.reviewed) parts.push(`${summary.reviewed} reviewed`);
  parts.push(`${summary.in_triage} in_triage`);
  console.log(`vexproof: ${results.length} finding(s) → ${parts.join(', ')} → ${written.join(' + ')}${signedBy ? ` (signed by ${signedBy})` : ''}`);

  for (const result of results) {
    const tag = result.origin === 'reviewed' ? `${result.state} (${result.carriedFrom ? 'carried' : 'reviewed'})` : result.state + (result.level === 'module' ? ' (module)' : '');
    const why = result.state === 'in_triage' && result.moduleReason && (moduleMap || result.reReview || result.generatedCode) ? `  ← ${result.moduleReason}` : '';
    console.log(`  ${tag.padEnd(24)} ${String(result.id).padEnd(22)} ${result.purl}${result.isNew ? '  [new]' : ''}${why}`);
  }
}

/** The Pro hint for free users: never more than two lines, never with --quiet. */
function printProHint(results, { summary, moduleMap }) {
  if (summary.proWouldSettle > 0) {
    const counts = {};
    for (const result of results) {
      if (!result.proWouldSettle) continue;
      const name = result.key.replace(/^npm\//, '');
      counts[name] = (counts[name] ?? 0) + 1;
    }
    const list = Object.entries(counts).map(([name, count]) => `${name} ${count}`).join(', ');
    log(`\nvexproof Pro would settle ${summary.proWouldSettle} of your ${summary.in_triage} open finding(s) by checking which files of each package shipped (${list}),`);
    log(`and write an audit-ready report with the evidence. One yearly price per organization, free for community open-source projects: ${PRO_URL} (hide this with --quiet)`);

    return;
  }

  if (!moduleMap && summary.in_triage > 0) {
    log(`\nTip: add --modules <stats.json> to see how many of the ${summary.in_triage} open finding(s) module-level analysis could settle.`);
  }
}

export async function vex({ options, now, argv, env = process.env }) {
  if (!options.lockfile) throw new Stop('missing --lockfile');
  // The gate is checked before any work: a mode that can't run must not leave a VEX behind and a build that passed.
  const failOn = options['fail-on'] ?? null;
  if (failOn === 'new' && !options.baseline) throw new UsageError("--fail-on new needs --baseline <the previous release's VEX>: without one, nothing is new");
  if (!options.bundle && !options.modules && !options.deploy) throw new Stop('need --bundle, --modules or --deploy to know what ships');

  const root = options.root ?? process.cwd();
  const lockfileSbom = readJson(options.lockfile, 'lockfile SBOM');
  const givenBundle = options.bundle ? readJson(options.bundle, 'bundle SBOM') : null;
  const productPurl = options.product ?? lockfileSbom?.metadata?.component?.purl ?? 'pkg:generic/app';
  const inputs = [{ role: 'lockfile-sbom', path: options.lockfile, sha256: sha256(options.lockfile) }];
  if (options.bundle) inputs.push({ role: 'bundle-sbom', path: options.bundle, sha256: sha256(options.bundle) });

  const license = loadLicense(options.license);
  const has = (feature) => licensedFor(license, feature);
  const findings = await readFindings(options, lockfileSbom, inputs);

  // a large deployment takes minutes to read: its slow stages say how far they are
  const progress = progressReporter(log);
  const shipped = whatShipped({
    lockfileSbom, findings, bundleSbom: givenBundle, modules: options.modules ?? [], deploy: options.deploy ?? null, maps: options.maps ?? null,
    root, browserOnly: Boolean(options['browser-only']), readJson, sha256, log, progress,
  });
  inputs.push(...shipped.inputs);
  const { moduleMap, bundleSbom } = shipped;

  let rules = pro ? pro.loadRules() : null;
  if (options.rules) {
    if (has('modules')) {
      try {
        rules = pro.mergeRules(rules, pro.validateRules(readJson(options.rules, 'rules file'), options.rules));
      } catch (error) {
        if (error instanceof Stop) throw error;
        throw new Stop(error.message);
      }
      inputs.push({ role: 'rules', path: options.rules, sha256: sha256(options.rules) });
    } else log('vexproof: --rules is a Pro feature; ignoring it');
  }

  // what each package's absence is read from, as its not_affected detail says
  const shippedFrom = [
    ...(givenBundle ? ['bundle-sbom'] : []),
    ...(options.modules?.length ? ['module-map'] : []),
    ...(options.deploy?.length ? ['deployment'] : []),
  ];
  const results = triage({
    lockfileSbom, bundleSbom, findings, moduleMap, rules, moduleCheck: pro?.evaluateModuleRule ?? null,
    pro: has('modules'), acceptDerived: Boolean(options['accept-derived']) && has('modules'), shippedFrom,
  });

  // Independent of the maps: a package about to be called absent must not have its own strings in what ships.
  checkContent(results, { moduleMap, shippedDirs: shipped.shippedDirs, selfVouched: shipped.selfVouched, root, progress });
  attachFingerprints(results, { moduleMap, rules, cwd: root });

  let gateSkipped = null;
  if (options.baseline) {
    if (has('baseline')) {
      const days = options['review-max-age'] === undefined ? DEFAULT_REVIEW_MAX_AGE_DAYS : Number(options['review-max-age']);
      pro.applyBaseline(results, pro.readBaseline(readJson(options.baseline, 'baseline VEX')), { now, maxAgeDays: days > 0 ? days : null });
      inputs.push({ role: 'baseline-vex', path: options.baseline, sha256: sha256(options.baseline) });
    } else {
      log('vexproof: --baseline is a Pro feature; ignoring it');
      if (failOn === 'new') {
        // The Pro terms promise that a missing or expired key never fails a build (src/pro/LICENSE.md, section 6),
        // so the run goes on. A gate that was asked for and did not run must at least be impossible to miss.
        gateSkipped = '--fail-on new did not run: it compares against --baseline, a Pro feature no license here covers. This build was not gated. Use --fail-on in_triage for a gate that needs no license.';
        log(`vexproof: WARNING: ${gateSkipped}`);
      }
    }
  }

  if (!/^urn:uuid:[0-9a-f-]{36}$/i.test(String(lockfileSbom?.serialNumber ?? ''))) {
    log('vexproof: the lockfile SBOM has no serialNumber, so the CycloneDX VEX can\'t point into it with BOM-Links, and Trivy and');
    log('Dependency-Track will not apply it (OpenVEX is unaffected). Generate the SBOM without --output-reproducible.');
  }

  // ---------- every output, built before anything is written ----------
  const licensee = license.valid ? license.org : null;
  let document;
  try {
    document = toCycloneDxVex({ results, bundleSbom, lockfileSbom, productPurl, inputs, licensee, scope: options['browser-only'] ? 'browser-bundle' : null, specVersion: options['spec-version'] ?? '1.6', now });
  } catch (error) {
    throw new Stop(error.message);
  }

  // CSAF (Pro)
  let csaf = null;
  if (options.csaf) {
    if (has('csaf')) {
      try {
        csaf = pro.csaf.toCsaf({
          results, productPurl, licensee: license.org, version: VERSION, now,
          publisher: { name: options['csaf-publisher'], namespace: options['csaf-namespace'] },
          trackingId: options['csaf-id'], status: options['csaf-status'] ?? 'final', tlp: options['csaf-tlp'] ?? 'WHITE', url: options['csaf-url'] ?? null,
          previous: options['csaf-previous'] ? readJson(options['csaf-previous'], 'previous CSAF document') : null,
        });
      } catch (error) {
        if (error instanceof Stop) throw error;
        throw new Stop(error.message);
      }
    } else log('vexproof: --csaf is a Pro feature; skipped');
  }

  // Signing (Pro): the CycloneDX VEX carries its signature; the other files get a detached one beside them.
  let signingKey = null;
  if (options.sign) {
    if (has('signing')) {
      try {
        signingKey = pro.sign.loadPrivateKey(options.sign);
      } catch (error) {
        throw new Stop(`cannot read --sign key: ${error.message}`);
      }
      try {
        document = pro.sign.signCycloneDx(document, signingKey, { keyId: options.signer ?? null });
      } catch (error) {
        throw new Stop(error.message);
      }
    } else log('vexproof: --sign is a Pro feature; skipped');
  }

  const out = options.out ?? 'vex.cdx.json';
  const files = [{ path: out, text: JSON.stringify(document, null, 2) }];
  const withSignature = (path, text) => {
    files.push({ path, text });
    if (signingKey) files.push({ path: `${path}.sig`, text: JSON.stringify(pro.sign.signBytes(Buffer.from(text), signingKey, { keyId: options.signer ?? null }), null, 2) });
  };
  if (options.openvex) {
    const openvex = toOpenVex({ results, productPurl, author: licensee ?? 'vexproof', packageProducts: options['openvex-package-products'], now });
    withSignature(options.openvex, JSON.stringify(openvex, null, 2));
  }
  if (csaf) withSignature(options.csaf, JSON.stringify(csaf, null, 2));

  const summary = summarize(results);
  if (options.report) {
    if (has('report')) {
      // the command as run, without the license
      const shown = argv.filter((argument, index, all) => argument !== '--license' && all[index - 1] !== '--license' && !argument.startsWith('--license='));
      files.push({ path: options.report, text: pro.renderReport({ results, summary, inputs, productPurl, license, command: `vexproof ${shown.join(' ')}`, version: VERSION, now }) });
    } else log('vexproof: --report is a Pro feature; skipped');
  }

  writeAll(files);

  // ---------- what was written, and what it says ----------
  const written = [out, options.openvex, csaf ? options.csaf : null].filter(Boolean);
  printSummary(results, { summary, moduleMap, written, signedBy: signingKey ? document.signature.keyId : null });
  if (csaf) {
    const fileName = pro.csaf.csafFileName(csaf.document.tracking.id);
    log(`vexproof: CSAF tracking id ${csaf.document.tracking.id}, version ${csaf.document.tracking.version}; publish it as ${fileName}`);
    if (options['csaf-url'] && !options['csaf-url'].endsWith(`/${fileName}`)) log(`vexproof: --csaf-url should end with ${fileName} (CSAF section 5.1); validators flag the document otherwise`);
  }
  if (options.report && has('report')) console.log(`vexproof: report → ${options.report}`);

  const quiet = options.quiet || env.VEXPROOF_QUIET === '1';
  if (!quiet && pro && !has('modules')) printProHint(results, { summary, moduleMap });

  // ---------- the gate ----------
  if (gateSkipped) {
    // said again at the end, where a log is read, and as an annotation on the workflow run
    log(`vexproof: WARNING: ${gateSkipped}`);
    if (env.GITHUB_ACTIONS === 'true') console.log(`::warning title=vexproof gate did not run::${gateSkipped}`);

    return EXIT.ok;
  }
  if (failOn) {
    // "in_triage" trips on every open finding, and "new" on open findings no valid review covered before. A finding
    // a person confirmed exploitable trips either: it is the risk a gate is for, however long it has been known.
    const exploitable = (result) => result.state === 'exploitable';
    const tripsGate = failOn === 'new'
      ? (result) => result.isNew || exploitable(result)
      : (result) => result.state === 'in_triage' || exploitable(result);
    const tripped = results.filter(tripsGate);

    if (tripped.length) {
      const exploitableCount = tripped.filter(exploitable).length;
      const openCount = tripped.length - exploitableCount;
      const open = `${openCount} ${failOn === 'new' ? 'new ' : ''}open`;
      let counted;
      if (openCount && exploitableCount) {
        counted = `${open} and ${exploitableCount} exploitable finding(s)`;
      } else if (exploitableCount) {
        counted = `${exploitableCount} exploitable finding(s)`;
      } else {
        counted = `${open} finding(s)`;
      }
      log(`vexproof: gate failed — ${counted}: ${[...new Set(tripped.map((result) => result.id))].join(', ')}`);

      return EXIT.failed;
    }
  }

  return EXIT.ok;
}
