// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Pro: a self-contained, printable evidence report for auditors and customer security reviews.
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}[character]));

const advisoryLink = (id) => (/^GHSA-/.test(id)
  ? `<a href="https://github.com/advisories/${escapeHtml(id)}">${escapeHtml(id)}</a>`
  : escapeHtml(id));

const LABEL = {
  package: 'Package not in bundle',
  module: 'Vulnerable files not in bundle',
  reviewed: 'Reviewed decision',
  open: 'Open — needs review',
};

function group(result) {
  if (result.origin === 'reviewed') {
    return 'reviewed';
  }
  if (result.state === 'not_affected' && result.level) {
    return result.level;
  }

  return 'open';
}

export function renderReport({ results, summary, inputs, productPurl, license, command, version, now = new Date() }) {
  const groups = { open: [], module: [], package: [], reviewed: [] };
  for (const result of results) groups[group(result)].push(result);

  const row = (result) => {
    const advisory = advisoryLink(result.id);

    const evidence = result.evidence;
    let evidenceHtml = '';
    if (evidence?.survivingFiles) {
      const between = evidence.derivedFrom?.fixed
        ? ` between ${escapeHtml(evidence.derivedFrom.installed)} and ${escapeHtml(evidence.derivedFrom.fixed)}`
        : '';
      const ruleOrigin = evidence.ruleOrigin === 'derived'
        ? `derived from the files the fix changed${between}, accepted with --accept-derived`
        : 'hand-checked';
      const copies = evidence.copies?.length
        ? `<p>Copy checked: <code>${evidence.copies.map(escapeHtml).join('</code>, <code>')}</code></p>`
        : '';
      const checked = escapeHtml(evidence.checkedFiles.join(', '));
      const ruleSource = escapeHtml(evidence.ruleSource);
      const ruleNote = `${ruleOrigin}; rules ${escapeHtml(evidence.rulesVersion)}, ${escapeHtml(evidence.moduleMapFormat)}`;
      evidenceHtml = `<details><summary>${evidence.survivingFiles.length} surviving files; checked ${checked}</summary>
        <p class="files">${evidence.survivingFiles.map(escapeHtml).join(' ')}</p>
        <p>Rule: <a href="${ruleSource}">${ruleSource}</a> (${ruleNote})</p>
        ${copies}</details>`;
    }

    const who = result.reviewedBy ? `<p class="who">Reviewed by ${escapeHtml(result.reviewedBy)}</p>` : '';
    const isNew = result.isNew ? ' <span class="new">new since baseline</span>' : '';
    const justification = result.justification ? `<br><small>${escapeHtml(result.justification)}</small>` : '';
    const verdict = `<span class="state s-${escapeHtml(result.state)}">${escapeHtml(result.state)}</span>${justification}`;
    const basis = `${escapeHtml(result.detail)}${evidenceHtml}${who}`;

    return `<tr><td>${advisory}${isNew}</td><td><code>${escapeHtml(result.purl)}</code></td><td>${verdict}</td><td>${basis}</td></tr>`;
  };

  // package-level statements share one basis per package: one row per package, all its advisories listed
  const packageRows = () => {
    const byPackage = new Map();
    for (const result of groups.package) {
      if (!byPackage.has(result.purl)) byPackage.set(result.purl, []);
      byPackage.get(result.purl).push(result);
    }

    return [...byPackage.values()].map((packageResults) => {
      const links = packageResults.map((result) => advisoryLink(result.id)).join('<br>');
      const first = packageResults[0];
      const verdict = '<span class="state s-not_affected">not_affected</span><br><small>code_not_present</small>';
      const appliesToAll = packageResults.length > 1
        ? ` <span class="muted">Applies to all ${packageResults.length} advisories listed.</span>`
        : '';
      const basis = `${escapeHtml(first.detail)}${appliesToAll}`;

      return `<tr><td>${links}</td><td><code>${escapeHtml(first.purl)}</code></td><td>${verdict}</td><td>${basis}</td></tr>`;
    }).join('');
  };

  const section = (groupName) => {
    if (groups[groupName].length === 0) {
      return '';
    }

    const rows = groupName === 'package' ? packageRows() : groups[groupName].map(row).join('');

    return `
    <h2>${LABEL[groupName]} <span class="count">${groups[groupName].length}</span></h2>
    <table><thead><tr><th>Advisory</th><th>Package</th><th>Verdict</th><th>Basis</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
  };

  const licensedTo = license?.org
    ? ` · licensed to ${escapeHtml(license.org)}${license.plan === 'oss' ? ' (open-source license)' : ''}`
    : '';
  const sections = `${section('open')}${section('module')}${section('package')}${section('reviewed')}`;
  const inputList = inputs
    .map((input) => `<dt>${escapeHtml(input.role)}</dt><dd>${escapeHtml(input.path)}<br>sha256 ${escapeHtml(input.sha256)}</dd>`)
    .join('');

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability applicability report — ${escapeHtml(productPurl)}</title>
<style>
  :root{--ink:#12213A;--ink2:#4A5A72;--rule:#C9D3DE;--bg:#fff;--ok:#2E7A69;--okbg:#DDF0EA;--warn:#B5731C;--warnbg:#FBEBD2;--bad:#A33A3A;--badbg:#F6DADA}
  body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);background:var(--bg);max-width:1100px;margin:0 auto;padding:32px 20px}
  h1{font-size:1.6rem;margin:0 0 4px} h2{font-size:1.15rem;margin:36px 0 10px;border-bottom:1px solid var(--rule);padding-bottom:6px}
  .meta{color:var(--ink2);margin:0 0 24px} .count{color:var(--ink2);font-weight:400}
  .totals{display:flex;flex-wrap:wrap;gap:28px;margin:20px 0}
  .totals div{font-size:.9rem;color:var(--ink2)} .totals b{display:block;font-size:1.6rem;color:var(--ink)}
  table{width:100%;border-collapse:collapse;font-size:.88rem} th,td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid var(--rule)}
  th{font-weight:600;color:var(--ink2)} td:first-child{white-space:nowrap} td:nth-child(2){min-width:11rem} code{font-size:.85em;overflow-wrap:anywhere} .muted{color:var(--ink2)}
  .state{padding:1px 7px;border-radius:4px;font-size:.82rem;white-space:nowrap}
  .s-not_affected,.s-false_positive,.s-resolved{background:var(--okbg);color:var(--ok)} .s-in_triage{background:var(--warnbg);color:var(--warn)} .s-exploitable{background:var(--badbg);color:var(--bad)}
  .new{background:var(--badbg);color:var(--bad);font-size:.75rem;padding:1px 5px;border-radius:4px;margin-left:4px}
  details{margin-top:6px} summary{cursor:pointer;color:var(--ink2)} .files{font-family:ui-monospace,monospace;font-size:.78rem;color:var(--ink2)}
  .who{color:var(--ink2);margin:4px 0 0} pre{background:#F2F5F8;padding:12px;border-radius:6px;overflow-x:auto;font-size:.8rem;white-space:pre-wrap}
  dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;font-size:.88rem} dt{color:var(--ink2)} dd{margin:0;font-family:ui-monospace,monospace;word-break:break-all}
  @media print{a{color:inherit;text-decoration:none} details{display:block} details>*{display:block} h2{break-after:avoid} tr{break-inside:avoid}}
</style></head><body>
<h1>Vulnerability applicability report</h1>
<p class="meta">${escapeHtml(productPurl)} · generated ${escapeHtml(now.toISOString())} by vexproof ${escapeHtml(version)}${licensedTo}</p>

<div class="totals">
  <div><b>${results.length}</b>advisories matched the lockfile</div>
  <div><b>${summary.package}</b>package not in bundle</div>
  <div><b>${summary.module}</b>vulnerable files not in bundle</div>
  <div><b>${summary.reviewed}</b>reviewed decisions</div>
  <div><b>${summary.in_triage}</b>open</div>
</div>

<h2>Method</h2>
<p>Each advisory reported against the dependency lockfile is checked against what actually ships. A statement is marked <em>not affected</em> only when it can be shown mechanically: either no component of that package appears in the SBOM generated from the production build, or the package is present but none of the files containing the vulnerable code survived bundling, according to the bundler's own module graph and a per-advisory rule. A rule is hand-checked, or derived from the files the advisory's fix changed and accepted with --accept-derived; each statement below says which. Anything else stays open for human review. Reviewed decisions record who made them.</p>
${sections}

<h2>Inputs</h2>
<dl>${inputList}</dl>
<h2>Reproduce</h2>
<pre>${escapeHtml(command)}</pre>
</body></html>`;
}
