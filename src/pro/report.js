// SPDX-License-Identifier: LicenseRef-vexproof-Pro
// Part of vexproof Pro. Not MIT: see LICENSE.md in this directory.
// Pro: a self-contained, printable evidence report for auditors and customer security reviews.
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const LABEL = {
  package: 'Package not in bundle',
  module: 'Vulnerable files not in bundle',
  reviewed: 'Reviewed decision',
  open: 'Open — needs review',
};

function group(r) {
  if (r.origin === 'reviewed') return 'reviewed';
  if (r.state === 'not_affected' && r.level) return r.level;
  return 'open';
}

export function renderReport({ results, summary, inputs, productPurl, license, command, version, now = new Date() }) {
  const groups = { open: [], module: [], package: [], reviewed: [] };
  for (const r of results) groups[group(r)].push(r);

  const row = (r) => {
    const adv = /^GHSA-/.test(r.id) ? `<a href="https://github.com/advisories/${esc(r.id)}">${esc(r.id)}</a>` : esc(r.id);
    let ev = '';
    if (r.evidence?.survivingFiles) {
      ev = `<details><summary>${r.evidence.survivingFiles.length} surviving files; checked ${esc(r.evidence.checkedFiles.join(', '))}</summary>
        <p class="files">${r.evidence.survivingFiles.map(esc).join(' ')}</p>
        <p>Rule: <a href="${esc(r.evidence.ruleSource)}">${esc(r.evidence.ruleSource)}</a> (rules ${esc(r.evidence.rulesVersion)}, ${esc(r.evidence.moduleMapFormat)})</p>
        ${r.evidence.copies?.length ? `<p>Copy checked: <code>${r.evidence.copies.map(esc).join('</code>, <code>')}</code></p>` : ''}</details>`;
    }
    const who = r.reviewedBy ? `<p class="who">Reviewed by ${esc(r.reviewedBy)}</p>` : '';
    const isNew = r.isNew ? ' <span class="new">new since baseline</span>' : '';
    return `<tr><td>${adv}${isNew}</td><td><code>${esc(r.purl)}</code></td><td><span class="state s-${esc(r.state)}">${esc(r.state)}</span>${r.justification ? `<br><small>${esc(r.justification)}</small>` : ''}</td><td>${esc(r.detail)}${ev}${who}</td></tr>`;
  };

  // package-level statements share one basis per package: one row per package, all its advisories listed
  const packageRows = () => {
    const byPkg = new Map();
    for (const r of groups.package) { if (!byPkg.has(r.purl)) byPkg.set(r.purl, []); byPkg.get(r.purl).push(r); }
    return [...byPkg.values()].map((rs) => {
      const links = rs.map((r) => (/^GHSA-/.test(r.id) ? `<a href="https://github.com/advisories/${esc(r.id)}">${esc(r.id)}</a>` : esc(r.id))).join('<br>');
      return `<tr><td>${links}</td><td><code>${esc(rs[0].purl)}</code></td><td><span class="state s-not_affected">not_affected</span><br><small>code_not_present</small></td><td>${esc(rs[0].detail)}${rs.length > 1 ? ` <span class="muted">Applies to all ${rs.length} advisories listed.</span>` : ''}</td></tr>`;
    }).join('');
  };

  const section = (k) => groups[k].length === 0 ? '' : `
    <h2>${LABEL[k]} <span class="count">${groups[k].length}</span></h2>
    <table><thead><tr><th>Advisory</th><th>Package</th><th>Verdict</th><th>Basis</th></tr></thead>
    <tbody>${k === 'package' ? packageRows() : groups[k].map(row).join('')}</tbody></table>`;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability applicability report — ${esc(productPurl)}</title>
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
<p class="meta">${esc(productPurl)} · generated ${esc(now.toISOString())} by vexproof ${esc(version)}${license?.org ? ` · licensed to ${esc(license.org)}${license.plan === 'oss' ? ' (open-source license)' : ''}` : ''}</p>

<div class="totals">
  <div><b>${results.length}</b>advisories matched the lockfile</div>
  <div><b>${summary.package}</b>package not in bundle</div>
  <div><b>${summary.module}</b>vulnerable files not in bundle</div>
  <div><b>${summary.reviewed}</b>reviewed decisions</div>
  <div><b>${summary.in_triage}</b>open</div>
</div>

<h2>Method</h2>
<p>Each advisory reported against the dependency lockfile is checked against what actually ships. A statement is marked <em>not affected</em> only when it can be shown mechanically: either no component of that package appears in the SBOM generated from the production build, or the package is present but none of the files containing the vulnerable code survived bundling, according to the bundler's own module graph and a published per-advisory rule. Anything else stays open for human review. Reviewed decisions record who made them.</p>
${section('open')}${section('module')}${section('package')}${section('reviewed')}

<h2>Inputs</h2>
<dl>${inputs.map((i) => `<dt>${esc(i.role)}</dt><dd>${esc(i.path)}<br>sha256 ${esc(i.sha256)}</dd>`).join('')}</dl>
<h2>Reproduce</h2>
<pre>${esc(command)}</pre>
</body></html>`;
}
