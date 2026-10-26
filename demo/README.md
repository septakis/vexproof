# Demo: vulnerable code your own imports never mention

A small dashboard with a line chart and a treemap. It depends on recharts 2.15.4 and, through it,
lodash 4.17.21. **`src/main.jsx` never imports lodash.**

```
grep -c lodash src/main.jsx   →  0
```

`npm audit` reports three lodash advisories. Here is what each approach concludes:

| Advisory | Affects | Files shipped in `dist/app.js` | Import-only analysis | vexproof |
|---|---|---|---|---|
| GHSA-r5fr-rjxr-66jc (CVE-2026-4800) | `_.template` | `template.js` not shipped | safe | **not_affected**, module level |
| GHSA-f23m-r3pf-42rh (CVE-2026-2950) | `_.unset`, `_.omit` | **`omit.js`, `_baseUnset.js` shipped** | safe | **in_triage**: vulnerable files bundled |
| GHSA-xxjr-mmjv-4gpg (CVE-2025-13465) | `_.unset`, `_.omit` | **`omit.js`, `_baseUnset.js` shipped** | safe | **in_triage**: vulnerable files bundled |

recharts' `Treemap` imports `lodash/omit`, and `omit.js` is where the prototype-pollution code lives.
esbuild's module graph shows 225 lodash files in the output, including those two.

An analysis that reads only your source's import statements sees no lodash import and reports every
lodash advisory as not reachable. That is a false "not affected" for two of the three, and it is the
kind of statement that fails an audit. vexproof reads what the bundler actually emitted, so it settles
the one it can prove and leaves the two it cannot.

Whether `omit` can be reached with attacker-controlled input through a treemap is a question for a
person; vexproof's job is not to answer it for them. Record the answer with `vexproof review`.

## Reproduce

```
./run.sh
```

`out/` holds the files from the run in this repo:

- `vex.trivy.cdx.json`, `vex.trivy.openvex.json` from Trivy-format findings (CVE ids)
- `vex.grype.openvex.json` from Grype-format findings (GHSA ids), written with `--openvex-package-products`
- `trivy.json`, `grype.json` follow each scanner's JSON schema; `audit.json` is real `npm audit` output

`../interop/run.sh out` applies those files with the matching code Trivy and Grype use.
