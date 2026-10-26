# Reviews that follow their evidence

A small app (`settings-panel`) uses `omit` from lodash-es. Built with esbuild; the same results come from
the Vite plugin and the webpack plugin.

## 1. lodash-es 4.17.22: two findings open, one review

```
vexproof --lockfile bom.lockfile.json --modules meta.json --findings audit.json --out vex.cdx.json
  not_affected (module)    GHSA-r5fr-rjxr-66jc    pkg:npm/lodash-es@4.17.22
  in_triage                GHSA-f23m-r3pf-42rh    pkg:npm/lodash-es@4.17.22  ← vulnerable file(s) bundled: _baseUnset.js, omit.js
  in_triage                GHSA-xxjr-mmjv-4gpg    pkg:npm/lodash-es@4.17.22  ← vulnerable file(s) bundled: _baseUnset.js, omit.js

vexproof review --vex vex.cdx.json --id GHSA-f23m-r3pf-42rh --state not_affected \
  --justification code_not_reachable --by "Jane Doe" --same-cause \
  --detail "omit() only receives a fixed key list from src/main.js; no user input reaches the path argument"
vexproof: GHSA-f23m-r3pf-42rh → not_affected (reviewed by Jane Doe)
vexproof: GHSA-xxjr-mmjv-4gpg → not_affected (same vulnerable files: _baseUnset.js omit.js)
```

Each open statement records what the decision rests on (`1-reviewed-4.17.22.cdx.json`):

```
vexproof:vulnerable-files       _baseUnset.js omit.js
vexproof:evidence-files         _baseUnset.js=7773e16762af23ca omit.js=de577fc677627a13
vexproof:importers              src/main.js
```

## 2. Bump to lodash-es 4.17.23: the review carries

4.17.23 fixes GHSA-xxjr-mmjv-4gpg; GHSA-f23m-r3pf-42rh still applies. `_baseUnset.js` and `omit.js` are
byte-identical in both releases, and only `src/main.js` imports them, so nobody is asked again.

```
vexproof … --baseline 1-reviewed-4.17.22.cdx.json --fail-on new
  not_affected (module)    GHSA-r5fr-rjxr-66jc    pkg:npm/lodash-es@4.17.23
  not_affected (carried)   GHSA-f23m-r3pf-42rh    pkg:npm/lodash-es@4.17.23
exit 0
```

The statement keeps Jane Doe's name, date and reasoning, and says it was carried forward from 4.17.22
because the evidence is unchanged (`2-bumped-4.17.23.cdx.json`).

## 3. New code calls omit() with URL input: the review is re-opened

`src/filters.js` passes `?hide=` from the URL to `omit`. No dependency changed.

```
vexproof … --baseline 2-bumped-4.17.23.cdx.json --fail-on new
  in_triage   GHSA-f23m-r3pf-42rh   pkg:npm/lodash-es@4.17.23  [new]  ← the review by Jane Doe on 2026-09-27
              needs re-confirming: new importer: src/filters.js
vexproof: gate failed — 1 new open finding(s): GHSA-f23m-r3pf-42rh
exit 1
```

That is the case the original review didn't cover: user input reaching `omit`'s path argument.
