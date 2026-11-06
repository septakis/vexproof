# Gitea (Vite 8, pnpm) end to end

Gitea's web frontend, built from commit in `gitea-commit.txt` with the vexproof plugin added
(`vite.config.ts.diff`: one line in the main build, one in the nested `iife` builds).

1. First build with the plugin in the main build only: vexproof refused to run, because two shipped
   files came from nested `build()` calls it had not seen:
   `public/assets/js/iife.*.js` and `public/assets/js/external-render-helper.*.js`.
2. Plugin added to the nested builds too: all 284 chunks covered.

```
pnpm sbom --sbom-format cyclonedx --sbom-type application --prod --out bom.lockfile.json
pnpm audit --prod --json > audit.pnpm.json
vexproof --lockfile bom.lockfile.json --modules vexproof-modules.json --findings audit.pnpm.json \
         --product pkg:npm/gitea@main --out vex.cdx.json --openvex vex.openvex.json
```

Result: 8 production advisories.

- Free: 2 settled (`form-data`, `postcss-selector-parser` never reach the bundle).
- Pro: 4 settled. Both lodash-es advisories (GHSA-r5fr-rjxr-66jc, GHSA-f23m-r3pf-42rh, against 4.17.23)
  resolve at file level. lodash-es ships twice, 4.17.23 and 4.18.1, from separate pnpm store paths.
  vexproof checks only the 227 files of the 4.17.23 copy, none of which hold the vulnerable code, and
  the statement names that copy.
- Still open: js-yaml (3 advisories) and fflate (1), which have no file-level rules yet.

`vex.pro.cdx.json` and `report.html` are the Pro outputs; the VEX validates against CycloneDX 1.6.
