# Releasing

vexproof.dev and its docs live in [septakis/vexproof-site](https://github.com/septakis/vexproof-site), and
septakis.io in [septakis/septakis-site](https://github.com/septakis/septakis-site); each publishes itself to
GitHub Pages on push. This file covers the npm package.

1. Add the version's section to `CHANGELOG.md` and set `version` in `package.json` to match.
2. Commit, then tag and push: `git tag v1.0.0 && git push origin v1.0.0`.
3. The `Release` workflow (`.github/workflows/release.yml`) runs the tests, publishes to npm with provenance,
   and drafts a GitHub release from the changelog section. A pre-release version (`1.0.0-beta.1`) goes under
   the `beta` dist-tag. Publish the draft from the **Releases** page once `npx vexproof@<version> --version`
   answers.

One-time setup: on npmjs.com, under the package's **Settings → Trusted publisher**, allow repository
`septakis/vexproof` and workflow `release.yml`; and in this repository's **Settings → Environments**, create
`release` (optionally with a required reviewer, which holds every publish for approval).
