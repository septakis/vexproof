# Releasing

vexproof.dev and its docs live in `septakis/vexproof-site`, and septakis.io in `septakis/septakis-site`
(both private repositories); each publishes itself to GitHub Pages on push. This file covers the npm package.

1. Add the version's section to `CHANGELOG.md` and set `version` in `package.json` to match.
2. Commit, then tag and push: `git tag v1.0.0 && git push origin v1.0.0`.
3. The `Release` workflow (`.github/workflows/release.yml`) runs the tests, publishes to npm with provenance,
   and drafts a GitHub release from the changelog section. A pre-release version (`1.0.0-beta.1`) goes under
   the `beta` dist-tag. Publish the draft from the **Releases** page once `npx vexproof@<version> --version`
   answers.

One-time setup: on npmjs.com, under the package's **Settings → Trusted publisher**, allow repository
`septakis/vexproof` and workflow `release.yml`; and in this repository's **Settings → Environments**, create
`release` (optionally with a required reviewer, which holds every publish for approval).

## Licenses

Licenses are issued, and the signing key made, with the maintainers' license tooling, which is kept outside
this repository. The public half of the signing key is `src/pro/license-key.js`; re-keying replaces it and
invalidates every license already issued.

## Revoking a license

A license is revoked by adding its id to `src/pro/revoked.json` (the maintainers' tooling does this from the
license itself, or from its id). It takes effect in the next version you
publish: runs on that version or later treat the license as invalid and use free features. The
GitHub Action runs the release its tag names, so a workflow picks up a revocation when it moves to a newer
tag, and a project that installs vexproof as a dependency when it updates; a copy pinned to an older
version keeps accepting the license until it expires. The list, notes included, is public in the
npm package, so keep customer names out of notes.
