# Contributing

Thanks for looking. Bug reports and pull requests are welcome; here is what helps them land.

## Reporting a bug

Open an issue with the vexproof version, the command you ran, and the inputs that reproduce it (a lockfile
SBOM and a findings file are usually enough). If the output seems wrong, say which statement you expected to be
different and why. For a security problem, see [SECURITY.md](SECURITY.md) instead.

## Proposing a change

For anything beyond a small fix, open an issue first so the shape can be agreed before the work is done. The
CLI contract and the VEX output are the public API, so changes to flags, exit codes or the output shape need
a strong reason and a changelog entry.

## Working on the code

```
npm ci
npm test
```

Tests are plain `node:test` files in `test/`; every change comes with one. The suite validates every generated
file against the CycloneDX schema and runs the webpack and Angular fixtures, so it covers more than it looks.
No build step, no dependencies beyond `acorn` at runtime.

Two things to know:

- `src/pro/` is under its own license ([src/pro/LICENSE.md](src/pro/LICENSE.md)), and MIT code reaches it only
  through one optional import in `src/cli.js`. A test enforces the line; keep new code on the right side of it.
- Never run `npm run keygen` in a checkout you care about: it overwrites `src/pro/license-key.js`, the public
  key every issued license is checked against.

Keep pull requests to one change each, add a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md), and
match the surrounding style. By contributing you agree your contribution is licensed under the license of the
files it touches.
