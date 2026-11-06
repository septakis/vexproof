# Security

## Reporting a vulnerability

Email **security@septakis.io**. Please don't open a public issue for anything that could put users at risk.

You'll get an acknowledgement within two business days. Include the vexproof version, what you ran, and what
you saw; a minimal input that reproduces it helps most.

## What counts

vexproof writes VEX statements that make scanners hide findings, so the bugs that matter most are ones that
make it claim `not_affected` for code that ships. Also in scope: anything that lets an input file run code,
read files outside the project, or send data anywhere other than the public sources the docs name (OSV, the
npm registry, and GitHub's API for `vexproof dependabot`).

## Supported versions

Security fixes go to the current major release. After a new major, the previous one keeps getting security
fixes for six months.

## How releases are verified

Every release is published from GitHub Actions with npm provenance, so `npm audit signatures` can confirm the
package on the registry was built from the tagged commit in this repository.
