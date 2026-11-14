#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// The vexproof command. This file only checks the Node.js version and reports how a run ended; the commands are
// in src/cli/. It loads them after the check, so an old Node is told what it needs instead of failing on syntax
// or an API it doesn't have.

const MINIMUM_NODE = 22;
if (Number(process.versions.node.split('.')[0]) < MINIMUM_NODE) {
  console.error(`vexproof: needs Node.js ${MINIMUM_NODE} or later; this is ${process.version}`);
  process.exit(2);
}

// Exit 1 means only "the --fail-on gate tripped" (or, for verify, "the signature does not check"). Anything else
// that stops a run (unreadable or unrecognised input, a network failure, a bug) exits 2 with a message.
const stop = (error) => {
  const lines = error?.lines ?? [error?.message ?? String(error)];
  console.error(`vexproof: ${lines[0]}`);
  for (const line of lines.slice(1)) console.error(line);
  process.exit(error?.code ?? 2);
};
process.on('uncaughtException', stop);
process.on('unhandledRejection', stop);

const { main } = await import('./cli/main.js');
process.exitCode = await main(process.argv.slice(2));
