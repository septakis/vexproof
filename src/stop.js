// SPDX-License-Identifier: MIT
// How vexproof stops a run. A command returns an exit code or throws a Stop, and src/cli.js is the one place that
// prints a Stop and exits. Library code (src/shipped.js) throws a Stop too, for a check that a run cannot get past.

/** The exit codes vexproof uses (docs/CONTRACT.md): nothing else is ever returned. */
export const EXIT = {
  ok: 0, // the command did what it was asked
  failed: 1, // the --fail-on gate tripped (the VEX was still written), or vexproof verify found a bad signature
  stopped: 2, // the command stopped before doing what it was asked: see the message
};

/**
 * A reason to stop, with the lines that say why and what to do. `lines[0]` is printed after "vexproof: ";
 * the rest as they are. `code` is the exit code, 2 unless given.
 */
export class Stop extends Error {
  constructor(lines, code = EXIT.stopped) {
    const list = Array.isArray(lines) ? lines : [lines];
    super(list[0]);
    this.lines = list;
    this.code = code;
  }
}

/** An option, value or command the user gave that vexproof can't take. */
export class UsageError extends Stop {}
