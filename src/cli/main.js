// SPDX-License-Identifier: MIT
// The command line: read the arguments, run the command they name, and say how it ended.
import { VERSION, outputTime } from '../index.js';
import { parseArgs } from './args.js';
import { helpPage } from './help.js';
import { review } from './commands/review.js';
import { verify } from './commands/verify.js';
import { keygen } from './commands/keygen.js';
import { rollup } from './commands/rollup.js';
import { rulesDerive } from './commands/rules-derive.js';
import { dependabot } from './commands/dependabot.js';
import { vex } from './commands/vex.js';
import { EXIT } from '../stop.js';

const COMMANDS = { vex, review, verify, keygen, rollup, 'rules-derive': rulesDerive, dependabot };

/** Run the command `argv` names. Returns its exit code; throws a Stop when it stops. */
export async function main(argv) {
  const { command, words, options, help, version } = parseArgs(argv);
  if (help) {
    console.log(helpPage(command, words));

    return EXIT.ok;
  }
  if (version) {
    console.log(VERSION);

    return EXIT.ok;
  }

  // Every timestamp vexproof writes. SOURCE_DATE_EPOCH pins it, so the same inputs write the same files.
  const now = outputTime();

  return COMMANDS[command]({ options, words, now, argv });
}
