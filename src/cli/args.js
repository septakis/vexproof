// SPDX-License-Identifier: MIT
// Command-line arguments: which command, and its options, each checked before any work is done. An option the
// command doesn't have stops the run, and so does a value an option can't take: a misspelt --fail-on, or a
// --review-max-age of "90d", that was passed over in silence would leave a build with no gate, or reviews that
// never expire, and nothing to show for it.
import { UsageError } from '../stop.js';
import { CYCLONEDX_VERSIONS } from '../index.js';

const FLAG = 'flag'; // --quiet
const VALUE = 'value'; // --out vex.json, once
const LIST = 'list'; // --modules a.json --modules b.json, or --modules a.json,b.json

const COMMON = { help: FLAG, version: FLAG };

/** The options of each command, by name, and what each takes. docs/CONTRACT.md lists the same. */
export const OPTIONS = {
  vex: {
    ...COMMON,
    lockfile: VALUE, bundle: VALUE, modules: LIST, deploy: LIST, maps: LIST, root: VALUE,
    findings: VALUE, 'enrich-aliases': FLAG,
    product: VALUE, out: VALUE, 'spec-version': VALUE, openvex: VALUE, 'openvex-package-products': FLAG, 'browser-only': FLAG,
    csaf: VALUE, 'csaf-namespace': VALUE, 'csaf-publisher': VALUE, 'csaf-id': VALUE, 'csaf-status': VALUE, 'csaf-tlp': VALUE, 'csaf-url': VALUE, 'csaf-previous': VALUE,
    'fail-on': VALUE, baseline: VALUE, 'review-max-age': VALUE,
    license: VALUE, rules: VALUE, 'accept-derived': FLAG, report: VALUE, sign: VALUE, signer: VALUE, quiet: FLAG,
  },
  review: { ...COMMON, vex: VALUE, id: VALUE, state: VALUE, detail: VALUE, by: VALUE, justification: VALUE, package: VALUE, 'same-cause': FLAG },
  verify: { ...COMMON, key: VALUE },
  keygen: { ...COMMON, out: VALUE, type: VALUE },
  rollup: { ...COMMON, vex: LIST, product: VALUE, out: VALUE, sign: VALUE, signer: VALUE, license: VALUE },
  'rules-derive': { ...COMMON, lockfile: VALUE, findings: VALUE, modules: LIST, out: VALUE },
  dependabot: { ...COMMON, vex: LIST, lockfile: LIST, repo: VALUE, manifest: LIST, link: VALUE, token: VALUE, 'dry-run': FLAG, license: VALUE },
};

/** How each command is typed, and how many words follow it (verify's file). */
const COMMANDS = { review: { words: 0 }, verify: { words: 1 }, keygen: { words: 0 }, rollup: { words: 0 }, rules: { words: 0, sub: 'derive' }, dependabot: { words: 0 } };
const COMMAND_LIST = 'review, verify, keygen, rollup, rules derive, dependabot';

const oneOf = (allowed) => (value, name) => {
  if (!allowed.includes(value)) throw new UsageError(`--${name} must be ${allowed.slice(0, -1).join(', ')} or ${allowed.at(-1)}, not "${value}"`);
};

/** Values an option can't take, checked at once. */
const VALUES = {
  'fail-on': oneOf(['in_triage', 'new']),
  'spec-version': oneOf(CYCLONEDX_VERSIONS),
  'csaf-status': oneOf(['draft', 'interim', 'final']),
  'csaf-tlp': oneOf(['WHITE', 'GREEN', 'AMBER', 'RED']),
  type: oneOf(['ed25519', 'p256']),
  'review-max-age': (value, name) => {
    if (!/^\d+$/.test(value)) throw new UsageError(`--${name} must be a whole number of days (0 turns it off), not "${value}"`);
  },
};

// whatever a command takes, an option is a flag everywhere or takes a value everywhere
const TAKES_VALUE = new Set(Object.values(OPTIONS).flatMap((table) => Object.entries(table).filter(([, kind]) => kind !== FLAG).map(([name]) => name)));
const KNOWN = new Set(Object.values(OPTIONS).flatMap((table) => Object.keys(table)));

/** The known option closest to a misspelt one, when it is close enough to be what was meant. */
function nearest(name, known) {
  const flatten = (text) => text.toLowerCase().replace(/[-_]/g, '');
  const distance = (left, right) => {
    const rows = Array.from({ length: left.length + 1 }, (_, row) => [row, ...Array(right.length).fill(0)]);
    for (let column = 1; column <= right.length; column++) rows[0][column] = column;
    for (let row = 1; row <= left.length; row++) {
      for (let column = 1; column <= right.length; column++) {
        const substitution = rows[row - 1][column - 1] + (left[row - 1] === right[column - 1] ? 0 : 1);
        rows[row][column] = Math.min(rows[row - 1][column] + 1, rows[row][column - 1] + 1, substitution);
      }
    }

    return rows[left.length][right.length];
  };

  const ranked = [...known].map((candidate) => [distance(flatten(name), flatten(candidate)), candidate]).sort((left, right) => left[0] - right[0]);
  const best = ranked[0];

  // a short name is close to too much to guess: one edit away at most, two for longer ones
  const allowed = name.length <= 5 ? 1 : 2;

  return best && best[0] <= allowed ? best[1] : null;
}

/** The arguments split into words and options: [{ option, value?, inline }] and words, in order. */
function tokenize(argv) {
  const words = [];
  const options = [];
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    if (argument === '-h' || argument === '-v') {
      options.push({ name: argument === '-h' ? 'help' : 'version' });
      continue;
    }
    if (!argument.startsWith('-') || argument === '-') {
      words.push(argument);
      continue;
    }
    if (!argument.startsWith('--')) throw new UsageError(`unknown option ${argument} (options start with two dashes; see vexproof --help)`);

    const equals = argument.indexOf('=');
    const name = equals < 0 ? argument.slice(2) : argument.slice(2, equals);
    if (!KNOWN.has(name)) {
      const meant = nearest(name, KNOWN);
      throw new UsageError(`unknown option --${name}${meant ? ` (did you mean --${meant}?)` : ''}; see vexproof --help all`);
    }
    if (!TAKES_VALUE.has(name)) {
      if (equals >= 0) throw new UsageError(`--${name} takes no value`);
      options.push({ name });
      continue;
    }

    let value = equals < 0 ? undefined : argument.slice(equals + 1);
    if (value === undefined) {
      value = argv[index + 1];
      if (value === undefined || (value.startsWith('--') && value.length > 2)) throw new UsageError(`--${name} needs a value`);
      index++;
    }
    if (value === '') throw new UsageError(`--${name} needs a value`);
    options.push({ name, value });
  }

  return { words, options };
}

/**
 * Parse the arguments. Returns { command, words, options, help, version }: `command` is 'vex' (the main
 * command), 'review', 'verify', 'keygen', 'rollup', 'rules-derive' or 'dependabot'; `words` the words after it
 * (verify's file; 'all' after --help); `options` each option's value: true for a flag, a string, or for an option
 * that may repeat an array of its values (comma-separated ones split). Throws UsageError.
 */
export function parseArgs(argv) {
  const { words, options: given } = tokenize(argv);
  const help = given.some((option) => option.name === 'help');
  const version = given.some((option) => option.name === 'version');

  // the command, and the words that belong to it
  let command = 'vex';
  let rest = words;
  if (words.length && COMMANDS[words[0]]) {
    const spec = COMMANDS[words[0]];
    if (spec.sub) {
      if (words[1] !== spec.sub && !help) throw new UsageError(`the ${words[0]} command is "vexproof ${words[0]} ${spec.sub}"; see vexproof ${words[0]} --help`);
      command = `${words[0]}-${spec.sub}`;
      rest = words.slice(words[1] === spec.sub ? 2 : 1);
    } else {
      command = words[0];
      rest = words.slice(1);
    }
    if (rest.length > spec.words) throw new UsageError(`unexpected argument "${rest[spec.words]}"; see vexproof ${words[0]} --help`);
  } else if (words.length && !(help && words.length === 1 && words[0] === 'all')) {
    // A word that is not a command is a mistake (an option's value that lost its option, a misspelt command),
    // and running the main command without it would do something other than what was asked.
    throw new UsageError(`unknown command "${words[0]}" (commands: ${COMMAND_LIST}; see vexproof --help)`);
  }

  // each option: one the command has, given once unless it may repeat, with a value it can take
  const table = OPTIONS[command];
  const options = {};
  for (const { name, value } of given) {
    const kind = table[name];
    if (!kind) {
      const label = command === 'vex' ? 'the main command' : `vexproof ${command.replace('-', ' ')}`;
      throw new UsageError(`--${name} is not an option of ${label}; see vexproof ${command === 'vex' ? '--help all' : `${command.replace('-', ' ')} --help`}`);
    }
    if (kind === FLAG) {
      options[name] = true;
      continue;
    }

    VALUES[name]?.(value, name);
    if (kind === LIST) {
      options[name] = [...(options[name] ?? []), ...value.split(',').map((part) => part.trim()).filter(Boolean)];
      continue;
    }
    if (name in options) throw new UsageError(`--${name} was given twice`);
    options[name] = value;
  }

  return { command, words: rest, options, help, version };
}
