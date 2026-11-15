// SPDX-License-Identifier: MIT
// Progress for the stages that can take minutes on a large app: reading a big deployment, its digest, the content
// check. The work runs synchronously, so no timer can interrupt it; a stage reports each step instead, and the
// reporter decides what to print. A stage that ends within `quietSeconds` prints nothing. One that runs longer
// says how far it is, at most every `everySeconds`, and how long it took when it ends.

/** A reporter that prints through `log`. Its stages: `const stage = reporter.stage(name, total, unit)`. */
export function progressReporter(log, { quietSeconds = 5, everySeconds = 20, clock = Date.now } = {}) {
  return {
    stage(name, total, unit = 'files') {
      const started = clock();
      let lastPrinted = null;
      const seconds = (time) => Math.round((time - started) / 1000);

      return {
        /** `done` of the stage's `total` steps are done. */
        step(done) {
          const time = clock();
          if (time - started < quietSeconds * 1000) {
            return;
          }
          if (lastPrinted !== null && time - lastPrinted < everySeconds * 1000) {
            return;
          }

          lastPrinted = time;
          log(`vexproof: ${name}: ${done.toLocaleString('en-US')} of ${total.toLocaleString('en-US')} ${unit}, ${seconds(time)} s so far…`);
        },

        /** The stage is over: its time is said only if its progress was. */
        end() {
          if (lastPrinted !== null) {
            log(`vexproof: ${name}: done in ${seconds(clock())} s`);
          }
        },
      };
    },
  };
}

/** A reporter that prints nothing: the default wherever no one asked for progress. */
export const NO_PROGRESS = {
  stage: () => ({ step() {}, end() {} }),
};
