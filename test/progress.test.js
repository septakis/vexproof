// SPDX-License-Identifier: MIT
// Progress lines for slow stages: silent when a stage is quick, then a count at most every so often, and the
// stage's time at its end. Driven by a stand-in clock.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { progressReporter, NO_PROGRESS } from '../src/progress.js';

/** A reporter whose clock the test moves, and the lines it printed. */
function reporterWithClock() {
  const lines = [];
  let now = 0;
  const reporter = progressReporter((line) => lines.push(line), { quietSeconds: 5, everySeconds: 20, clock: () => now });

  return { reporter, lines, advance: (seconds) => (now += seconds * 1000) };
}

test('a stage that ends within the quiet time prints nothing', () => {
  const { reporter, lines, advance } = reporterWithClock();

  const stage = reporter.stage('reading the deployment', 1000);
  for (let done = 1; done <= 1000; done++) {
    stage.step(done);
  }
  advance(4);
  stage.step(1000);
  stage.end();

  assert.deepEqual(lines, []);
});

test('a slow stage says how far it is, at most every so often, and how long it took', () => {
  const { reporter, lines, advance } = reporterWithClock();
  const stage = reporter.stage('reading the deployment', 12345);

  advance(6);
  stage.step(1200);
  advance(10);
  stage.step(2400); // within 20 s of the last line: nothing
  advance(10);
  stage.step(3600);
  advance(5);
  stage.end();

  assert.deepEqual(lines, [
    'vexproof: reading the deployment: 1,200 of 12,345 files, 6 s so far…',
    'vexproof: reading the deployment: 3,600 of 12,345 files, 26 s so far…',
    'vexproof: reading the deployment: done in 31 s',
  ]);
});

test('without a reporter, stages print nothing', () => {
  const stage = NO_PROGRESS.stage('anything', 10);

  assert.doesNotThrow(() => {
    stage.step(5);
    stage.end();
  });
});
