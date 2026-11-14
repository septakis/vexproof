// SPDX-License-Identifier: MIT
// Temporary folders for tests, removed when the test, or the test file, that made them is done.
import { after } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * A new empty folder under the system's temporary folder, named from `prefix`. It is removed, with everything
 * in it, when test context `testContext` ends.
 */
export function temporaryFolder(testContext, prefix = 'vxp-') {
  const folder = mkdtempSync(join(tmpdir(), prefix));
  testContext.after(() => rmSync(folder, { recursive: true, force: true }));

  return folder;
}

// Folders made for a whole test file. `node --test` runs each file in a process of its own, so this list, and
// the hook that removes its folders, belong to one file.
const fileFolders = [];
after(() => {
  for (const folder of fileFolders) {
    rmSync(folder, { recursive: true, force: true });
  }
});

/**
 * A new empty folder, removed after the last test of the file: for helpers that make folders outside any one
 * test's context.
 */
export function temporaryFolderForFile(prefix = 'vxp-') {
  const folder = mkdtempSync(join(tmpdir(), prefix));
  fileFolders.push(folder);

  return folder;
}
