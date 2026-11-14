// SPDX-License-Identifier: MIT
// The package has two licenses. These tests keep the line between them where the LICENSE file says it is.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, cpSync, symlinkSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { modulesArgs } from './lib/built.js';
import { temporaryFolder } from './lib/temporary.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const walk = (dir) => readdirSync(dir).flatMap((name) => {
  const path = join(dir, name);
  return statSync(path).isDirectory() ? walk(path) : [path];
});
const sources = walk(join(ROOT, 'src')).filter((file) => /\.(js|cjs)$/.test(file));
const isPro = (file) => relative(ROOT, file).split(sep).join('/').startsWith('src/pro/');
const fixturePath = (name) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));

test('every source file names its license, and the license matches where the file lives', () => {
  for (const file of sources) {
    const header = readFileSync(file, 'utf8').split('\n').slice(0, 3).join('\n');
    const id = /SPDX-License-Identifier: (\S+)/.exec(header)?.[1];
    assert.equal(id, isPro(file) ? 'LicenseRef-vexproof-Pro' : 'MIT', relative(ROOT, file));
  }

  assert.match(JSON.parse(readFileSync(join(ROOT, 'src/pro/rules/module-rules.json'))).license, /LicenseRef-vexproof-Pro/);
  assert.match(JSON.parse(readFileSync(join(ROOT, 'src/pro/revoked.json'))).license, /LicenseRef-vexproof-Pro/);
});

test('both license texts ship, and package.json names both', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json')));

  assert.equal(pkg.license, 'MIT AND LicenseRef-vexproof-Pro'); // SPDX expression: MIT core plus the Pro files
  assert.match(readFileSync(join(ROOT, 'LICENSE'), 'utf8'), /src\/pro\/LICENSE\.md[\s\S]*MIT License/);
  assert.ok(existsSync(join(ROOT, 'src/pro/LICENSE.md')));
  assert.ok(pkg.files.includes('src/') && pkg.files.includes('LICENSE'));
});

test('MIT files reach Pro only through the one optional import in the CLI', () => {
  for (const file of sources.filter((path) => !isPro(path))) {
    const references = readFileSync(file, 'utf8').split('\n').filter((line) => /(from|import\(|require\()\s*['"][^'"]*\/pro\//.test(line));
    if (relative(ROOT, file) === join('src', 'cli', 'common.js')) {
      assert.deepEqual(references.map((line) => /import\('\.\.\/pro\/index\.js'\)\.catch/.test(line)), [true]);
    } else {
      assert.deepEqual(references, [], relative(ROOT, file));
    }
  }
});

test('with src/pro removed, the CLI still writes package-level VEX and offers nothing from Pro', (testContext) => {
  const dir = temporaryFolder(testContext, 'vexproof-mit-');
  cpSync(join(ROOT, 'src'), join(dir, 'src'), {
    recursive: true,
    filter: (source) => !isPro(source + sep) && !source.endsWith(`${sep}pro`),
  });
  cpSync(join(ROOT, 'package.json'), join(dir, 'package.json'));
  symlinkSync(join(ROOT, 'node_modules'), join(dir, 'node_modules'), 'junction');
  assert.ok(!existsSync(join(dir, 'src', 'pro')));
  const run = (...extraArgs) => spawnSync(process.execPath, [
    join(dir, 'src', 'cli.js'),
    '--lockfile', fixturePath('recharts.bom.lockfile.json'),
    '--findings', fixturePath('recharts.audit.json'),
    '--out', join(dir, 'vex.json'),
    ...extraArgs,
  ], { cwd: dir, encoding: 'utf8' });

  const pkgLevel = run('--bundle', fixturePath('recharts.bom.bundle.json'));
  assert.equal(pkgLevel.status, 0, pkgLevel.stderr);
  const vex = JSON.parse(readFileSync(join(dir, 'vex.json')));
  assert.ok(vex.vulnerabilities.length > 0);
  assert.doesNotMatch(pkgLevel.stderr, /Pro would settle/);

  // a module map and Pro flags are accepted, but nothing settles at module level and nothing crashes
  const withMap = run(
    ...modulesArgs(fixturePath('recharts.metafile.json')),
    '--rules', fixturePath('lodash.derived-rules.json'),
    '--report', join(dir, 'r.html'),
    '--license', 'vxp1.x.y',
  );
  assert.equal(withMap.status, 0, withMap.stderr);
  assert.doesNotMatch(withMap.stdout, /\(module\)/);
  assert.match(withMap.stderr, /no Pro files/);
  assert.ok(!existsSync(join(dir, 'r.html')));

  const dependabot = spawnSync(
    process.execPath,
    [join(dir, 'src', 'cli.js'), 'dependabot', '--vex', 'v.json', '--lockfile', 'l.json'],
    { cwd: dir, encoding: 'utf8' },
  );
  assert.equal(dependabot.status, 0, dependabot.stderr);
  assert.match(dependabot.stderr, /Pro feature; no alerts changed/);
});
