#!/usr/bin/env node
// build-platform-packages.mjs: assemble the npm payloads for a release from
// the release archives (twigpine-node-<version>-<target>.tar.gz / .zip).
//
// Layout written under --out-dir (default dist/npm):
//   wrapper/                     @twigpine/cli@X.Y.Z: the command launchers
//                                (npm/cli/bin) and a manifest with NO scripts
//                                and NO dependencies, only optionalDependencies
//                                aliasing the platform versions below.
//   platforms/cli-<platform>-<arch>/
//                                @twigpine/cli@X.Y.Z-<platform>-<arch>: the
//                                twigpine and git-remote-twigpine programs
//                                from that platform's archive.
//
// The platform payloads are versions of the SAME package at suffixed
// (semver prerelease) versions, referenced from the wrapper through npm:
// aliases, so one package name needs one trusted-publisher setting. See
// docs/NPM_PACKAGING.md.
//
// Each archive is checked against its .sha256 file before extraction. Every
// platform is required except those named in --allow-missing: the release
// builds Windows best-effort, so CI passes --allow-missing win32-x64. A
// platform left out is left out of the wrapper too, its aliases and its `os`
// list, so npm on that platform refuses the install with a clear error
// instead of installing commands with no program. --only narrows the set for
// tests the same way.
//
// Usage:
//   node scripts/npm/build-platform-packages.mjs --version X.Y.Z \
//     --artifacts-dir <dir> [--out-dir dist/npm] [--allow-missing win32-x64] \
//     [--only linux-x64,...]

import {
  realpathSync,
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repoRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const sourceDir = join(repoRoot, 'npm', 'cli');

// Node's platform/arch names (the launcher derives the alias from them) and
// the release target each one is built from.
export const MATRIX = [
  { platform: 'darwin', arch: 'arm64', target: 'aarch64-apple-darwin', ext: 'tar.gz' },
  { platform: 'darwin', arch: 'x64', target: 'x86_64-apple-darwin', ext: 'tar.gz' },
  { platform: 'linux', arch: 'arm64', target: 'aarch64-unknown-linux-musl', ext: 'tar.gz' },
  { platform: 'linux', arch: 'x64', target: 'x86_64-unknown-linux-musl', ext: 'tar.gz' },
  { platform: 'win32', arch: 'x64', target: 'x86_64-pc-windows-msvc', ext: 'zip' },
];

// The programs a payload carries. The daemon is not part of the npm package.
const PROGRAMS = ['twigpine', 'git-remote-twigpine'];

function fail(message) {
  console.error(`[build-platform-packages] ${message}`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = {
    version: '',
    artifactsDir: '',
    outDir: join(repoRoot, 'dist', 'npm'),
    only: null,
    allowMissing: new Set(),
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) fail(`missing value for ${arg}`);
      return argv[i];
    };
    switch (arg) {
      case '--version':
        args.version = next();
        break;
      case '--artifacts-dir':
        args.artifactsDir = next();
        break;
      case '--out-dir':
        args.outDir = next();
        break;
      case '--only':
        args.only = new Set(next().split(',').map((entry) => entry.trim()).filter(Boolean));
        break;
      case '--allow-missing':
        args.allowMissing = new Set(next().split(',').map((entry) => entry.trim()).filter(Boolean));
        break;
      default:
        fail(`unknown argument ${arg}`);
    }
  }
  if (!args.artifactsDir) fail('--artifacts-dir is required');
  // A plain release version: it becomes part of every platform version, and a
  // prerelease suffix here would be read as part of the platform suffix.
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(args.version)) {
    fail(`--version must be X.Y.Z, got ${JSON.stringify(args.version)}`);
  }
  return args;
}

function readSourceManifest() {
  const pkg = JSON.parse(readFileSync(join(sourceDir, 'package.json'), 'utf8'));
  if (!pkg.name) fail('npm/cli/package.json has no name');
  return pkg;
}

export function platformVersion(version, entry) {
  return `${version}-${entry.platform}-${entry.arch}`;
}

export function optionalDependencies(packageName, version, entries = MATRIX) {
  const aliases = {};
  for (const entry of entries) {
    aliases[`${packageName}-${entry.platform}-${entry.arch}`] =
      `npm:${packageName}@${platformVersion(version, entry)}`;
  }
  return aliases;
}

// "<hex>  <name>" or "<hex> *<name>", as sha256sum writes it. A line that names
// a file must name this one.
function expectedDigest(text, assetName) {
  for (const raw of text.split(/\r?\n/)) {
    const match = raw.trim().match(/^([a-fA-F0-9]{64})(?:\s+\*?(.+))?$/);
    if (!match) continue;
    if (!match[2] || match[2].trim() === assetName) return match[1].toLowerCase();
  }
  fail(`no SHA-256 for ${assetName} in its .sha256 file`);
}

function verifyChecksum(archivePath, assetName) {
  const sumPath = `${archivePath}.sha256`;
  if (!existsSync(sumPath)) fail(`missing checksum file ${sumPath}`);
  const expected = expectedDigest(readFileSync(sumPath, 'utf8'), assetName);
  const actual = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
  if (actual !== expected) fail(`checksum mismatch for ${assetName}: expected ${expected}, got ${actual}`);
}

function extract(archivePath, ext, destDir) {
  mkdirSync(destDir, { recursive: true });
  const attempts =
    ext === 'zip'
      ? [['unzip', ['-q', archivePath, '-d', destDir]], ['tar', ['-xf', archivePath, '-C', destDir]]]
      : [['tar', ['-xzf', archivePath, '-C', destDir]]];
  let lastError = '';
  for (const [command, commandArgs] of attempts) {
    const result = spawnSync(command, commandArgs, { stdio: ['ignore', 'ignore', 'pipe'] });
    // unzip exits 1 for warnings (a backslash in a stored path, say) after
    // extracting everything; whether the programs are there is checked next.
    if (result.status === 0 || (command === 'unzip' && result.status === 1)) return;
    lastError = result.error ? result.error.message : String(result.stderr || '').trim();
  }
  fail(`could not extract ${archivePath}: ${lastError}`);
}

// Release archives hold one directory named after the archive; accept the
// programs at the root too.
function programsDir(extracted, packageDirName, probe) {
  for (const dir of [join(extracted, packageDirName), extracted]) {
    if (existsSync(join(dir, probe))) return dir;
  }
  const dirs = readdirSync(extracted, { withFileTypes: true }).filter((e) => e.isDirectory());
  if (dirs.length === 1 && existsSync(join(extracted, dirs[0].name, probe))) {
    return join(extracted, dirs[0].name);
  }
  fail(`${packageDirName} does not contain ${probe}`);
}

function archivePathFor(entry, version, artifactsDir) {
  return join(artifactsDir, `twigpine-node-${version}-${entry.target}.${entry.ext}`);
}

function buildPlatformPackage(entry, source, version, artifactsDir, outDir) {
  const base = `twigpine-node-${version}-${entry.target}`;
  const assetName = `${base}.${entry.ext}`;
  const archivePath = archivePathFor(entry, version, artifactsDir);
  if (!existsSync(archivePath)) fail(`missing release archive ${archivePath}`);
  verifyChecksum(archivePath, assetName);

  const suffix = entry.platform === 'win32' ? '.exe' : '';
  const temp = mkdtempSync(join(tmpdir(), 'twigpine-npm-'));
  try {
    extract(archivePath, entry.ext, temp);
    const from = programsDir(temp, base, `twigpine${suffix}`);
    const packageDir = join(outDir, 'platforms', `cli-${entry.platform}-${entry.arch}`);
    rmSync(packageDir, { recursive: true, force: true });
    mkdirSync(packageDir, { recursive: true });
    for (const program of PROGRAMS) {
      const file = `${program}${suffix}`;
      if (!existsSync(join(from, file))) fail(`${assetName} does not contain ${file}`);
      cpSync(join(from, file), join(packageDir, file));
      if (!suffix) chmodSync(join(packageDir, file), 0o755);
    }
    for (const license of ['LICENSE-MIT', 'LICENSE-APACHE']) {
      cpSync(join(repoRoot, license), join(packageDir, license));
    }
    const manifest = {
      name: source.name,
      version: platformVersion(version, entry),
      description: `Twigpine programs for ${entry.platform}-${entry.arch} (installed by ${source.name}@${version})`,
      os: [entry.platform],
      // Windows on ARM has no build of its own and runs the x64 one under
      // emulation; npm installs a payload only when its cpu list matches.
      cpu: entry.platform === 'win32' && entry.arch === 'x64' ? ['x64', 'arm64'] : [entry.arch],
      license: source.license,
      repository: source.repository,
      // Yarn's Plug'n'Play keeps packages in zip files unless told otherwise,
      // and a program inside a zip cannot be started.
      preferUnplugged: true,
      // No bin, no scripts, no dependencies: the wrapper runs the programs.
    };
    writeFileSync(join(packageDir, 'package.json'), JSON.stringify(manifest, null, 2) + '\n');
    return packageDir;
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

function buildWrapper(source, version, outDir, entries) {
  const wrapperDir = join(outDir, 'wrapper');
  rmSync(wrapperDir, { recursive: true, force: true });
  mkdirSync(join(wrapperDir, 'bin'), { recursive: true });
  for (const file of readdirSync(join(sourceDir, 'bin'))) {
    if (!file.endsWith('.js')) continue;
    cpSync(join(sourceDir, 'bin', file), join(wrapperDir, 'bin', file));
    chmodSync(join(wrapperDir, 'bin', file), 0o755);
  }
  for (const file of ['README.md']) {
    cpSync(join(sourceDir, file), join(wrapperDir, file));
  }
  for (const license of ['LICENSE-MIT', 'LICENSE-APACHE']) {
    cpSync(join(repoRoot, license), join(wrapperDir, license));
  }
  const pkg = { ...source };
  // No lifecycle scripts and no regular dependencies, ever: nothing for a
  // package manager to run, block or warn about.
  delete pkg.scripts;
  delete pkg.dependencies;
  pkg.version = version;
  pkg.optionalDependencies = optionalDependencies(source.name, version, entries);
  // Install only where a payload was published.
  const platforms = new Set(entries.map((entry) => entry.platform));
  pkg.os = (pkg.os || []).filter((platform) => platforms.has(platform));
  writeFileSync(join(wrapperDir, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');
  return wrapperDir;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const source = readSourceManifest();
  for (const [flag, keys] of [['--only', args.only], ['--allow-missing', args.allowMissing]]) {
    for (const key of keys || []) {
      if (!MATRIX.some((e) => `${e.platform}-${e.arch}` === key)) fail(`${flag} lists unknown platform ${key}`);
    }
  }
  const selected = MATRIX.filter((e) => {
    const key = `${e.platform}-${e.arch}`;
    if (args.only && !args.only.has(key)) return false;
    if (args.allowMissing.has(key) && !existsSync(archivePathFor(e, args.version, args.artifactsDir))) {
      console.error(`[build-platform-packages] no ${key} archive in this release; leaving that platform out`);
      return false;
    }
    return true;
  });
  if (selected.length === 0) fail('no platforms to build');
  // A payload left from an earlier build into the same directory must not be
  // published beside a wrapper that no longer names it.
  for (const entry of MATRIX) {
    if (!selected.includes(entry)) {
      rmSync(join(args.outDir, 'platforms', `cli-${entry.platform}-${entry.arch}`), { recursive: true, force: true });
    }
  }
  const platformDirs = selected.map((e) => buildPlatformPackage(e, source, args.version, args.artifactsDir, args.outDir));
  const wrapperDir = buildWrapper(source, args.version, args.outDir, selected);
  process.stdout.write(
    JSON.stringify({ name: source.name, version: args.version, wrapperDir, platformDirs }, null, 2) + '\n',
  );
}

// Run when executed, not when imported. Both sides through realpath: macOS
// reaches temp and checkout paths through symlinks.
if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  main();
}
