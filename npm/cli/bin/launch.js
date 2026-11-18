// Shared by the command launchers in this directory. Finds the native program
// in this platform's payload and runs it, passing arguments, stdio, the exit
// status and any terminating signal straight through.
//
// The payload is a version of this same package, installed under an npm:
// alias named after process.platform and process.arch (see
// docs/NPM_PACKAGING.md). There is no install script and no downloader: if
// npm did not install the payload, the launcher says how to fix it.

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const DEFAULT_PACKAGE_NAME = '@twigpine/cli';

// The platforms a payload is published for. Anything else has no prebuilt
// program; Windows on ARM runs the x64 one under emulation.
export const SUPPORTED = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-x64'];

// The npm name this wrapper was published under, read from its own manifest
// so the name lives in one place.
export function readPackageName(root = packageRoot) {
  try {
    const { name } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    if (typeof name === 'string' && name !== '') return name;
  } catch {
    // An unreadable manifest must not stop the command from running.
  }
  return DEFAULT_PACKAGE_NAME;
}

// The payload alias for a platform. Windows on ARM falls back to x64.
export function payloadName(packageName, platform = process.platform, arch = process.arch) {
  const effectiveArch = platform === 'win32' && arch === 'arm64' ? 'x64' : arch;
  return `${packageName}-${platform}-${effectiveArch}`;
}

// Path of `program` inside the installed payload, or null when the payload or
// the program is missing.
export function nativeProgram(program, {
  packageName = readPackageName(),
  platform = process.platform,
  arch = process.arch,
  resolve = (specifier) => createRequire(import.meta.url).resolve(specifier),
} = {}) {
  let manifest;
  try {
    manifest = resolve(`${payloadName(packageName, platform, arch)}/package.json`);
  } catch {
    return null;
  }
  const file = platform === 'win32' ? `${program}.exe` : program;
  const candidate = join(dirname(manifest), file);
  return existsSync(candidate) ? candidate : null;
}

export function missingProgramMessage(command, packageName, platform = process.platform, arch = process.arch) {
  const here = `${platform}-${arch}`;
  const supported = SUPPORTED.includes(here) || (platform === 'win32' && arch === 'arm64');
  const lines = [`${command}: the Twigpine program for ${here} is not installed.`];
  if (supported) {
    lines.push(
      `npm installs it as an optional dependency (${payloadName(packageName, platform, arch)}).`,
      'Reinstall without omitting optional dependencies:',
      `  npm install -g ${packageName}`,
    );
  } else {
    lines.push(`No prebuilt program is published for ${here} (supported: ${SUPPORTED.join(', ')}).`);
  }
  lines.push(
    'Or install without npm:',
    platform === 'win32'
      ? '  irm https://twigpine.com/install.ps1 | iex'
      : '  curl -fsSL https://twigpine.com/install.sh | sh',
  );
  return lines.join('\n');
}

// Run `program` with this process's arguments. `argv0` is what the program
// sees as its own name; the CLI uses it to tell when it was started as `gl`.
export function run(program, argv0) {
  const packageName = readPackageName();
  const binary = nativeProgram(program, { packageName });
  if (!binary) {
    process.stderr.write(missingProgramMessage(argv0, packageName) + '\n');
    process.exit(1);
  }
  const child = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit', argv0 });
  if (child.error) {
    process.stderr.write(`${argv0}: could not start ${binary}: ${child.error.message}\n`);
    process.exit(1);
  }
  if (child.signal) {
    // End the same way the program did, so a shell or git sees the signal.
    process.kill(process.pid, child.signal);
  }
  process.exit(child.status ?? 1);
}
