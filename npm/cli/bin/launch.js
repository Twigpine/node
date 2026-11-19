// Shared by the command launchers in this directory. Finds the native program
// in this platform's payload and runs it, passing arguments, stdio and the exit
// status straight through, forwarding termination signals to it, and ending
// the way it ended.
//
// The payload is a version of this same package, installed under an npm:
// alias named after process.platform and process.arch (see
// docs/NPM_PACKAGING.md). There is no install script and no downloader: if
// npm did not install the payload, the launcher says how to fix it.

import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { constants } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const DEFAULT_PACKAGE_NAME = '@twigpine/cli';

// The platforms a payload is published for. Windows on ARM installs the x64
// payload (its manifest accepts arm64) and runs it under emulation.
export const SUPPORTED = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-x64'];

// Signals that, sent to the launcher alone (a supervisor, an MCP client or
// git stopping it by pid), must reach the program too. A terminal's Ctrl-C
// already reaches both, as they share a process group.
const FORWARDED = ['SIGINT', 'SIGTERM', 'SIGHUP'];

// On Windows the launcher only listens to these, so that it outlives the
// program and passes its exit status through: the console already delivers
// Ctrl-C and window close to the program, and there kill() can only end it
// outright (or throws, for SIGHUP).
const FORWARD_TO_PROGRAM = process.platform !== 'win32';

// Signals the launcher can re-raise on itself to end the same way. Node
// ignores SIGPIPE and turns SIGUSR1 into its debugger, so for any other
// signal the launcher exits with the shell's 128 + number instead.
const RERAISED = new Set(['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT', 'SIGABRT', 'SIGKILL']);

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

// The payload alias for a platform. Windows on ARM uses the x64 payload.
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
  return [
    `${command}: the Twigpine program for ${here} is not installed.`,
    `npm installs it as an optional dependency (${payloadName(packageName, platform, arch)}),`,
    'so reinstall without omitting optional dependencies, for example:',
    `  npm install -g --include=optional ${packageName}`,
    'If this release has no build for your platform, install without npm:',
    platform === 'win32'
      ? '  irm https://twigpine.com/install.ps1 | iex'
      : '  curl -fsSL https://twigpine.com/install.sh | sh',
  ].join('\n');
}

// End this process the way the program ended.
function endLike(code, signal) {
  if (signal) {
    if (RERAISED.has(signal)) {
      for (const name of FORWARDED) process.removeAllListeners(name);
      try {
        process.kill(process.pid, signal);
      } catch {
        // Fall through to the exit status below.
      }
    }
    process.exit(128 + (constants.signals[signal] ?? 0));
  }
  process.exit(code ?? 1);
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
  const child = spawn(binary, process.argv.slice(2), { stdio: 'inherit', argv0 });
  for (const name of FORWARDED) {
    process.on(name, () => {
      if (!FORWARD_TO_PROGRAM || child.exitCode !== null || child.signalCode !== null) return;
      try {
        child.kill(name);
      } catch {
        // The program is already gone, or this signal cannot be sent here.
      }
    });
  }
  child.on('error', (error) => {
    process.stderr.write(`${argv0}: could not start ${binary}: ${error.message}\n`);
    process.exit(1);
  });
  child.on('exit', endLike);
}
