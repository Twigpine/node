#!/usr/bin/env node

const { existsSync, copyFileSync, chmodSync, mkdirSync } = require("fs");
const { join, dirname } = require("path");

const PLATFORM_PACKAGES = {
  "darwin-arm64": "@gitlawb/gl-darwin-arm64",
  "darwin-x64": "@gitlawb/gl-darwin-x64",
  "linux-arm64": "@gitlawb/gl-linux-arm64",
  "linux-x64": "@gitlawb/gl-linux-x64",
};

const BINARIES = ["gl", "git-remote-gitlawb"];

function getPlatformKey() {
  const platform = process.platform;
  const arch = process.arch;

  if (arch !== "arm64" && arch !== "x64") {
    throw new Error(
      `Unsupported architecture: ${arch}. Twigpine CLI supports x64 and arm64.`
    );
  }

  if (platform !== "darwin" && platform !== "linux") {
    throw new Error(
      `Unsupported platform: ${platform}. Twigpine CLI supports macOS and Linux.\n` +
        `For Windows, use WSL or the installer: https://twigpine.com/install.ps1`
    );
  }

  return `${platform}-${arch}`;
}

function findPlatformPackage(packageName) {
  try {
    const pkgJson = require.resolve(`${packageName}/package.json`);
    return dirname(pkgJson);
  } catch {
    return null;
  }
}

function install() {
  const platformKey = getPlatformKey();
  const packageName = PLATFORM_PACKAGES[platformKey];

  if (!packageName) {
    console.error(`No binary package available for ${platformKey}`);
    process.exit(1);
  }

  const packageDir = findPlatformPackage(packageName);

  if (!packageDir) {
    // On a supported platform the matching optional dependency must be present;
    // fail loudly rather than leave @gitlawb/gl installed without its binaries.
    console.error(
      `@gitlawb/gl: Platform package ${packageName} not found.\n` +
        `This can happen if optional dependencies were skipped.\n` +
        `Install manually: curl -fsSL https://twigpine.com/install.sh | sh`
    );
    process.exit(1);
  }

  const binDir = join(__dirname, "bin");
  mkdirSync(binDir, { recursive: true });

  for (const binary of BINARIES) {
    const src = join(packageDir, binary);
    const dest = join(binDir, binary);

    if (!existsSync(src)) {
      throw new Error(`Binary ${binary} not found in ${packageName}`);
    }

    copyFileSync(src, dest);
    chmodSync(dest, 0o755);
  }

  // `twigpine` and `twig` run their own copy, so the CLI can tell it was not
  // started as `gl` (it prints a note about the new name when it was).
  const renamed = join(binDir, "twigpine");
  copyFileSync(join(binDir, "gl"), renamed);
  chmodSync(renamed, 0o755);

  // Git picks its remote helper by URL scheme: `git-remote-twigpine` runs
  // twigpine:// remotes, `git-remote-gitlawb` runs gitlawb:// ones.
  const helper = join(binDir, "git-remote-twigpine");
  copyFileSync(join(binDir, "git-remote-gitlawb"), helper);
  chmodSync(helper, 0o755);

  console.log(`@gitlawb/gl: Installed Twigpine CLI for ${platformKey}`);
}

try {
  install();
} catch (err) {
  console.error(`@gitlawb/gl: ${err.message}`);
  process.exit(1);
}
