# npm distribution for the Twigpine CLI

Two packages are built from this directory. The full description, publishing
rules and one-time setup are in [`docs/NPM_PACKAGING.md`](../docs/NPM_PACKAGING.md).

```text
cli/                   @twigpine/cli   the package: launchers + manifest; the
                                       release job adds one payload per platform
packages/              @gitlawb/gl     the old package, published once more as a
                                       bridge to @twigpine/cli, then removed
```

## `@twigpine/cli`

One package, the layout Zero and esbuild use: a wrapper whose launchers run the
program from a per-platform payload, published as versions of the same
package (`X.Y.Z-<platform>-<arch>`) and pinned through `npm:` aliases. No
install script. macOS and Linux (arm64, x64) and Windows (x64, also used on
Windows on ARM).

`scripts/npm/build-platform-packages.mjs` builds the payloads and wrapper from
the release archives, `scripts/npm/publish-packages.sh` publishes them, and
`scripts/npm/test-npm-packages.sh` tests both and the launchers. The
`npm-publish-cli` job in `.github/workflows/release.yml` runs them on every
release. The `version` in `cli/package.json` is a placeholder; the release
version comes from the tag.

## `@gitlawb/gl` (being retired)

A wrapper whose `postinstall` (`packages/gl/install.js`) copied the programs
out of four `@gitlawb/gl-<platform>` packages. npm links commands before
`postinstall` runs, so `packages/gl/bin/` holds placeholders for npm to link,
which `install.js` overwrites. The `npm-publish` job publishes it for one more
release, after which it is deprecated and this directory and that job go.
