# npm packaging

How `@twigpine/cli` is put together on npm and the rules the release pipeline
follows. Read this before touching `npm/cli/`, `scripts/npm/`, or the npm jobs
in `.github/workflows/release.yml`. The design is the one Zero uses
(`Twigpine/zero`, `docs/NPM_PACKAGING.md`), without Zero's vendored helpers
and without a fallback downloader.

## Goals

`npm install -g @twigpine/cli` must be silent and self-contained:

- **No install scripts anywhere in the tree.** npm's `allow-scripts` gating,
  Bun's blocked-by-default scripts and pnpm's strict mode all install it
  without prompts. The old package, `@gitlawb/gl`, copied its programs into
  place from a `postinstall` script, and npm links commands before that runs,
  so for a while it installed with no commands on PATH at all.
- **Nothing fetched outside the npm registry at install time.**
- **Every command name works:** `twigpine`, `twig`, `gl`, and the git helper
  under both names git looks for, `git-remote-twigpine` and `git-remote-gitlawb`.

## Architecture

```
@twigpine/cli                     <- wrapper: launchers + optionalDependencies
├─ @twigpine/cli-darwin-arm64 -> npm:@twigpine/cli@{version}-darwin-arm64
├─ @twigpine/cli-darwin-x64   -> npm:@twigpine/cli@{version}-darwin-x64
├─ @twigpine/cli-linux-arm64  -> npm:@twigpine/cli@{version}-linux-arm64
├─ @twigpine/cli-linux-x64    -> npm:@twigpine/cli@{version}-linux-x64
└─ @twigpine/cli-win32-x64    -> npm:@twigpine/cli@{version}-win32-x64
```

- The platform payloads are **versions of the same package**, published at
  suffixed versions (`0.9.0-linux-x64`) and referenced through `npm:` aliases.
  One package name means one trusted-publisher setting. Each payload sets `os`
  and `cpu`, so npm installs exactly one.
- A payload holds `twigpine` and `git-remote-twigpine` (`.exe` on Windows),
  copied from that platform's release archive after its checksum is checked,
  plus the licence files. It has no `bin`, no scripts and no dependencies.
  The node daemon is not on npm.
- The wrapper holds the launchers in `npm/cli/bin/` and a manifest with no
  scripts and no dependencies, only the exact-version `optionalDependencies`.
  `scripts/npm/build-platform-packages.mjs` writes both from the release
  archives.
- A launcher finds its payload from `process.platform`/`process.arch` and runs
  the program with stdio, the exit status and a terminating signal passed
  straight through, so git can drive the helper through it. `gl` starts the
  program under the name `gl`, which prints a note about the new name on a
  terminal. Windows on ARM runs the x64 payload.
- There is no downloader. If the payload is missing (`--omit=optional`, an
  unsupported platform), the launcher says how to reinstall or install
  without npm.

## Publishing rules

`scripts/npm/publish-packages.sh` implements these and
`scripts/npm/test-npm-packages.sh` checks them against a fake registry.

1. **Platform versions never become `latest`.** They are semver prereleases
   of the release version, so each goes out under the `platform` dist-tag,
   and the script checks `latest` was not moved before it publishes the wrapper.
2. **Payloads are on the registry before the wrapper.** npm applies a publish
   asynchronously, so the script waits until npm shows every payload before
   publishing the wrapper (up to 30 minutes in all).
3. **Exact pinning.** The wrapper at `X.Y.Z` references `X.Y.Z-<platform>-<arch>`
   exactly; the script refuses to start when the wrapper's aliases do not
   match the payloads beside it.
4. **`latest` never moves backward.** A backfill of an older release publishes
   the wrapper under `backfill` instead.
5. **Re-runs are safe.** A version already on the registry is skipped. Only
   npm's E404 counts as "not published"; any other lookup failure stops the job.
6. **Trusted publishing only.** The `npm-publish-cli` job runs in the
   `npm-publish` environment and authenticates with GitHub OIDC; no tokens.
   npm checks provenance against `repository` in the manifest, so it must
   name `Twigpine/node`.

## Before the first publish

Done once, by a maintainer:

1. Publish a placeholder `@twigpine/cli@0.0.0` by hand; npm only lets a
   trusted publisher be configured on a package that exists.
2. On npmjs.com, add a trusted publisher to `@twigpine/cli`: repository
   `Twigpine/node`, workflow `release.yml`, environment `npm-publish`.
3. In the GitHub repository settings, create the `npm-publish` environment,
   limited to the `main` branch, with a required reviewer.

Until then the `npm-publish-cli` job fails on its own; the rest of the release
is unaffected.

## The move from `@gitlawb/gl`

Both packages provide the same commands, so npm refuses to install one over
the other (`EEXIST`), and forcing it lets a later uninstall of the old package
delete the shared commands. Users uninstall the old package first:

```sh
npm uninstall -g @gitlawb/gl
npm install -g @twigpine/cli
```

To reach existing users:

- The first release that publishes `@twigpine/cli` also publishes
  `@gitlawb/gl` once more (the `npm-publish` job), so `npm update -g
  @gitlawb/gl` installs something and shows its deprecation message.
- A CLI installed from `@gitlawb/gl` prints the two commands above on a
  terminal.
- After that release, a maintainer deprecates every `@gitlawb/gl*` version
  with a pointer to `@twigpine/cli`, and the `npm-publish` job and
  `npm/packages/` are removed. The old versions stay on the registry: existing
  installs resolve their platform packages through them.
