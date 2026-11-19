# @twigpine/cli

The Twigpine command line: `twigpine` (short form `twig`) and the git remote
helper that lets plain `git clone`, `git fetch` and `git push` talk to
Twigpine nodes.

```sh
npm install -g @twigpine/cli
twigpine doctor
twigpine quickstart
```

npm installs one prebuilt program for your platform: macOS (arm64, x64),
Linux (arm64, x64) or Windows (x64, which also runs on Windows on ARM).
There is no install script. Without a global install:
`npx -p @twigpine/cli twigpine doctor`.

The git helper runs through Node, so git needs `node` on its PATH. A GUI git
client started with a minimal PATH may not find it; the installers below put
the native helper on PATH instead.

The package also provides `gl`, the command's name before the rename, and the
helper under both names git looks for: `git-remote-twigpine` and
`git-remote-gitlawb`.

## Moving from `@gitlawb/gl`

Both packages provide the same commands, so npm will not install one over
the other. Uninstall the old one first:

```sh
npm uninstall -g @gitlawb/gl
npm install -g @twigpine/cli
```

## Without npm

```sh
curl -fsSL https://twigpine.com/install.sh | sh        # macOS, Linux
irm https://twigpine.com/install.ps1 | iex             # Windows
brew install twigpine/tap/gl                           # Homebrew
```

Source, issues and documentation: https://github.com/Twigpine/node
