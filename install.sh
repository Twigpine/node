#!/bin/sh
# Twigpine installer (macOS / Linux): twigpine, git-remote-twigpine and
# twigpine-node.
#
# Downloads a pre-built release archive from GitHub and installs it only if its
# SHA-256 is listed at https://twigpine.com/install-checksums.txt. That list is
# served by twigpine.com, not by GitHub, so a hijacked, renamed or look-alike
# GitHub repository cannot get a different binary installed on its own. The
# list also names the latest version, so no GitHub API call is needed.
#
# Usage:
#   curl -fsSL https://twigpine.com/install.sh | sh
#   curl -fsSL https://twigpine.com/install.sh | sh -s -- --version v0.7.1
#
# Plain POSIX sh on purpose: `curl ... | sh` runs dash on Debian and Ubuntu.
set -eu

# Settings are TWIGPINE_*; the GITLAWB_* names from before the rename still work.
REPO="${TWIGPINE_RELEASE_REPO:-${GITLAWB_RELEASE_REPO:-Twigpine/node}}"
DOWNLOAD_BASE="${TWIGPINE_DOWNLOAD_BASE:-${GITLAWB_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}}"
CHECKSUMS_URL="${TWIGPINE_CHECKSUMS_URL:-${GITLAWB_CHECKSUMS_URL:-https://twigpine.com/install-checksums.txt}}"
INSTALL_DIR="${TWIGPINE_INSTALL_DIR:-${GITLAWB_INSTALL_DIR:-$HOME/.local/bin}}"
VERSION_ARG="latest"

usage() {
  cat <<EOF
Twigpine installer

Options:
  --version <tag>   Install a specific release tag, for example v0.7.1.
  -h, --help        Show this help.

Environment:
  TWIGPINE_INSTALL_DIR    Install directory (default: $HOME/.local/bin)
  TWIGPINE_RELEASE_REPO   GitHub repo to download from (default: Twigpine/node)
  TWIGPINE_DOWNLOAD_BASE  Release download base URL, for mirrors
                         (default: https://github.com/<repo>/releases/download)
  TWIGPINE_CHECKSUMS_URL  Checksum list every download must match
                         (default: https://twigpine.com/install-checksums.txt)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      if [ "$#" -lt 2 ]; then
        echo "error: --version requires a value" >&2
        exit 1
      fi
      VERSION_ARG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      VERSION_ARG="$1"
      shift
      ;;
  esac
done

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Linux)  OS_NAME="linux" ;;
  Darwin) OS_NAME="darwin" ;;
  *)
    echo "error: unsupported OS: $OS" >&2
    echo "       please build from source: cargo install --git https://github.com/${REPO} twigpine-cli git-remote-twigpine" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)          ARCH_NAME="x86_64" ;;
  aarch64 | arm64) ARCH_NAME="aarch64" ;;
  *)
    echo "error: unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "${OS_NAME}-${ARCH_NAME}" in
  linux-x86_64)   TARGET="x86_64-unknown-linux-musl" ;;
  linux-aarch64)  TARGET="aarch64-unknown-linux-musl" ;;
  darwin-x86_64)  TARGET="x86_64-apple-darwin" ;;
  darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
esac

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# The checksum list comes first: it names the latest version and is the only
# thing that can vouch for an archive.
echo "Fetching checksums from ${CHECKSUMS_URL}"
SUMS="$TMP_DIR/install-checksums.txt"
if ! curl -fsSL -o "$SUMS.raw" "$CHECKSUMS_URL"; then
  echo "error: could not download the checksum list: $CHECKSUMS_URL" >&2
  echo "       Nothing was installed." >&2
  exit 1
fi
tr -d '\r' < "$SUMS.raw" > "$SUMS"

if [ "$VERSION_ARG" = "latest" ]; then
  TAG=$(sed -n 's/^# latest: *\(v[0-9][0-9A-Za-z.+-]*\) *$/\1/p' "$SUMS" | head -n 1)
  if [ -z "$TAG" ]; then
    echo "error: the checksum list does not name a latest version: $CHECKSUMS_URL" >&2
    exit 1
  fi
else
  TAG="$VERSION_ARG"
fi

case "$TAG" in
  v*) VERSION="${TAG#v}" ;;
  *)  VERSION="$TAG"; TAG="v$TAG" ;;
esac
case "$VERSION" in
  "" | *[!0-9A-Za-z.+-]*)
    echo "error: not a release version: $TAG" >&2
    exit 1
    ;;
esac

# "<sha256>  <file>" (or "<sha256> *<file>"), as sha256sum writes it.
listed_sha() {
  awk -v f="$1" '
    ($2 == f || $2 == "*" f) && length($1) == 64 && $1 ~ /^[0-9A-Fa-f]+$/ { print tolower($1); exit }
  ' "$SUMS"
}

# Releases before the rename to Twigpine named their archives gitlawb-node-*.
# Take whichever name the list vouches for, new name first.
PACKAGE_NAME=""
EXPECTED=""
for PREFIX in twigpine-node gitlawb-node; do
  EXPECTED=$(listed_sha "${PREFIX}-${VERSION}-${TARGET}.tar.gz")
  if [ -n "$EXPECTED" ]; then
    PACKAGE_NAME="${PREFIX}-${VERSION}-${TARGET}"
    break
  fi
done
if [ -z "$EXPECTED" ]; then
  echo "error: twigpine-node-${VERSION}-${TARGET}.tar.gz is not in the checksum list at ${CHECKSUMS_URL}" >&2
  echo "       Refusing to install a build the list does not vouch for." >&2
  LISTED=$(awk -v suf="-${TARGET}.tar.gz" '
    { n = $2; sub(/^\*/, "", n) }
    {
      pre = ""
      if (index(n, "twigpine-node-") == 1) pre = "twigpine-node-"
      else if (index(n, "gitlawb-node-") == 1) pre = "gitlawb-node-"
    }
    pre != "" && length(n) > length(pre) + length(suf) &&
      substr(n, length(n) - length(suf) + 1) == suf {
      printf "%s v%s", sep, substr(n, length(pre) + 1, length(n) - length(pre) - length(suf)); sep = ","
    }' "$SUMS")
  if [ -n "$LISTED" ]; then
    echo "       Listed for ${TARGET}:${LISTED}" >&2
  fi
  exit 1
fi
ARCHIVE="${PACKAGE_NAME}.tar.gz"
DOWNLOAD_URL="${DOWNLOAD_BASE}/${TAG}/${ARCHIVE}"

echo "Installing Twigpine ${TAG} for ${OS_NAME}/${ARCH_NAME}"
echo "  Archive:  ${ARCHIVE}"
echo "  Into:     ${INSTALL_DIR}"
echo ""

echo "Downloading..."
if ! curl -fSL --progress-bar -o "$TMP_DIR/$ARCHIVE" "$DOWNLOAD_URL"; then
  echo ""
  echo "error: download failed: $DOWNLOAD_URL" >&2
  echo "       Check https://github.com/${REPO}/releases for available builds." >&2
  exit 1
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    return 1
  fi
}

echo "Verifying checksum..."
if ! ACTUAL=$(sha256_of "$TMP_DIR/$ARCHIVE"); then
  echo "error: no SHA-256 tool found (need sha256sum, shasum or openssl). Nothing was installed." >&2
  exit 1
fi
ACTUAL=$(printf '%s' "$ACTUAL" | tr 'A-F' 'a-f')
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "error: checksum mismatch for ${ARCHIVE}" >&2
  echo "  expected: $EXPECTED (${CHECKSUMS_URL})" >&2
  echo "  actual:   $ACTUAL (${DOWNLOAD_URL})" >&2
  echo "The download is corrupted or is not the published build. Nothing was installed." >&2
  exit 1
fi
echo "  checksum OK"

echo "Extracting..."
tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"
PACKAGE_DIR="$TMP_DIR/$PACKAGE_NAME"
if [ ! -d "$PACKAGE_DIR" ]; then
  PACKAGE_DIR=$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)
fi
if [ ! -d "$PACKAGE_DIR" ]; then
  echo "error: could not find extracted package directory" >&2
  exit 1
fi

# The CLI and the helper always ship together. An archive with only one of
# them would leave a mixed-version install behind.
for PAIR in "twigpine gl" "git-remote-twigpine git-remote-gitlawb"; do
  FOUND=""
  for NAME in $PAIR; do
    if [ -f "$PACKAGE_DIR/$NAME" ]; then FOUND="$NAME"; fi
  done
  if [ -z "$FOUND" ]; then
    echo "error: $ARCHIVE is missing a required program: ${PAIR%% *}. Nothing was installed." >&2
    exit 1
  fi
done

mkdir -p "$INSTALL_DIR"

# Check every name this run will write before changing anything. A directory in
# the way cannot be replaced by a file: mv and ln would put the program inside
# it and report success.
# The same goes for the <name>.new staging files.
for NAME in twigpine twig gl git-remote-twigpine git-remote-gitlawb twigpine-node gitlawb-node \
  twigpine.new gl.new git-remote-twigpine.new git-remote-gitlawb.new twigpine-node.new gitlawb-node.new; do
  if [ -d "$INSTALL_DIR/$NAME" ] && [ ! -L "$INSTALL_DIR/$NAME" ]; then
    echo "error: ${INSTALL_DIR}/${NAME} is a directory, and the installer needs that name for a program." >&2
    echo "       Move it away or set TWIGPINE_INSTALL_DIR. Nothing was installed." >&2
    exit 1
  fi
done

INSTALLED=""

# install_file <name>: copy one binary from the archive into place.
install_file() {
  # A leftover staging link would be followed; start from nothing.
  rm -f "$INSTALL_DIR/$1.new"
  install -m 755 "$PACKAGE_DIR/$1" "$INSTALL_DIR/$1.new"
  # A link left by an earlier install (or one pointing at a directory) is
  # removed first: mv would follow a link to a directory and move into it.
  if [ -L "$INSTALL_DIR/$1" ]; then rm -f "$INSTALL_DIR/$1"; fi
  mv -f "$INSTALL_DIR/$1.new" "$INSTALL_DIR/$1"
  INSTALLED="$INSTALLED $1"
}

# link_name <target> <name>: make <name> run <target>. -n replaces a link to a
# directory instead of linking inside it.
link_name() {
  ln -sfn "$1" "$INSTALL_DIR/$2"
  INSTALLED="$INSTALLED $2"
}

# install_pair <name> <old-name>: every program has the name it carries now and
# the one it had before the rename. The archive ships one of them; the other
# becomes a link to it, so both names always run the same build. The old names
# matter: git picks its remote helper by URL scheme, so gitlawb:// remotes run
# git-remote-gitlawb, and scripts or service units may still call gl and
# gitlawb-node. When the archive ships neither, both names are removed.
install_pair() {
  if [ -f "$PACKAGE_DIR/$1" ]; then
    install_file "$1"
    link_name "$1" "$2"
  elif [ -f "$PACKAGE_DIR/$2" ]; then
    install_file "$2"
    link_name "$2" "$1"
  else
    # Not shipped (the daemon is optional): drop a leftover from an earlier
    # install, so an upgrade never leaves a stale, mixed-version program.
    rm -f "$INSTALL_DIR/$1" "$INSTALL_DIR/$2"
  fi
}

install_pair twigpine gl
install_pair git-remote-twigpine git-remote-gitlawb
install_pair twigpine-node gitlawb-node
# twig is the short form of the command.
if [ -f "$PACKAGE_DIR/twigpine" ] || [ -f "$PACKAGE_DIR/gl" ]; then
  link_name twigpine twig
fi

if [ -z "$INSTALLED" ]; then
  echo "error: no installable binaries found in $ARCHIVE" >&2
  exit 1
fi

echo ""
echo "Installed Twigpine ${TAG}"
for BIN in $INSTALLED; do
  echo "  ${BIN} -> ${INSTALL_DIR}/${BIN}"
done
echo ""

if echo ":$PATH:" | grep -q ":${INSTALL_DIR}:"; then
  echo "Run:"
  echo "  twigpine doctor"
  echo "  twigpine quickstart"
else
  SHELL_NAME=$(basename "${SHELL:-bash}")
  case "$SHELL_NAME" in
    zsh)  RC="$HOME/.zshrc" ;;
    fish) RC="$HOME/.config/fish/config.fish" ;;
    *)    RC="$HOME/.bashrc" ;;
  esac

  echo "Add ${INSTALL_DIR} to your PATH:"
  echo ""
  if [ "$SHELL_NAME" = "fish" ]; then
    echo "  fish_add_path ${INSTALL_DIR}"
  else
    echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ${RC}"
    echo "  source ${RC}"
  fi
  echo ""
  echo "Then run:"
  echo "  twigpine doctor"
  echo "  twigpine quickstart"
fi

echo ""
echo "Docs: https://explorer.twigpine.com/docs"
