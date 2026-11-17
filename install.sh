#!/usr/bin/env bash
# Twigpine installer - downloads pre-built binaries from GitHub Releases.
#
# Usage:
#   curl -fsSL https://twigpine.com/install.sh | sh
#   curl -fsSL https://twigpine.com/install.sh | sh -s -- --version v0.3.9
set -euo pipefail

REPO="${GITLAWB_RELEASE_REPO:-Twigpine/node}"
INSTALL_DIR="${GITLAWB_INSTALL_DIR:-$HOME/.local/bin}"
VERSION_ARG="latest"

usage() {
  cat <<EOF
Twigpine installer

Options:
  --version <tag>   Install a specific release tag, for example v0.3.9.
  -h, --help        Show this help.

Environment:
  GITLAWB_INSTALL_DIR   Install directory (default: $HOME/.local/bin)
  GITLAWB_RELEASE_REPO  GitHub repo to download from (default: Twigpine/node)
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

if [ "$VERSION_ARG" = "latest" ]; then
  echo "Fetching latest release version..."
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  if [ -z "$TAG" ]; then
    echo "error: could not determine latest release. Check https://github.com/${REPO}/releases" >&2
    exit 1
  fi
else
  TAG="$VERSION_ARG"
fi

case "$TAG" in
  v*) VERSION="${TAG#v}" ;;
  *)  VERSION="$TAG"; TAG="v$TAG" ;;
esac

PACKAGE_NAME="twigpine-node-${VERSION}-${TARGET}"
ARCHIVE="${PACKAGE_NAME}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

echo "Installing Twigpine ${TAG} for ${OS_NAME}/${ARCH_NAME}"
echo "  Archive:  ${ARCHIVE}"
echo "  Into:     ${INSTALL_DIR}"
echo ""

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading..."
if ! curl -fSL --progress-bar -o "$TMP_DIR/$ARCHIVE" "$DOWNLOAD_URL"; then
  echo ""
  echo "error: download failed: $DOWNLOAD_URL" >&2
  echo "       Check https://github.com/${REPO}/releases for available builds." >&2
  echo "       Older releases use different file names; install those with" >&2
  echo "       the installer from their own tag:" >&2
  echo "       https://raw.githubusercontent.com/${REPO}/${TAG}/install.sh" >&2
  exit 1
fi

if curl -fsSL -o "$TMP_DIR/$ARCHIVE.sha256" "$CHECKSUM_URL" 2>/dev/null; then
  echo "Verifying checksum..."
  EXPECTED=$(awk '{print $1}' "$TMP_DIR/$ARCHIVE.sha256")
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$TMP_DIR/$ARCHIVE" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$TMP_DIR/$ARCHIVE" | awk '{print $1}')
  else
    echo "warning: no sha256 tool found, skipping checksum verification"
    ACTUAL="$EXPECTED"
  fi
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "error: checksum mismatch!" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  actual:   $ACTUAL" >&2
    exit 1
  fi
  echo "  checksum OK"
fi

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

mkdir -p "$INSTALL_DIR"

INSTALLED=()
for BIN in twigpine git-remote-twigpine twigpine-node; do
  if [ -f "$PACKAGE_DIR/$BIN" ]; then
    install -m 755 "$PACKAGE_DIR/$BIN" "$INSTALL_DIR/$BIN.new"
    mv -f "$INSTALL_DIR/$BIN.new" "$INSTALL_DIR/$BIN"
    INSTALLED+=("$BIN")
  fi
done

# Other names for the binaries installed above: the short form of the command,
# and the names used before the rename. Git picks its remote helper by URL
# scheme, so existing remotes still run the old helper name, and scripts or
# service units may still call the old command and daemon names.
link_old_name() {
  if [ -f "$INSTALL_DIR/$1" ]; then
    ln -sf "$1" "$INSTALL_DIR/$2"
    INSTALLED+=("$2")
  fi
}
link_old_name twigpine twig
link_old_name twigpine gl
link_old_name git-remote-twigpine git-remote-gitlawb
link_old_name twigpine-node gitlawb-node

if [ "${#INSTALLED[@]}" -eq 0 ]; then
  echo "error: no installable binaries found in $ARCHIVE" >&2
  exit 1
fi

echo ""
echo "Installed Twigpine ${TAG}"
for BIN in "${INSTALLED[@]}"; do
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
echo "Docs: https://docs.gitlawb.com"
