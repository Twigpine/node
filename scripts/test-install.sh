#!/bin/sh
# Tests install.sh and scripts/update-install-checksums.sh against a fake
# release server on 127.0.0.1 (python3 http.server). No network access.
#
# The server plays both sides:
#   /gh/<tag>/twigpine-node-<ver>-<target>.tar.gz(.sha256)  "GitHub releases"
#   /web/install-checksums.txt                              "twigpine.com"
# The key case is the hijack: whoever controls the GitHub side swaps an
# archive and its .sha256 together, and the install must still be refused.
#
# Usage: scripts/test-install.sh [shell...]   (default: every one of sh, dash
# and bash that exists; install.sh must work under plain POSIX sh). When pwsh
# is on PATH, install.ps1 runs through the same cases.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
INSTALLER="$ROOT/install.sh"
UPDATE="$ROOT/scripts/update-install-checksums.sh"
TARGETS="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl"

W=$(mktemp -d)
SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "${W:?}"
}
trap cleanup EXIT

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# make_release <ver> [marker] [style]: fake archives (+ .sha256) for every
# target. style "no-daemon" ships no daemon, "cli-only" no helper either; style "old" builds a release from before the rename to Twigpine:
# gitlawb-node-* archives holding gl, git-remote-gitlawb and gitlawb-node.
make_release() {
  ver=$1
  marker=${2:-genuine}
  style=${3:-new}
  if [ "$style" = old ]; then
    prefix=gitlawb-node
    bins="gl git-remote-gitlawb gitlawb-node"
  elif [ "$style" = no-daemon ]; then
    prefix=twigpine-node
    bins="twigpine git-remote-twigpine"
  elif [ "$style" = cli-only ]; then
    prefix=twigpine-node
    bins="twigpine"
  else
    prefix=twigpine-node
    bins="twigpine git-remote-twigpine twigpine-node"
  fi
  mkdir -p "$W/srv/gh/v$ver"
  for t in $TARGETS; do
    pkg="$prefix-$ver-$t"
    rm -rf "${W:?}/pkg" && mkdir -p "$W/pkg/$pkg"
    for b in $bins; do
      printf '#!/bin/sh\necho "%s %s %s"\n' "$b" "$ver" "$marker" > "$W/pkg/$pkg/$b"
      chmod 755 "$W/pkg/$pkg/$b"
    done
    COPYFILE_DISABLE=1 tar -czf "$W/srv/gh/v$ver/$pkg.tar.gz" -C "$W/pkg" "$pkg"
    (cd "$W/srv/gh/v$ver" && printf '%s  %s\n' "$(sha "$pkg.tar.gz")" "$pkg.tar.gz" > "$pkg.tar.gz.sha256")
  done
  # Windows: a real zip (install.ps1 extracts it), .sha256 in sha256sum's
  # binary-mode form, as the Windows release runner writes it.
  pkg="$prefix-$ver-x86_64-pc-windows-msvc"
  # shellcheck disable=SC2086 # bins is a word list by design
  python3 - "$W/srv/gh/v$ver/$pkg.zip" "$pkg" "$ver" "$marker" $bins <<'EOF'
import sys, zipfile
path, pkg, ver, marker = sys.argv[1:5]
with zipfile.ZipFile(path, "w") as z:
    for b in sys.argv[5:]:
        z.writestr(f"{pkg}/{b}.exe", f"{b} {ver} {marker}\n")
EOF
  (cd "$W/srv/gh/v$ver" && printf '%s *%s\n' "$(sha "$pkg.zip")" "$pkg.zip" > "$pkg.zip.sha256")
}

make_release 9.7.0 genuine old   # cut before the rename
make_release 9.8.0
make_release 9.9.0
make_release 9.9.1            # published on "GitHub" but never listed on the web
mkdir -p "$W/srv/web"
for v in 9.7.0 9.8.0 9.9.0; do
  sh "$UPDATE" "$W/srv/web/install-checksums.txt" "v$v" "$W/srv/gh/v$v"/*.sha256 >/dev/null
done
cp "$W/srv/web/install-checksums.txt" "$W/genuine-list"
mkdir -p "$W/genuine" && cp "$W/srv/gh/v9.9.0/"* "$W/genuine/"

# Fake server on a free port.
cat > "$W/serve.py" <<'EOF'
import http.server, os, sys
os.chdir(sys.argv[1])
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
with open(sys.argv[2] + ".tmp", "w") as f:
    f.write(str(srv.server_address[1]))
os.rename(sys.argv[2] + ".tmp", sys.argv[2])
srv.serve_forever()
EOF
python3 "$W/serve.py" "$W/srv" "$W/port" &
SERVER_PID=$!
i=0
while [ ! -s "$W/port" ]; do
  i=$((i + 1))
  [ "$i" -lt 100 ] || { echo "fake server did not start" >&2; exit 1; }
  sleep 0.1
done
BASE="http://127.0.0.1:$(cat "$W/port")"

# Every case starts from the genuine server state and default settings.
# (Settings are plain globals: "VAR=x func" is not portable across shells.)
reset_server() {
  cp "$W/genuine-list" "$W/srv/web/install-checksums.txt"
  cp "$W/genuine/"* "$W/srv/gh/v9.9.0/"
  LIST_URL=""
  RUN_PATH=""
}

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok    $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; sed 's/^/        | /' "$W/out" | tail -n 8; }

# run_installer <shell> [args...]: fresh HOME and install dir each run, unless
# KEEP_HOME=yes (an upgrade over the previous run's install).
run_installer() {
  shell=$1
  shift
  if [ "${KEEP_HOME:-}" != yes ]; then rm -rf "${W:?}/home" && mkdir -p "$W/home"; fi
  HOME="${W:?}/home" \
    GITLAWB_INSTALL_DIR="$W/home/bin" \
    GITLAWB_DOWNLOAD_BASE="$BASE/gh" \
    GITLAWB_CHECKSUMS_URL="${LIST_URL:-$BASE/web/install-checksums.txt}" \
    PATH="${RUN_PATH:-$PATH}" \
    "$shell" "$INSTALLER" "$@" > "$W/out" 2>&1
}
# runs <name> <output>: the installed <name> exists and prints <output>.
runs() { [ -x "$W/home/bin/$1" ] && [ "$("$W/home/bin/$1")" = "$2" ]; }
# installed <ver>: a renamed release is in place under every name, old and new.
installed() {
  runs twigpine "twigpine $1 genuine" && runs twig "twigpine $1 genuine" && runs gl "twigpine $1 genuine" \
    && runs git-remote-twigpine "git-remote-twigpine $1 genuine" \
    && runs git-remote-gitlawb "git-remote-twigpine $1 genuine" \
    && runs twigpine-node "twigpine-node $1 genuine" && runs gitlawb-node "twigpine-node $1 genuine"
}
# installed_old <ver>: a release from before the rename, also under every name.
installed_old() {
  runs gl "gl $1 genuine" && runs twigpine "gl $1 genuine" && runs twig "gl $1 genuine" \
    && runs git-remote-gitlawb "git-remote-gitlawb $1 genuine" \
    && runs git-remote-twigpine "git-remote-gitlawb $1 genuine" \
    && runs gitlawb-node "gitlawb-node $1 genuine" && runs twigpine-node "gitlawb-node $1 genuine"
}
# Nothing at all: no program, no stray file, no dangling link.
nothing_installed() { [ ! -d "$W/home/bin" ] || [ -z "$(ls -A "$W/home/bin")" ]; }

# A PATH with every tool install.sh needs except the SHA-256 ones.
mkdir -p "$W/nohash"
for tool in awk basename cat curl dirname find grep gzip head install mkdir \
  mktemp mv rm sed tar tr uname; do
  p=$(command -v "$tool" 2>/dev/null) && ln -sf "$p" "$W/nohash/$tool"
done

suite() {
  shell=$(command -v "$1")
  echo "install.sh under $1 ($shell)"

  reset_server
  if run_installer "$shell" && installed 9.9.0 && grep -q "checksum OK" "$W/out"; then
    ok "installs the latest listed version"
  else bad "installs the latest listed version"; fi

  reset_server
  if run_installer "$shell" --version v9.8.0 && installed 9.8.0; then
    ok "installs a pinned listed version"
  else bad "installs a pinned listed version"; fi

  reset_server
  if run_installer "$shell" --version 9.8.0 && installed 9.8.0; then
    ok "accepts a version without the v"
  else bad "accepts a version without the v"; fi

  reset_server
  if run_installer "$shell" --version v9.7.0 && installed_old 9.7.0; then
    ok "installs a release from before the rename under both sets of names"
  else bad "installs a release from before the rename under both sets of names"; fi

  # Upgrade in place: the old names were real files and must end up running
  # the new build, with nothing left behind from the old one. Then back again.
  KEEP_HOME=yes
  if run_installer "$shell" && installed 9.9.0; then
    ok "upgrades an install from before the rename"
  else bad "upgrades an install from before the rename"; fi
  if run_installer "$shell" --version v9.7.0 && installed_old 9.7.0; then
    ok "goes back to a release from before the rename"
  else bad "goes back to a release from before the rename"; fi
  KEEP_HOME=""

  # A directory sitting on a name the installer writes: refuse, change nothing.
  for blocked in twigpine twig git-remote-gitlawb twigpine.new; do
    reset_server
    rm -rf "${W:?}/home" && mkdir -p "$W/home/bin/$blocked"
    KEEP_HOME=yes
    if run_installer "$shell"; then
      bad "refuses to install over a directory named $blocked"
    elif grep -q "is a directory" "$W/out" && [ -z "$(ls -A "$W/home/bin/$blocked")" ] \
      && [ "$(ls -A "$W/home/bin")" = "$blocked" ]; then
      ok "refuses to install over a directory named $blocked"
    else bad "refuses to install over a directory named $blocked"; fi
    KEEP_HOME=""
  done
  # A link to a directory is replaced, not installed into.
  reset_server
  rm -rf "${W:?}/home" && mkdir -p "$W/home/bin" "$W/home/elsewhere"
  ln -s ../elsewhere "$W/home/bin/twigpine"
  KEEP_HOME=yes
  if run_installer "$shell" && installed 9.9.0 && [ -z "$(ls -A "$W/home/elsewhere")" ]; then
    ok "replaces a link to a directory instead of installing into it"
  else bad "replaces a link to a directory instead of installing into it"; fi
  KEEP_HOME=""

  # An archive without the daemon removes the one an earlier install left.
  reset_server
  make_release 9.6.1 genuine no-daemon
  sh "$UPDATE" "$W/srv/web/install-checksums.txt" v9.6.1 "$W/srv/gh/v9.6.1"/*.sha256 > /dev/null
  if run_installer "$shell" --version v9.7.0 && installed_old 9.7.0; then
    KEEP_HOME=yes
    if run_installer "$shell" --version v9.6.1 && runs twigpine "twigpine 9.6.1 genuine" \
      && runs git-remote-gitlawb "git-remote-twigpine 9.6.1 genuine" \
      && [ ! -e "$W/home/bin/twigpine-node" ] && [ ! -L "$W/home/bin/twigpine-node" ] \
      && [ ! -e "$W/home/bin/gitlawb-node" ] && [ ! -L "$W/home/bin/gitlawb-node" ]; then
      ok "removes a daemon the new archive no longer ships"
    else bad "removes a daemon the new archive no longer ships"; fi
    KEEP_HOME=""
  else bad "removes a daemon the new archive no longer ships"; fi

  # An archive without the helper would leave a mixed-version install.
  reset_server
  make_release 9.6.0 genuine cli-only
  sh "$UPDATE" "$W/srv/web/install-checksums.txt" v9.6.0 "$W/srv/gh/v9.6.0"/*.sha256 > /dev/null
  if ! run_installer "$shell" --version v9.6.0 && nothing_installed \
    && grep -q "missing a required program" "$W/out"; then
    ok "refuses an archive without the helper"
  else bad "refuses an archive without the helper"; fi

  # Hijack: the GitHub side swaps every archive AND its .sha256.
  reset_server
  make_release 9.9.0 hijacked
  if ! run_installer "$shell" && nothing_installed && grep -q "checksum mismatch" "$W/out"; then
    ok "refuses a swapped archive even with a matching .sha256"
  else bad "refuses a swapped archive even with a matching .sha256"; fi

  reset_server
  if ! run_installer "$shell" --version v9.9.1 && nothing_installed \
    && grep -q "is not in the checksum list" "$W/out" && grep -q "v9.9.0, v9.8.0, v9.7.0" "$W/out"; then
    ok "refuses a GitHub-only release the list does not vouch for"
  else bad "refuses a GitHub-only release the list does not vouch for"; fi

  reset_server
  LIST_URL="$BASE/web/missing.txt"
  if run_installer "$shell"; then
    bad "fails closed when the checksum list is unreachable"
  elif nothing_installed && grep -q "could not download the checksum list" "$W/out"; then
    ok "fails closed when the checksum list is unreachable"
  else bad "fails closed when the checksum list is unreachable"; fi

  reset_server
  grep -v '^# latest:' "$W/genuine-list" > "$W/srv/web/install-checksums.txt"
  if ! run_installer "$shell" && nothing_installed && grep -q "does not name a latest version" "$W/out"; then
    ok "fails closed when the list names no latest version"
  else bad "fails closed when the list names no latest version"; fi

  reset_server
  grep -v "twigpine-node-9.9.0-" "$W/genuine-list" > "$W/srv/web/install-checksums.txt"
  if ! run_installer "$shell" && nothing_installed && grep -q "is not in the checksum list" "$W/out"; then
    ok "fails closed when the latest version has no entry for this platform"
  else bad "fails closed when the latest version has no entry for this platform"; fi

  reset_server
  rm "$W/srv/gh/v9.9.0/"*.tar.gz
  if ! run_installer "$shell" && nothing_installed && grep -q "download failed" "$W/out"; then
    ok "fails when the listed archive cannot be downloaded"
  else bad "fails when the listed archive cannot be downloaded"; fi

  reset_server
  RUN_PATH="$W/nohash"
  if run_installer "$shell"; then
    bad "fails closed without a SHA-256 tool"
  elif nothing_installed && grep -q "no SHA-256 tool" "$W/out"; then
    ok "fails closed without a SHA-256 tool"
  else bad "fails closed without a SHA-256 tool"; fi

  reset_server
  if ! run_installer "$shell" --version 'v9.9.0;touch pwned' && nothing_installed \
    && grep -q "not a release version" "$W/out"; then
    ok "rejects a malformed version"
  else bad "rejects a malformed version"; fi

  # Format tolerance: CRLF line endings, upper-case hex, sha256sum's "*" marker.
  reset_server
  awk '/^#/ { printf "%s\r\n", $0; next } { printf "%s *%s\r\n", toupper($1), $2 }' \
    "$W/genuine-list" > "$W/srv/web/install-checksums.txt"
  if run_installer "$shell" && installed 9.9.0; then
    ok "reads CRLF, upper-case and binary-marker entries"
  else bad "reads CRLF, upper-case and binary-marker entries"; fi

  reset_server
  LIST_URL="file://$W/genuine-list"
  if run_installer "$shell" && installed 9.9.0; then
    ok "accepts a local checksum list (file://)"
  else bad "accepts a local checksum list (file://)"; fi
}

# Shells named on the command line must exist; the default set is whatever
# of sh, dash and bash this machine has.
SHELLS=${*:-"sh dash bash"}
for s in $SHELLS; do
  if command -v "$s" >/dev/null 2>&1; then suite "$s"
  elif [ "$#" -gt 0 ]; then
    FAIL=$((FAIL + 1))
    echo "  FAIL  shell not found: $s"
  fi
done

# install.ps1: same server, same cases. PROCESSOR_ARCHITECTURE stands in for
# Windows; on macOS/Linux the script's user-PATH update is a no-op.
run_ps1() {
  if [ "${KEEP_HOME:-}" != yes ]; then rm -rf "${W:?}/home" && mkdir -p "$W/home"; fi
  PROCESSOR_ARCHITECTURE=AMD64 \
    GITLAWB_INSTALL_DIR="$W/home/bin" \
    GITLAWB_DOWNLOAD_BASE="$BASE/gh" \
    GITLAWB_CHECKSUMS_URL="${LIST_URL:-$BASE/web/install-checksums.txt}" \
    pwsh -NoProfile -NonInteractive -File "$ROOT/install.ps1" "$@" > "$W/out" 2>&1
}
# has <name> <content>: the installed <name>.exe is the build that says <content>.
has() { grep -qx "$2" "$W/home/bin/$1.exe" 2>/dev/null; }
ps1_installed() {
  has twigpine "twigpine $1 genuine" && has twig "twigpine $1 genuine" && has gl "twigpine $1 genuine" \
    && has git-remote-twigpine "git-remote-twigpine $1 genuine" \
    && has git-remote-gitlawb "git-remote-twigpine $1 genuine" \
    && has twigpine-node "twigpine-node $1 genuine" && has gitlawb-node "twigpine-node $1 genuine"
}
ps1_installed_old() {
  has gl "gl $1 genuine" && has twigpine "gl $1 genuine" && has twig "gl $1 genuine" \
    && has git-remote-gitlawb "git-remote-gitlawb $1 genuine" \
    && has git-remote-twigpine "git-remote-gitlawb $1 genuine" \
    && has gitlawb-node "gitlawb-node $1 genuine" && has twigpine-node "gitlawb-node $1 genuine"
}
ps1_nothing() { nothing_installed; }

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) PS1_OK=no ;; # would edit the real user PATH
  *) PS1_OK=yes ;;
esac
if [ "$PS1_OK" = yes ] && command -v pwsh >/dev/null 2>&1; then
  echo "install.ps1 under pwsh"

  reset_server
  if run_ps1 && ps1_installed 9.9.0 && grep -q "checksum OK" "$W/out"; then
    ok "installs the latest listed version"
  else bad "installs the latest listed version"; fi

  reset_server
  if run_ps1 -Version v9.8.0 && ps1_installed 9.8.0; then
    ok "installs a pinned listed version"
  else bad "installs a pinned listed version"; fi

  reset_server
  if run_ps1 -Version v9.7.0 && ps1_installed_old 9.7.0; then
    ok "installs a release from before the rename under both sets of names"
  else bad "installs a release from before the rename under both sets of names"; fi
  KEEP_HOME=yes
  if run_ps1 && ps1_installed 9.9.0; then
    ok "upgrades an install from before the rename"
  else bad "upgrades an install from before the rename"; fi
  KEEP_HOME=""

  # A directory sitting on a name the installer writes: refuse, copy nothing.
  for blocked in twigpine.exe twig.exe git-remote-gitlawb.exe; do
    reset_server
    rm -rf "${W:?}/home" && mkdir -p "$W/home/bin/$blocked"
    KEEP_HOME=yes
    if run_ps1; then
      bad "refuses to install over a directory named $blocked"
    elif grep -q "is a directory" "$W/out" && [ -z "$(ls -A "$W/home/bin/$blocked")" ] \
      && [ "$(ls -A "$W/home/bin")" = "$blocked" ]; then
      ok "refuses to install over a directory named $blocked"
    else bad "refuses to install over a directory named $blocked"; fi
    KEEP_HOME=""
  done

  reset_server
  make_release 9.9.0 hijacked
  if ! run_ps1 && ps1_nothing && grep -q "checksum mismatch" "$W/out"; then
    ok "refuses a swapped archive even with a matching .sha256"
  else bad "refuses a swapped archive even with a matching .sha256"; fi

  reset_server
  if ! run_ps1 -Version v9.9.1 && ps1_nothing && grep -q "is not in the checksum list" "$W/out"; then
    ok "refuses a GitHub-only release the list does not vouch for"
  else bad "refuses a GitHub-only release the list does not vouch for"; fi

  reset_server
  LIST_URL="$BASE/web/missing.txt"
  if run_ps1; then
    bad "fails closed when the checksum list is unreachable"
  elif ps1_nothing; then
    ok "fails closed when the checksum list is unreachable"
  else bad "fails closed when the checksum list is unreachable"; fi

  reset_server
  grep -v '^# latest:' "$W/genuine-list" > "$W/srv/web/install-checksums.txt"
  if ! run_ps1 && ps1_nothing && grep -q "does not name a latest version" "$W/out"; then
    ok "fails closed when the list names no latest version"
  else bad "fails closed when the list names no latest version"; fi

  reset_server
  if ! run_ps1 -Version 'v9.9.0;x' && ps1_nothing && grep -q "not a release version" "$W/out"; then
    ok "rejects a malformed version"
  else bad "rejects a malformed version"; fi

  reset_server
  awk '/^#/ { printf "%s\r\n", $0; next } { printf "%s *%s\r\n", toupper($1), $2 }' \
    "$W/genuine-list" > "$W/srv/web/install-checksums.txt"
  if run_ps1 && ps1_installed 9.9.0; then
    ok "reads CRLF, upper-case and binary-marker entries"
  else bad "reads CRLF, upper-case and binary-marker entries"; fi
fi

echo "update-install-checksums.sh"
L="$W/list"
expect_reject() {
  name=$1
  shift
  if sh "$UPDATE" "$@" > "$W/out" 2>&1; then bad "$name"; else ok "$name"; fi
}
rm -f "$L"
expect_reject "rejects a latest release missing a platform" \
  "$L" v9.9.0 "$W/srv/gh/v9.9.0/twigpine-node-9.9.0-aarch64-apple-darwin.tar.gz.sha256"
[ ! -e "$L" ] && ok "leaves no file behind on error" || bad "leaves no file behind on error"
expect_reject "rejects a pre-release tag" "$L" v9.9.0-rc.1 "$W/srv/gh/v9.9.0/"*.sha256
expect_reject "rejects a tag with an extra part" "$L" v9.9.0.1 "$W/srv/gh/v9.9.0/"*.sha256
expect_reject "rejects a tag with an empty part" "$L" v9..0 "$W/srv/gh/v9.9.0/"*.sha256
expect_reject "rejects checksums of another version" "$L" v9.8.0 "$W/srv/gh/v9.9.0/"*.sha256
printf 'deadbeef  twigpine-node-9.9.0-x86_64-apple-darwin.tar.gz\n' > "$W/short.sha256"
expect_reject "rejects a malformed checksum line" "$L" v9.9.0 "$W/short.sha256"
sh "$UPDATE" "$L" v9.9.0 "$W/srv/gh/v9.9.0/"*.sha256 > /dev/null
sh "$UPDATE" "$L" v9.8.0 "$W/srv/gh/v9.8.0/"*.sha256 > /dev/null
if grep -qx '# latest: v9.9.0' "$L"; then ok "a backfill does not move latest back"; else bad "a backfill does not move latest back"; fi
cp "$L" "$W/before"
sh "$UPDATE" "$L" v9.9.0 "$W/srv/gh/v9.9.0/"*.sha256 > /dev/null
if cmp -s "$W/before" "$L"; then ok "is idempotent"; else bad "is idempotent"; fi
printf '%s  %s\n' "$(printf '0%.0s' $(seq 1 64))" "twigpine-node-9.9.0-x86_64-apple-darwin.tar.gz" > "$W/dup.sha256"
expect_reject "rejects two checksums for one file" "$L" v9.9.0 "$W/srv/gh/v9.9.0/"*.sha256 "$W/dup.sha256"
if cmp -s "$W/before" "$L"; then ok "keeps the list unchanged on error"; else bad "keeps the list unchanged on error"; fi
printf '%s  %s\n' "$(printf '0%.0s' $(seq 1 64))" "other-node-9.9.0-x86_64-apple-darwin.tar.gz" > "$W/other.sha256"
expect_reject "rejects an archive that is not a node release" "$L" v9.9.0 "$W/other.sha256"
# A list that still ends at a release from before the rename (as the live one
# does) takes a renamed release and moves latest to it.
printf '%s  %s\n' "$(printf '0%.0s' $(seq 1 64))" "twigpine-node-9.9.0-evil.tar.gz" > "$W/evil.sha256"
expect_reject "rejects an archive for a platform no installer serves" "$L" v9.9.0 "$W/srv/gh/v9.9.0/"*.sha256 "$W/evil.sha256"
sed 's/twigpine-node-/gitlawb-node-/' "$W/srv/gh/v9.9.0/twigpine-node-9.9.0-x86_64-apple-darwin.tar.gz.sha256" > "$W/mixed.sha256"
expect_reject "rejects one version under both archive names" "$L" v9.9.0 "$W/srv/gh/v9.9.0/"*.sha256 "$W/mixed.sha256"
grep -v '^# latest:' "$L" > "$W/nolatest"
expect_reject "rejects a list with no latest line" "$W/nolatest" v9.8.0 "$W/srv/gh/v9.8.0/"*.sha256
rm -f "$L"
sh "$UPDATE" "$L" v9.7.0 "$W/srv/gh/v9.7.0/"*.sha256 > /dev/null
sh "$UPDATE" "$L" v9.9.0 "$W/srv/gh/v9.9.0/"*.sha256 > /dev/null
if grep -qx '# latest: v9.9.0' "$L" && grep -q '  gitlawb-node-9.7.0-x86_64-apple-darwin.tar.gz$' "$L" \
  && grep -q '  twigpine-node-9.9.0-x86_64-apple-darwin.tar.gz$' "$L"; then
  ok "lists a renamed release after one from before the rename"
else bad "lists a renamed release after one from before the rename"; fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
