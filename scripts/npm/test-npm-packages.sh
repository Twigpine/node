#!/usr/bin/env bash
# Tests the @twigpine/cli npm packaging with no network and no registry:
#
#   - build-platform-packages.mjs against fake release archives: manifests,
#     aliases, programs, checksum refusal;
#   - the command launchers against an installed layout: arguments, exit
#     status, stdin/stdout, signals, a missing payload, and (when a built CLI
#     is passed as $1) the real program;
#   - publish-packages.sh against a fake `npm` that keeps a registry in a
#     directory: order, dist-tags, re-runs, backfills, refusals.
#
# Usage: scripts/npm/test-npm-packages.sh [path/to/built/twigpine]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="$ROOT/scripts/npm/build-platform-packages.mjs"
PUBLISH="$ROOT/scripts/npm/publish-packages.sh"
REAL_CLI="${1:-}"
VERSION=9.9.0
TARGETS="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl"

W="$(mktemp -d)"
trap 'rm -rf "${W:?}"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok    $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; if [ -f "$W/out" ]; then sed 's/^/        | /' "$W/out" | tail -n 12; fi; }
check() { if "${@:2}"; then ok "$1"; else bad "$1"; fi; }

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
field() { node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); const v=process.argv[2].split(".").reduce((o,k)=>o==null?o:o[k],p); process.stdout.write(v===undefined?"":typeof v==="object"?JSON.stringify(v):String(v));' "$1" "$2"; }

# ── fake release archives ──────────────────────────────────────────────────
# A fake program prints its name and arguments, echoes stdin, and exits with
# FAKE_EXIT; FAKE_SIGNAL makes it kill itself with that signal.
fake_program() {
  cat > "$1" <<EOF
#!/bin/sh
if [ -n "\${FAKE_PIDFILE:-}" ]; then echo \$\$ > "\$FAKE_PIDFILE"; sleep 30; exit 0; fi
if [ -n "\${FAKE_SIGNAL:-}" ]; then kill -"\$FAKE_SIGNAL" \$\$; fi
echo "$2 \$*"
if [ -n "\${FAKE_STDIN:-}" ]; then cat; fi
exit "\${FAKE_EXIT:-0}"
EOF
  chmod 755 "$1"
}

ART="$W/artifacts"
mkdir -p "$ART"
for t in $TARGETS; do
  pkg="twigpine-node-$VERSION-$t"
  mkdir -p "$W/stage/$pkg"
  for p in twigpine git-remote-twigpine twigpine-node; do fake_program "$W/stage/$pkg/$p" "$p"; done
  COPYFILE_DISABLE=1 tar -czf "$ART/$pkg.tar.gz" -C "$W/stage" "$pkg"
  (cd "$ART" && printf '%s  %s\n' "$(sha "$pkg.tar.gz")" "$pkg.tar.gz" > "$pkg.tar.gz.sha256")
done
pkg="twigpine-node-$VERSION-x86_64-pc-windows-msvc"
python3 - "$ART/$pkg.zip" "$pkg" <<'PY'
import sys, zipfile
path, pkg = sys.argv[1:]
with zipfile.ZipFile(path, "w") as z:
    for b in ("twigpine", "git-remote-twigpine", "twigpine-node"):
        z.writestr(f"{pkg}/{b}.exe", f"{b} exe\n")
PY
(cd "$ART" && printf '%s *%s\n' "$(sha "$pkg.zip")" "$pkg.zip" > "$pkg.zip.sha256")

# ── build ──────────────────────────────────────────────────────────────────
echo "build-platform-packages.mjs"
OUT="$W/npm"
if node "$BUILD" --version "$VERSION" --artifacts-dir "$ART" --out-dir "$OUT" > "$W/out" 2>&1; then
  ok "builds the wrapper and five payloads"
else
  bad "builds the wrapper and five payloads"
fi
WP="$OUT/wrapper/package.json"
check "the wrapper is @twigpine/cli at the release version" \
  test "$(field "$WP" name)@$(field "$WP" version)" = "@twigpine/cli@$VERSION"
check "the wrapper has no scripts and no dependencies" \
  test "$(field "$WP" scripts)$(field "$WP" dependencies)" = ""
check "the wrapper pins all five payloads exactly" test "$(field "$WP" optionalDependencies)" = \
  '{"@twigpine/cli-darwin-arm64":"npm:@twigpine/cli@9.9.0-darwin-arm64","@twigpine/cli-darwin-x64":"npm:@twigpine/cli@9.9.0-darwin-x64","@twigpine/cli-linux-arm64":"npm:@twigpine/cli@9.9.0-linux-arm64","@twigpine/cli-linux-x64":"npm:@twigpine/cli@9.9.0-linux-x64","@twigpine/cli-win32-x64":"npm:@twigpine/cli@9.9.0-win32-x64"}'
check "the wrapper provides every command name" test "$(field "$WP" bin)" = \
  '{"twigpine":"bin/twigpine.js","twig":"bin/twigpine.js","gl":"bin/gl.js","git-remote-twigpine":"bin/git-remote-twigpine.js","git-remote-gitlawb":"bin/git-remote-twigpine.js"}'
check "the wrapper ships its launchers, executable" \
  test -x "$OUT/wrapper/bin/twigpine.js" -a -x "$OUT/wrapper/bin/gl.js" -a -x "$OUT/wrapper/bin/git-remote-twigpine.js" -a -f "$OUT/wrapper/bin/launch.js"
LP="$OUT/platforms/cli-linux-x64/package.json"
check "a payload is a platform version, limited to its platform" \
  test "$(field "$LP" name)@$(field "$LP" version) $(field "$LP" os) $(field "$LP" cpu)" = '@twigpine/cli@9.9.0-linux-x64 ["linux"] ["x64"]'
check "a payload has no bin, scripts or dependencies" \
  test "$(field "$LP" bin)$(field "$LP" scripts)$(field "$LP" dependencies)" = ""
check "a payload carries the CLI and the helper, executable" \
  test -x "$OUT/platforms/cli-linux-x64/twigpine" -a -x "$OUT/platforms/cli-linux-x64/git-remote-twigpine"
check "a payload leaves the daemon out" test ! -e "$OUT/platforms/cli-linux-x64/twigpine-node"
check "the Windows payload carries .exe programs" \
  test -f "$OUT/platforms/cli-win32-x64/twigpine.exe" -a -f "$OUT/platforms/cli-win32-x64/git-remote-twigpine.exe"
check "the Windows payload also installs on Windows on ARM" \
  test "$(field "$OUT/platforms/cli-win32-x64/package.json" cpu)" = '["x64","arm64"]'
check "payloads ask Yarn not to keep them zipped" test "$(field "$LP" preferUnplugged)" = true
check "the wrapper installs on every published platform" test "$(field "$WP" os) $(field "$WP" cpu)" = '["darwin","linux","win32"] ["x64","arm64"]'
packed="$(cd "$OUT/wrapper" && npm pack --dry-run --json 2>/dev/null | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d)[0].files.map(f=>f.path).sort().join(" ")))')"
check "the wrapper tarball carries the launchers and both licence files" test "$packed" = \
  "LICENSE-APACHE LICENSE-MIT README.md bin/git-remote-twigpine.js bin/gl.js bin/launch.js bin/twigpine.js package.json"

cp -R "$ART" "$W/art-bad"
printf 'tampered' >> "$W/art-bad/twigpine-node-$VERSION-x86_64-unknown-linux-musl.tar.gz"
if node "$BUILD" --version "$VERSION" --artifacts-dir "$W/art-bad" --out-dir "$W/npm-bad" > "$W/out" 2>&1; then
  bad "refuses an archive that does not match its checksum"
elif grep -q "checksum mismatch" "$W/out"; then ok "refuses an archive that does not match its checksum"
else bad "refuses an archive that does not match its checksum"; fi
cp -R "$ART" "$W/art-missing"
rm "$W/art-missing/twigpine-node-$VERSION-x86_64-apple-darwin.tar.gz"
if node "$BUILD" --version "$VERSION" --artifacts-dir "$W/art-missing" --out-dir "$W/npm-bad" > "$W/out" 2>&1; then
  bad "refuses a missing archive"
elif grep -q "missing release archive" "$W/out"; then ok "refuses a missing archive"
else bad "refuses a missing archive"; fi

# The release builds Windows best-effort.
cp -R "$ART" "$W/art-nowin"
rm "$W/art-nowin/twigpine-node-$VERSION-x86_64-pc-windows-msvc.zip"*
if node "$BUILD" --version "$VERSION" --artifacts-dir "$W/art-nowin" --out-dir "$W/npm-nowin" > "$W/out" 2>&1; then
  bad "without --allow-missing, a missing Windows archive is an error"
else ok "without --allow-missing, a missing Windows archive is an error"; fi
if node "$BUILD" --version "$VERSION" --artifacts-dir "$W/art-nowin" --out-dir "$W/npm-nowin" \
  --allow-missing win32-x64 > "$W/out" 2>&1 \
  && [ ! -d "$W/npm-nowin/platforms/cli-win32-x64" ] \
  && [ "$(field "$W/npm-nowin/wrapper/package.json" os)" = '["darwin","linux"]' ] \
  && ! grep -q win32 <<< "$(field "$W/npm-nowin/wrapper/package.json" optionalDependencies)"; then
  ok "a release without Windows is packaged without it, and the wrapper says so"
else bad "a release without Windows is packaged without it, and the wrapper says so"; fi

# One architecture of a system left out while another stays: npm checks os and
# cpu separately, so such a wrapper would install where it has no program.
cp -R "$ART" "$W/art-noarm"
rm "$W/art-noarm/twigpine-node-$VERSION-aarch64-apple-darwin.tar.gz"*
if node "$BUILD" --version "$VERSION" --artifacts-dir "$W/art-noarm" --out-dir "$W/npm-noarm" \
  --allow-missing darwin-arm64 > "$W/out" 2>&1; then
  bad "refuses to leave out one architecture of a system that keeps another"
elif grep -q "no darwin-arm64 payload" "$W/out" && [ ! -e "$W/npm-noarm/wrapper" ]; then
  ok "refuses to leave out one architecture of a system that keeps another"
else bad "refuses to leave out one architecture of a system that keeps another"; fi
if node "$BUILD" --version "$VERSION" --artifacts-dir "$ART" --out-dir "$W/npm-only" \
  --only linux-x64 > "$W/out" 2>&1 \
  && [ "$(field "$W/npm-only/wrapper/package.json" os) $(field "$W/npm-only/wrapper/package.json" cpu)" = '["linux"] ["x64"]' ]; then
  ok "a one-platform build limits the wrapper to that system and architecture"
else bad "a one-platform build limits the wrapper to that system and architecture"; fi

# Rebuilt into a directory that held a full build: the old Windows payload goes.
cp -R "$OUT" "$W/npm-rebuild"
if node "$BUILD" --version "$VERSION" --artifacts-dir "$W/art-nowin" --out-dir "$W/npm-rebuild" \
  --allow-missing win32-x64 > "$W/out" 2>&1 && [ ! -e "$W/npm-rebuild/platforms/cli-win32-x64" ] \
  && [ -d "$W/npm-rebuild/platforms/cli-linux-x64" ]; then
  ok "a rebuild without Windows removes the earlier Windows payload"
else bad "a rebuild without Windows removes the earlier Windows payload"; fi

# Called through a symlinked path (macOS temp and checkout paths often are).
ln -s "$ROOT" "$W/linked-root"
if node "$W/linked-root/scripts/npm/build-platform-packages.mjs" --version "$VERSION" \
  --artifacts-dir "$ART" --out-dir "$W/npm-linked" > "$W/out" 2>&1 \
  && [ -f "$W/npm-linked/wrapper/package.json" ]; then
  ok "builds when called through a symlinked path"
else bad "builds when called through a symlinked path"; fi
for v in 9.9 v9.9.0 9.9.0-rc.1 09.9.0; do
  if node "$BUILD" --version "$v" --artifacts-dir "$ART" --out-dir "$W/npm-bad" > "$W/out" 2>&1; then
    bad "refuses version $v"
  else ok "refuses version $v"; fi
done

# ── launchers ──────────────────────────────────────────────────────────────
echo "launchers"
HOST_PLATFORM="$(node -p 'process.platform')"
HOST_ARCH="$(node -p 'process.arch')"
INSTALL="$W/install/@twigpine/cli"
mkdir -p "$INSTALL"
cp -R "$OUT/wrapper/." "$INSTALL/"
PAYLOAD="$INSTALL/node_modules/@twigpine/cli-$HOST_PLATFORM-$HOST_ARCH"
mkdir -p "$PAYLOAD"
fake_program "$PAYLOAD/twigpine" twigpine
fake_program "$PAYLOAD/git-remote-twigpine" git-remote-twigpine
echo '{"name":"@twigpine/cli","version":"9.9.0-host"}' > "$PAYLOAD/package.json"

out="$(node "$INSTALL/bin/twigpine.js" repo list --json 2>&1)"
check "twigpine runs the CLI with its arguments" test "$out" = "twigpine repo list --json"
out="$(node "$INSTALL/bin/gl.js" doctor 2>&1)"
check "gl runs the same CLI" test "$out" = "twigpine doctor"
status=0
FAKE_EXIT=7 node "$INSTALL/bin/twigpine.js" x > /dev/null 2>&1 || status=$?
check "the program's exit status comes through" test "$status" = 7
out="$(printf 'capabilities\n\n' | FAKE_STDIN=1 node "$INSTALL/bin/git-remote-twigpine.js" origin twigpine://did:key:z/r 2>&1)"
check "the helper gets git's stdin and answers on stdout" \
  test "$out" = "$(printf 'git-remote-twigpine origin twigpine://did:key:z/r\ncapabilities')"
# Through `sh -c ...; echo $?`, so the signal is observed as a status and the
# test's own shell does not report a killed job.
status="$(sh -c 'FAKE_SIGNAL=TERM node "$1" > /dev/null 2>&1; echo $?' _ "$INSTALL/bin/twigpine.js" 2>/dev/null)"
check "a program killed by a signal ends the launcher the same way" test "$status" = 143
status="$(sh -c 'FAKE_SIGNAL=PIPE node "$1" > /dev/null 2>&1; echo $?' _ "$INSTALL/bin/twigpine.js" 2>/dev/null)"
check "a program killed by SIGPIPE ends the launcher with 141, as a shell expects" test "$status" = 141

FAKE_PIDFILE="$W/child.pid" node "$INSTALL/bin/twigpine.js" > /dev/null 2>&1 &
launcher=$!
for _ in $(seq 1 50); do [ -s "$W/child.pid" ] && break; sleep 0.1; done
child="$(cat "$W/child.pid" 2>/dev/null || true)"
kill -TERM "$launcher" 2>/dev/null || true
# Poll before waiting: the launcher outlives the program, so waiting first
# would also pass when nothing was forwarded and the program simply ran out
# its sleep.
gone=no
for _ in $(seq 1 30); do kill -0 "$child" 2>/dev/null || { gone=yes; break; }; sleep 0.1; done
[ "$gone" = yes ] || kill -KILL "$child" 2>/dev/null || true
wait "$launcher" 2>/dev/null || true
check "a signal sent to the launcher alone reaches the program" test -n "$child" -a "$gone" = yes

rm -rf "$PAYLOAD"
status=0
node "$INSTALL/bin/twigpine.js" > "$W/out" 2>&1 || status=$?
if [ "$status" = 1 ] && grep -q "npm install -g --include=optional @twigpine/cli" "$W/out" && grep -q "install.sh" "$W/out"; then
  ok "a missing payload says how to fix it"
else bad "a missing payload says how to fix it"; fi

if [ -n "$REAL_CLI" ]; then
  mkdir -p "$PAYLOAD"
  cp "$REAL_CLI" "$PAYLOAD/twigpine"
  echo '{"name":"@twigpine/cli","version":"9.9.0-host"}' > "$PAYLOAD/package.json"
  out="$(node "$INSTALL/bin/twigpine.js" --version 2>&1)"
  case "$out" in
    twigpine\ *) ok "runs the real CLI ($out)" ;;
    *) echo "$out" > "$W/out"; bad "runs the real CLI" ;;
  esac
fi

# ── publish ────────────────────────────────────────────────────────────────
echo "publish-packages.sh"
FAKEBIN="$W/fakebin"
mkdir -p "$FAKEBIN"
# A registry in $REG: versions/<version> per published version, tags/<tag>.
# `npm view` of anything unknown answers E404; FAKE_VIEW_BROKEN makes every
# lookup fail some other way. Every call is logged.
cat > "$FAKEBIN/npm" <<'EOF'
#!/usr/bin/env bash
echo "npm $*" >> "$REG/log"
case "$1" in
  view)
    [ -z "${FAKE_VIEW_BROKEN:-}" ] || { echo "npm error code ECONNRESET" >&2; exit 1; }
    spec="$2"; what="$3"
    if [ "$what" = version ]; then
      v="${spec##*@}"
      [ -f "$REG/versions/$v" ] && { echo "$v"; exit 0; }
      echo "npm error code E404" >&2; exit 1
    fi
    tag="${what#dist-tags.}"
    [ -d "$REG/versions" ] && [ -n "$(ls -A "$REG/versions" 2>/dev/null)" ] || { echo "npm error code E404" >&2; exit 1; }
    [ -f "$REG/tags/$tag" ] && cat "$REG/tags/$tag"
    exit 0
    ;;
  publish)
    v="$(node -p 'require("./package.json").version')"
    tag=latest
    while [ $# -gt 0 ]; do [ "$1" = --tag ] && tag="$2"; shift; done
    mkdir -p "$REG/versions" "$REG/tags"
    touch "$REG/versions/$v"
    echo "$v" > "$REG/tags/$tag"
    echo "published $v $tag" >> "$REG/log"
    ;;
  *) echo "unexpected npm $*" >&2; exit 2 ;;
esac
EOF
chmod 755 "$FAKEBIN/npm"

run_publish() {
  rm -f "$REG/log"
  PATH="$FAKEBIN:$PATH" REG="$REG" TWIGPINE_NPM_PUBLISH_RETRY_DELAY=0 TWIGPINE_NPM_PUBLISH_WAIT_TIMEOUT=5 \
    bash "$PUBLISH" "$1" > "$W/out" 2>&1
}
published_order() { grep '^published' "$REG/log" | awk '{print $2, $3}'; }

REG="$W/reg1"; mkdir -p "$REG"
if run_publish "$OUT"; then ok "publishes a first release"; else bad "publishes a first release"; fi
check "platform payloads go first under the platform tag, the wrapper last under latest" \
  test "$(published_order | tr '\n' ';')" = "9.9.0-darwin-arm64 platform;9.9.0-darwin-x64 platform;9.9.0-linux-arm64 platform;9.9.0-linux-x64 platform;9.9.0-win32-x64 platform;9.9.0 latest;"
check "latest ends on the release" test "$(cat "$REG/tags/latest")" = "$VERSION"
check "every publish skips install scripts" \
  test "$(grep -c '^npm publish' "$REG/log")" = "$(grep '^npm publish' "$REG/log" | grep -c -- '--ignore-scripts')"

if run_publish "$OUT" && [ -z "$(published_order)" ] && grep -q "already on the registry" "$W/out"; then
  ok "a re-run publishes nothing twice"
else bad "a re-run publishes nothing twice"; fi

REG="$W/reg2"; mkdir -p "$REG/versions" "$REG/tags"
touch "$REG/versions/9.9.0-darwin-arm64" "$REG/versions/9.9.0-darwin-x64"
echo "9.8.0" > "$REG/tags/latest"; touch "$REG/versions/9.8.0"
if run_publish "$OUT" && test "$(published_order | tr '\n' ';')" = "9.9.0-linux-arm64 platform;9.9.0-linux-x64 platform;9.9.0-win32-x64 platform;9.9.0 latest;"; then
  ok "a re-run after a partial publish finishes the rest"
else bad "a re-run after a partial publish finishes the rest"; fi

REG="$W/reg3"; mkdir -p "$REG/versions" "$REG/tags"
touch "$REG/versions/9.10.0"; echo "9.10.0" > "$REG/tags/latest"
if run_publish "$OUT" && grep -q '^published 9.9.0 backfill$' "$REG/log" && [ "$(cat "$REG/tags/latest")" = 9.10.0 ]; then
  ok "a backfill of an older release leaves latest where it is"
else bad "a backfill of an older release leaves latest where it is"; fi

REG="$W/reg3b"; mkdir -p "$REG/versions" "$REG/tags"
for v in 9.9.0 9.9.0-darwin-arm64 9.9.0-darwin-x64 9.9.0-linux-arm64 9.9.0-linux-x64 9.9.0-win32-x64 9.10.0; do
  touch "$REG/versions/$v"
done
echo "9.10.0" > "$REG/tags/latest"
start=$SECONDS
if run_publish "$OUT" && [ -z "$(published_order)" ] && [ $((SECONDS - start)) -lt 4 ]; then
  ok "re-running a backfill that already went out finishes at once"
else bad "re-running a backfill that already went out finishes at once"; fi

REG="$W/reg4"; mkdir -p "$REG"
cp -R "$OUT" "$W/npm-short"; rm -rf "$W/npm-short/platforms/cli-win32-x64"
if run_publish "$W/npm-short"; then bad "refuses payloads that do not match the wrapper"
elif [ ! -f "$REG/log" ] || ! grep -q '^published' "$REG/log"; then ok "refuses payloads that do not match the wrapper, before publishing"
else bad "refuses payloads that do not match the wrapper"; fi

REG="$W/reg5"; mkdir -p "$REG"
rm -f "$REG/log"
if PATH="$FAKEBIN:$PATH" REG="$REG" FAKE_VIEW_BROKEN=1 TWIGPINE_NPM_PUBLISH_RETRY_DELAY=0 \
  bash "$PUBLISH" "$OUT" > "$W/out" 2>&1; then
  bad "stops when the registry cannot be read"
elif ! grep -q '^published' "$REG/log" 2>/dev/null; then ok "stops when the registry cannot be read, before publishing"
else bad "stops when the registry cannot be read"; fi

for bad_value in 601 -1 abc; do
  REG="$W/reg6"; rm -rf "$REG"; mkdir -p "$REG"
  if PATH="$FAKEBIN:$PATH" REG="$REG" TWIGPINE_NPM_PUBLISH_RETRY_DELAY="$bad_value" \
    bash "$PUBLISH" "$OUT" > "$W/out" 2>&1; then
    bad "refuses retry delay $bad_value"
  else ok "refuses retry delay $bad_value"; fi
done

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
