#!/bin/sh
# Maintain the checksum list that twigpine.com serves at /install-checksums.txt
# (web repo: public/install-checksums.txt).
#
#   scripts/update-install-checksums.sh <list> <tag> <archive.sha256>...
#
# Adds the release's archive checksums to <list>, replacing any earlier lines
# for the same version, and moves "# latest:" to <tag> unless the list already
# names a newer release. install.sh and install.ps1 install only archives that
# are listed, and default to the "# latest:" version, so a release reaches
# installer users only once this change is merged and deployed on twigpine.com.
# That review step is the point: GitHub alone can never vouch for a binary.
set -eu

die() {
  echo "error: $*" >&2
  exit 1
}

[ "$#" -ge 3 ] || die "usage: $0 <list> <tag> <archive.sha256>..."
LIST="$1"
TAG="$2"
shift 2

# Exactly vX.Y.Z, three numeric parts: no pre-release, no extra or empty part.
printf '%s\n' "$TAG" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+' ||
  die "only plain vX.Y.Z releases can be listed: $TAG"
VERSION="${TAG#v}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# New entries, one per archive, normalised to "<lowercase sha256>  <file>".
: > "$TMP/new"
for SUM in "$@"; do
  [ -f "$SUM" ] || die "no such file: $SUM"
  tr -d '\r' < "$SUM" | awk -v ver="$VERSION" -v src="$SUM" '
    # Only the archives the installers can ask for are listable.
    function known_target(n, v,    rest) {
      rest = n
      sub(/^(twigpine|gitlawb)-node-/, "", rest)
      rest = substr(rest, length(v) + 2)
      return rest == "aarch64-apple-darwin.tar.gz" || rest == "x86_64-apple-darwin.tar.gz" ||
        rest == "aarch64-unknown-linux-musl.tar.gz" || rest == "x86_64-unknown-linux-musl.tar.gz" ||
        rest == "x86_64-pc-windows-msvc.zip"
    }
    NF == 0 { next }
    {
      name = $2
      sub(/^\*/, "", name)
      # Archives are twigpine-node-*; releases before the rename used
      # gitlawb-node-*, and a backfill of one of those must still be listable.
      if (NF != 2 || length($1) != 64 || $1 !~ /^[0-9A-Fa-f]+$/ ||
          (index(name, "twigpine-node-" ver "-") != 1 && index(name, "gitlawb-node-" ver "-") != 1) ||
          name ~ /[^A-Za-z0-9._-]/ || !known_target(name, ver)) {
        printf "error: %s: not a sha256 line for a %s archive: %s\n", src, ver, $0 > "/dev/stderr"
        bad = 1
        exit 1
      }
      printf "%s  %s\n", tolower($1), name
    }
    END { if (bad) exit 1 }
  ' >> "$TMP/new" || die "rejected $SUM"
done
[ -s "$TMP/new" ] || die "no checksums given for $TAG"
# One release has one archive name; both at once would list two builds as one version.
if grep -q '  twigpine-node-' "$TMP/new" && grep -q '  gitlawb-node-' "$TMP/new"; then
  die "$TAG has archives under both names (twigpine-node-* and gitlawb-node-*)"
fi

HEADER_DEFAULT='# SHA-256 checksums of Twigpine release archives (github.com/Twigpine/node).
#
# https://twigpine.com/install.sh and /install.ps1 install an archive only if
# its checksum is listed here, and install the "latest" version below unless
# asked for another. This list is served by twigpine.com, not by GitHub, so a
# hijacked or look-alike GitHub repository cannot pass the check on its own.
#
# Check a download by hand:
#   grep " <archive>$" install-checksums.txt | shasum -a 256 -c
#
# Maintained by scripts/update-install-checksums.sh in the node repo (release
# workflow, web-sync job). Review every change before it is deployed.
#'

LATEST=""
if [ -f "$LIST" ]; then
  tr -d '\r' < "$LIST" > "$TMP/old"
  grep '^#' "$TMP/old" | grep -v '^# latest:' > "$TMP/header" || true
  LATEST=$(sed -n 's/^# latest: *v\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\) *$/\1/p' "$TMP/old" | head -n 1)
  # Without a readable latest line this run could move latest backwards.
  [ -n "$LATEST" ] || die "$LIST has no '# latest: vX.Y.Z' line; fix the list by hand first"
  # Keep every other version's entries.
  awk -v ver="$VERSION" '
    /^#/ || NF == 0 { next }
    {
      name = $2; sub(/^\*/, "", name)
      if (index(name, "twigpine-node-" ver "-") != 1 && index(name, "gitlawb-node-" ver "-") != 1)
        printf "%s  %s\n", tolower($1), name
    }
  ' "$TMP/old" > "$TMP/kept"
else
  printf '%s\n' "$HEADER_DEFAULT" > "$TMP/header"
  : > "$TMP/kept"
fi
[ -s "$TMP/header" ] || printf '%s\n' "$HEADER_DEFAULT" > "$TMP/header"

# ver_gt A B: true when version A is newer than version B (plain X.Y.Z).
ver_gt() {
  [ "$1" != "$2" ] &&
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)" = "$1" ]
}
if [ -z "$LATEST" ] || ver_gt "$VERSION" "$LATEST"; then
  LATEST="$VERSION"
fi

{
  cat "$TMP/header"
  echo "# latest: v${LATEST}"
  # Newest version first, then by file name.
  cat "$TMP/kept" "$TMP/new" | awk '{
    v = $2
    sub(/^(twigpine|gitlawb)-node-/, "", v)
    split(v, p, /[.-]/)
    printf "%d %d %d %s %s\n", p[1], p[2], p[3], $2, $1
  }' | LC_ALL=C sort -k1,1nr -k2,2nr -k3,3nr -k4,4 | uniq | awk '{ printf "%s  %s\n", $5, $4 }'
} > "$TMP/list"

DUP=$(grep -v '^#' "$TMP/list" | awk '{ print $2 }' | sort | uniq -d | head -n 1)
[ -z "$DUP" ] || die "two different checksums for $DUP"

# The installers need the latest version listed for every target they serve,
# under either archive name.
has_latest() {
  grep -Eq "  (twigpine|gitlawb)-node-${LATEST_RE}-$1\$" "$TMP/list"
}
LATEST_RE=$(printf '%s' "$LATEST" | sed 's/\./\\./g')
for T in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl \
  x86_64-unknown-linux-musl; do
  has_latest "${T}\.tar\.gz" || die "latest v${LATEST} has no ${T}.tar.gz checksum"
done
has_latest 'x86_64-pc-windows-msvc\.zip' ||
  die "latest v${LATEST} has no x86_64-pc-windows-msvc.zip checksum"

cp "$TMP/list" "$LIST"
echo "$LIST: listed ${TAG} ($(wc -l < "$TMP/new" | tr -d ' ') archives), latest is v${LATEST}"
