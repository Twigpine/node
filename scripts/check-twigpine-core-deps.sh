#!/usr/bin/env bash
#
# Dependency-purity gate for the `twigpine-core` crate.
#
# twigpine-core is embedded by every consumer (the twigpine CLI, git-remote-twigpine,
# the node daemon), so it must stay lean. This script recomputes twigpine-core's
# NORMAL (non-dev, non-build) transitive dependency set and fails if it contains
# any crate not present in ci/twigpine-core-allowed-deps.txt.
#
# Hard-fail direction: a crate present now but NOT allowlisted. That is the case
# the gate exists to catch (core silently gaining a heavy dependency).
# Informational only: an allowlisted crate no longer present (stale entry) — a
# legitimate dependency removal should not red CI, so it is reported, not failed.
#
# Runnable from anywhere in the repo.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ALLOW="$ROOT/ci/twigpine-core-allowed-deps.txt"

if [ ! -f "$ALLOW" ]; then
  echo "ERROR: allowlist not found at $ALLOW" >&2
  exit 1
fi

# `cargo tree` resolves WITHOUT --locked on purpose, unlike the blocking cargo
# jobs in pr-checks. This gate answers one question, whether twigpine-core's
# dependency closure gained something unallowlisted, and a stale Cargo.lock
# would red it for a reason that has nothing to do with that closure. Lock
# staleness is already caught by the --locked cargo jobs, so it does not need a
# second gate here.
#
# Resolving can refresh Cargo.lock as a side effect, so snapshot and restore
# it: this check must never leave the working tree dirty when run locally.
lock_backup="$(mktemp)"
cp "$ROOT/Cargo.lock" "$lock_backup"
restore_lock() { cp "$lock_backup" "$ROOT/Cargo.lock"; rm -f "$lock_backup"; }
trap restore_lock EXIT

# Current normal-dependency closure of twigpine-core, one crate name per line.
# Must match the regen command documented in the allowlist header exactly.
current="$(
  cargo tree -p twigpine-core --edges normal --prefix none --manifest-path "$ROOT/Cargo.toml" \
    | sed -E 's/ v[0-9].*$//' \
    | grep -v '^twigpine-core$' \
    | sort -u
)"

# Allowlist with comments and blank lines stripped.
allowed="$(grep -vE '^[[:space:]]*(#|$)' "$ALLOW" | sort -u)"

# comm needs sorted input; both sides are sorted above.
offenders="$(comm -23 <(printf '%s\n' "$current") <(printf '%s\n' "$allowed"))"
stale="$(comm -13 <(printf '%s\n' "$current") <(printf '%s\n' "$allowed"))"

if [ -n "$stale" ]; then
  echo "NOTE: allowlisted crates no longer in twigpine-core's dependency tree"
  echo "      (safe to prune from ci/twigpine-core-allowed-deps.txt):"
  printf '  %s\n' $stale
  echo
fi

if [ -n "$offenders" ]; then
  {
    echo "ERROR: twigpine-core gained dependencies not on the allowlist:"
    printf '  %s\n' $offenders
    echo
    echo "twigpine-core must stay embeddable and lean. If a new dependency is"
    echo "intentional, add it to ci/twigpine-core-allowed-deps.txt (regen command"
    echo "is in that file's header). Otherwise, drop the dependency."
  } >&2
  exit 1
fi

echo "twigpine-core dependency purity: OK ($(printf '%s\n' "$current" | wc -l | tr -d ' ') normal deps, all allowlisted)."
