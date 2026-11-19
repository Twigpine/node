#!/usr/bin/env bash
# publish-packages.sh: publish the npm payloads build-platform-packages.mjs
# assembled under <npm-dir> (wrapper/ plus platforms/*/), in the order and
# with the dist-tags docs/NPM_PACKAGING.md requires:
#
#   1. every platform payload under the `platform` dist-tag, never `latest`;
#   2. wait until npm shows every platform version, then check `latest` was
#      not moved onto one;
#   3. the wrapper: under `latest` when it is the newest release, otherwise
#      (a backfill of an older version) under `backfill`, so `latest` never
#      moves backward; then wait until npm shows it.
#
# The waits exist because npm applies a publish asynchronously: `npm publish`
# returns once the upload is accepted, and the version can appear minutes
# later. Ordering the uploads alone would still let the wrapper appear first,
# with aliases that 404.
#
# A version already on the registry is skipped, so re-running a job that failed
# halfway finishes the release instead of failing on what went out.
#
# Usage: scripts/npm/publish-packages.sh <npm-dir>
#
# Auth comes from the environment (npm trusted publishing in CI).
# TWIGPINE_NPM_PUBLISH_RETRY_DELAY sets the seconds between registry lookups
# (default 5), TWIGPINE_NPM_PUBLISH_WAIT_TIMEOUT the seconds to wait for npm to
# apply the publishes (default 1800), and TWIGPINE_NPM_PUBLISH_FLAGS extra
# flags for every `npm publish` (CI passes --provenance).
set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

npm_dir="${1:-}"
[ -n "$npm_dir" ] || fail "usage: publish-packages.sh <npm-dir>"
npm_dir="${npm_dir%/}"
wrapper_dir="${npm_dir}/wrapper"
[ -f "${wrapper_dir}/package.json" ] || fail "${wrapper_dir}/package.json not found; run build-platform-packages.mjs first"

manifest_field() {
  node -e 'const v = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))[process.argv[2]]; process.stdout.write(v === undefined ? "" : String(v));' "$1/package.json" "$2"
}

name="$(manifest_field "$wrapper_dir" name)"
version="$(manifest_field "$wrapper_dir" version)"
[ -n "$name" ] && [ -n "$version" ] || fail "${wrapper_dir}/package.json has no name or version"

# whole_seconds <variable> <value> <max>: a decimal number of seconds, checked
# before anything is published (Bash reads a leading zero as octal).
whole_seconds() {
  case "$2" in
    '' | *[!0-9]*) fail "$1 must be a whole number of seconds, got '$2'" ;;
  esac
  [ "${#2}" -le 18 ] || fail "$1 must be at most $3 seconds, got '$2'"
  local seconds=$((10#$2))
  [ "$seconds" -le "$3" ] || fail "$1 must be at most $3 seconds, got '$2'"
  echo "$seconds"
}

delay="$(whole_seconds TWIGPINE_NPM_PUBLISH_RETRY_DELAY "${TWIGPINE_NPM_PUBLISH_RETRY_DELAY:-5}" 600)"
wait_timeout="$(whole_seconds TWIGPINE_NPM_PUBLISH_WAIT_TIMEOUT "${TWIGPINE_NPM_PUBLISH_WAIT_TIMEOUT:-1800}" 86400)"
read -r -a extra_flags <<< "${TWIGPINE_NPM_PUBLISH_FLAGS:-}"

# The wrapper pins every platform version exactly; a wrapper whose aliases do
# not match the payloads beside it would install aliases that 404.
shopt -s nullglob
platform_dirs=("${npm_dir}"/platforms/*/)
shopt -u nullglob
[ "${#platform_dirs[@]}" -gt 0 ] || fail "no platform payloads under ${npm_dir}/platforms"
expected_platforms="$(node -e 'const p = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); process.stdout.write(Object.values(p.optionalDependencies || {}).sort().join("\n"));' "${wrapper_dir}/package.json")"
actual_platforms=""
for dir in "${platform_dirs[@]}"; do
  dir="${dir%/}"
  platform_name="$(manifest_field "$dir" name)"
  platform_version="$(manifest_field "$dir" version)"
  [ "$platform_name" = "$name" ] || fail "${dir} is ${platform_name}, not ${name}"
  case "$platform_version" in
    "${version}-"*) ;;
    *) fail "${dir} version ${platform_version} is not a platform version of ${name}@${version}" ;;
  esac
  actual_platforms="${actual_platforms}npm:${name}@${platform_version}"$'\n'
done
actual_platforms="$(printf '%s' "$actual_platforms" | sort)"
if [ "$actual_platforms" != "$expected_platforms" ]; then
  fail "the wrapper's optionalDependencies do not match the payloads under ${npm_dir}/platforms (wrapper: $(echo "$expected_platforms" | tr '\n' ' '); payloads: $(echo "$actual_platforms" | tr '\n' ' '))"
fi

# Only npm's E404 means "not published". Any other lookup failure is retried
# and then stops the job: guessing would republish a version already out.
already_published() {
  local output status errors
  errors="$(mktemp)"
  for _ in 1 2 3; do
    status=0
    output="$(npm view "${name}@$1" version 2>"$errors")" || status=$?
    if [ "$status" -eq 0 ]; then
      rm -f "$errors"
      [ "$output" = "$1" ]
      return
    fi
    if grep -q 'E404' "$errors"; then
      rm -f "$errors"
      return 1
    fi
    sleep "$delay"
  done
  cat "$errors" >&2
  rm -f "$errors"
  fail "could not look up ${name}@$1 on the registry, so cannot tell whether it is already published"
}

# publish <dir> <version> [npm publish flags...]
publish() {
  local dir="$1" package_version="$2"
  shift 2
  if already_published "$package_version"; then
    echo "${name}@${package_version} is already on the registry; not publishing it again."
    return 0
  fi
  echo "publishing ${name}@${package_version} from ${dir}"
  (cd "$dir" && npm publish --access public --ignore-scripts ${extra_flags[@]+"${extra_flags[@]}"} "$@")
}

# While npm has not applied a publish, an error and an E404 both mean "not
# yet"; the deadline bounds the wait.
version_visible() {
  [ "$(npm view "${name}@$1" version 2>/dev/null || true)" = "$1" ]
}

tag_is() {
  [ "$(npm view "$name" "dist-tags.$1" 2>/dev/null || true)" = "$2" ]
}

deadline=$((SECONDS + wait_timeout))

# wait_until <what> <command...>
wait_until() {
  local what="$1"
  shift
  until "$@"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "npm accepted the upload but still does not show ${what} after ${wait_timeout}s. Re-run once it does: versions already on the registry are skipped."
    fi
    sleep "$delay"
  done
}

# The wrapper's dist-tag, decided before anything is published. `latest`
# unless the registry already has a newer release. A failed lookup other
# than E404 (no package yet) stops the job rather than guess.
latest_errors="$(mktemp)"
trap 'rm -f -- "$latest_errors"' EXIT
latest_before=""
if ! latest_before="$(npm view "$name" dist-tags.latest 2>"$latest_errors")"; then
  grep -q 'E404' "$latest_errors" || { cat "$latest_errors" >&2; fail "could not read ${name}'s latest dist-tag; not guessing the wrapper's dist-tag"; }
  latest_before=""
fi
wrapper_tag="latest"
case "$latest_before" in
  '' | "${version}" | "${version}-"*) ;;
  *)
    newest="$(printf '%s\n%s\n' "$latest_before" "$version" | sort -V | tail -n 1)"
    if [ "$newest" != "$version" ]; then
      wrapper_tag="backfill"
      echo "::notice::${version} is older than ${name}@${latest_before}; publishing the wrapper under dist-tag backfill"
    fi
    ;;
esac

for dir in "${platform_dirs[@]}"; do
  dir="${dir%/}"
  publish "$dir" "$(manifest_field "$dir" version)" --tag platform
done

for dir in "${platform_dirs[@]}"; do
  platform_version="$(manifest_field "${dir%/}" version)"
  wait_until "${name}@${platform_version}" version_visible "$platform_version"
  echo "${name}@${platform_version} is on the registry."
done

# Platform versions are semver prereleases of the wrapper version; one that
# took `latest` would make a plain install deliver a payload with no commands.
latest="$(npm view "$name" dist-tags.latest 2>/dev/null || true)"
case "$latest" in
  "${version}-"*)
    fail "dist-tag latest points at platform version ${latest}; a platform publish moved it. Fix the dist-tag before publishing the wrapper."
    ;;
esac
echo "dist-tag latest is ${latest:-unset} (unchanged by the platform publishes)."

if already_published "$version"; then
  # Out already, under whatever tag it went out with then (a re-run, or a
  # backfill of a release published at the time): nothing to wait for.
  echo "${name}@${version} is already on the registry; not publishing it again."
else
  publish "$wrapper_dir" "$version" --tag "$wrapper_tag"
  wait_until "${name}@${version} as dist-tag ${wrapper_tag}" tag_is "$wrapper_tag" "$version"
  echo "dist-tag ${wrapper_tag} is ${version}."
fi
