#!/usr/bin/env bash
set -euo pipefail

: "${GH_TOKEN:?FOLDERBASE_HOMEBREW_TAP_TOKEN is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"
cd "$repository_root"

test -f dist/SHA256SUMS
test "$(
  gh api "repos/chalkagents/folderbase/releases/tags/${RELEASE_TAG}" --jq '.immutable'
)" = true

temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT
formula="$temporary_root/folderbase.rb"
current="$temporary_root/current.rb"

node scripts/release/render-homebrew-formula.mjs \
  --tag "$RELEASE_TAG" \
  --checksums dist/SHA256SUMS > "$formula"

tap_path="Formula/folderbase.rb"
tap_api="repos/chalkagents/homebrew-tap/contents/${tap_path}"
metadata="$(gh api "$tap_api")"
current_sha="$(jq -r '.sha' <<<"$metadata")"
jq -r '.content' <<<"$metadata" | base64 --decode > "$current"

if ! cmp -s "$formula" "$current"; then
  encoded="$(base64 < "$formula" | tr -d '\n')"
  gh api \
    --method PUT \
    "$tap_api" \
    -f message="folderbase ${RELEASE_TAG}" \
    -f content="$encoded" \
    -f sha="$current_sha" >/dev/null
fi

gh api "$tap_api" --jq '.content' | base64 --decode > "$current"
cmp "$formula" "$current"
