#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"
cd "$repository_root"

workspace_version="$(
  cargo metadata --format-version 1 --no-deps |
    jq -r '[.packages[].version] | unique | if length == 1 then .[0] else error("workspace package versions differ") end'
)"
target_directory="${CARGO_TARGET_DIR:-$repository_root/target}"
registry_user_agent="folderbase-release-workflow/1.0 (https://github.com/chalkagents/folderbase)"
temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

registry_metadata() {
  local crate_name=$1
  local destination=$2
  local status
  status="$(
    curl \
      --silent \
      --show-error \
      --location \
      --user-agent "$registry_user_agent" \
      --output "$destination" \
      --write-out '%{http_code}' \
      "https://crates.io/api/v1/crates/${crate_name}/${workspace_version}"
  )"
  case "$status" in
    200) return 0 ;;
    404) printf '%s\n' 'null' > "$destination"; return 1 ;;
    *) printf 'crates.io returned HTTP %s for %s@%s\n' \
         "$status" "$crate_name" "$workspace_version" >&2; return 2 ;;
  esac
}

wait_for_registry() {
  local crate_name=$1
  local destination=$2
  local attempt
  local status
  for attempt in $(seq 1 120); do
    if registry_metadata "$crate_name" "$destination"; then
      return 0
    fi
    status=$?
    if [[ "$status" -ne 1 ]]; then return "$status"; fi
    sleep 5
  done
  printf 'Timed out waiting for %s@%s on crates.io.\n' \
    "$crate_name" "$workspace_version" >&2
  return 1
}

wait_for_cargo_index() {
  local crate_name=$1
  local attempt
  for attempt in $(seq 1 120); do
    if cargo info "${crate_name}@${workspace_version}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  printf 'Timed out waiting for %s@%s in the Cargo registry index.\n' \
    "$crate_name" "$workspace_version" >&2
  return 1
}

for crate_name in folderbase-core folderbase-cli; do
  cargo package --locked --package "$crate_name"
  archive="$target_directory/package/${crate_name}-${workspace_version}.crate"
  test -f "$archive"
  local_checksum="$(sha256_file "$archive")"
  metadata="$temporary_root/${crate_name}.json"
  published_json=null
  if registry_metadata "$crate_name" "$metadata"; then
    published_json="$(
      jq '{version: .version.num, checksum: .version.checksum, yanked: .version.yanked}' \
        "$metadata"
    )"
  else
    status=$?
    if [[ "$status" -ne 1 ]]; then exit "$status"; fi
  fi
  decision="$(
    jq -n \
      --arg crateName "$crate_name" \
      --arg version "$workspace_version" \
      --arg localChecksum "$local_checksum" \
      --argjson published "$published_json" \
      '{crateName: $crateName, version: $version, localChecksum: $localChecksum, published: $published}' |
      node scripts/release/crate-publication-policy.mjs
  )"
  if [[ "$(jq -r '.skipPublish' <<<"$decision")" != true ]]; then
    : "${CARGO_REGISTRY_TOKEN:?CARGO_REGISTRY_TOKEN is required for an unpublished crate}"
    cargo publish \
      --locked \
      --package "$crate_name" \
      --token "$CARGO_REGISTRY_TOKEN"
    wait_for_registry "$crate_name" "$metadata"
  fi
  published_checksum="$(jq -r '.version.checksum' "$metadata")"
  published_version="$(jq -r '.version.num' "$metadata")"
  published_yanked="$(jq -r '.version.yanked' "$metadata")"
  test "$published_version" = "$workspace_version"
  test "$published_checksum" = "$local_checksum"
  test "$published_yanked" = false
  if [[ "$crate_name" == folderbase-core ]]; then
    wait_for_cargo_index "$crate_name"
  fi
done
