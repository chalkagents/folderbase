#!/usr/bin/env bash
set -euo pipefail

script_directory=$(
  CDPATH= cd -- "$(dirname -- "$0")" >/dev/null 2>&1
  pwd
)
repository_root=$(
  CDPATH= cd -- "$script_directory/.." >/dev/null 2>&1
  pwd
)
package_directory=${1:-"$repository_root/target/package"}
extraction_root=$(mktemp -d)
trap 'rm -R "$extraction_root"' EXIT

resolve_archive() {
  local package_name=$1
  local matches=("$package_directory/$package_name"-*.crate)

  if [[ ${#matches[@]} -ne 1 || ! -f "${matches[0]}" ]]; then
    printf 'Expected exactly one %s archive in %s.\n' \
      "$package_name" \
      "$package_directory" >&2
    exit 1
  fi

  printf '%s\n' "${matches[0]}"
}

core_archive=$(resolve_archive folderbase-core)
cli_archive=$(resolve_archive folderbase-cli)

tar -xzf "$core_archive" -C "$extraction_root"
tar -xzf "$cli_archive" -C "$extraction_root"

core_source="$extraction_root/$(basename "$core_archive" .crate)"
cli_source="$extraction_root/$(basename "$cli_archive" .crate)"

cargo test \
  --manifest-path "$core_source/Cargo.toml" \
  --locked

cargo test \
  --manifest-path "$cli_source/Cargo.toml" \
  --offline \
  --config "patch.crates-io.folderbase-core.path='$core_source'"

printf '%s\n' 'Extracted Cargo packages are self-contained and testable.'
