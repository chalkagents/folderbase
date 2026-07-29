#!/bin/bash

set -euo pipefail

script_directory=$(
  CDPATH= cd -- "$(dirname -- "$0")" >/dev/null 2>&1
  pwd
)
repository_root=$(
  CDPATH= cd -- "$script_directory/.." >/dev/null 2>&1
  pwd
)
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT

export CARGO_TARGET_DIR="$temporary_root/target"

cd "$repository_root"

node scripts/verify-folderbase-version-distribution.mjs

for template in \
  person \
  organization \
  engagement \
  project-0.2.1 \
  project-0.2.2 \
  customer \
  temporary \
  custom
do
  cmp \
    "protocol/templates/0.2/$template/template.json" \
    "crates/folderbase-core/assets/templates/0.2/$template/template.json"
done

for package in folderbase-core folderbase-cli
do
  for legal_file in LICENSE NOTICE
  do
    cmp "$legal_file" "crates/$package/$legal_file"
  done

  package_files=$(
    cargo package \
      --package "$package" \
      --locked \
      --allow-dirty \
      --list
  )
  for legal_file in LICENSE NOTICE
  do
    if ! grep -Fxq "$legal_file" <<<"$package_files"; then
      printf '%s\n' "$package archive omits $legal_file" >&2
      exit 1
    fi
  done
done

cargo package --workspace --locked --allow-dirty
"$repository_root/scripts/test-extracted-packages.sh" \
  "$CARGO_TARGET_DIR/package"
