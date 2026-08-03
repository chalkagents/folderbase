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

node scripts/verify-folderbase-version-digest-vectors.mjs
node scripts/verify-folderbase-version-distribution.mjs
node scripts/verify-folderbase-version-0.5-digest-vectors.mjs
node scripts/verify-folderbase-version-0.5-distribution.mjs

cmp \
  "protocol/capabilities/v1/registry.json" \
  "crates/folderbase-cli/assets/capability-registry-v1.json"

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

cmp \
  "protocol/conformance/folderbase-version-0.5/valid/minimal-ordinary-v1.json" \
  "crates/folderbase-cli/tests/fixtures/protocol/minimal-folderbase-version-0.5.json"
cmp \
  "protocol/conformance/chunk-manifest/invalid/unknown-format.json" \
  "crates/folderbase-cli/tests/fixtures/protocol/unknown-chunk-manifest-format.json"

node --test \
  protocol/conformance/capabilities/run.test.mjs \
  scripts/tests/capability-contract.test.mjs

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
"$repository_root/scripts/test-extracted-package-source-sensitivity.sh" \
  "$CARGO_TARGET_DIR/package"
"$repository_root/scripts/test-extracted-packages.sh" \
  "$CARGO_TARGET_DIR/package"
