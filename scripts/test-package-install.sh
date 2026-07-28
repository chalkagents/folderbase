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
cargo install \
  --path crates/folderbase-cli \
  --locked \
  --root "$temporary_root/install"

folderbase="$temporary_root/install/bin/folderbase"
"$folderbase" --version

mkdir -p "$temporary_root/outside-checkout/unmanaged"
cd "$temporary_root/outside-checkout"
"$folderbase" init unmanaged \
  --template folderbase.project@0.2.2 \
  --answer purpose='Verify the installed Folderbase package.' \
  --answer current_state='The package is installed outside its checkout.' \
  --answer next_action='Continue from the initialized Folderbase.' \
  --json > initialization.json

test -f unmanaged/.folderbase/manifest.json
test -f unmanaged/.folderbaseignore
test -f unmanaged/FOLDERBASE.md
