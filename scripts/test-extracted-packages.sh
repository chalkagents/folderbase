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

test -f "$core_source/src/folderbase_version.rs"
for package in folderbase-core folderbase-cli
do
  source_root="$repository_root/crates/$package"
  extracted_root="$extraction_root/$(basename "$(resolve_archive "$package")" .crate)"
  while IFS= read -r extracted_path
  do
    relative_path=${extracted_path#"$extracted_root/"}
    cmp "$source_root/$relative_path" "$extracted_path"
  done < <(
    find "$extracted_root" \
      -type f \
      \( \
        -name '*.rs' -o \
        -path "$extracted_root/assets/*" \
      \) \
      -print 2>/dev/null |
      LC_ALL=C sort
  )
done
test ! -e "$core_source/protocol"
test ! -e "$core_source/tests/folderbase_version_conformance.rs"
grep -Fq 'contract = "folderbase-version-v1"' "$core_source/Cargo.toml"
grep -Fq 'compatibility-contract = "folderbase-compatibility-contract-v1"' "$core_source/Cargo.toml"
grep -Fq 'protocol-version = "0.4"' "$core_source/Cargo.toml"
grep -Fq 'additional-protocol-version = "0.5"' "$core_source/Cargo.toml"
grep -Fq 'native-root-protocol-version = "0.5.0"' "$core_source/Cargo.toml"
grep -Fq 'distribution = "repository-tag-source-archive"' "$core_source/Cargo.toml"
grep -Fq 'cargo-package-role = "runtime-implementation-only"' "$core_source/Cargo.toml"

test -f "$core_source/tests/local_versions.rs"
test -f "$core_source/tests/sharing.rs"
test -f "$core_source/tests/sync_simulator.rs"
test -f "$core_source/tests/template_upgrades.rs"
test -f "$core_source/tests/workspace.rs"
test -f "$cli_source/tests/cli.rs"

cargo test \
  --manifest-path "$core_source/Cargo.toml" \
  --locked

cargo fetch \
  --manifest-path "$cli_source/Cargo.toml" \
  --config "patch.crates-io.folderbase-core.path='$core_source'"

cargo test \
  --manifest-path "$cli_source/Cargo.toml" \
  --offline \
  --config "patch.crates-io.folderbase-core.path='$core_source'"

cargo install \
  --path "$cli_source" \
  --offline \
  --root "$extraction_root/install" \
  --config "patch.crates-io.folderbase-core.path='$core_source'"

folderbase="$extraction_root/install/bin/folderbase"
test "$("$folderbase" --version)" = "folderbase 0.5.0"
node "$repository_root/protocol/conformance/capabilities/run.mjs" \
  --implementation "$folderbase"

mkdir -p "$extraction_root/outside-checkout/unmanaged"
cd "$extraction_root/outside-checkout"
"$folderbase" init unmanaged \
  --template folderbase.project@0.2.2 \
  --answer purpose='Verify the installed Folderbase package.' \
  --answer current_state='The package is installed outside its checkout.' \
  --answer next_action='Continue from the initialized Folderbase.' \
  --json > initialization.json

test -f unmanaged/.folderbase/manifest.json
test ! -e unmanaged/.folderbaseignore
test -f unmanaged/FOLDERBASE.md

printf '%s\n' 'Extracted Cargo packages are self-contained and testable.'
