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
temporary_parent=${TMPDIR:-/tmp}
mkdir -p "$temporary_parent"
temporary_root=$(mktemp -d "$temporary_parent/folderbase-package-sensitivity.XXXXXX")
trap 'rm -R "$temporary_root"' EXIT

package_directory=${1:-"$temporary_root/package"}
if [[ $# -eq 0 ]]; then
  mkdir -p "$package_directory"
  CARGO_TARGET_DIR="$temporary_root/target" cargo package \
    --workspace \
    --locked \
    --allow-dirty \
    --no-verify
  cp "$temporary_root/target/package/"*.crate "$package_directory/"
fi

mutated_package_directory="$temporary_root/mutated-package"
mutation_root="$temporary_root/mutation"
fake_bin="$temporary_root/fake-bin"
mkdir -p "$mutated_package_directory" "$mutation_root" "$fake_bin"
cp "$package_directory/"*.crate "$mutated_package_directory/"

core_archives=("$mutated_package_directory"/folderbase-core-*.crate)
if [[ ${#core_archives[@]} -ne 1 || ! -f "${core_archives[0]}" ]]; then
  printf 'Expected exactly one folderbase-core archive in %s.\n' \
    "$mutated_package_directory" >&2
  exit 1
fi

core_archive=${core_archives[0]}
core_directory=$(basename "$core_archive" .crate)
tar -xzf "$core_archive" -C "$mutation_root"
test -f "$mutation_root/$core_directory/tests/local_versions.rs"
printf '\n// package-byte-sensitivity mutation\n' \
  >> "$mutation_root/$core_directory/tests/local_versions.rs"
rm "$core_archive"
tar -czf "$core_archive" -C "$mutation_root" "$core_directory"

printf '%s\n' '#!/usr/bin/env bash' 'exit 97' > "$fake_bin/cargo"
chmod +x "$fake_bin/cargo"

set +e
PATH="$fake_bin:$PATH" \
  "$repository_root/scripts/test-extracted-packages.sh" \
  "$mutated_package_directory" >/dev/null 2>&1
proof_status=$?
set -e

if [[ $proof_status -eq 97 ]]; then
  printf '%s\n' \
    'Extracted-package proof did not detect the mutated packaged Rust test.' >&2
  exit 1
fi

if [[ $proof_status -ne 1 ]]; then
  printf 'Expected byte-proof status 1, received %s.\n' "$proof_status" >&2
  exit 1
fi

printf '%s\n' \
  'Extracted-package proof rejects a mutated packaged integration test.'
