#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_LATEST:?GITHUB_LATEST is required}"
: "${GITHUB_PRERELEASE:?GITHUB_PRERELEASE is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"
cd "$repository_root"

if [[ "$GITHUB_PRERELEASE" == true ]]; then
  GITHUB_LATEST=false
fi

if gh release view "$RELEASE_TAG" >/dev/null 2>&1; then
  release_metadata="$(
    gh release view "$RELEASE_TAG" \
      --json isDraft,isImmutable,isPrerelease
  )"
  existing_draft="$(printf '%s' "$release_metadata" | jq -r '.isDraft')"
  existing_immutable="$(printf '%s' "$release_metadata" | jq -r '.isImmutable')"
  existing_prerelease="$(printf '%s' "$release_metadata" | jq -r '.isPrerelease')"
  test "$existing_prerelease" = "$GITHUB_PRERELEASE"
  if [[ "$existing_draft" != true ]]; then
    test "$existing_immutable" = true
  fi
else
  existing_draft=true
  github_release_flags=(--draft --latest="$GITHUB_LATEST")
  if [[ "$GITHUB_PRERELEASE" == true ]]; then
    github_release_flags+=(--prerelease)
  fi
  gh release create "$RELEASE_TAG" \
    --generate-notes \
    --title "Folderbase Core $RELEASE_TAG" \
    --verify-tag \
    "${github_release_flags[@]}"
fi

remote_assets="$(mktemp -d)"
trap 'rm -rf "$remote_assets"' EXIT
expected_assets="$(find dist -maxdepth 1 -type f -exec basename {} \; | sort)"
published_assets="$(
  gh release view "$RELEASE_TAG" --json assets --jq '.assets[].name' | sort
)"
if [[ "$existing_draft" == true ]]; then
  while IFS= read -r published_asset; do
    [[ -z "$published_asset" ]] && continue
    if ! grep -Fqx "$published_asset" <<<"$expected_assets"; then
      echo "Draft release contains unexpected asset $published_asset." >&2
      exit 1
    fi
  done <<<"$published_assets"
  for asset in dist/*; do
    asset_name="$(basename "$asset")"
    if grep -Fqx "$asset_name" <<<"$published_assets"; then
      gh release download "$RELEASE_TAG" \
        --dir "$remote_assets" \
        --pattern "$asset_name"
      cmp "$asset" "$remote_assets/$asset_name"
    else
      gh release upload "$RELEASE_TAG" "$asset"
    fi
  done
  release_edit_flags=(--draft=false --latest="$GITHUB_LATEST")
  if [[ "$GITHUB_PRERELEASE" == true ]]; then
    release_edit_flags+=(--prerelease=true)
  else
    release_edit_flags+=(--prerelease=false)
  fi
  gh release edit "$RELEASE_TAG" "${release_edit_flags[@]}"
else
  test "$published_assets" = "$expected_assets"
  for asset in dist/*; do
    asset_name="$(basename "$asset")"
    gh release download "$RELEASE_TAG" \
      --dir "$remote_assets" \
      --pattern "$asset_name"
    cmp "$asset" "$remote_assets/$asset_name"
  done
fi

test "$(
  gh release view "$RELEASE_TAG" --json isImmutable --jq '.isImmutable'
)" = true
