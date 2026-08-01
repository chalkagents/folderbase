#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "FOLDERBASE_IMMUTABLE_RELEASES_READ_TOKEN is required." >&2
  exit 1
fi

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

test "$(
  gh api "repos/$GITHUB_REPOSITORY/immutable-releases" --jq '.enabled'
)" = true
