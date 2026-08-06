#!/usr/bin/env bash
set -euo pipefail

release_version=${1:?release version is required}
: "${RELEASE_TAG:?RELEASE_TAG is required for crate publication}"

if [[ "$RELEASE_TAG" != "v${release_version}" ]]; then
  printf 'RELEASE_TAG must be v%s, found %s\n' \
    "$release_version" "$RELEASE_TAG" >&2
  exit 1
fi

if [[ "$(git cat-file -t "$RELEASE_TAG" 2>/dev/null || true)" != tag ]]; then
  printf 'RELEASE_TAG must name an annotated tag: %s\n' "$RELEASE_TAG" >&2
  exit 1
fi

tag_commit="$(git rev-parse --verify "${RELEASE_TAG}^{commit}")"
head_commit="$(git rev-parse --verify HEAD)"
if [[ "$head_commit" != "$tag_commit" ]]; then
  printf 'HEAD must equal the canonical release tag commit: HEAD=%s %s=%s\n' \
    "$head_commit" "$RELEASE_TAG" "$tag_commit" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  printf 'crate publication working tree must be clean at %s\n' \
    "$RELEASE_TAG" >&2
  exit 1
fi
