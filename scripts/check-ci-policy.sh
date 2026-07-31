#!/usr/bin/env bash
set -euo pipefail

workflow="${CI_WORKFLOW:-.github/workflows/ci.yml}"
release_workflow="${RELEASE_WORKFLOW:-.github/workflows/release-cli.yml}"

require_release_fragment() {
  local fragment=$1
  local message=$2

  if ! grep -Fq -- "$fragment" "$release_workflow"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_fragment_minimum_count() {
  local fragment=$1
  local minimum=$2
  local message=$3
  local actual

  actual=$(grep -Fc -- "$fragment" "$release_workflow" || true)
  if [[ "$actual" -lt "$minimum" ]]; then
    printf '%s (expected at least %s, found %s)\n' \
      "$message" "$minimum" "$actual" >&2
    exit 1
  fi
}

if ! grep -Fqx "  pull_request:" "$workflow"; then
  echo "CI must run for pull requests." >&2
  exit 1
fi

if ! awk '
  $0 == "  push:" {
    in_push = 1
    next
  }
  in_push && $0 ~ /^  [^ ]/ {
    in_push = 0
  }
  in_push && $0 == "    branches: [main]" {
    found = 1
  }
  END {
    exit found ? 0 : 1
  }
' "$workflow"; then
  echo "Push CI must be limited to main so pull-request branches run once." >&2
  exit 1
fi

for action_workflow in .github/workflows/*.yml
do
  while IFS= read -r action_line
  do
    action_reference=${action_line#*@}
    action_reference=${action_reference%% *}
    if [[ ! "$action_reference" =~ ^[0-9a-f]{40}$ ]]; then
      printf 'CI action is not pinned to an immutable commit in %s: %s\n' \
        "$action_workflow" "$action_line" >&2
      exit 1
    fi
  done < <(grep -E '^[[:space:]]*uses:' "$action_workflow")
done

require_release_fragment_minimum_count \
  'ref: refs/tags/${{ env.RELEASE_TAG }}' \
  1 \
  "The native release source must check out the canonical tag ref."
require_release_fragment_minimum_count \
  "fetch-depth: 0" \
  1 \
  "The tagged native checkout must include tag history."
require_release_fragment_minimum_count \
  'canonical_tag="v${package_version}"' \
  2 \
  "The release tag must be derived canonically from the package version."
require_release_fragment_minimum_count \
  'git -C native-source ls-remote --exit-code --tags origin "refs/tags/${RELEASE_TAG}"' \
  1 \
  "The native release source must verify the canonical remote tag ref."
require_release_fragment_minimum_count \
  'test "$checked_out_commit" = "$remote_tag_commit"' \
  1 \
  "The native release source must prove its checked-out commit is the remote tag commit."
require_release_fragment \
  '"$binary" init "$smoke_root" --name "Release Smoke" --json' \
  "The exact tagged native CLI must initialize an ordinary folder before publication."
require_release_fragment \
  '"$binary" validate "$smoke_root" --json' \
  "The exact tagged native CLI must validate its ordinary-folder result before publication."
require_release_fragment \
  'github_release_flags+=(--prerelease --latest=false)' \
  "Semver prereleases must create a GitHub prerelease that cannot become latest."
require_release_fragment \
  'npm_dist_tag=next' \
  "Semver prereleases must use a non-latest npm dist-tag."
require_release_fragment \
  'npm pack --dry-run --json' \
  "npm reruns must compute the exact local package integrity."
require_release_fragment \
  'npm view "$package_spec" version dist.integrity --json' \
  "npm reruns must inspect the immutable published package version."
require_release_fragment \
  'published_integrity" != "$local_integrity' \
  "npm reruns must fail closed when published and local package integrities differ."
require_release_fragment \
  'echo "skip_publish=true" >> "$GITHUB_OUTPUT"' \
  "Matching npm reruns must explicitly skip immutable-version publication."
require_release_fragment \
  'npm publish --access public --tag "$NPM_DIST_TAG"' \
  "npm publication must use the release-selected dist-tag."

echo "CI and release workflow policy is valid."
