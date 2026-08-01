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

require_release_step_fragment() {
  local step_name=$1
  local fragment=$2
  local message=$3

  if ! awk -v step_name="$step_name" -v fragment="$fragment" '
    $0 == "      - name: " step_name {
      in_step = 1
      next
    }
    in_step && $0 ~ /^      - name:/ {
      exit
    }
    in_step && index($0, fragment) {
      found = 1
    }
    END {
      exit found ? 0 : 1
    }
  ' "$release_workflow"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_step_fragment_before() {
  local step_name=$1
  local required_fragment=$2
  local boundary_fragment=$3
  local message=$4

  if ! awk -v step_name="$step_name" -v required="$required_fragment" -v boundary="$boundary_fragment" '
    $0 == "      - name: " step_name {
      in_step = 1
      next
    }
    in_step && $0 ~ /^      - name:/ {
      exit
    }
    in_step && index($0, required) && !boundary_seen {
      found = 1
    }
    in_step && index($0, boundary) {
      boundary_seen = 1
    }
    END {
      exit found ? 0 : 1
    }
  ' "$release_workflow"; then
    printf '%s\n' "$message" >&2
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
require_release_step_fragment \
  "Publish GitHub release artifacts" \
  'github_release_flags+=(--prerelease --latest=false)' \
  "Semver prereleases must create a GitHub prerelease that cannot become latest."
require_release_fragment \
  'npm_dist_tag=next' \
  "Semver prereleases must use a non-latest npm dist-tag."
require_release_step_fragment \
  "Publish GitHub release artifacts" \
  "--json isImmutable --jq '.isImmutable'" \
  "The publication step must prove the final GitHub release is immutable."
require_release_step_fragment \
  "Publish GitHub release artifacts" \
  'github_release_flags=(--draft)' \
  "New GitHub releases must be assembled as drafts before publication."
require_release_step_fragment_before \
  "Publish GitHub release artifacts" \
  'gh api "repos/$GITHUB_REPOSITORY/immutable-releases" --jq '\''.enabled'\''' \
  'if gh release view "$RELEASE_TAG"' \
  "Repository immutability must be required before publication begins."
require_release_step_fragment \
  "Check immutable npm publication state" \
  'npm pack --dry-run --json' \
  "npm reruns must compute the exact local package integrity."
require_release_step_fragment \
  "Check immutable npm publication state" \
  'npm view "$package_spec" version dist.integrity --json' \
  "npm reruns must inspect the immutable published package version."
require_release_step_fragment \
  "Check immutable npm publication state" \
  'node ../../scripts/npm-publication-policy.mjs' \
  "The immutable npm check must apply the tested monotonic publication policy."
require_release_step_fragment \
  "Publish the public npm launcher" \
  'npm publish --access public --tag "$PUBLISH_TAG"' \
  "npm publication must use the policy-selected non-regressing tag."
require_release_step_fragment \
  "Remove the temporary npm backfill tag" \
  'npm dist-tag rm @folderbase/cli "$CLEANUP_TAG"' \
  "Older npm backfills must remove their temporary non-channel tag."

echo "CI and release workflow policy is valid."
