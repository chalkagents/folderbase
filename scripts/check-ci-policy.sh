#!/usr/bin/env bash
set -euo pipefail

workflow="${CI_WORKFLOW:-.github/workflows/ci.yml}"
release_workflow="${RELEASE_WORKFLOW:-.github/workflows/release-cli.yml}"
active_release_workflow="$(mktemp)"
trap 'rm -f "$active_release_workflow"' EXIT

awk '
  function without_unquoted_comment(value, i, character, previous, in_single, in_double, escaped, single_quote) {
    single_quote = sprintf("%c", 39)
    for (i = 1; i <= length(value); i += 1) {
      character = substr(value, i, 1)
      previous = i == 1 ? "" : substr(value, i - 1, 1)
      if (escaped) {
        escaped = 0
        continue
      }
      if (in_double && character == "\\") {
        escaped = 1
        continue
      }
      if (!in_double && character == single_quote) {
        in_single = !in_single
        continue
      }
      if (!in_single && character == "\"") {
        in_double = !in_double
        continue
      }
      if (!in_single && !in_double && character == "#" && (i == 1 || previous ~ /[[:space:]|&;()<>]/)) {
        return substr(value, 1, i - 1)
      }
    }
    return value
  }
  { print without_unquoted_comment($0) }
' "$release_workflow" > "$active_release_workflow"

require_release_fragment() {
  local fragment=$1
  local message=$2

  if ! awk -v fragment="$fragment" '
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
    }
    line !~ /^#/ && line !~ /^run:[[:space:]]*#/ && index(line, fragment) {
      found = 1
    }
    END {
      exit found ? 0 : 1
    }
  ' "$active_release_workflow"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_fragment_minimum_count() {
  local fragment=$1
  local minimum=$2
  local message=$3
  local actual

  actual=$(awk -v fragment="$fragment" '
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
    }
    line !~ /^#/ && line !~ /^run:[[:space:]]*#/ && index(line, fragment) {
      count += 1
    }
    END {
      print count + 0
    }
  ' "$active_release_workflow")
  if [[ "$actual" -lt "$minimum" ]]; then
    printf '%s (expected at least %s, found %s)\n' \
      "$message" "$minimum" "$actual" >&2
    exit 1
  fi
}

require_release_step_fragment_minimum_count() {
  local step_name=$1
  local fragment=$2
  local minimum=$3
  local message=$4
  local actual

  actual=$(awk -v step_name="$step_name" -v fragment="$fragment" '
    $0 == "      - name: " step_name {
      in_step = 1
      next
    }
    in_step && $0 ~ /^      - name:/ {
      exit
    }
    in_step {
      line = $0
      sub(/^[[:space:]]*/, "", line)
    }
    in_step && line !~ /^#/ && line !~ /^run:[[:space:]]*#/ && index(line, fragment) {
      count += 1
    }
    END {
      print count + 0
    }
  ' "$active_release_workflow")
  if [[ "$actual" -lt "$minimum" ]]; then
    printf '%s (expected at least %s, found %s)\n' \
      "$message" "$minimum" "$actual" >&2
    exit 1
  fi
}

reject_release_step_fragment() {
  local step_name=$1
  local fragment=$2
  local message=$3

  if awk -v step_name="$step_name" -v fragment="$fragment" '
    $0 == "      - name: " step_name {
      in_step = 1
      next
    }
    in_step && $0 ~ /^      - name:/ {
      exit
    }
    in_step {
      line = $0
      sub(/^[[:space:]]*/, "", line)
    }
    in_step && line !~ /^#/ && index(line, fragment) {
      found = 1
    }
    END {
      exit found ? 0 : 1
    }
  ' "$active_release_workflow"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_step_before() {
  local first_step=$1
  local second_step=$2
  local message=$3

  if ! awk -v first_step="$first_step" -v second_step="$second_step" '
    $0 == "      - name: " first_step && !first_seen {
      first_seen = NR
    }
    $0 == "      - name: " second_step && !second_seen {
      second_seen = NR
    }
    END {
      exit first_seen && second_seen && first_seen < second_seen ? 0 : 1
    }
  ' "$active_release_workflow"; then
    printf '%s\n' "$message" >&2
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
    in_step {
      line = $0
      sub(/^[[:space:]]*/, "", line)
    }
    in_step && line !~ /^#/ && line !~ /^run:[[:space:]]*#/ && index(line, fragment) {
      found = 1
    }
    END {
      exit found ? 0 : 1
    }
  ' "$active_release_workflow"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_job_fragment() {
  local job_name=$1
  local fragment=$2
  local message=$3

  if ! awk -v job_name="$job_name" -v fragment="$fragment" '
    $0 == "  " job_name ":" {
      in_job = 1
      next
    }
    in_job && $0 ~ /^  [^ ]/ {
      exit
    }
    in_job {
      line = $0
      sub(/^[[:space:]]*/, "", line)
    }
    in_job && line !~ /^#/ && index(line, fragment) {
      found = 1
    }
    END {
      exit found ? 0 : 1
    }
  ' "$active_release_workflow"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_fragment_only_after_fragment() {
  local gate_fragment=$1
  local guarded_fragment=$2
  local message=$3

  if ! awk -v gate_fragment="$gate_fragment" -v guarded_fragment="$guarded_fragment" '
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
    }
    index(line, guarded_fragment) && !gate_seen {
      invalid = 1
    }
    index(line, gate_fragment) {
      gate_seen = 1
    }
    END {
      exit !gate_seen || invalid ? 1 : 0
    }
  ' "$active_release_workflow"; then
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
  'github_release_flags+=(--prerelease)' \
  "Semver prereleases must create a GitHub prerelease that cannot become latest."
require_release_step_fragment \
  "Publish GitHub release artifacts" \
  "--json isImmutable --jq '.isImmutable'" \
  "The publication step must prove the final GitHub release is immutable."
require_release_step_fragment \
  "Publish GitHub release artifacts" \
  'GITHUB_LATEST: ${{ steps.npm-publication.outputs.advance_github_latest }}' \
  "GitHub Latest must consume the tested monotonic channel decision."
require_release_step_fragment_minimum_count \
  "Publish GitHub release artifacts" \
  '--latest="$GITHUB_LATEST"' \
  2 \
  "GitHub Latest must be set explicitly for new and resumed releases."
require_release_step_fragment \
  "Publish GitHub release artifacts" \
  'GITHUB_LATEST=false' \
  "GitHub prereleases must never become Latest."
require_release_step_fragment \
  "Publish GitHub release artifacts" \
  'github_release_flags=(--draft --latest="$GITHUB_LATEST")' \
  "New GitHub releases must be assembled as drafts before publication."
require_release_step_fragment \
  "Require repository immutable releases" \
  'gh api "repos/$GITHUB_REPOSITORY/immutable-releases" --jq '\''.enabled'\''' \
  "Repository immutability must be required before publication begins."
require_release_step_fragment \
  "Require repository immutable releases" \
  'GH_TOKEN: ${{ secrets.FOLDERBASE_IMMUTABLE_RELEASES_READ_TOKEN }}' \
  "The immutable-release preflight requires a repository-scoped Administration-read token."
require_release_step_fragment \
  "Require repository immutable releases" \
  ')" = true' \
  "The immutable-release setting must equal literal true."
reject_release_step_fragment \
  "Require repository immutable releases" \
  "continue-on-error: true" \
  "The immutable-release preflight must fail closed."
require_release_step_fragment \
  "Publish GitHub release artifacts" \
  'GH_TOKEN: ${{ github.token }}' \
  "GitHub release writes must use the short-lived workflow token."
require_release_step_fragment \
  "Check immutable npm publication state" \
  'GH_TOKEN: ${{ github.token }}' \
  "GitHub Latest reads must use the short-lived workflow token."
require_release_fragment_only_after_fragment \
  ')" = true' \
  "gh release " \
  "Every GitHub release operation must occur after the immutable-release proof."
require_release_job_fragment \
  "publish" \
  "group: folderbase-publication" \
  "GitHub and npm publication must be serialized in one shared concurrency group."
require_release_job_fragment \
  "publish" \
  "cancel-in-progress: false" \
  "A publication in progress must never be cancelled by another release."
require_release_job_fragment \
  "publish" \
  "queue: max" \
  "The serialized publication group must retain the maximal waiter queue."
require_release_step_before \
  "Check immutable npm publication state" \
  "Publish GitHub release artifacts" \
  "The monotonic npm/GitHub channel decision must precede GitHub publication."
require_release_fragment_only_after_fragment \
  'echo "advance_github_latest=' \
  "gh release " \
  "Every GitHub release operation must follow the monotonic channel decision."
require_release_step_fragment \
  "Select stable or prerelease publication channels" \
  'node scripts/npm-publication-policy.mjs classify "$package_version"' \
  "Stable and prerelease channels must use the tested SemVer parser."
require_release_step_fragment \
  "Check immutable npm publication state" \
  'gh api "repos/$GITHUB_REPOSITORY/releases/latest" --jq '\''.tag_name'\''' \
  "GitHub Latest state must be read independently under the publication lock."
require_release_step_fragment \
  "Check immutable npm publication state" \
  ".advanceChannel" \
  "The tested publication decision must expose whether the npm channel may advance."
require_release_step_fragment \
  "Check immutable npm publication state" \
  ".advanceGithubLatest" \
  "The tested publication decision must expose whether GitHub Latest may advance."
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
