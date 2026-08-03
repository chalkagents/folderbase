#!/usr/bin/env bash
set -euo pipefail

workflow="${CI_WORKFLOW:-.github/workflows/ci.yml}"
release_workflow="${RELEASE_WORKFLOW:-.github/workflows/release-cli.yml}"

require_file_fragment_minimum_count() {
  local file=$1
  local fragment=$2
  local minimum=$3
  local message=$4
  local actual

  actual=$(awk -v fragment="$fragment" '
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
    }
    line !~ /^#/ && index(line, fragment) {
      count += 1
    }
    END {
      print count + 0
    }
  ' "$file")
  if [[ "$actual" -lt "$minimum" ]]; then
    printf '%s (expected at least %s, found %s)\n' \
      "$message" "$minimum" "$actual" >&2
    exit 1
  fi
}

reject_workflow_job_fragment() {
  local file=$1
  local job_name=$2
  local fragment=$3
  local message=$4

  if awk -v job_name="$job_name" -v fragment="$fragment" '
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
  ' "$file"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_workflow_job_exact_line() {
  local file=$1
  local job_name=$2
  local exact_line=$3
  local message=$4

  if ! awk -v job_name="$job_name" -v exact_line="$exact_line" '
    $0 == "  " job_name ":" {
      in_job = 1
      next
    }
    in_job && $0 ~ /^  [^ ]/ {
      exit
    }
    in_job && $0 == exact_line {
      count += 1
    }
    END {
      exit count == 1 ? 0 : 1
    }
  ' "$file"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_fragment() {
  local fragment=$1
  local message=$2

  require_file_fragment_minimum_count "$release_workflow" "$fragment" 1 "$message"
}

require_release_fragment_minimum_count() {
  local fragment=$1
  local minimum=$2
  local message=$3

  require_file_fragment_minimum_count \
    "$release_workflow" "$fragment" "$minimum" "$message"
}

require_script_fragment() {
  local script=$1
  local fragment=$2
  local message=$3

  require_file_fragment_minimum_count "$script" "$fragment" 1 "$message"
}

require_script_fragment_minimum_count() {
  local script=$1
  local fragment=$2
  local minimum=$3
  local message=$4

  require_file_fragment_minimum_count "$script" "$fragment" "$minimum" "$message"
}

require_release_step_exact_run() {
  local step_name=$1
  local entrypoint=$2
  local message=$3

  if ! awk -v step_name="$step_name" -v entrypoint="$entrypoint" '
    $0 == "      - name: " step_name {
      step_count += 1
      in_step = 1
      next
    }
    in_step && $0 ~ /^      - name:/ {
      in_step = 0
    }
    in_step && $0 ~ /^        run[[:space:]]*:/ {
      run_count += 1
      if ($0 == "        run: " entrypoint) {
        exact_run_count += 1
      }
    }
    END {
      exit step_count == 1 && run_count == 1 && exact_run_count == 1 ? 0 : 1
    }
  ' "$release_workflow"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_step_exact_line() {
  local step_name=$1
  local exact_line=$2
  local message=$3

  if ! awk -v step_name="$step_name" -v exact_line="$exact_line" '
    $0 == "      - name: " step_name {
      in_step = 1
      next
    }
    in_step && $0 ~ /^      - name:/ {
      exit
    }
    in_step && $0 == exact_line {
      count += 1
    }
    END {
      exit count == 1 ? 0 : 1
    }
  ' "$release_workflow"; then
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
    in_step && line !~ /^#/ && index(line, fragment) {
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
  ' "$release_workflow"; then
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
  ' "$release_workflow"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_job_exact_line() {
  local job_name=$1
  local exact_line=$2
  local message=$3

  if ! awk -v job_name="$job_name" -v exact_line="$exact_line" '
    $0 == "  " job_name ":" {
      in_job = 1
      next
    }
    in_job && $0 ~ /^  [^ ]/ {
      exit
    }
    in_job && $0 == exact_line {
      count += 1
    }
    END {
      exit count == 1 ? 0 : 1
    }
  ' "$release_workflow"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

require_release_script() {
  local script=$1

  if [[ ! -x "$script" ]]; then
    printf 'Release entrypoint must exist and be executable: %s\n' "$script" >&2
    exit 1
  fi
  bash -n "$script"
}

require_sealed_release_control() {
  local file=$1
  local expected_sha256=$2
  local actual_sha256

  if [[ ! -f "$file" ]]; then
    printf 'Missing sealed release control: %s\n' "$file" >&2
    exit 1
  fi
  actual_sha256="$(
    node -e '
      const { createHash } = require("node:crypto");
      const { readFileSync } = require("node:fs");
      process.stdout.write(createHash("sha256").update(readFileSync(process.argv[1])).digest("hex"));
    ' "$file"
  )"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    printf 'Unreviewed sealed release control bytes: %s\n' "$file" >&2
    printf 'Expected SHA-256 %s, found %s.\n' \
      "$expected_sha256" "$actual_sha256" >&2
    exit 1
  fi
}

if ! grep -Fqx "  pull_request:" "$workflow"; then
  echo "CI must run for pull requests." >&2
  exit 1
fi

if ! grep -Fqx "  cancel-in-progress: true" "$workflow"; then
  echo "CI must cancel superseded CI runs." >&2
  exit 1
fi

for required_ci_line in \
  '  schedule:' \
  '  workflow_dispatch:' \
  '  group: ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.event_name }}-${{ github.ref }}'
do
  if ! grep -Fqx "$required_ci_line" "$workflow"; then
    printf 'CI optimization control is missing: %s\n' "$required_ci_line" >&2
    exit 1
  fi
done

require_file_fragment_minimum_count \
  "$workflow" \
  "scripts/ci/classify-changes.mjs" \
  3 \
  "CI must classify changed paths and fail safe to full confidence."

require_file_fragment_minimum_count \
  "$workflow" \
  "protocol/conformance/capabilities/run.mjs" \
  1 \
  "CI must run every advertised optional-capability profile."
require_file_fragment_minimum_count \
  "$workflow" \
  "protocol/conformance/capabilities/run.test.mjs" \
  1 \
  "CI must test optional-capability selection."
require_file_fragment_minimum_count \
  "$workflow" \
  "scripts/tests/capability-contract.test.mjs" \
  1 \
  "CI must test the public capability registry contract."
require_release_fragment \
  "native-source/protocol/conformance/capabilities/run.mjs" \
  "Native releases must pass every advertised capability suite."
require_release_fragment \
  "protocol/conformance/capabilities/run.test.mjs" \
  "Release policy must test optional-capability selection."

reject_workflow_job_fragment \
  "$workflow" \
  "rust" \
  "scripts/test-package-install.sh" \
  "Fresh installation proof must remain in its separate scoped job."
require_workflow_job_exact_line \
  "$workflow" \
  "docs" \
  "    if: needs.plan.outputs.docs == 'true'" \
  "The documentation lane must remain change-aware."
for docs_gate_line in \
  "        run: node --test scripts/tests/docs-site.test.mjs" \
  "        run: npm ci --prefix apps/docs" \
  "        run: npm test --prefix apps/docs"
do
  require_workflow_job_exact_line \
    "$workflow" \
    "docs" \
    "$docs_gate_line" \
    "The documentation gate must retain policy, locked install, and production-build verification."
done
require_workflow_job_exact_line \
  "$workflow" \
  "npm-cli" \
  "    if: needs.plan.outputs.npm == 'true'" \
  "The npm lane must remain change-aware."
require_workflow_job_exact_line \
  "$workflow" \
  "npm-cli" \
  "        run: node --test protocol/conformance/capabilities/query-index-0.1/suite.test.mjs" \
  "The optional capability contract suite must remain policy-pinned in CI."
require_workflow_job_exact_line \
  "$workflow" \
  "rust" \
  "    if: needs.plan.outputs.rust == 'true'" \
  "The Linux Core lane must remain change-aware."
require_workflow_job_exact_line \
  "$workflow" \
  "package-install" \
  "    if: needs.plan.outputs.install == 'true'" \
  "Fresh installation proof must remain change-aware."
require_workflow_job_exact_line \
  "$workflow" \
  "package-install" \
  "        run: scripts/test-package-install.sh" \
  "Fresh installation proof must remain in its scoped job."
require_workflow_job_exact_line \
  "$workflow" \
  "core-platforms" \
  "    if: github.event_name != 'pull_request' && needs.plan.outputs.platform == 'true'" \
  "Cross-platform runners must not run for pull requests."
require_workflow_job_exact_line \
  "$workflow" \
  "core-platforms" \
  "        run: cargo build --package folderbase-cli --locked" \
  "Native post-merge runners must build the actual query CLI candidate."
require_workflow_job_exact_line \
  "$workflow" \
  "core-platforms" \
  "        run: node protocol/conformance/capabilities/query-index-0.1/run.mjs --implementation ./target/debug/folderbase\${{ runner.os == 'Windows' && '.exe' || '' }}" \
  "Native post-merge runners must conform the actual optional query CLI candidate."
require_workflow_job_exact_line \
  "$workflow" \
  "required" \
  "    name: Rust quality gate" \
  "The protected required-check name must remain stable."
require_workflow_job_exact_line \
  "$workflow" \
  "required" \
  "    needs: [plan, docs, npm-cli, rust, package-install, core-platforms]" \
  "The required check must aggregate every CI lane."
require_workflow_job_exact_line \
  "$workflow" \
  "required" \
  "    if: always()" \
  "The required check must report dependency failures and skips."
require_workflow_job_exact_line \
  "$workflow" \
  "required" \
  "        run: node scripts/ci/verify-required-results.mjs" \
  "The required check must verify scoped CI results."

for required_result_line in \
  '      DOCS_REQUIRED: ${{ needs.plan.outputs.docs }}' \
  '      NPM_REQUIRED: ${{ needs.plan.outputs.npm }}' \
  '      RUST_REQUIRED: ${{ needs.plan.outputs.rust }}' \
  '      INSTALL_REQUIRED: ${{ needs.plan.outputs.install }}' \
  "      PLATFORM_REQUIRED: \${{ github.event_name != 'pull_request' && needs.plan.outputs.platform == 'true' }}"
do
  require_workflow_job_exact_line \
    "$workflow" \
    "required" \
    "$required_result_line" \
    "The required check must compare its result with the CI plan."
done

for dependency_result_line in \
  '      PLAN_RESULT: ${{ needs.plan.result }}' \
  '      DOCS_RESULT: ${{ needs.docs.result }}' \
  '      NPM_RESULT: ${{ needs.npm-cli.result }}' \
  '      RUST_RESULT: ${{ needs.rust.result }}' \
  '      INSTALL_RESULT: ${{ needs.package-install.result }}' \
  '      PLATFORM_RESULT: ${{ needs.core-platforms.result }}'
do
  require_workflow_job_exact_line \
    "$workflow" \
    "required" \
    "$dependency_result_line" \
    "The required check must use the real dependency results."
done

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

if grep -Eq '(^|[^[:alnum:]_])gh([^[:alnum:]_]|$)' "$release_workflow" ||
  grep -Eq 'repos/[^[:space:]]*/releases|api\.github\.com/[^[:space:]]*/releases' "$release_workflow"; then
  echo "Raw workflow steps cannot contain GitHub release operations." >&2
  exit 1
fi

immutable_script="scripts/release/require-immutable-releases.sh"
decision_script="scripts/release/decide-publication-state.sh"
publication_script="scripts/release/publish-github-release.sh"
require_release_script "$immutable_script"
require_release_script "$decision_script"
require_release_script "$publication_script"

require_release_step_exact_run \
  "Require repository immutable releases" \
  "$immutable_script" \
  "The immutable-release preflight must have exactly one run key naming its dedicated entrypoint."
require_release_step_exact_run \
  "Check immutable npm publication state" \
  "$decision_script" \
  "The registry-state decision must have exactly one run key naming its dedicated entrypoint."
require_release_step_exact_run \
  "Publish GitHub release artifacts" \
  "$publication_script" \
  "GitHub publication must have exactly one run key naming its dedicated entrypoint."
require_release_step_before \
  "Require repository immutable releases" \
  "Check immutable npm publication state" \
  "The immutable-release preflight must precede the registry-state decision."
require_release_step_before \
  "Check immutable npm publication state" \
  "Publish GitHub release artifacts" \
  "The registry-state decision must precede GitHub publication."

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

require_release_step_exact_line \
  "Require repository immutable releases" \
  '          GH_TOKEN: ${{ secrets.FOLDERBASE_IMMUTABLE_RELEASES_READ_TOKEN }}' \
  "The immutable-release preflight requires the Administration-read token."
reject_release_step_fragment \
  "Require repository immutable releases" \
  "continue-on-error: true" \
  "The immutable-release preflight must fail closed."
require_release_step_exact_line \
  "Check immutable npm publication state" \
  '          GH_TOKEN: ${{ github.token }}' \
  "GitHub Latest reads must use the short-lived workflow token."
require_release_step_exact_line \
  "Publish GitHub release artifacts" \
  '          GH_TOKEN: ${{ github.token }}' \
  "GitHub release writes must use the short-lived workflow token."
require_release_step_exact_line \
  "Publish GitHub release artifacts" \
  '          GITHUB_LATEST: ${{ steps.npm-publication.outputs.advance_github_latest }}' \
  "GitHub Latest must consume its independent registry-state decision."

require_release_job_exact_line \
  "publish" \
  "      group: folderbase-publication" \
  "GitHub and npm publication must be serialized in one shared concurrency group."
require_release_job_exact_line \
  "publish" \
  "      cancel-in-progress: false" \
  "A publication in progress must never be cancelled by another release."
require_release_job_exact_line \
  "publish" \
  "      queue: max" \
  "The serialized publication group must retain the maximal waiter queue."

require_release_step_fragment \
  "Select stable or prerelease publication channels" \
  'node scripts/npm-publication-policy.mjs classify "$package_version"' \
  "Stable and prerelease channels must use the tested SemVer parser."
require_release_step_exact_run \
  "Publish the public npm launcher" \
  'npm publish --access public --tag "$PUBLISH_TAG"' \
  "npm publication must use exactly the policy-selected non-regressing tag."
require_release_step_exact_run \
  "Remove the temporary npm backfill tag" \
  'npm dist-tag rm @folderbase/cli "$CLEANUP_TAG"' \
  "Older npm backfills must exactly remove their temporary non-channel tag."

require_script_fragment \
  "$immutable_script" \
  'gh api "repos/$GITHUB_REPOSITORY/immutable-releases" --jq '\''.enabled'\''' \
  "The immutable-release entrypoint must inspect the repository setting."
require_script_fragment \
  "$immutable_script" \
  ')" = true' \
  "The immutable-release entrypoint must require literal true."
require_script_fragment \
  "$decision_script" \
  'gh api "repos/$GITHUB_REPOSITORY/releases/latest" --jq '\''.tag_name'\''' \
  "GitHub Latest state must be read independently under the publication lock."
require_script_fragment \
  "$decision_script" \
  'npm pack --dry-run --json' \
  "npm reruns must compute the exact local package integrity."
require_script_fragment \
  "$decision_script" \
  'npm view "$package_spec" version dist.integrity --json' \
  "npm reruns must inspect the immutable published package version."
require_script_fragment \
  "$decision_script" \
  'node "$repository_root/scripts/npm-publication-policy.mjs"' \
  "The registry-state entrypoint must apply the tested publication policy."
require_script_fragment \
  "$decision_script" \
  '.advanceChannel' \
  "The tested decision must expose whether the npm channel may advance."
require_script_fragment \
  "$decision_script" \
  '.advanceGithubLatest' \
  "The tested decision must expose whether GitHub Latest may advance."
require_script_fragment \
  "$publication_script" \
  'github_release_flags=(--draft --latest="$GITHUB_LATEST")' \
  "New GitHub releases must be assembled as drafts."
require_script_fragment_minimum_count \
  "$publication_script" \
  '--latest="$GITHUB_LATEST"' \
  2 \
  "GitHub Latest must be set explicitly for new and resumed releases."
require_script_fragment \
  "$publication_script" \
  'github_release_flags+=(--prerelease)' \
  "SemVer prereleases must create a GitHub prerelease."
require_script_fragment \
  "$publication_script" \
  'GITHUB_LATEST=false' \
  "GitHub prereleases must never become Latest."
require_script_fragment \
  "$publication_script" \
  "--json isImmutable --jq '.isImmutable'" \
  "The publication entrypoint must prove the final release is immutable."

# The text checks above retain focused diagnostics. This exact-byte seal is the
# fail-closed boundary: YAML aliases, quoted duplicate keys, conditionals, shell
# escapes, or policy-script changes cannot silently alter release authority.
require_sealed_release_control \
  "$release_workflow" \
  "ae981a245e544527880673b8dceb5854e512dd46e2e4fd61ca8b827c483de91b"
require_sealed_release_control \
  "$immutable_script" \
  "1898cdb0efcb49cbf346d7057cac0dc34e838305ec8b14a7bd42082e20ffe627"
require_sealed_release_control \
  "$decision_script" \
  "2210a59d942bbd49132c3ddb639379ecb8498e1e45177b81af5cb712d3080e9c"
require_sealed_release_control \
  "$publication_script" \
  "5a9e8cc98c5b250a36180be1beb29b2657cd77f7bbbe2980040e5a9ac9fd63bb"
require_sealed_release_control \
  "scripts/npm-publication-policy.mjs" \
  "7d3682901f38b1fba7afe066ed479cd41bb4279de0ad56872c9d7f13ca8cd643"

echo "CI and release workflow policy is valid."
