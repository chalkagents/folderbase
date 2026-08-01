#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${NPM_DIST_TAG:?NPM_DIST_TAG is required}"

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"
cd "$repository_root/packages/npm-cli"

package_name="$(node -p "require('./package.json').name")"
package_version="$(node -p "require('./package.json').version")"
package_spec="${package_name}@${package_version}"
local_integrity="$(
  npm pack --dry-run --json |
    node -e 'let input = ""; process.stdin.on("data", chunk => input += chunk); process.stdin.on("end", () => process.stdout.write(JSON.parse(input)[0].integrity));'
)"
published_version=""
published_integrity=""
view_error="$(mktemp)"
github_error="$(mktemp)"
trap 'rm -f "$view_error" "$github_error"' EXIT

github_latest_version=""
if github_latest_tag="$(
  gh api "repos/$GITHUB_REPOSITORY/releases/latest" --jq '.tag_name' 2>"$github_error"
)"; then
  if [[ "$github_latest_tag" != v* ]]; then
    echo "GitHub Latest tag is not canonical: $github_latest_tag" >&2
    exit 1
  fi
  github_latest_version="${github_latest_tag#v}"
elif ! grep -Eq 'HTTP 404|Not Found' "$github_error"; then
  cat "$github_error" >&2
  exit 1
fi

if published_metadata="$(
  npm view "$package_spec" version dist.integrity --json 2>"$view_error"
)"; then
  published_version="$(
    printf '%s' "$published_metadata" |
      node -e 'let input = ""; process.stdin.on("data", chunk => input += chunk); process.stdin.on("end", () => process.stdout.write(JSON.parse(input).version || ""));'
  )"
  published_integrity="$(
    printf '%s' "$published_metadata" |
      node -e 'let input = ""; process.stdin.on("data", chunk => input += chunk); process.stdin.on("end", () => process.stdout.write(JSON.parse(input)["dist.integrity"] || ""));'
  )"
else
  if ! grep -Eq 'E404|404 Not Found' "$view_error"; then
    cat "$view_error" >&2
    exit 1
  fi
fi

if ! dist_tags="$(npm view "$package_name" dist-tags --json 2>"$view_error")"; then
  if grep -Eq 'E404|404 Not Found' "$view_error"; then
    dist_tags='{}'
  else
    cat "$view_error" >&2
    exit 1
  fi
fi

decision="$(
  jq -n \
    --arg packageVersion "$package_version" \
    --arg channel "$NPM_DIST_TAG" \
    --arg localIntegrity "$local_integrity" \
    --arg publishedVersion "$published_version" \
    --arg publishedIntegrity "$published_integrity" \
    --arg githubLatestVersion "$github_latest_version" \
    --argjson distTags "$dist_tags" \
    '{
      packageVersion: $packageVersion,
      channel: $channel,
      localIntegrity: $localIntegrity,
      publishedVersion: (if $publishedVersion == "" then null else $publishedVersion end),
      publishedIntegrity: (if $publishedIntegrity == "" then null else $publishedIntegrity end),
      githubLatestVersion: (if $githubLatestVersion == "" then null else $githubLatestVersion end),
      distTags: $distTags
    }' |
    node "$repository_root/scripts/npm-publication-policy.mjs"
)"

echo "skip_publish=$(printf '%s' "$decision" | jq -r '.skipPublish')" >> "$GITHUB_OUTPUT"
echo "publish_tag=$(printf '%s' "$decision" | jq -r '.publishTag // ""')" >> "$GITHUB_OUTPUT"
echo "cleanup_tag=$(printf '%s' "$decision" | jq -r '.cleanupTag // ""')" >> "$GITHUB_OUTPUT"
echo "advance_channel=$(printf '%s' "$decision" | jq -r '.advanceChannel')" >> "$GITHUB_OUTPUT"
echo "advance_github_latest=$(printf '%s' "$decision" | jq -r '.advanceGithubLatest')" >> "$GITHUB_OUTPUT"
