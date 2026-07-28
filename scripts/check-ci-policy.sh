#!/usr/bin/env bash
set -euo pipefail

workflow=".github/workflows/ci.yml"

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

while IFS= read -r action_line
do
  action_reference=${action_line#*@}
  action_reference=${action_reference%% *}
  if [[ ! "$action_reference" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'CI action is not pinned to an immutable commit: %s\n' \
      "$action_line" >&2
    exit 1
  fi
done < <(grep -E '^[[:space:]]*uses:' "$workflow")

echo "CI trigger policy is valid."
