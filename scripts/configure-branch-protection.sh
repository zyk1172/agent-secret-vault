#!/usr/bin/env bash
set -euo pipefail

# Run this only after the CI workflow has landed on main. It deliberately
# requires an authenticated gh CLI and never changes repository settings
# through an unscoped token or a silent fallback.
if ! command -v gh >/dev/null 2>&1; then
  echo "需要 gh CLI 才能配置 branch protection。" >&2
  exit 2
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "gh CLI 尚未登录，拒绝修改 branch protection。" >&2
  exit 2
fi

REPOSITORY="${GH_REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
BRANCH="${GH_BRANCH:-main}"

gh api --method PUT "repos/$REPOSITORY/branches/$BRANCH/protection" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Swift tests",
      "MCP typecheck and tests",
      "Obsidian typecheck and tests",
      "Security and repository checks"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_linear_history": false
}
JSON

echo "已为 $REPOSITORY:$BRANCH 启用标准安全保护。"
