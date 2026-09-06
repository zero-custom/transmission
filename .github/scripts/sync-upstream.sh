#!/usr/bin/env bash
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-zero-custom/transmission}"
UPSTREAM_URL="https://github.com/transmission/transmission.git"
PATCH_DIR="patches"

# --- helpers ---------------------------------------------------------------
create_or_update_issue() { # title, body
  local title="$1" body="$2"
  local existing
  existing="$(gh issue list --repo "$REPO" --search "in:title \"$title\"" \
    --state open --json number --jq '.[0].number // empty')"
  if [ -n "$existing" ]; then
    gh issue edit "$existing" --repo "$REPO" --body "$body" >/dev/null
    echo "::notice::updated issue #$existing: $title"
  else
    printf '%s\n' "$body" | gh issue create --repo "$REPO" --title "$title" --body-file - >/dev/null
    echo "::notice::created issue: $title"
  fi
}

# --- fetch upstream ----------------------------------------------------------
git remote add upstream "$UPSTREAM_URL" 2>/dev/null || git remote set-url upstream "$UPSTREAM_URL"
git fetch upstream main --force --prune
echo "::notice::fetched upstream/main @ $(git rev-parse --short upstream/main)"

# --- ff-first, rebase fallback ----------------------------------------------
if git merge --ff-only upstream/main >/dev/null 2>&1; then
  echo "::notice::fast-forwarded to upstream/main"
elif git rebase upstream/main; then
  echo "::notice::rebased fork main onto upstream/main"
else
  git rebase --abort 2>/dev/null || true
  create_or_update_issue \
    "sync: rebase conflict against upstream main" \
    "fork main could not be rebased onto upstream/main. Resolve locally or wait for the next scheduled sync."
  exit 1
fi

# --- validate patches ----------------------------------------------------------
failures=0
failed_list=""
for patch in "$PATCH_DIR"/*.patch; do
  [ -e "$patch" ] || { echo "::error::no patches found in $PATCH_DIR"; exit 1; }
  if git apply --check "$patch" >/dev/null 2>&1; then
    echo "::notice::patch OK: $(basename "$patch")"
  else
    echo "::error::patch does not apply cleanly: $(basename "$patch")"
    failures=$((failures + 1))
    failed_list="${failed_list}- $(basename "$patch")\n"
  fi
done

if [ "$failures" -gt 0 ]; then
  create_or_update_issue \
    "sync: $failures patch(es) conflict with upstream main" \
    "The following patches no longer apply cleanly on upstream/main:\n\n$failed_list\nFix or update them in $PATCH_DIR, then re-run this workflow."
  echo "::error::patch validation failed; fork main NOT pushed"
  exit 1
fi

git push origin main --force-with-lease
echo "::notice::fork main synced to upstream/main"
