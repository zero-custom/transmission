#!/usr/bin/env bash
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-zero-custom/transmission}"
UPSTREAM_REPO="transmission/transmission"
MANUAL_TAG="${1:-}"
FORCE="${2:-0}"

if [ -n "$MANUAL_TAG" ]; then
  if [ "$FORCE" != "1" ] && gh release list --repo "$REPO" --json tagName \
      --jq ".[].tagName | select(test(\"^${MANUAL_TAG}-p[0-9]+\$\"))" | grep -q .; then
    echo "::notice::$MANUAL_TAG already built; pass force=true to rebuild" >&2
    printf '["__skip__"]\n'
    exit 0
  fi
  printf '["%s"]\n' "$MANUAL_TAG"
  exit 0
fi

mapfile -t upstream_tags < <(
  gh api "repos/$UPSTREAM_REPO/releases" --paginate \
    --jq '.[] | select(.draft == false and .prerelease == false) | .tag_name' | head -10
)
built_tags="$(gh release list --repo "$REPO" --json tagName --jq '.[].tagName')"

to_build=()
for t in "${upstream_tags[@]:-}"; do
  [ -n "$t" ] || continue
  if ! printf '%s\n' "$built_tags" | grep -E "^${t}-p[0-9]+$" >/dev/null; then
    to_build+=("$t")
  fi
done

if [ "${#to_build[@]}" -eq 0 ]; then
  printf '["__skip__"]\n'
else
  printf '%s\n' "${to_build[@]}" | jq -R . | jq -s .
fi
