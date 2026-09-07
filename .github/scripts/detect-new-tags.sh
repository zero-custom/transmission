#!/usr/bin/env bash
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-zero-custom/transmission}"
UPSTREAM_REPO="transmission/transmission"
MANUAL_TAG="${1:-}"
FORCE="${2:-0}"

version_gt() { # a b: 0 if a > b（语义化版本比较）
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

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

# 基线 = fork 已发布（-pN）的最大 base 版本；旧版本（<= 基线）不做 backport，跳过
baseline="$(printf '%s\n' "$built_tags" | sed -nE 's/^([0-9]+\.[0-9]+\.[0-9]+)-p[0-9]+$/\1/p' | sort -V | tail -1)"

for t in "${upstream_tags[@]:-}"; do
  [ -n "$t" ] || continue
  printf '%s\n' "$t" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || continue
  if printf '%s\n' "$built_tags" | grep -E "^${t}-p[0-9]+$" >/dev/null; then
    continue
  fi
  if [ -n "$baseline" ] && ! version_gt "$t" "$baseline"; then
    echo "::notice::upstream tag $t <= baseline $baseline; skipped (no backport for old versions)" >&2
    continue
  fi
  printf '["%s"]\n' "$t"
  exit 0
done

printf '["__skip__"]\n'