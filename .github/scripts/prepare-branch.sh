#!/usr/bin/env bash
set -euo pipefail

TAGS_FILE="${1:?usage: prepare-branch.sh <tags.json>}"
REPO="${GITHUB_REPOSITORY:-zero-custom/transmission}"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/transmission/transmission.git}"
ROOT="$PWD"
PATCH_DIR="$ROOT/patches"

# 确保 CI 环境有提交身份
git config user.name "zero-custom bot" >/dev/null 2>&1 || true
git config user.email "actions@users.noreply.github.com" >/dev/null 2>&1 || true

version_gt() { # a b: 0 if a > b（语义化版本比较）
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

conflict_title() { printf 'build: %s - patch rebase conflict' "$1"; }

notify_conflict() { # tag, detail
  local tag="$1" detail="${2:-}" title existing body
  title="$(conflict_title "$tag")"
  existing="$(gh issue list --repo "$REPO" --search "in:title \"$title\"" \
    --state open --json number --jq '.[0].number // empty' 2>/dev/null || true)"
  body="Cherry-picking the proxy-protocol patch onto upstream **$tag** failed. Resolve the conflict and re-run the workflow, or push a fixed \`$tag\` branch. $detail"
  if [ -n "$existing" ]; then
    gh issue edit "$existing" --repo "$REPO" --body "$body" >/dev/null 2>&1 || true
  else
    printf '%s\n' "$body" | gh issue create --repo "$REPO" --title "$title" --body-file - >/dev/null 2>&1 || true
  fi
}

close_conflict_issue() { # tag
  local tag="$1" title n
  title="$(conflict_title "$tag")"
  while read -r n; do
    [ -n "$n" ] && gh issue close "$n" --repo "$REPO" >/dev/null 2>&1 || true
  done < <(gh issue list --repo "$REPO" --search "in:title \"$title\"" \
    --state open --json number --jq '.[].number' 2>/dev/null || true)
}

# 最近一个更旧版本分支的 tip = 该版本的补丁提交（分支 = upstream tag + 1 patch commit）
prev_patch_sha() { # tag -> sha，无则空
  local tag="$1" best="" v
  while read -r v; do
    v="${v#refs/remotes/origin/}"
    printf '%s\n' "$v" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || continue
    [ "$v" = "$tag" ] && continue
    version_gt "$tag" "$v" || continue
    if [ -z "$best" ] || version_gt "$v" "$best"; then best="$v"; fi
  done < <(git for-each-ref --format='%(refname)' refs/remotes/origin)
  [ -n "$best" ] && git rev-parse "refs/remotes/origin/$best" || true
}

branch_exists() { # tag
  git ls-remote --exit-code --heads origin "$1" >/dev/null 2>&1
}

mapfile -t tags < <(jq -r '.[]' "$TAGS_FILE")
prepared=()
for tag in "${tags[@]}"; do
  [ "$tag" = "__skip__" ] && continue
  if branch_exists "$tag"; then
    echo "::notice::branch $tag already exists; use as-is"
    prepared+=("$tag")
    continue
  fi
  echo "::group::prepare branch $tag"
  git fetch "$UPSTREAM_URL" "refs/tags/$tag:refs/tags/$tag" 2>&1 | tail -2
  wt="$ROOT/.wt-prepare-$tag"
  git worktree add "$wt" "refs/tags/$tag" >/dev/null
  src="$(prev_patch_sha "$tag")" || src=""
  ok=1
  if [ -n "$src" ]; then
    # patch 提交化：把上一版本分支的补丁提交 cherry-pick 到新 tag 上（3-way 合并）
    ( cd "$wt" && git cherry-pick --no-commit "$src" ) >/dev/null 2>&1 || ok=0
    [ "$ok" = 1 ] && ( cd "$wt" && git commit -q -m "patch: add proxy-protocol support ($tag)" ) >/dev/null 2>&1 || ok=0
  else
    # 首版（无更旧分支）：直接用仓库内 patch 文件作为首笔补丁提交
    first="$(ls "$PATCH_DIR"/*.patch 2>/dev/null | head -1 || true)"
    if [ -z "$first" ]; then
      notify_conflict "$tag" "no patch file found in patches/"
      ok=0
    else
      ( cd "$wt" && git apply --3way "$first" ) >/dev/null 2>&1 || ok=0
      [ "$ok" = 1 ] && ( cd "$wt" && git add -A && git commit -q -m "patch: add proxy-protocol support ($tag)" ) >/dev/null 2>&1 || ok=0
    fi
  fi
  if [ "$ok" != 1 ]; then
    ( cd "$wt" && git cherry-pick --abort ) >/dev/null 2>&1 || true
    git worktree remove --force "$wt" 2>/dev/null || true
    notify_conflict "$tag" "rebase failed while preparing branch"
    echo "::error::patch does not apply to $tag; conflict issue created"
    echo "::endgroup::prepare branch $tag"
    continue
  fi
  head="$(git -C "$wt" rev-parse HEAD)"
  git -C "$wt" push origin "HEAD:refs/heads/$tag" 2>&1 | tail -1
  git worktree remove --force "$wt"
  close_conflict_issue "$tag"
  echo "::notice::branch $tag prepared ($head)"
  echo "::endgroup::prepare branch $tag"
  prepared+=("$tag")
done

if [ "${#prepared[@]}" -eq 0 ]; then
  printf '["__skip__"]\n'
else
  printf '%s\n' "${prepared[@]}" | jq -R . | jq -s -c .
fi