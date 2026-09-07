#!/usr/bin/env bash
set -euo pipefail

ARCH="$1"
LIBC="$2"
TAGS_FILE="$3"
FORCE="${4:-0}"
REPO="${GITHUB_REPOSITORY:-zero-custom/transmission}"
ROOT="$PWD"

# libc 变体 → 对应构建镜像
case "$LIBC" in
  glibc) DOCKERFILE="docker/build/Dockerfile.build" ;;
  musl)  DOCKERFILE="docker/build/Dockerfile.build.alpine" ;;
  *) echo "::error::unknown libc: $LIBC (glibc|musl)"; exit 1 ;;
esac

# arch → BuildKit 平台字符串（armv7 的合法平台是 linux/arm/v7，不是 linux/armv7）
case "$ARCH" in
  amd64) PLATFORM="linux/amd64" ;;
  arm64) PLATFORM="linux/arm64" ;;
  armv7) PLATFORM="linux/arm/v7" ;;
  *) echo "::error::unknown arch: $ARCH (amd64|arm64|armv7)"; exit 1 ;;
esac

# 每 tag 1 条 issue（标题不含矩阵维度）；force 重建失败只红日志，不建 issue
notify_failure() { # tag, reason, detail
  local tag="$1" reason="$2" detail="${3:-}"
  if [ "$FORCE" = "1" ]; then
    echo "::error::$reason ($tag) — force rebuild, no issue filed"
    return 0
  fi
  local title="build: $tag failed" existing body
  existing="$(gh issue list --repo "$REPO" --search "in:title \"$title\"" \
    --state open --json number --jq '.[0].number // empty' 2>/dev/null || true)"
  body="**$reason** ($tag). Rerun the workflow or fix the patch. $detail"
  if [ -n "$existing" ]; then
    gh issue edit "$existing" --repo "$REPO" --body "$body" >/dev/null 2>&1 || true
  else
    printf '%s\n' "$body" | gh issue create --repo "$REPO" --title "$title" --body-file - >/dev/null 2>&1 || true
  fi
}

mapfile -t tags < <(jq -r '.[]' "$TAGS_FILE")
for tag in "${tags[@]}"; do
  [ "$tag" = "__skip__" ] && continue
  echo "== building $tag for linux/$ARCH ($LIBC) =="
  wt="$ROOT/.wt-$tag-$LIBC-$ARCH"      # worktree 放在仓库内，避免跨文件系统
  dest="$ROOT/out-$tag-$LIBC-$ARCH"
  # 补丁已作为提交存在 fork 分支 <tag> 上（prepare-branch job 保证），直接检出分支构建
  git fetch origin "refs/heads/$tag:refs/heads/$tag" 2>/dev/null \
    || { notify_failure "$tag" "branch $tag not found on fork" ""; exit 1; }
  git worktree add -f "$wt" "refs/heads/$tag" \
    || { notify_failure "$tag" "worktree add failed" ""; exit 1; }
  # submodules（third-party/fmt/libdeflate 等）：上游 CI 用 submodules: recursive，缺则 CMake 配置失败
  ( cd "$wt" && git submodule update --init --recursive ) \
    || { notify_failure "$tag" "submodule fetch failed" ""; exit 1; }
  cat > "$wt/.dockerignore" <<'EOF'
.git
patches
.github
docs
*.tar.gz
EOF
  cp "$DOCKERFILE" "$wt/Dockerfile.build"
  ( cd "$wt" && docker buildx build \
      --platform "$PLATFORM" \
      --output "type=local,dest=$dest" \
      -f Dockerfile.build . ) \
    || { notify_failure "$tag" "build failed"; exit 1; }

  mkdir -p "$dest/pkg"
  mv "$dest"/out/* "$dest/pkg/"
  cp "$wt/COPYING" "$wt/README.md" "$dest/pkg/"
  mkdir -p "$dest/pkg/public_html"
  cp -a "$wt/web/public_html/." "$dest/pkg/public_html/"
  ( cd "$dest/pkg" && tar -czf "../transmission-$tag-linux-$LIBC-$ARCH.tar.gz" . )
  rm -rf "$dest/pkg"
  # 源码包跨 libc/架构完全一致，只由 glibc+amd64 组合生成，避免矩阵重复上传同名文件
  if [ "$LIBC" = glibc ] && [ "$ARCH" = amd64 ]; then
    tar --exclude=.git -czf "$dest/transmission-$tag-patched.tar.gz" -C "$wt" .
  fi
  git worktree remove --force "$wt"
  echo "::notice::built $tag for $LIBC/$ARCH"
done