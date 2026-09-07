#!/usr/bin/env bash
set -euo pipefail

ARCH="$1"
LIBC="$2"
TAGS_FILE="$3"
REPO="${GITHUB_REPOSITORY:-zero-custom/transmission}"
UPSTREAM_URL="https://github.com/transmission/transmission.git"
PATCH_DIR="$PWD/patches"
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

notify_failure() { # tag, libc, arch, reason, detail
  local tag="$1" libc="$2" arch="$3" reason="$4" detail="${5:-}"
  local title="build: $tag ($libc/$arch) failed" existing
  existing="$(gh issue list --repo "$REPO" --search "in:title \"$title\"" \
    --state open --json number --jq '.[0].number // empty' 2>/dev/null || true)"
  local body="**$reason** ($tag, $libc/$arch). Rerun the workflow or fix patches. $detail"
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
  git fetch "$UPSTREAM_URL" "refs/tags/$tag:refs/tags/$tag"
  git worktree add -f "$wt" "refs/tags/$tag"
  # submodules（third-party/fmt/libdeflate 等）：上游 CI 用 submodules: recursive，缺则 CMake 配置失败
  ( cd "$wt" && git submodule update --init --recursive ) \
    || { notify_failure "$tag" "$LIBC" "$ARCH" "submodule fetch failed" ""; exit 1; }
  cat > "$wt/.dockerignore" <<'EOF'
.git
patches
.github
docs
*.tar.gz
EOF
  cp "$DOCKERFILE" "$wt/Dockerfile.build"
  # apply patches（路径相对 repo 根，worktree 内同样适用）
  for patch in "$PATCH_DIR"/*.patch; do
    [ -e "$patch" ] || { echo "::error::no patches in $PATCH_DIR"; exit 1; }
    ( cd "$wt" && git apply --3way "$patch" ) \
      || { notify_failure "$tag" "$LIBC" "$ARCH" "patch apply failed" "$(basename "$patch")"; exit 1; }
  done
  ( cd "$wt" && docker buildx build \
      --platform "$PLATFORM" \
      --output "type=local,dest=$dest" \
      -f Dockerfile.build . ) \
    || { notify_failure "$tag" "$LIBC" "$ARCH" "build failed"; exit 1; }

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
