#!/usr/bin/env bash
set -euo pipefail

TAGS_FILE="$1"
ART_DIR="$2"
REPO="${GITHUB_REPOSITORY:-zero-custom/transmission}"
LIBCS=(glibc musl)
ARCHS=(amd64 arm64 armv7)

mapfile -t tags < <(jq -r '.[]' "$TAGS_FILE")
for tag in "${tags[@]}"; do
  [ "$tag" = "__skip__" ] && continue
  ok=1
  for libc in "${LIBCS[@]}"; do
    for arch in "${ARCHS[@]}"; do
      [ -f "$ART_DIR/transmission-$tag-linux-$libc-$arch.tar.gz" ] || { ok=0; break 2; }
    done
  done
  [ -f "$ART_DIR/transmission-$tag-patched.tar.gz" ] || ok=0
  if [ "$ok" != "1" ]; then
    echo "::warning::incomplete artifacts for $tag; release skipped"
    continue
  fi
  n="$(gh release list --repo "$REPO" --json tagName \
    --jq "[.[].tagName | select(test(\"^${tag}-p[0-9]+\$\")) | capture(\"p(?<n>[0-9]+)\$\") | .n | tonumber] | max // 0")"
  n=$((n + 1))
  rel_tag="${tag}-p${n}"
  patch_list="$(gh api "repos/$REPO/contents/patches" --jq '.[].name' 2>/dev/null || echo "see patches/ dir")"
  body="$(printf 'Upstream **%s** with local patches applied.\n\n**Patches applied:**\n%s\n\n**Runtime:**\n- glibc variant: glibc >= 2.35 (Ubuntu 22.04+/Debian 12+); requires libcurl4, libevent, libssl3, zlib1g, libb64, libdeflate, libminiupnpc, libnatpmp, libpsl5, libsystemd0 (Ubuntu 22.04 names)\n- musl variant: Alpine/musl distros (glibc binaries cannot run on musl); requires libcurl, libevent, openssl, zlib, miniupnpc, libnatpmp, libpsl, libdeflate (apk names)\n\n**Archives:**\n- transmission-%s-linux-libc-arch.tar.gz (6: libc in {glibc,musl}, arch in {amd64,arm64,armv7})\n- transmission-%s-patched.tar.gz (source)\n' \
    "$tag" "$patch_list" "$tag" "$tag")"
  gh release create "$rel_tag" \
    "$ART_DIR/transmission-$tag-linux-glibc-amd64.tar.gz" \
    "$ART_DIR/transmission-$tag-linux-glibc-arm64.tar.gz" \
    "$ART_DIR/transmission-$tag-linux-glibc-armv7.tar.gz" \
    "$ART_DIR/transmission-$tag-linux-musl-amd64.tar.gz" \
    "$ART_DIR/transmission-$tag-linux-musl-arm64.tar.gz" \
    "$ART_DIR/transmission-$tag-linux-musl-armv7.tar.gz" \
    "$ART_DIR/transmission-$tag-patched.tar.gz" \
    --repo "$REPO" --title "Transmission $rel_tag" --notes "$body"
  echo "::notice::published $rel_tag"
done
