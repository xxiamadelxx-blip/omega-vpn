#!/usr/bin/env bash
set -euo pipefail

# Reproducible Go/mobile AAR build. Never commit or copy proprietary Happ binaries.
CORE_REPOSITORY="https://github.com/2dust/AndroidLibXrayLite.git"
CORE_COMMIT="ea96a7f9c33d6e18021386db96bf95680e853c93"
MOBILE_VERSION="v0.0.0-20260908204917-8b95e45f8d3e"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/28.0.13004108}"
export PATH="$(go env GOPATH)/bin:$PATH"
export GOMAXPROCS="${GOMAXPROCS:-2}"
export GOFLAGS="-p=2"

[[ -f "$ANDROID_NDK_HOME/source.properties" ]] || { echo "NDK r28 required"; exit 2; }
command -v go >/dev/null
test "$(go version | sed -E 's/.*go([0-9]+\.[0-9]+).*/\1/')" = "1.27" || {
  echo "This core requires Go 1.27"; exit 2; }

mkdir -p "$ROOT/app/libs"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
git -C "$BUILD_DIR" init -q
git -C "$BUILD_DIR" remote add origin "$CORE_REPOSITORY"
git -C "$BUILD_DIR" fetch -q --depth 1 origin "$CORE_COMMIT"
git -C "$BUILD_DIR" checkout -q --detach FETCH_HEAD
actual="$(git -C "$BUILD_DIR" rev-parse HEAD)"
test "$actual" = "$CORE_COMMIT" || { echo "Core commit mismatch"; exit 3; }

go install "golang.org/x/mobile/cmd/gomobile@$MOBILE_VERSION"
go install "golang.org/x/mobile/cmd/gobind@$MOBILE_VERSION"
gomobile init
(cd "$BUILD_DIR" && gomobile bind -target=android/arm64 -androidapi 26 -trimpath \
  -ldflags='-s -w -buildid= -checklinkname=0' \
  -o "$ROOT/app/libs/libv2ray.aar" .)
unzip -l "$ROOT/app/libs/libv2ray.aar" | grep -q 'jni/arm64-v8a/libgojni.so'
sha256sum "$ROOT/app/libs/libv2ray.aar"
echo "Android Xray AAR ready from commit $CORE_COMMIT"
