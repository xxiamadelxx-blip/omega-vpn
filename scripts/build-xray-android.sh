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

# Network and Go checksum servers sometimes reset HTTP/2 streams on CI.
# Retry transient failures, but NEVER bypass go.sum / GOSUMDB verification.
retry_network() {
  local attempt
  for attempt in 1 2 3; do
    if "$@"; then return 0; fi
    if [[ "$attempt" -eq 3 ]]; then
      echo "Failed after 3 attempts: $1" >&2
      return 1
    fi
    echo "Transient Go tool/download error; retry $((attempt + 1))/3" >&2
    sleep "$((attempt * 8))"
  done
}
retry_network go install "golang.org/x/mobile/cmd/gomobile@$MOBILE_VERSION"
retry_network go install "golang.org/x/mobile/cmd/gobind@$MOBILE_VERSION"
retry_network gomobile init
for attempt in 1 2 3; do
  rm -f "$ROOT/app/libs/libv2ray.aar"
  if (cd "$BUILD_DIR" && gomobile bind -target="${OMEGA_ANDROID_TARGETS:-android/arm64}" -androidapi 26 -trimpath \
    -ldflags='-s -w -buildid= -checklinkname=0' \
    -o "$ROOT/app/libs/libv2ray.aar" .); then
    break
  fi
  if [[ "$attempt" -eq 3 ]]; then
    echo "Go/mobile AAR build failed after 3 attempts" >&2
    exit 4
  fi
  echo "Transient dependency or compiler failure; rebuild retry $((attempt + 1))/3" >&2
  sleep "$((attempt * 8))"
done
# Verify the ABI actually requested by the caller. Android x86_64 uses Go amd64.
TARGETS="${OMEGA_ANDROID_TARGETS:-android/arm64}"
if [[ "$TARGETS" == *"android/arm64"* ]]; then
  unzip -l "$ROOT/app/libs/libv2ray.aar" | grep -q 'jni/arm64-v8a/libgojni.so'
fi
if [[ "$TARGETS" == *"android/amd64"* ]]; then
  unzip -l "$ROOT/app/libs/libv2ray.aar" | grep -q 'jni/x86_64/libgojni.so'
fi
sha256sum "$ROOT/app/libs/libv2ray.aar"
echo "Android Xray AAR ready from commit $CORE_COMMIT"
