#!/usr/bin/env bash
# Build the RootHide port of Dopamine from the repository root.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

die() {
    echo "error: $*" >&2
    exit 1
}

if [[ "$(uname -s)" != "Darwin" ]]; then
    cat >&2 <<'EOF'
error: full Dopamine builds require macOS and Xcode.

This source tree invokes xcodebuild and uses the iPhoneOS SDK, which are not
available on Linux. Copy this directory to a macOS machine/VM with Xcode, then
run ./build_roothide.sh again from the repository root.
EOF
    exit 1
fi

command -v xcodebuild >/dev/null || die "Xcode command-line tools are not available. Install Xcode and run: xcode-select --install"
command -v brew >/dev/null || die "Homebrew is required to install GNU Make and libarchive: https://brew.sh"

if ! command -v gmake >/dev/null; then
    echo "Installing GNU Make..."
    brew install make
fi

if ! brew --prefix libarchive >/dev/null 2>&1; then
    echo "Installing libarchive..."
    brew install libarchive
fi

command -v ldid >/dev/null || die "ldid is missing. Install the Procursus build dependencies, then rerun this script."
command -v trustcache >/dev/null || die "trustcache is missing. Build/install CRKatri/trustcache, then rerun this script."

if [[ -z "${THEOS:-}" ]]; then
    export THEOS="$ROOT/theos"
fi

[[ -d "$THEOS/makefiles" ]] || die "THEOS is not installed at $THEOS"

BOOTSTRAP_DIR="$ROOT/Application/Dopamine/Resources"
if [[ ! -s "$BOOTSTRAP_DIR/bootstrap_1800.tar.zst" || ! -s "$BOOTSTRAP_DIR/bootstrap_1900.tar.zst" ]]; then
    echo "Downloading missing bootstrap archives..."
    bash "$BOOTSTRAP_DIR/download_bootstraps.sh"
fi

JOBS="${JOBS:-$(sysctl -n hw.logicalcpu)}"
echo "Building with $JOBS jobs..."
gmake -j"$JOBS"

for artifact in \
    "$ROOT/BaseBin/basebin.tar" \
    "$ROOT/Application/Dopamine.ipa" \
    "$ROOT/Application/Dopamine.tipa" \
    "$ROOT/Standalone/Dopamine.tar"; do
    [[ -s "$artifact" ]] || die "build finished without expected artifact: $artifact"
done

echo "Build complete."
printf '%s\n' \
    "  $ROOT/Application/Dopamine.ipa" \
    "  $ROOT/Application/Dopamine.tipa" \
    "  $ROOT/BaseBin/basebin.tar" \
    "  $ROOT/Standalone/Dopamine.tar"
