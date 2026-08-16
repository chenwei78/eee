#!/usr/bin/env bash
# Linux / THEOS build launcher. Full output is saved to b.log.
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

export THEOS="${THEOS:-/opt/theos}"
export PATH="$THEOS/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export LD_LIBRARY_PATH="/usr/lib/llvm-18/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

{
    echo "== Dopamine RootHide Linux build =="
    echo "root:  $ROOT"
    echo "THEOS: $THEOS"
    echo "make:  $(command -v make || echo missing)"
    echo "ldid:  $(command -v ldid || echo missing)"
    echo "xcrun: $(command -v xcrun || echo missing)"
    echo "xcodebuild: $(command -v xcodebuild || echo missing)"
    echo
} | tee b.log

make -j"${JOBS:-$(nproc)}" 2>&1 | tee -a b.log
exit ${PIPESTATUS[0]}
