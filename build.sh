#!/usr/bin/env bash
# Convenience wrapper; CMake is the authoritative build on both hosts.
set -euo pipefail
cd "$(dirname "$0")"
mode=release
target=
run_test=0
for arg in "$@"; do
    case "$arg" in
        release|debug|asan|tsan) mode=$arg ;;
        test) target=npxf-selftest; run_test=1 ;;
        npxf|npxf-server|npxf-selftest) target=$arg ;;
        clean) cmake --build build/release --target clean; exit ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done
type=RelWithDebInfo
sanitizer=
case "$mode" in
    debug) type=Debug ;;
    asan) type=Debug; sanitizer=address ;;
    tsan) type=Debug; sanitizer=thread ;;
esac
args=()
if [[ $(uname -s) == Darwin ]] && command -v brew >/dev/null; then
    args+=("-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)")
fi
cmake -S . -B "build/$mode" -DCMAKE_BUILD_TYPE="$type" -DNPXF_SANITIZER="$sanitizer" "${args[@]}"
if [[ -n "$target" ]]; then
    cmake --build "build/$mode" --parallel "${JOBS:-4}" --target "$target"
else
    cmake --build "build/$mode" --parallel "${JOBS:-4}"
fi
if [[ $run_test == 1 ]]; then ctest --test-dir "build/$mode" --output-on-failure; fi
