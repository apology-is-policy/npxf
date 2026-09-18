#!/usr/bin/env bash
# npxf build driver.  clang + lld + bash, nothing else.
#
#   ./build.sh                 build everything (release)
#   ./build.sh debug           -O0 -g, assertions on
#   ./build.sh asan            AddressSanitizer + UBSan
#   ./build.sh tsan            ThreadSanitizer
#   ./build.sh npxf-server     build one target
#   ./build.sh test            build and run the self-test
#   ./build.sh clean
#
# Environment overrides: CXX, LD (linker name for -fuse-ld), JOBS, NPXF_LTO=1.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

CXX=${CXX:-clang++}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 4)}
SRC=src
OUT=build

# ------------------------------------------------------------------ targets

# Modules shared by every binary.
COMMON_SRCS=(crypto.cpp crypto_vectors.cpp net.cpp channel.cpp ninep.cpp)

declare -A TARGET_SRCS=(
    [npxf-server]="${COMMON_SRCS[*]} server.cpp server_ops.cpp"
    [npxf]="${COMMON_SRCS[*]} client.cpp npxf_main.cpp"
    [npxf-selftest]="${COMMON_SRCS[*]} selftest.cpp"
)
ALL_TARGETS=(npxf-server npxf npxf-selftest)

# ------------------------------------------------------------------- flags

mode=release
requested=()

for arg in "$@"; do
    case $arg in
        release | debug | asan | tsan) mode=$arg ;;
        clean)
            rm -rf "$OUT"
            echo "cleaned"
            exit 0
            ;;
        test) requested+=(npxf-selftest) RUN_TEST=1 ;;
        *)
            if [[ -v TARGET_SRCS[$arg] ]]; then
                requested+=("$arg")
            else
                echo "build.sh: unknown argument '$arg'" >&2
                echo "targets: ${ALL_TARGETS[*]}   modes: release debug asan tsan" >&2
                exit 2
            fi
            ;;
    esac
done
[[ ${#requested[@]} -gt 0 ]] || requested=("${ALL_TARGETS[@]}")

CXXFLAGS=(
    -std=c++20
    -pthread
    -Wall -Wextra -Wpedantic
    -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
    -Wno-unused-parameter
    -fno-strict-aliasing            # we type-pun through uint8_t buffers
    -fvisibility=hidden
    -ffunction-sections -fdata-sections
    -MMD -MP
)

UNAME_S=$(uname -s)

# Hardening.  All of this is clang/lld built-in, no runtime dependency.
HARDEN=(
    -fstack-protector-strong
    -fPIE
)
# Not accepted by the Darwin/arm64 driver; clang warns and ignores it there,
# which is noise on every single compile line.
[[ $UNAME_S != Darwin ]] && HARDEN+=(-fstack-clash-protection)
[[ $(uname -m) == x86_64 ]] && HARDEN+=(-fcf-protection=full)

# The -z options and --gc-sections are ELF, and Mach-O spells the latter
# differently.  Darwin links PIE by default and has no equivalent for the
# rest; the Linux build is the hardened one and remains unchanged.
if [[ $UNAME_S == Darwin ]]; then
    LDFLAGS=(-pthread -Wl,-dead_strip)
else
    LDFLAGS=(-pthread -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--gc-sections)
fi

case $mode in
    release)
        CXXFLAGS+=(-O2 -g -DNDEBUG -D_FORTIFY_SOURCE=2)
        CXXFLAGS+=("${HARDEN[@]}")
        LDFLAGS+=("${HARDEN[@]}")
        if [[ ${NPXF_LTO:-0} == 1 ]]; then
            CXXFLAGS+=(-flto=thin)
            LDFLAGS+=(-flto=thin)
        fi
        ;;
    debug)
        CXXFLAGS+=(-O0 -g3 -fno-omit-frame-pointer)
        CXXFLAGS+=("${HARDEN[@]}")
        LDFLAGS+=("${HARDEN[@]}")
        ;;
    asan)
        CXXFLAGS+=(-O1 -g -fno-omit-frame-pointer
            -fsanitize=address,undefined -fno-sanitize-recover=all)
        LDFLAGS+=(-fsanitize=address,undefined)
        ;;
    tsan)
        CXXFLAGS+=(-O1 -g -fno-omit-frame-pointer -fsanitize=thread)
        LDFLAGS+=(-fsanitize=thread)
        ;;
esac

# lld is the requested linker; fall back loudly rather than failing the build.
# Skipped on Darwin: the probe there can succeed with a toolchain lld that then
# rejects --build-id, and ld64 is the right linker for Mach-O anyway.
if [[ $UNAME_S != Darwin ]]; then
    LINKER=${LD:-lld}
    if $CXX "-fuse-ld=$LINKER" -xc++ /dev/null -o /dev/null -shared >/dev/null 2>&1; then
        LDFLAGS+=("-fuse-ld=$LINKER" -Wl,--build-id=sha1)
    else
        echo "build.sh: warning: -fuse-ld=$LINKER unavailable, using the default linker" >&2
        echo "build.sh:          install it with:  sudo apt install lld" >&2
    fi
fi

OBJDIR=$OUT/$mode
mkdir -p "$OBJDIR"

# ------------------------------------------------------------- dependencies

# True when $obj is missing or older than its source or any header it pulled in
# on the previous build (recorded by clang's -MMD in the .d file).
needs_rebuild() {
    local obj=$1 src=$2 dep=${1%.o}.d p
    [[ -f $obj ]] || return 0
    [[ $src -nt $obj ]] && return 0
    [[ -f $dep ]] || return 0
    while read -r p; do
        [[ -n $p && -f $p && $p -nt $obj ]] && return 0
    done < <(sed -e 's/^[^:]*://' -e 's/\\$//' "$dep" | tr -s ' \t' '\n')
    return 1
}

fail=0
compile_one() {
    local src=$1 obj=$2
    if ! $CXX "${CXXFLAGS[@]}" -c "$src" -o "$obj"; then
        return 1
    fi
}

# ------------------------------------------------------------------- build

# Deduplicate the object list across targets so shared modules compile once.
declare -A seen=()
pending_src=() pending_obj=()
for t in "${requested[@]}"; do
    for s in ${TARGET_SRCS[$t]}; do
        [[ -v seen[$s] ]] && continue
        seen[$s]=1
        src=$SRC/$s obj=$OBJDIR/${s%.cpp}.o
        [[ -f $src ]] || {
            echo "build.sh: missing source $src" >&2
            exit 1
        }
        if needs_rebuild "$obj" "$src"; then
            pending_src+=("$src")
            pending_obj+=("$obj")
        fi
    done
done

if [[ ${#pending_src[@]} -gt 0 ]]; then
    echo "==> compiling ${#pending_src[@]} file(s) [$mode, -j$JOBS]"
    running=0
    for i in "${!pending_src[@]}"; do
        echo "    CXX ${pending_src[$i]}"
        compile_one "${pending_src[$i]}" "${pending_obj[$i]}" &
        # Plain $((...)) rather than ((...)): an arithmetic command that
        # evaluates to zero exits non-zero, which under `set -e` would kill
        # the build the moment the last job drains.
        running=$((running + 1))
        if ((running >= JOBS)); then
            wait -n || fail=1
            running=$((running - 1))
        fi
    done
    while ((running > 0)); do
        wait -n || fail=1
        running=$((running - 1))
    done
    ((fail == 0)) || {
        echo "==> compile failed" >&2
        exit 1
    }
fi

for t in "${requested[@]}"; do
    objs=()
    for s in ${TARGET_SRCS[$t]}; do objs+=("$OBJDIR/${s%.cpp}.o"); done
    bin=$OBJDIR/$t
    relink=0
    [[ -f $bin ]] || relink=1
    for o in "${objs[@]}"; do
        if [[ $o -nt $bin ]]; then relink=1; fi
    done
    if ((relink)); then
        echo "    LD  $bin"
        $CXX "${objs[@]}" "${LDFLAGS[@]}" -o "$bin"
    fi
    ln -sf "$mode/$t" "$OUT/$t"
done

echo "==> ok: $OUT/{$(
    IFS=,
    echo "${requested[*]}"
)}"

if [[ ${RUN_TEST:-0} == 1 ]]; then
    echo
    exec "$OBJDIR/npxf-selftest"
fi
