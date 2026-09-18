#!/usr/bin/env bash
# npxf end-to-end tests: starts a real server on the loopback interface and
# drives it with the real client.  Run ./build.sh first, or pass --build.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT=$PWD
MODE=${NPXF_TEST_MODE:-release}

[[ ${1:-} == --build ]] && { ./build.sh "$MODE" || exit 1; }

SERVER=$ROOT/build/$MODE/npxf-server
CLIENT=$ROOT/build/$MODE/npxf
for b in "$SERVER" "$CLIENT"; do
    [[ -x $b ]] || {
        echo "missing $b -- run ./build.sh first" >&2
        exit 1
    }
done

pass=0
fail=0
srv_pid=

ok() {
    printf '  \033[32mok\033[0m    %s\n' "$1"
    pass=$((pass + 1))
}
no() {
    printf '  \033[31mFAIL\033[0m  %s\n' "$1"
    [[ $# -gt 1 ]] && printf '        %s\n' "$2"
    fail=$((fail + 1))
}

# check NAME EXPECTED ACTUAL
check() {
    if [[ $2 == "$3" ]]; then ok "$1"; else no "$1" "expected [$2], got [$3]"; fi
}

# expect_fail NAME CMD... -- the command must exit non-zero
expect_fail() {
    local name=$1
    shift
    if "$@" >/dev/null 2>&1; then no "$name" "command unexpectedly succeeded"; else ok "$name"; fi
}

# Runs a python protocol suite and folds its ok/FAIL lines into our tally.
run_p9_suite() {
    local script=$1 sock=$2
    local line
    while IFS= read -r line; do
        case $line in
            "ok "*) ok "${line#ok }" ;;
            "FAIL "*) no "${line#FAIL }" ;;
            *) printf '        %s\n' "$line" ;;
        esac
    done < <(python3 "$script" "$sock" "$EXPORT" 2>&1)
}

TMP=$(mktemp -d /tmp/npxf-test.XXXXXX)
cleanup() {
    [[ -n $srv_pid ]] && kill "$srv_pid" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

EXPORT=$TMP/export
WORK=$TMP/work
mkdir -p "$EXPORT" "$WORK"

TOKEN=$TMP/token
printf 'correct-horse-battery-staple' >"$TOKEN"
chmod 600 "$TOKEN"

# Grab a free ephemeral port by binding one and reading back the number.
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()' 2>/dev/null || echo 15640)
ADDR=127.0.0.1:$PORT
N=("$CLIENT" -a "$ADDR" -t "$TOKEN")

# ------------------------------------------------------------------ fixtures

echo "hello from 9p" >"$EXPORT/hello.txt"
printf 'alpha\nbeta\ngamma\n' >"$EXPORT/three.txt"
mkdir -p "$EXPORT/tree/a/b"
echo "deep" >"$EXPORT/tree/a/b/deep.txt"
echo "shallow" >"$EXPORT/tree/top.txt"
ln -sf hello.txt "$EXPORT/alink"
ln -sf ../../../../../etc/passwd "$EXPORT/tree/escape"
: >"$EXPORT/empty.txt"
head -c 5000000 /dev/urandom >"$EXPORT/big.bin"
# Exercise the msize boundary: exactly one iounit, and one byte over.
head -c 1048552 /dev/urandom >"$EXPORT/exact.bin"
head -c 1048553 /dev/urandom >"$EXPORT/exact1.bin"

start_server() {
    "$SERVER" -r "$EXPORT" -t "$TOKEN" -l "$ADDR" "$@" >"$TMP/server.log" 2>&1 &
    srv_pid=$!
    for _ in $(seq 1 100); do
        if "${N[@]}" ls >/dev/null 2>&1; then return 0; fi
        kill -0 "$srv_pid" 2>/dev/null || {
            echo "server died on startup:" >&2
            cat "$TMP/server.log" >&2
            exit 1
        }
        sleep 0.05
    done
    echo "server never became ready" >&2
    cat "$TMP/server.log" >&2
    exit 1
}

stop_server() {
    [[ -n $srv_pid ]] && kill "$srv_pid" 2>/dev/null
    wait "$srv_pid" 2>/dev/null
    srv_pid=
}

echo "npxf end-to-end tests ($MODE, port $PORT)"
echo
echo "-- unit --"
"$ROOT/build/$MODE/npxf-selftest" | sed 's/^/  /' || fail=$((fail + 1))

echo
echo "-- listing --"
start_server

check "ls lists the export root" \
    "alink big.bin empty.txt exact.bin exact1.bin hello.txt three.txt tree/" \
    "$("${N[@]}" ls | tr '\n' ' ' | sed 's/ $//')"

check "ls of a subdirectory" "a/ escape top.txt" "$("${N[@]}" ls tree | tr '\n' ' ' | sed 's/ $//')"

check "ls -l reports a symlink target" "1" \
    "$("${N[@]}" ls -l | grep -c 'alink -> hello.txt')"

check "ls -l reports the file mode" "1" \
    "$("${N[@]}" ls -l | grep -c '^-rw.* hello.txt$')"

check "stat reports the size" "1" \
    "$("${N[@]}" stat hello.txt | grep -c '^  size: 14$')"

check "readlink" "hello.txt" "$("${N[@]}" readlink alink)"
check "cat" "hello from 9p" "$("${N[@]}" cat hello.txt)"
check "cat of an empty file" "" "$("${N[@]}" cat empty.txt)"
check "df reports a block size" "1" "$("${N[@]}" df | grep -c '^block size : [0-9]')"

echo
echo "-- copy out --"
"${N[@]}" get big.bin "$WORK/big.bin" >/dev/null
check "get of a 5 MB file is byte-identical" \
    "$(sha256sum <"$EXPORT/big.bin" | cut -d' ' -f1)" \
    "$(sha256sum <"$WORK/big.bin" | cut -d' ' -f1)"

for f in exact.bin exact1.bin empty.txt; do
    "${N[@]}" get "$f" "$WORK/$f" >/dev/null
    check "get $f round-trips" \
        "$(sha256sum <"$EXPORT/$f" | cut -d' ' -f1)" \
        "$(sha256sum <"$WORK/$f" | cut -d' ' -f1)"
done

"${N[@]}" -d 1 get big.bin "$WORK/big-d1.bin" >/dev/null
check "get with no pipelining agrees" \
    "$(sha256sum <"$EXPORT/big.bin" | cut -d' ' -f1)" \
    "$(sha256sum <"$WORK/big-d1.bin" | cut -d' ' -f1)"

"${N[@]}" -d 32 get big.bin "$WORK/big-d32.bin" >/dev/null
check "get with 32 requests in flight agrees" \
    "$(sha256sum <"$EXPORT/big.bin" | cut -d' ' -f1)" \
    "$(sha256sum <"$WORK/big-d32.bin" | cut -d' ' -f1)"

"${N[@]}" get -r tree "$WORK/tree" >/dev/null
check "get -r reproduces the tree" "" "$(diff -r "$EXPORT/tree" "$WORK/tree" 2>&1)"

echo
echo "-- copy in --"
head -c 4000000 /dev/urandom >"$WORK/upload.bin"
"${N[@]}" put "$WORK/upload.bin" uploaded.bin >/dev/null
check "put of a 4 MB file is byte-identical" \
    "$(sha256sum <"$WORK/upload.bin" | cut -d' ' -f1)" \
    "$(sha256sum <"$EXPORT/uploaded.bin" | cut -d' ' -f1)"

"${N[@]}" -d 1 put "$WORK/upload.bin" uploaded-d1.bin >/dev/null
check "put with no pipelining agrees" \
    "$(sha256sum <"$WORK/upload.bin" | cut -d' ' -f1)" \
    "$(sha256sum <"$EXPORT/uploaded-d1.bin" | cut -d' ' -f1)"

mkdir -p "$WORK/up/x/y"
echo "one" >"$WORK/up/one.txt"
echo "two" >"$WORK/up/x/two.txt"
echo "three" >"$WORK/up/x/y/three.txt"
ln -sf one.txt "$WORK/up/onelink"
"${N[@]}" put -r "$WORK/up" uptree >/dev/null
check "put -r reproduces the tree" "" "$(diff -r "$WORK/up" "$EXPORT/uptree" 2>&1)"

echo
echo "-- namespace --"
"${N[@]}" mkdir newdir
check "mkdir" "1" "$([[ -d $EXPORT/newdir ]] && echo 1 || echo 0)"
"${N[@]}" mkdir -p a/b/c
check "mkdir -p creates intermediates" "1" "$([[ -d $EXPORT/a/b/c ]] && echo 1 || echo 0)"
"${N[@]}" mv newdir renamed
check "mv" "1" "$([[ -d $EXPORT/renamed && ! -d $EXPORT/newdir ]] && echo 1 || echo 0)"
"${N[@]}" ln -s ../hello.txt renamed/hl
check "ln -s" "../hello.txt" "$(readlink "$EXPORT/renamed/hl")"
"${N[@]}" rm renamed/hl
check "rm a symlink" "1" "$([[ ! -L $EXPORT/renamed/hl ]] && echo 1 || echo 0)"
"${N[@]}" rm -r a
check "rm -r" "1" "$([[ ! -e $EXPORT/a ]] && echo 1 || echo 0)"
expect_fail "rm of a non-empty directory without -r" "${N[@]}" rm uptree

echo
echo "-- containment --"
# The client sends ".." as a walk name; the server pops its own component list
# and clamps at the root, so this can only ever land back inside the export.
expect_fail "'..' cannot escape the export root" "${N[@]}" cat ../../../../etc/passwd
expect_fail "'..' from a subdirectory cannot escape" "${N[@]}" cat tree/../../../../etc/passwd
expect_fail "an absolute path is not special" "${N[@]}" cat /etc/passwd
# A symlink pointing outside is stored verbatim but never followed by a walk.
expect_fail "a symlink out of the export is not followed" "${N[@]}" cat tree/escape
check "the escaping symlink is still readable as a link" "../../../../../etc/passwd" \
    "$("${N[@]}" readlink tree/escape)"

echo
echo "-- authentication --"
BAD=$TMP/badtoken
printf 'wrong-token' >"$BAD"
chmod 600 "$BAD"
expect_fail "a wrong token is rejected" "$CLIENT" -a "$ADDR" -t "$BAD" ls
expect_fail "an empty token is rejected" env NPXF_TOKEN= "$CLIENT" -a "$ADDR" ls
check "the server survives a failed handshake" "hello from 9p" "$("${N[@]}" cat hello.txt)"

# A peer that speaks TCP but not npxf must be turned away, not hang the server.
python3 - "$PORT" <<'EOF' >/dev/null 2>&1
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(b"GET / HTTP/1.0\r\n\r\n" + b"\0" * 64)
s.close()
EOF
check "the server survives a garbage handshake" "hello from 9p" "$("${N[@]}" cat hello.txt)"

stop_server

echo
echo "-- read-only mode --"
start_server --read-only
check "reads still work" "hello from 9p" "$("${N[@]}" cat hello.txt)"
expect_fail "put is refused" "${N[@]}" put "$WORK/upload.bin" nope.bin
expect_fail "mkdir is refused" "${N[@]}" mkdir nope
expect_fail "rm is refused" "${N[@]}" rm hello.txt
check "nothing was created" "1" "$([[ ! -e $EXPORT/nope.bin && ! -e $EXPORT/nope ]] && echo 1 || echo 0)"
check "nothing was deleted" "1" "$([[ -e $EXPORT/hello.txt ]] && echo 1 || echo 0)"
stop_server

echo
echo "-- tunnel (plain 9P for mount(8)) --"
start_server
SOCK=$TMP/tunnel.sock
"$CLIENT" -a "$ADDR" -t "$TOKEN" tunnel --unix "$SOCK" >"$TMP/tunnel.log" 2>&1 &
tun_pid=$!
for _ in $(seq 1 100); do [[ -S $SOCK ]] && break; sleep 0.05; done

# Speak unencrypted 9P2000.L straight at the tunnel, the way the kernel's v9fs
# client would.  This is the check that the relay preserves real framing.
out=$(python3 - "$SOCK" 2>&1 <<'PYEOF'
import socket, struct, sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(sys.argv[1])

def rd(n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise SystemExit("unexpected eof")
        b += c
    return b

def send(t, tag, body):
    s.sendall(struct.pack("<IBH", 7 + len(body), t, tag) + body)

def recv():
    size, t, tag = struct.unpack("<IBH", rd(7))
    return t, tag, rd(size - 7)

def st(x):
    b = x.encode()
    return struct.pack("<H", len(b)) + b

send(100, 0xFFFF, struct.pack("<I", 65536) + st("9P2000.L"))     # Tversion
t, _, body = recv()
assert t == 101, f"Rversion expected, got {t}"
vlen = struct.unpack("<H", body[4:6])[0]
assert body[6:6 + vlen] == b"9P2000.L", body[6:6 + vlen]

send(104, 1, struct.pack("<II", 0, 0xFFFFFFFF) + st("tester") + st("") + struct.pack("<I", 1000))
assert recv()[0] == 105, "Rattach"                                # Tattach
send(110, 2, struct.pack("<IIH", 0, 1, 1) + st("hello.txt"))      # Twalk
t, _, body = recv()
assert t == 111 and struct.unpack("<H", body[:2])[0] == 1, "Rwalk"
send(12, 3, struct.pack("<II", 1, 0))                             # Tlopen
assert recv()[0] == 13, "Rlopen"
send(116, 4, struct.pack("<IQI", 1, 0, 4096))                     # Tread
t, _, body = recv()
assert t == 117, "Rread"
n = struct.unpack("<I", body[:4])[0]
sys.stdout.write(body[4:4 + n].decode())
send(120, 5, struct.pack("<I", 1))                                # Tclunk
assert recv()[0] == 121, "Rclunk"
s.close()
PYEOF
)
check "an unmodified 9P client can talk through the tunnel" "hello from 9p" "$out"
check "the tunnel socket is owner-only" "srw-------" "$(stat -c %A "$SOCK" 2>/dev/null)"
kill "$tun_pid" 2>/dev/null
wait "$tun_pid" 2>/dev/null
stop_server

echo
echo "-- protocol operations (raw 9P) --"
start_server
OSOCK=$TMP/ops.sock
"$CLIENT" -a "$ADDR" -t "$TOKEN" tunnel --unix "$OSOCK" >"$TMP/ops-tunnel.log" 2>&1 &
ops_tun=$!
for _ in $(seq 1 100); do [[ -S $OSOCK ]] && break; sleep 0.05; done
run_p9_suite "$ROOT/tests/ops.py" "$OSOCK"
kill "$ops_tun" 2>/dev/null
wait "$ops_tun" 2>/dev/null
stop_server

echo
echo "-- malformed input --"
start_server
FSOCK=$TMP/fuzz.sock
"$CLIENT" -a "$ADDR" -t "$TOKEN" tunnel --unix "$FSOCK" >"$TMP/fuzz-tunnel.log" 2>&1 &
fuzz_tun=$!
for _ in $(seq 1 100); do [[ -S $FSOCK ]] && break; sleep 0.05; done

# Throw structurally-valid frames with garbage inside at the real server, via
# the tunnel.  Dropping the connection is a fine response to a protocol
# violation; crashing, hanging or leaking is not.
fuzz_out=$(python3 - "$FSOCK" 2>&1 <<'PYEOF'
import random, socket, struct, sys

random.seed(20260827)
path = sys.argv[1]
TYPES = [6,7,8,9,12,14,16,18,20,22,24,26,30,32,40,50,52,54,70,72,74,76,
         100,102,104,108,110,116,118,120,122,124,126,0,1,255,199]

sent = 0
s = None
for i in range(600):
    if s is None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        try:
            s.connect(path)
        except OSError as e:
            print("connect failed: %s" % e)
            break
        # Most iterations start from a properly versioned session so the fuzz
        # reaches the op handlers rather than bouncing off the version gate.
        if i % 3:
            try:
                body = struct.pack("<I", 65536) + struct.pack("<H", 8) + b"9P2000.L"
                s.sendall(struct.pack("<IBH", 7 + len(body), 100, 0xFFFF) + body)
                s.recv(4096)
            except OSError:
                s.close(); s = None; continue

    t = random.choice(TYPES)
    n = random.choice([0, 1, 2, 3, 4, 7, 8, 13, 17, 64, 300])
    body = bytes(random.getrandbits(8) for _ in range(n))
    try:
        s.sendall(struct.pack("<IBH", 7 + len(body), t, random.getrandbits(16)) + body)
        sent += 1
        s.settimeout(2)
        try:
            s.recv(65536)      # a reply, or nothing, or a close: all acceptable
        except socket.timeout:
            pass
    except OSError:
        s.close(); s = None
        continue
    if random.random() < 0.1:
        s.close(); s = None

if s is not None:
    s.close()
print("sent %d" % sent)
PYEOF
)
check "the server accepts 600 malformed messages without dying" "1"     "$(echo "$fuzz_out" | grep -c '^sent 6')"
kill "$fuzz_tun" 2>/dev/null
wait "$fuzz_tun" 2>/dev/null
check "the server still serves correctly afterwards" "hello from 9p" "$("${N[@]}" cat hello.txt)"
check "the server process is still alive" "1" "$(kill -0 "$srv_pid" 2>/dev/null && echo 1 || echo 0)"
stop_server

echo
echo "-- concurrency --"
start_server
rc=0
# Wait on these specific pids: a bare `wait` would also block on the server,
# which is a background job of this same shell and never exits on its own.
pids=()
for i in $(seq 1 8); do
    (
        "${N[@]}" get big.bin "$WORK/par-$i.bin" >/dev/null 2>&1 || exit 1
        cmp -s "$EXPORT/big.bin" "$WORK/par-$i.bin" || exit 1
    ) &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || rc=1; done
check "eight concurrent clients each get a correct copy" "0" "$rc"
stop_server

echo
if grep -qiE 'fatal|unexpected' "$TMP/server.log" 2>/dev/null; then
    echo "server log contains unexpected entries:"
    grep -iE 'fatal|unexpected' "$TMP/server.log" | sed 's/^/  /'
fi
echo "$((pass + fail)) test(s), $fail failure(s)"
exit $((fail > 0 ? 1 : 0))
