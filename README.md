# npxf

A 9P2000.L server and client in C++20, over an authenticated and encrypted
channel. No third-party libraries: libc, POSIX/Linux syscalls, and the C++
standard library. Built with clang, lld and bash.

```
./build.sh            # release into build/
./build.sh test       # build and run the unit self-test
./test.sh             # end-to-end suite against a real server
```

`lld` is the intended linker; if it is not installed the build warns and falls
back (`sudo apt install lld`).

## Quick start

```console
$ head -c 32 /dev/urandom | base64 > ~/.npxf-token && chmod 600 ~/.npxf-token

# server: exports the current directory
$ npxf-server -t ~/.npxf-token -l :5640

# client
$ export NPXF_TOKEN=$(cat ~/.npxf-token)
$ npxf -a server.example:5640 ls -l
$ npxf -a server.example:5640 get -r project ./project
$ npxf -a server.example:5640 put -r ./build build
```

## The secure channel

`libc` ships no TLS, so the transport is built from primitives implemented here
against their RFCs: X25519 (RFC 7748), ChaCha20-Poly1305 (RFC 8439), and
SHA-256/HMAC/HKDF. Every one has known-answer tests from the defining RFC in
`src/crypto_vectors.cpp`, and **both binaries run the full vector set at
startup** and refuse to run if any of it fails.

The handshake is three flights, one round trip:

```
    psk = HMAC-SHA256("npxf token v1", token)
    h0  = SHA256("npxf-handshake-v1")

  c->s   "NPXF" | ver | rsv[3] | CE          h1 = SHA256(h0 | msg1)
  s->c   SE | HMAC(k_cfm, "server")          h2 = SHA256(h1 | SE)
  c->s   HMAC(k_cfm, "client")

    prk   = HKDF-Extract(salt = psk, ikm = X25519(own ephemeral, peer ephemeral))
    k_c2s = HKDF-Expand(prk, "npxf c2s v1" | h2, 32)
    k_s2c = HKDF-Expand(prk, "npxf s2c v1" | h2, 32)
    k_cfm = HKDF-Expand(prk, "npxf cfm v1" | h2, 32)
```

**The token is never transmitted, in any form.** It is mixed into the key
schedule as a pre-shared key, and each side proves possession of it by
producing a MAC that only a holder could produce. This is deliberately not a
bearer credential: there is nothing on the wire for a middlebox, a log, or a
malicious server to capture and replay somewhere else.

What that buys, concretely:

| Property | How |
| --- | --- |
| Mutual authentication | Both confirmation MACs derive from the token. A plain bearer token sent to an *unauthenticated* server is trivially harvested by an active attacker; this is not that. |
| Forward secrecy | Session keys depend on two fresh ephemeral X25519 keys, so the long-lived token cannot decrypt recorded traffic. |
| Transcript binding | Both MACs cover `h2`, which covers the protocol version and both ephemeral public keys — so a downgrade or a swapped key breaks the handshake. |
| Replay resistance | Fresh ephemerals every connection; no handshake message can be replayed. |
| Contributory behaviour | An all-zero X25519 result (a small-order peer key) aborts the handshake. |

After the handshake, each 9P message is one AEAD record:

```
len[4] LE  |  ciphertext[len-16]  |  tag[16]
```

AAD is the four length bytes. The nonce is `00000000 | LE64(counter)` with an
independent counter per direction, so a nonce is never reused under a key and
records cannot be reordered, dropped, duplicated or truncated without the tag
failing. The self-test asserts each of those.

**Caveat worth stating plainly:** this is hand-written cryptography. The
primitives are standard, constant-time by construction, and verified against
RFC vectors, and the handshake is a deliberately small Noise-style PSK pattern.
It has not had third-party review. If you would rather not run hand-rolled
crypto, run the server on localhost and put it behind an SSH tunnel instead —
`npxf` will work fine over one.

## The file server

`npxf-server` exports one directory tree, given by `--root` or the cwd.

Containment is structural rather than checked:

- The export root is an `O_PATH` descriptor held for the process's lifetime,
  and **every fid is a descriptor**, never a path string.
- A walk resolves exactly one component at a time relative to the fid it starts
  from, via `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` where available
  and `openat(O_PATH | O_NOFOLLOW)` otherwise. Names containing `/` are
  rejected.
- `..` never reaches the filesystem. The server pops a component from its own
  canonical list for the fid and clamps at the root, so the export behaves like
  a chroot from the client's point of view.
- Symlinks are never followed — 9P2000.L expects the *client* to resolve them
  via `Treadlink`. A symlink planted in the export that points outside it is
  stored verbatim and is inert on the server side.

Since there is no path string to smuggle a traversal through, and no gap
between checking a name and opening it, the usual traversal and TOCTOU classes
do not arise. `test.sh` covers `..` escapes, absolute paths, and outward-facing
symlinks.

Some operations need a real descriptor where the fid only has an `O_PATH` one
(read, write, chmod, truncate). Those go through `/proc/self/fd/N`, which is
the race-free way to upgrade such a handle; the server checks `/proc` is
mounted at startup rather than failing obscurely later.

### Credentials

All file access uses the server process's own uid and gid. `Tattach`'s
`n_uname` is **not** honoured as an identity — this is a single-user export.
`--user NAME` drops privileges after the listening socket is bound. Anyone
holding the token has exactly the access the server process has, so run it as
the user whose files you mean to share, and use `--read-only` when that is all
you need.

### Implemented messages

The full 9P2000.L set:

```
version  auth  attach  flush  walk  read  write  clunk  remove
statfs  lopen  lcreate  symlink  mknod  rename  readlink
getattr  setattr  xattrwalk  xattrcreate  readdir  fsync
lock  getlock  link  mkdir  renameat  unlinkat
```

Notes on the ones with a real choice behind them:

- **`auth`** returns `EOPNOTSUPP`. Authentication already happened, at the
  channel layer, before a single 9P byte moved; declining `Tauth` is how a 9P
  server says "no afid needed".
- **`lock`/`getlock`** use *open file description* locks (`F_OFD_SETLK`). Plain
  POSIX locks are per-process, so one server holding many clients' locks would
  see them silently merge. OFD locks belong to the descriptor, which is exactly
  the fid. Contention returns `BLOCKED` rather than blocking a worker; the
  Linux client retries.
- **`flush`** never blocks the reader. If the target request is still running,
  the flush tag is parked and answered by the worker that finishes it, which
  satisfies the ordering the spec requires.
- **`xattrcreate`** buffers writes and applies them in one `setxattr` at clunk,
  so a value never becomes visible in fragments. A zero declared size removes
  the attribute.
- **qid.path** is a hash of `(st_dev, st_ino)`, not the raw inode. An export
  spanning more than one filesystem would otherwise hand the client two
  distinct files with the same inode number, which it would treat as one file.

## Performance

Over loopback, 512 MiB, default 1 MiB msize, on this machine:

| | throughput |
| --- | --- |
| `get`, 16 requests in flight | **402 MiB/s** |
| `put`, 16 requests in flight | **341 MiB/s** |
| `get`, no pipelining (`-d 1`) | 144 MiB/s |

Three things carry that:

- **Pipelining.** 9P is a synchronous RPC protocol; a copy that waits for each
  `Rread` before sending the next `Tread` costs one round trip per chunk. `-d`
  sets the depth (default 8). It is worth 2.8× even at loopback latency, and
  much more over a real link.
- **A large msize** (`-m`, default 1 MiB) so each round trip carries more.
- **Per-connection worker threads** on the server, so a slow request does not
  stall the ones behind it. Reads and writes take a *shared* lock on the fid —
  `pread`/`pwrite` carry their own offsets — so a pipelined copy runs genuinely
  in parallel; only operations that mutate fid state serialise.

The remaining bottleneck at these rates is ChaCha20-Poly1305 in portable C.

Memory is roughly `max_conns × workers × msize` in the worst case, since each
worker keeps a reply buffer; tune with `-c`, `-j` and `-m` if that matters.

## Mounting it

Because this is genuine 9P2000.L, the Linux kernel's own client can mount it.
`npxf tunnel` accepts plain 9P locally and relays it through the encrypted
session:

```console
$ npxf -a server.example:5640 tunnel            # unix socket, mode 0600
npxf tunnel: listening on /tmp/npxf-1000.sock
mount with:
  sudo mount -t 9p -o trans=unix,version=9p2000.L,msize=1048576 /tmp/npxf-1000.sock /mnt
```

The unix socket is the default because it is created 0600; `--tcp PORT` binds
loopback instead, where any local user could connect.

The test suite drives the tunnel with a raw 9P2000.L speaker — the same
conversation the kernel has — so the framing is verified even where a real
mount needs root.

## Layout

| | |
| --- | --- |
| `src/crypto.{hpp,cpp}` | X25519, ChaCha20-Poly1305, SHA-256, HMAC, HKDF |
| `src/crypto_vectors.cpp` | RFC known-answer tests, run at every startup |
| `src/channel.{hpp,cpp}` | handshake and AEAD record layer |
| `src/ninep.{hpp,cpp}` | 9P2000.L constants and codec |
| `src/net.{hpp,cpp}` | socket helpers |
| `src/server.{hpp,cpp}` | listener, session loop, dispatch |
| `src/server_ops.cpp` | the operations |
| `src/client.{hpp,cpp}` | client with tag demultiplexing |
| `src/npxf_main.cpp` | CLI |
| `src/selftest.cpp` | unit tests |
| `tests/p9.py` | an independent 9P2000.L client, for testing |
| `tests/ops.py` | protocol-level coverage of every operation |

## Testing

`./test.sh` runs 112 checks against a real server on loopback. Roughly:

- **Unit** — the RFC crypto vectors, codec round-trips and malformed-input
  rejection, and a live handshake over a socketpair that also asserts tampered,
  replayed and oversized records are refused.
- **CLI** — listings, copies both ways at several pipeline depths, files sized
  exactly at and one byte past an iounit, recursive trees with symlinks, and
  the namespace operations.
- **Protocol** — `tests/ops.py` drives the server through the tunnel with its
  own 9P implementation (`tests/p9.py`), not the npxf client, so the server is
  checked against something other than its own counterpart. This is what covers
  `setattr`, `link`, `rename`, `remove`, `mknod`, `fsync`, `statfs`, `flush`,
  the xattr and lock operations, and the directory cursor — paged at counts
  from 128 bytes up, verifying 200 entries come back exactly once each.
- **Adversarial** — containment (`..`, absolute paths, outward symlinks), wrong
  and empty tokens, a garbage handshake, read-only enforcement, 600 malformed
  9P frames, and eight concurrent clients.

It also passes clean under both sanitizers, including leak detection:

```console
$ ./build.sh asan && NPXF_TEST_MODE=asan ./test.sh
$ ./build.sh tsan && NPXF_TEST_MODE=tsan ./test.sh
```

The Python here is test scaffolding only — nothing in the shipped programs
depends on it.

## Known limits

- **The crypto has not been independently reviewed.** See above.
- **Single-user export.** No per-request credential switching; every client
  with the token gets the server process's access.
- If a process *outside* the server rearranges the exported tree mid-operation,
  a fid's cached path can go stale and an operation may land on the wrong file.
  It cannot land outside the export — resolution always restarts from the root
  descriptor — but the tree is assumed not to be moved under the server.
- `Tflush` is answered correctly but does not abort a syscall already in
  progress; each operation is a single syscall, so the wait is bounded.
- `getattr` does not report `gen` or `data_version`; those bits are left out of
  the valid mask rather than being faked.
