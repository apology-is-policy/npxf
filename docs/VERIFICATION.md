# OpenSSL and host portability verification

18 September 2026. Single-agent implementation and self-review; no independent
security audit is claimed.

The build uses OpenSSL 3 EVP digest, MAC, KDF, X25519 and AEAD interfaces,
OpenSSL randomness, constant-time comparison and cleansing. The adapter preserves
the NPXF v1 transcript and wire bytes. Relevant primary API references:

- https://docs.openssl.org/3.0/man7/EVP_KDF-HKDF/
- https://docs.openssl.org/3.0/man3/EVP_chacha20/

## Measured checks

- macOS arm64, AppleClang 17, OpenSSL 3.6.3: CMake build and both CTest targets pass.
- Linux arm64, Debian 13 on Raspberry Pi, GCC, OpenSSL 3.5.7: CMake build and both
  CTest targets pass, including the eight-client byte-comparison workload.
- macOS with Homebrew LLVM, ASan + UBSan: both CTest targets pass.
- Haul's existing Rust client: all 53 host tests, including the live encrypted
  handshake and Tversion/Rversion exchange against the macOS server, pass.

The suite includes RFC crypto vectors, invalid tags and low-order keys, channel
poisoning, exhausted counters, 1000 immediate reuses of one 9P tag, replacement
inode protection before truncation, directory pagination, xattrs, descriptor
locks, malformed messages and concurrent byte-verified file copies.

Two sanitizer runtime limitations were isolated with empty programs: Apple's
ASan on this Mac recursively deadlocks during allocator initialization before
main; the Pi GCC ASan fails reserving its allocator address range before main.
Those runs are not passes. The working macOS LLVM sanitizer run is separate.
ThreadSanitizer runtime coverage is not claimed.

## Findings and resolution

The first concurrent Linux run returned EINVAL after a successful Rwalk. Logs
showed the client immediately reusing tag 0 for Tgetattr. The server used to
publish a reply before retiring that tag. Admission could therefore reject a
legal reuse. Reply publication and tag retirement now hold the same tag mutex;
normal filesystem operations still run on parallel workers. Lock order is
fid lock -> tag mutex -> channel send mutex; no reverse acquisition was added.

Darwin cannot reuse Linux errno/open/unlink/xattr constants, O_PATH, getdents64,
or /proc/self/fd. The port uses explicit wire translation, O_EVTONLY/O_SYMLINK
path handles, descriptor metadata, libc directory streams and OFD locks. Reopening
for I/O resolves under the pinned export root and compares device/inode before
O_TRUNC. Special-file data I/O is unsupported on Darwin. Existing directory
handles still refer to their inodes after external renames: administrators must
not move export directories across the export boundary while serving.

The channel now refuses nonce exhaustion, poisons both directions after an error,
wipes unauthenticated output and clears keys/intermediates on normal and exceptional
exit. OpenSSL's EVP decryption emits bytes before authenticating the tag; that is
why the adapter explicitly wipes output when Final rejects it.

The protocol test harness previously swallowed Python's failing exit status and
used host-specific filesystem inspection commands. It now propagates failures,
retains failed fixtures and client logs, and uses independent native Darwin xattr
checks instead of skipping them.

## Reproduction

```
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build/release --parallel
ctest --test-dir build/release --output-on-failure
```

For a sanitizer build, use a fresh build directory and add
`-DNPXF_SANITIZER=address`; select the working compiler with
`-DCMAKE_CXX_COMPILER=/path/to/clang++`. CTest integration checks operate only on
loopback and temporary export directories. GitHub CI runs the release suite on
Linux and macOS; its latest status must be read from GitHub, not inferred here.
