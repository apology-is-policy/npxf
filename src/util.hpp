// npxf -- shared utilities.  C++20 standard library + POSIX only.
#pragma once

#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <unistd.h>

namespace npxf {

using Bytes = std::vector<uint8_t>;

inline std::span<const uint8_t> byte_span(std::string_view s) {
    return {reinterpret_cast<const uint8_t *>(s.data()), s.size()};
}

inline std::span<const uint8_t> byte_span(const Bytes &b) { return {b.data(), b.size()}; }

// ---------------------------------------------------------------- endianness
// 9P and our record layer are both little-endian on the wire.  Explicit byte
// shifts keep this correct on any host and compile to a single load/store on
// the architectures anyone will actually run this on.

inline uint16_t ld16(const uint8_t *p) { return uint16_t(p[0]) | uint16_t(uint16_t(p[1]) << 8); }
inline uint32_t ld32(const uint8_t *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline uint64_t ld64(const uint8_t *p) { return uint64_t(ld32(p)) | (uint64_t(ld32(p + 4)) << 32); }

inline void st16(uint8_t *p, uint16_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
}
inline void st32(uint8_t *p, uint32_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}
inline void st64(uint8_t *p, uint64_t v) {
    st32(p, uint32_t(v));
    st32(p + 4, uint32_t(v >> 32));
}

// --------------------------------------------------------------------- errors

struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

[[noreturn]] inline void throw_errno(const std::string &what) {
    throw std::system_error(errno, std::generic_category(), what);
}

[[noreturn]] inline void fail(const std::string &what) { throw Error(what); }

// ------------------------------------------------------------------ file desc

// Owning file descriptor.  Move-only; closes on destruction.
class Fd {
  public:
    Fd() = default;
    explicit Fd(int fd) : fd_(fd) {}
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    Fd(Fd &&o) noexcept : fd_(std::exchange(o.fd_, -1)) {}
    Fd &operator=(Fd &&o) noexcept {
        if (this != &o) {
            reset();
            fd_ = std::exchange(o.fd_, -1);
        }
        return *this;
    }
    ~Fd() { reset(); }

    int get() const { return fd_; }
    explicit operator bool() const { return fd_ >= 0; }
    bool valid() const { return fd_ >= 0; }

    int release() { return std::exchange(fd_, -1); }
    void reset(int fd = -1) {
        if (fd_ >= 0 && fd_ != fd) {
            int e = errno;  // close() must never clobber a pending errno
            ::close(fd_);
            errno = e;
        }
        fd_ = fd;
    }

  private:
    int fd_ = -1;
};

// -------------------------------------------------------------------- logging

inline int g_verbose = 0;

__attribute__((format(printf, 2, 3))) inline void logf(int level, const char *fmt, ...) {
    if (level > g_verbose) return;
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

// ----------------------------------------------------------------- token file

// Strip the trailing newline a token FILE carries but the token does not.
//
// This is INTEROP SURFACE, not housekeeping.  npxf and Thylacine's haul(1) both
// derive the PSK from exactly these bytes, so a peer that trims a different
// amount derives a different key -- and the handshake then fails with "token
// mismatch, or the connection was intercepted", blaming an attacker for a byte
// an editor added.  Both \n and \r, and a RUN of them, so a CRLF file and a
// file that ends in a blank line still name the same token.
//
// An environment variable is deliberately NOT trimmed, here or in haul: a
// variable holds exactly what someone set it to, whereas a file conventionally
// ends with a newline nobody typed.
//
// Counterpart: `npxf::trim_token_file` in usr/haul/src/npxf.rs.
inline void trim_token_file(Bytes &b) {
    while (!b.empty() && (b.back() == '\n' || b.back() == '\r')) b.pop_back();
}

// ------------------------------------------------------------------------ hex

inline std::string to_hex(std::span<const uint8_t> b) {
    static const char *d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) {
        s.push_back(d[c >> 4]);
        s.push_back(d[c & 15]);
    }
    return s;
}

// Returns false on any non-hex input or odd length.
inline bool from_hex(std::string_view s, Bytes &out) {
    if (s.size() % 2) return false;
    out.clear();
    out.reserve(s.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(uint8_t(hi << 4 | lo));
    }
    return true;
}

}  // namespace npxf
