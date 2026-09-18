// npxf -- 9P2000.L wire protocol: constants and codec.
//
// Every message is  size[4] type[1] tag[2] body...  with all integers
// little-endian and strings encoded as len[2] followed by len bytes of UTF-8
// with no terminator.  `size` counts itself.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "util.hpp"

namespace npxf::ninep {

inline constexpr std::string_view kVersion = "9P2000.L";
inline constexpr uint32_t kNoFid = 0xFFFFFFFFu;
inline constexpr uint16_t kNoTag = 0xFFFFu;
inline constexpr size_t kHeaderLen = 7;  // size[4] type[1] tag[2]
inline constexpr size_t kQidLen = 13;    // type[1] version[4] path[8]

inline constexpr uint32_t kMinMsize = 8192;
inline constexpr uint32_t kDefaultMsize = 1u << 20;

// Largest Tread/Twrite payload for a given msize.  Twrite's header is the
// bigger of the two at size[4] type[1] tag[2] fid[4] offset[8] count[4] = 23;
// 24 keeps a byte in hand.
inline constexpr uint32_t iounit_for(uint32_t msize) { return msize - 24; }

// The 9P spec caps a single Twalk at sixteen names.
inline constexpr size_t kMaxWalkNames = 16;

// ------------------------------------------------------------ message types

enum Type : uint8_t {
    Tlerror = 6,
    Rlerror = 7,
    Tstatfs = 8,
    Rstatfs = 9,
    Tlopen = 12,
    Rlopen = 13,
    Tlcreate = 14,
    Rlcreate = 15,
    Tsymlink = 16,
    Rsymlink = 17,
    Tmknod = 18,
    Rmknod = 19,
    Trename = 20,
    Rrename = 21,
    Treadlink = 22,
    Rreadlink = 23,
    Tgetattr = 24,
    Rgetattr = 25,
    Tsetattr = 26,
    Rsetattr = 27,
    Txattrwalk = 30,
    Rxattrwalk = 31,
    Txattrcreate = 32,
    Rxattrcreate = 33,
    Treaddir = 40,
    Rreaddir = 41,
    Tfsync = 50,
    Rfsync = 51,
    Tlock = 52,
    Rlock = 53,
    Tgetlock = 54,
    Rgetlock = 55,
    Tlink = 70,
    Rlink = 71,
    Tmkdir = 72,
    Rmkdir = 73,
    Trenameat = 74,
    Rrenameat = 75,
    Tunlinkat = 76,
    Runlinkat = 77,
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
    Rerror = 107,  // 9P2000 only; .L uses Rlerror
    Tflush = 108,
    Rflush = 109,
    Twalk = 110,
    Rwalk = 111,
    Tread = 116,
    Rread = 117,
    Twrite = 118,
    Rwrite = 119,
    Tclunk = 120,
    Rclunk = 121,
    Tremove = 122,
    Rremove = 123,
};

const char *type_name(uint8_t t);

// -------------------------------------------------------------------- qids

enum QidType : uint8_t {
    QTFILE = 0x00,
    QTLINK = 0x01,
    QTSYMLINK = 0x02,
    QTTMP = 0x04,
    QTAUTH = 0x08,
    QTMOUNT = 0x10,
    QTEXCL = 0x20,
    QTAPPEND = 0x40,
    QTDIR = 0x80,
};

struct Qid {
    uint8_t type = QTFILE;
    uint32_t version = 0;
    uint64_t path = 0;
};

// ------------------------------------------------------------ getattr masks

enum GetattrMask : uint64_t {
    GETATTR_MODE = 0x00000001,
    GETATTR_NLINK = 0x00000002,
    GETATTR_UID = 0x00000004,
    GETATTR_GID = 0x00000008,
    GETATTR_RDEV = 0x00000010,
    GETATTR_ATIME = 0x00000020,
    GETATTR_MTIME = 0x00000040,
    GETATTR_CTIME = 0x00000080,
    GETATTR_INO = 0x00000100,
    GETATTR_SIZE = 0x00000200,
    GETATTR_BLOCKS = 0x00000400,
    GETATTR_BTIME = 0x00000800,
    GETATTR_GEN = 0x00001000,
    GETATTR_DATA_VERSION = 0x00002000,
    GETATTR_BASIC = 0x000007ff,
    GETATTR_ALL = 0x00003fff,
};

enum SetattrMask : uint32_t {
    SETATTR_MODE = 0x00000001,
    SETATTR_UID = 0x00000002,
    SETATTR_GID = 0x00000004,
    SETATTR_SIZE = 0x00000008,
    SETATTR_ATIME = 0x00000010,
    SETATTR_MTIME = 0x00000020,
    SETATTR_CTIME = 0x00000040,
    SETATTR_ATIME_SET = 0x00000080,
    SETATTR_MTIME_SET = 0x00000100,
};

// ------------------------------------------------------- 9P2000.L open flags
// These are the protocol's own numeric values.  They happen to match Linux on
// x86, but we translate explicitly rather than pass them through, so a client
// on another architecture -- or a malicious one -- cannot smuggle in a flag we
// did not intend to honour.

enum DotlOpenFlag : uint32_t {
    L_O_RDONLY = 000000000,
    L_O_WRONLY = 000000001,
    L_O_RDWR = 000000002,
    L_O_NOACCESS = 000000003,
    L_O_CREAT = 000000100,
    L_O_EXCL = 000000200,
    L_O_NOCTTY = 000000400,
    L_O_TRUNC = 000001000,
    L_O_APPEND = 000002000,
    L_O_NONBLOCK = 000004000,
    L_O_DSYNC = 000010000,
    L_O_FASYNC = 000020000,
    L_O_DIRECT = 000040000,
    L_O_LARGEFILE = 000100000,
    L_O_DIRECTORY = 000200000,
    L_O_NOFOLLOW = 000400000,
    L_O_NOATIME = 001000000,
    L_O_CLOEXEC = 002000000,
    L_O_SYNC = 004000000,
};

// ------------------------------------------------------------------- locking

enum LockType : uint8_t { LOCK_RDLCK = 0, LOCK_WRLCK = 1, LOCK_UNLCK = 2 };
enum LockFlag : uint32_t { LOCK_FLAG_BLOCK = 1, LOCK_FLAG_RECLAIM = 2 };
enum LockStatus : uint8_t {
    LOCK_SUCCESS = 0,
    LOCK_BLOCKED = 1,
    LOCK_ERROR = 2,
    LOCK_GRACE = 3,
};

// --------------------------------------------------------------------- codec

// Thrown when a peer's message is malformed or truncated.
struct ProtoError : Error {
    using Error::Error;
};

class Enc {
  public:
    explicit Enc(Bytes &b) : b_(b) {}

    void u8(uint8_t v) { b_.push_back(v); }
    void u16(uint16_t v);
    void u32(uint32_t v);
    void u64(uint64_t v);
    void str(std::string_view s);
    void raw(const uint8_t *p, size_t n) { b_.insert(b_.end(), p, p + n); }
    void raw(std::span<const uint8_t> s) { raw(s.data(), s.size()); }
    void qid(const Qid &q);

    // Reserves n bytes of uninitialised space and hands back a writable
    // pointer -- lets read handlers pull straight from the file into the
    // reply buffer with no bounce copy.
    uint8_t *reserve(size_t n);

    Bytes &buf() { return b_; }
    size_t size() const { return b_.size(); }

  private:
    Bytes &b_;
};

class Dec {
  public:
    Dec(const uint8_t *p, size_t n) : p_(p), e_(p + n) {}
    explicit Dec(std::span<const uint8_t> s) : Dec(s.data(), s.size()) {}

    uint8_t u8();
    uint16_t u16();
    uint32_t u32();
    uint64_t u64();
    std::string str();
    std::span<const uint8_t> raw(size_t n);
    Qid qid();

    size_t left() const { return size_t(e_ - p_); }
    // Rejects trailing junk, so a peer cannot hide data after a valid body.
    void end() const;

  private:
    void need(size_t n) const;
    const uint8_t *p_;
    const uint8_t *e_;
};

// Appends a header with a placeholder size; call finish() once the body is
// written to patch the real length in.
void begin(Bytes &b, uint8_t type, uint16_t tag);
void finish(Bytes &b);

// Parses and validates a complete framed message.  `body` points into `msg`.
struct Header {
    uint8_t type;
    uint16_t tag;
    std::span<const uint8_t> body;
};
Header parse(std::span<const uint8_t> msg);

// A single Rreaddir entry: qid[13] offset[8] type[1] name[s].
inline size_t readdir_entry_len(size_t namelen) { return kQidLen + 8 + 1 + 2 + namelen; }
void encode_dirent(Enc &e, const Qid &q, uint64_t offset, uint8_t dtype, std::string_view name);

}  // namespace npxf::ninep
