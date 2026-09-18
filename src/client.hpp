// npxf -- 9P2000.L client.
//
// Replies are demultiplexed by tag on a dedicated reader thread, so a caller
// can put many requests on the wire before waiting for the first answer.  That
// is the whole game for throughput: 9P is a synchronous RPC protocol, and a
// copy that waits for each Rread before sending the next Tread runs at one
// round trip per chunk no matter how fast the link is.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "channel.hpp"
#include "ninep.hpp"
#include "util.hpp"

namespace npxf::client {

// An Rlerror from the server, carrying the Linux errno it reported.
struct RemoteError : Error {
    int err;
    RemoteError(int e, const std::string &what) : Error(what), err(e) {}
};

struct Attrs {
    uint64_t valid = 0;
    ninep::Qid qid;
    uint32_t mode = 0, uid = 0, gid = 0;
    uint64_t nlink = 0, rdev = 0, size = 0, blksize = 0, blocks = 0;
    int64_t atime_sec = 0, mtime_sec = 0, ctime_sec = 0, btime_sec = 0;
    uint32_t atime_nsec = 0, mtime_nsec = 0, ctime_nsec = 0;
};

struct StatFs {
    uint32_t type = 0, bsize = 0, namelen = 0;
    uint64_t blocks = 0, bfree = 0, bavail = 0, files = 0, ffree = 0, fsid = 0;
};

struct DirEntry {
    std::string name;
    ninep::Qid qid;
    uint64_t offset = 0;
    uint8_t type = 0;  // DT_* from the server's getdents64
};

// Establishes the TCP connection and runs the handshake.  Returned separately
// from Client so `npxf tunnel` can drive a bare Channel with no 9P state.
struct Dialed {
    Fd sock;
    SessionKeys keys;
};
Dialed dial(const std::string &addr, std::span<const uint8_t> token);

class Client {
  public:
    Client() = default;
    ~Client();
    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    void connect(const std::string &addr, std::span<const uint8_t> token, uint32_t msize);
    void attach(const std::string &uname);
    void close();

    uint32_t msize() const { return msize_; }
    uint32_t iounit() const { return ninep::iounit_for(msize_); }
    uint32_t root() const { return root_fid_; }

    // ---- fid lifecycle
    uint32_t alloc_fid();
    void release_fid(uint32_t fid);  // returns the number to the pool, no Tclunk

    // ---- operations
    std::vector<ninep::Qid> walk(uint32_t fid, uint32_t newfid, const std::vector<std::string> &names);
    // Walks a '/'-separated path from the root and returns a fresh fid.
    uint32_t walk_path(const std::string &path);
    ninep::Qid lopen(uint32_t fid, uint32_t flags);
    ninep::Qid lcreate(uint32_t dfid, const std::string &name, uint32_t flags, uint32_t mode,
                       uint32_t gid);
    ninep::Qid mkdir(uint32_t dfid, const std::string &name, uint32_t mode, uint32_t gid);
    ninep::Qid symlink(uint32_t dfid, const std::string &name, const std::string &target, uint32_t gid);
    Attrs getattr(uint32_t fid, uint64_t mask = ninep::GETATTR_ALL);
    void setattr(uint32_t fid, uint32_t valid, uint32_t mode, uint32_t uid, uint32_t gid,
                 uint64_t size, int64_t atime_sec, int64_t atime_nsec, int64_t mtime_sec,
                 int64_t mtime_nsec);
    std::vector<DirEntry> readdir(uint32_t fid);
    std::string readlink(uint32_t fid);
    StatFs statfs(uint32_t fid);
    void renameat(uint32_t odfid, const std::string &oldname, uint32_t ndfid,
                  const std::string &newname);
    void unlinkat(uint32_t dfid, const std::string &name, uint32_t flags);
    void fsync(uint32_t fid, bool datasync);
    void clunk(uint32_t fid);

    // ---- bulk I/O, split so callers can keep several in flight
    uint16_t submit_read(uint32_t fid, uint64_t offset, uint32_t count);
    size_t complete_read(uint16_t tag, uint8_t *buf, size_t cap);
    uint16_t submit_write(uint32_t fid, uint64_t offset, const uint8_t *p, uint32_t n);
    size_t complete_write(uint16_t tag);

    // Convenience wrappers around the above.
    size_t read_at(uint32_t fid, uint64_t offset, uint8_t *buf, size_t n);
    size_t write_at(uint32_t fid, uint64_t offset, const uint8_t *p, size_t n);

  private:
    struct Pending {
        bool done = false;
        Bytes msg;
    };

    void reader_loop();
    uint16_t next_tag();
    void free_tag(uint16_t tag);

    // Builds a message, sends it, and registers the tag.
    uint16_t submit(uint8_t type, const std::function<void(ninep::Enc &)> &body);
    // Waits for `tag`, checks for Rlerror, and returns the whole reply.
    Bytes await(uint16_t tag, uint8_t expect);
    Bytes call(uint8_t type, const std::function<void(ninep::Enc &)> &body, uint8_t expect) {
        return await(submit(type, body), expect);
    }

    Fd sock_;
    std::optional<Channel> ch_;
    uint32_t msize_ = ninep::kDefaultMsize;
    uint32_t root_fid_ = 0;
    bool attached_ = false;

    std::mutex mu_;
    std::condition_variable cv_;
    std::unordered_map<uint16_t, std::shared_ptr<Pending>> pending_;
    std::string fatal_;
    std::thread reader_;

    std::mutex tag_mu_;
    uint16_t tag_next_ = 0;
    std::deque<uint16_t> tag_free_;

    std::mutex fid_mu_;
    uint32_t fid_next_ = 1;
    std::deque<uint32_t> fid_free_;
};

// Splits "a/b//c/." into {"a","b","c"}; a leading '/' is ignored because every
// path is relative to the export root.
std::vector<std::string> split_path(const std::string &p);

}  // namespace npxf::client
