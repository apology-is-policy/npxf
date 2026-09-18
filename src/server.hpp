// npxf -- 9P2000.L server.
//
// Security model for the file tree
// --------------------------------
// The export root is held open as a path descriptor for the process's
// lifetime. Every fid is likewise a descriptor, and every walk step
// resolves exactly one path component relative to the fid it starts from,
// using openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS) where the kernel
// supports it and openat(O_PATH | O_NOFOLLOW) otherwise.  Because component
// names are rejected if they contain a slash and ".." is handled by the server
// (popping its own canonical component list, clamped at the root), a client
// cannot name a file outside the export -- there is no path string for it to
// smuggle a traversal through, and no window between checking a path and
// opening it.
//
// Symlinks are never followed.  9P2000.L expects the client to resolve them
// via Treadlink, so a symlink fid refers to the link itself.  That also means
// a symlink planted inside the export cannot be used to reach outside it.
//
// Darwin uses O_EVTONLY/O_SYMLINK handles and identity-checked reopening
// beneath the root; a replaced inode fails ESTALE before O_TRUNC. Local
// administrators must not move open export directories across the boundary.
//
// Credentials
// -----------
// All file access uses the server process's own uid/gid.  Tattach's n_uname is
// not honoured as an identity: this is a single-user export, and --user lets
// you drop privileges at startup after the listening socket is bound.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/stat.h>
#include <dirent.h>

#include "channel.hpp"
#include "ninep.hpp"
#include "util.hpp"

namespace npxf::server {

struct Config {
    std::string listen = ":5640";
    std::string root;  // empty => cwd
    Bytes token;
    uint32_t msize = ninep::kDefaultMsize;
    int workers = 0;  // 0 => auto-size from hardware_concurrency
    int max_conns = 64;
    bool readonly = false;
    bool once = false;
    std::string drop_user;
};

// Thrown by op handlers; the dispatcher turns it into an Rlerror.
struct Errno {
    int e;
    explicit Errno(int v) : e(v) {}
};

[[noreturn]] inline void oserr(int e) { throw Errno(e); }
[[noreturn]] inline void oserr() { throw Errno(errno); }

// Wrap a syscall whose failure is signalled by a negative return.
template <typename T>
T check(T rc) {
    if (rc < 0) throw Errno(errno);
    return rc;
}

// --------------------------------------------------------------------- fids

struct Fid {
    // Identity and the dirfd for every *at() call.  Always valid.
    Fd pfd;
    // A real descriptor, opened by Tlopen/Tlcreate.  O_PATH descriptors cannot
    // be read or written, so I/O needs this separate handle.
    Fd iofd;

    // Canonical components relative to the export root.  Maintained by the
    // server so that ".." can be resolved without ever consulting the
    // filesystem's own parent links.
    std::vector<std::string> path;

    bool is_dir = false;
    bool is_symlink = false;
    bool opened = false;

    int64_t dir_off = 0;  // Last returned opaque directory cookie.
    std::unique_ptr<DIR, int (*)(DIR *)> dir_stream{nullptr, ::closedir};

    // Txattrwalk turns a fid into a read-only view of one xattr (or of the
    // name list); Txattrcreate turns it into a write buffer flushed on clunk.
    bool xattr = false;
    bool xattr_write = false;
    std::string xattr_name;
    Bytes xattr_buf;
    uint32_t xattr_flags = 0;
    uint64_t xattr_size = 0;

    // Shared for stateless work (read, write, getattr); exclusive for anything
    // that mutates the fid itself.  Keeping reads shared is what lets a
    // pipelined copy actually run in parallel.
    std::shared_mutex mu;

    std::string display() const;
};

using FidRef = std::shared_ptr<Fid>;

// ------------------------------------------------------------------ helpers

// Stable 64-bit identity for a file.  Hashing (dev, ino) rather than using the
// raw inode keeps two files on different filesystems inside one export from
// colliding, which the client would otherwise see as a single inode.
uint64_t qid_path(dev_t dev, ino_t ino);
ninep::Qid qid_of(const struct stat &st);

// Rejects "", ".." and anything containing '/' or NUL.  "." is accepted and
// treated as a no-op by the caller.
bool valid_component(const std::string &name);

// Translate 9P2000.L open flags to host O_* flags, dropping anything we do not
// intend to honour (O_CREAT in particular, which Tlopen must never perform).
int translate_open_flags(uint32_t dotl, bool readonly);

// ------------------------------------------------------------------- server

class Conn {
  public:
    Conn(std::shared_ptr<const Config> cfg, Fd sock, int rootfd);
    ~Conn();

    Conn(const Conn &) = delete;
    Conn &operator=(const Conn &) = delete;

    // Runs the handshake and then the message loop; returns on clean EOF.
    void serve();

  private:
    struct Job {
        uint8_t type;
        uint16_t tag;
        Bytes msg;
    };

    void start_workers();
    void stop_workers();
    void worker_loop();
    void run_job(Job &job);

    void send_reply(Bytes &b);
    void send_error(uint16_t tag, int e);
    void send_empty(uint8_t type, uint16_t tag);
    void publish_reply(Bytes &b);
    static thread_local bool worker_reply_;

    // ------ fid table
    FidRef get_fid(uint32_t id);
    FidRef get_open_fid(uint32_t id);
    void put_fid(uint32_t id, FidRef f);
    FidRef take_fid(uint32_t id);
    void clear_fids();

    // ------ path resolution (server_ops.cpp)
    Fd resolve(const std::vector<std::string> &comps) const;
    Fd walk_one(int dirfd, const std::string &name) const;
    Fd open_parent(const Fid &f) const;
    Fd reopen_fid(const Fid &f, int flags) const;
    FidRef make_fid(Fd pfd, std::vector<std::string> path) const;
    void require_writable() const;

    // ------ op handlers (server_ops.cpp)
    void op_version(uint16_t tag, ninep::Dec &d);
    void op_auth(uint16_t tag, ninep::Dec &d);
    void op_attach(uint16_t tag, ninep::Dec &d);
    void op_walk(uint16_t tag, ninep::Dec &d);
    void op_statfs(uint16_t tag, ninep::Dec &d);
    void op_lopen(uint16_t tag, ninep::Dec &d);
    void op_lcreate(uint16_t tag, ninep::Dec &d);
    void op_symlink(uint16_t tag, ninep::Dec &d);
    void op_mknod(uint16_t tag, ninep::Dec &d);
    void op_rename(uint16_t tag, ninep::Dec &d);
    void op_readlink(uint16_t tag, ninep::Dec &d);
    void op_getattr(uint16_t tag, ninep::Dec &d);
    void op_setattr(uint16_t tag, ninep::Dec &d);
    void op_xattrwalk(uint16_t tag, ninep::Dec &d);
    void op_xattrcreate(uint16_t tag, ninep::Dec &d);
    void op_readdir(uint16_t tag, ninep::Dec &d);
    void op_fsync(uint16_t tag, ninep::Dec &d);
    void op_lock(uint16_t tag, ninep::Dec &d);
    void op_getlock(uint16_t tag, ninep::Dec &d);
    void op_link(uint16_t tag, ninep::Dec &d);
    void op_mkdir(uint16_t tag, ninep::Dec &d);
    void op_renameat(uint16_t tag, ninep::Dec &d);
    void op_unlinkat(uint16_t tag, ninep::Dec &d);
    void op_read(uint16_t tag, ninep::Dec &d);
    void op_write(uint16_t tag, ninep::Dec &d);
    void op_clunk(uint16_t tag, ninep::Dec &d);
    void op_remove(uint16_t tag, ninep::Dec &d);

    // Shared, not a reference: connection threads outlive the accept loop on
    // shutdown, and a reference into main's frame would dangle under them.
    std::shared_ptr<const Config> cfg_;
    Fd sock_;
    int rootfd_;
    std::string peer_;
    std::optional<Channel> ch_;
    // Renegotiated by Tversion, which the reader thread only processes once
    // every worker has gone idle -- but workers read it on every reply, so
    // keep it atomic rather than relying on that invariant holding forever.
    std::atomic<uint32_t> msize_{ninep::kDefaultMsize};
    std::atomic<bool> versioned_{false};

    std::mutex fids_mu_;
    std::unordered_map<uint32_t, FidRef> fids_;

    // Tag bookkeeping for Tflush.  A flush that arrives while its target is
    // still running is parked here and answered by the worker that finishes
    // the target, so the reader thread never blocks.
    std::mutex tags_mu_;
    std::condition_variable tags_cv_;
    std::unordered_set<uint16_t> active_tags_;
    std::unordered_map<uint16_t, std::vector<uint16_t>> flush_waiters_;

    std::mutex q_mu_;
    std::condition_variable q_cv_;
    std::deque<Job> queue_;
    bool stopping_ = false;
    std::vector<std::thread> workers_;

    // Reply scratch buffer, one per worker thread, so building a reply never
    // reallocates on the hot path.
    static thread_local Bytes reply_buf_;
};

// Opens the root, binds, and accepts until interrupted.
int run(std::shared_ptr<const Config> cfg);

}  // namespace npxf::server
