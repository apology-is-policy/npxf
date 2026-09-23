#include "platform.hpp"
// npxf-server -- the 9P2000.L operations.
//
// Every handler follows the same shape: decode the body, resolve fids, do the
// one syscall that implements it, encode the reply.  Failures are thrown as
// Errno and turned into Rlerror by the dispatcher, so error paths do not
// clutter the handlers.
#include <algorithm>
#include <cstdio>
#include <cstddef>
#include <cstring>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#ifdef __APPLE__
#include <sys/mount.h>
#define st_atim st_atimespec
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#else
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#endif
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "server.hpp"

namespace npxf::server {

using namespace ninep;

namespace {

// ---------------------------------------------------------- syscall shims
// These are ABI-stable numbers and structures the kernel exports but glibc
// does not wrap; declaring them here keeps us on libc alone.

#ifdef __linux__
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

struct OpenHow {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

constexpr uint64_t kResolveNoMagiclinks = 0x02;
constexpr uint64_t kResolveBeneath = 0x08;

// openat2 is a hardening bonus, not a requirement: because we only ever
// resolve one already-validated component with O_NOFOLLOW, plain openat is
// equally incapable of escaping the export.  Fall back silently on kernels
// (or seccomp policies) that do not offer it.
std::atomic<bool> g_have_openat2{true};

#endif

int openat_beneath(int dirfd, const char *name, int flags) {
#ifdef __linux__
    if (g_have_openat2.load(std::memory_order_relaxed)) {
        OpenHow how{};
        how.flags = uint64_t(unsigned(flags));
        how.resolve = kResolveBeneath | kResolveNoMagiclinks;
        long rc = ::syscall(SYS_openat2, dirfd, name, &how, sizeof how);
        if (rc >= 0) return int(rc);
        if (errno != ENOSYS && errno != EPERM) return -1;
        g_have_openat2.store(false, std::memory_order_relaxed);
    }
#endif
#ifdef __APPLE__
    // O_SYMLINK opens the link itself; O_NOFOLLOW would reject it instead.
    if (flags & O_SYMLINK) flags &= ~O_NOFOLLOW;
#endif
    return ::openat(dirfd, name, flags);
}

// ------------------------------------------------------------- /proc helper

// An O_PATH descriptor cannot be read, written, chmod'ed or truncated.  Going
// back through /proc/self/fd is the only way to upgrade one without re-walking
// the name, which would reintroduce the race we opened it to avoid.
std::string proc_path(int fd) {
    char buf[48];
    std::snprintf(buf, sizeof buf, "/proc/self/fd/%d", fd);
    return buf;
}

ssize_t host_listxattr(int fd, const std::string &p, char *out, size_t n) {
#ifdef __APPLE__
    (void)p; return ::flistxattr(fd, out, n, 0);
#else
    (void)fd; return ::listxattr(p.c_str(), out, n);
#endif
}
ssize_t host_getxattr(int fd, const std::string &p, const char *name, void *out, size_t n) {
#ifdef __APPLE__
    (void)p; return ::fgetxattr(fd, name, out, n, 0, 0);
#else
    (void)fd; return ::getxattr(p.c_str(), name, out, n);
#endif
}
int host_setxattr(int fd, const std::string &p, const char *name, const void *in, size_t n, int flags) {
#ifdef __APPLE__
    (void)p; return ::fsetxattr(fd, name, in, n, 0, (flags & 1 ? XATTR_CREATE : 0) | (flags & 2 ? XATTR_REPLACE : 0));
#else
    (void)fd; return ::setxattr(p.c_str(), name, in, n, flags);
#endif
}
int host_removexattr(int fd, const std::string &p, const char *name) {
#ifdef __APPLE__
    (void)p; return ::fremovexattr(fd, name, 0);
#else
    (void)fd; return ::removexattr(p.c_str(), name);
#endif
}

// Best effort: an unprivileged server usually cannot hand a new file to an
// arbitrary group, and failing the whole create over that would be unhelpful.
void try_set_gid(int dirfd, const char *name, uint32_t gid) {
    if (::fchownat(dirfd, name, uid_t(-1), gid_t(gid), AT_SYMLINK_NOFOLLOW) != 0)
        logf(2, "could not set gid %u on %s: %s", gid, name, std::strerror(errno));
}

#ifdef __linux__
Fd reopen(int pfd, int flags) {
    std::string p = proc_path(pfd);
    int fd = ::open(p.c_str(), flags | O_CLOEXEC);
    if (fd < 0) oserr();
    return Fd(fd);
}

#endif

// ----------------------------------------------------------------- qid glue

uint32_t qid_version(const struct stat &st) {
    uint64_t v = uint64_t(st.st_mtim.tv_sec) * 1000000007ull ^ uint64_t(st.st_mtim.tv_nsec) ^
                 (uint64_t(st.st_size) << 17);
    return uint32_t(v ^ (v >> 32));
}

uint8_t qtype_of_mode(mode_t m) {
    if (S_ISDIR(m)) return QTDIR;
    if (S_ISLNK(m)) return QTSYMLINK;
    return QTFILE;
}

uint8_t qtype_of_dtype(uint8_t dt) {
    switch (dt) {
        case DT_DIR: return QTDIR;
        case DT_LNK: return QTSYMLINK;
        default: return QTFILE;
    }
}

struct stat fstat_or_throw(int fd) {
    struct stat st;
    if (::fstat(fd, &st) != 0) oserr();
    return st;
}

// Locks two fids without risking a lock-order inversion between concurrent
// requests naming the same pair in opposite orders.
struct TwoFidLock {
    std::unique_lock<std::shared_mutex> a;
    std::shared_lock<std::shared_mutex> b;

    TwoFidLock(const FidRef &fa, const FidRef &fb) {
        if (fa == fb) {
            a = std::unique_lock<std::shared_mutex>(fa->mu);
            return;
        }
        a = std::unique_lock<std::shared_mutex>(fa->mu, std::defer_lock);
        b = std::shared_lock<std::shared_mutex>(fb->mu, std::defer_lock);
        std::lock(a, b);
    }
};

}  // namespace

// ================================================================ helpers

std::string Fid::display() const {
    if (path.empty()) return "/";
    std::string s;
    for (const auto &c : path) {
        s += '/';
        s += c;
    }
    return s;
}

uint64_t qid_path(dev_t dev, ino_t ino) {
    uint64_t x = uint64_t(ino) ^ (uint64_t(dev) * 0x9E3779B97F4A7C15ull);
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBull;
    x ^= x >> 31;
    return x;
}

Qid qid_of(const struct stat &st) {
    Qid q;
    q.type = qtype_of_mode(st.st_mode);
    q.version = qid_version(st);
    q.path = qid_path(st.st_dev, st.st_ino);
    return q;
}

bool valid_component(const std::string &name) {
    if (name.empty() || name == "..") return false;
    return name.find('/') == std::string::npos && name.find('\0') == std::string::npos;
}

int translate_open_flags(uint32_t dotl, bool readonly) {
    int flags;
    switch (dotl & L_O_NOACCESS) {
        case L_O_RDONLY: flags = O_RDONLY; break;
        case L_O_WRONLY: flags = O_WRONLY; break;
        case L_O_RDWR: flags = O_RDWR; break;
        default: oserr(EINVAL);
    }
    if (dotl & L_O_TRUNC) flags |= O_TRUNC;
    if (dotl & L_O_APPEND) flags |= O_APPEND;
    if (dotl & L_O_EXCL) flags |= O_EXCL;
    if (dotl & L_O_DIRECTORY) flags |= O_DIRECTORY;
    if (dotl & L_O_NOFOLLOW) flags |= O_NOFOLLOW;
    if (dotl & L_O_SYNC) flags |= O_SYNC;
    if (dotl & L_O_DSYNC) flags |= O_DSYNC;
    // Deliberately not honoured: O_CREAT (only Tlcreate may create, and it
    // supplies its own), O_DIRECT / O_NONBLOCK / O_FASYNC / O_NOCTTY (the
    // client does not get to pick our I/O semantics), O_NOATIME (EPERMs unless
    // we own the file), O_LARGEFILE / O_CLOEXEC (always on here).
    if (readonly && ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))) oserr(EROFS);
    return flags | O_CLOEXEC;
}

// ------------------------------------------------------- path resolution

Fd Conn::walk_one(int dirfd, const std::string &name) const {
    if (!valid_component(name)) oserr(EINVAL);
    int fd = openat_beneath(dirfd, name.c_str(), platform::path_flags | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) oserr();
    return Fd(fd);
}

Fd Conn::resolve(const std::vector<std::string> &comps) const {
    int fd = ::openat(rootfd_, ".", platform::path_flags | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) oserr();
    Fd cur(fd);
    for (const auto &c : comps) cur = walk_one(cur.get(), c);
    return cur;
}

Fd Conn::open_parent(const Fid &f) const {
    if (f.path.empty()) oserr(EINVAL);  // the export root has no parent we may name
    return resolve(std::vector<std::string>(f.path.begin(), f.path.end() - 1));
}

Fd Conn::reopen_fid(const Fid &f, int flags) const {
#ifdef __linux__
    return reopen(f.pfd.get(), flags);
#else
    // Darwin cannot upgrade an O_EVTONLY descriptor. Re-resolve under the
    // pinned root, never follow a symlink, and reject a changed inode. In
    // particular O_TRUNC must not run until identity has been checked.
    auto before = fstat_or_throw(f.pfd.get());
    if (!S_ISREG(before.st_mode) && !S_ISDIR(before.st_mode)) oserr(EOPNOTSUPP);
    Fd parent = f.path.empty() ? resolve({}) : open_parent(f);
    const char *name = f.path.empty() ? "." : f.path.back().c_str();
    Fd fd(::openat(parent.get(), name, (flags & ~O_TRUNC) | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
    if (!fd) oserr();
    auto after = fstat_or_throw(fd.get());
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino) oserr(ESTALE);
    if (!S_ISREG(after.st_mode) && !S_ISDIR(after.st_mode)) oserr(EOPNOTSUPP);
    if ((flags & O_TRUNC) && ::ftruncate(fd.get(), 0) != 0) oserr();
    return fd;
#endif
}

FidRef Conn::make_fid(Fd pfd, std::vector<std::string> path) const {
    struct stat st = fstat_or_throw(pfd.get());
    auto f = std::make_shared<Fid>();
    f->is_dir = S_ISDIR(st.st_mode);
    f->is_symlink = S_ISLNK(st.st_mode);
    f->pfd = std::move(pfd);
    f->path = std::move(path);
    return f;
}

void Conn::require_writable() const {
    if (cfg_->readonly) oserr(EROFS);
}

// ================================================================== session

void Conn::op_version(uint16_t tag, Dec &d) {
    uint32_t want = d.u32();
    std::string ver = d.str();
    d.end();

    versioned_.store(false, std::memory_order_release);

    uint32_t neg = std::min(want, cfg_->msize);
    if (neg < 256) oserr(EINVAL);

    std::string reply_ver = "unknown";
    if (ver == kVersion || ver.rfind(std::string(kVersion) + ".", 0) == 0) {
        reply_ver = std::string(kVersion);
        msize_.store(neg, std::memory_order_release);
        versioned_.store(true, std::memory_order_release);
    } else {
        // Answering "unknown" is how 9P says "I do not speak that dialect".
        neg = want;
        logf(1, "[%s] client offered version %s, which we do not speak", peer_.c_str(), ver.c_str());
    }

    Bytes &b = reply_buf_;
    begin(b, Rversion, tag);
    Enc e(b);
    e.u32(neg);
    e.str(reply_ver);
    send_reply(b);
    logf(1, "[%s] version %s, msize %u", peer_.c_str(), reply_ver.c_str(), neg);
}

void Conn::op_auth(uint16_t tag, Dec &d) {
    // Authentication already happened, at the channel layer, before a single
    // 9P byte was exchanged.  Declining Tauth is how a server says "no afid
    // needed"; clients then attach with afid = NOFID.
    (void)d;
    send_error(tag, EOPNOTSUPP);
}

void Conn::op_attach(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint32_t afid = d.u32();
    std::string uname = d.str();
    std::string aname = d.str();
    (void)d.u32();  // n_uname: not honoured, see the note in server.hpp
    d.end();

    if (afid != kNoFid) oserr(EOPNOTSUPP);
    if (!aname.empty() && aname != "/") {
        logf(0, "[%s] attach refused: aname '%s' is not served (only '/')", peer_.c_str(),
             aname.c_str());
        oserr(ENOENT);
    }

    FidRef f = make_fid(resolve({}), {});
    struct stat st = fstat_or_throw(f->pfd.get());
    put_fid(fid, f);

    Bytes &b = reply_buf_;
    begin(b, Rattach, tag);
    Enc(b).qid(qid_of(st));
    send_reply(b);
    logf(0, "[%s] attached as '%s', aname '%s'", peer_.c_str(), uname.c_str(), aname.c_str());
}

void Conn::op_walk(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint32_t newfid = d.u32();
    uint16_t n = d.u16();
    if (n > kMaxWalkNames) oserr(EINVAL);
    std::vector<std::string> names;
    names.reserve(n);
    for (uint16_t i = 0; i < n; i++) names.push_back(d.str());
    d.end();

    FidRef f = get_fid(fid);
    std::unique_lock<std::shared_mutex> lk(f->mu);
    if (f->opened || f->xattr) oserr(EBADF);  // an open fid may not be walked

    Fd cur(check(::fcntl(f->pfd.get(), F_DUPFD_CLOEXEC, 0)));
    std::vector<std::string> path = f->path;
    std::vector<Qid> qids;
    qids.reserve(n);

    for (size_t i = 0; i < names.size(); i++) {
        try {
            if (names[i] == ".") {
                // Harmless no-op; still reports a qid for this position.
            } else if (names[i] == "..") {
                if (!path.empty()) {
                    path.pop_back();
                    cur = resolve(path);
                }
                // At the root, ".." stays put: the export is the whole world.
            } else {
                cur = walk_one(cur.get(), names[i]);
                path.push_back(names[i]);
            }
            qids.push_back(qid_of(fstat_or_throw(cur.get())));
        } catch (const Errno &) {
            // 9P: a walk that fails on its first name is an error; failing
            // later just yields a short Rwalk and no new fid.
            if (i == 0) throw;
            break;
        }
    }

    if (qids.size() == names.size()) {
        struct stat st = fstat_or_throw(cur.get());
        if (newfid == fid) {
            f->pfd = std::move(cur);
            f->path = std::move(path);
            f->is_dir = S_ISDIR(st.st_mode);
            f->is_symlink = S_ISLNK(st.st_mode);
        } else {
            auto nf = std::make_shared<Fid>();
            nf->is_dir = S_ISDIR(st.st_mode);
            nf->is_symlink = S_ISLNK(st.st_mode);
            nf->pfd = std::move(cur);
            nf->path = std::move(path);
            put_fid(newfid, std::move(nf));
        }
    }

    Bytes &b = reply_buf_;
    begin(b, Rwalk, tag);
    Enc e(b);
    e.u16(uint16_t(qids.size()));
    for (const auto &q : qids) e.qid(q);
    send_reply(b);
}

void Conn::op_statfs(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    d.end();
    FidRef f = get_fid(fid);
    std::shared_lock<std::shared_mutex> lk(f->mu);

    struct statfs sfs;
    if (::fstatfs(f->pfd.get(), &sfs) != 0) oserr();

    Bytes &b = reply_buf_;
    begin(b, Rstatfs, tag);
    Enc e(b);
    e.u32(uint32_t(sfs.f_type));
    e.u32(uint32_t(sfs.f_bsize));
    e.u64(uint64_t(sfs.f_blocks));
    e.u64(uint64_t(sfs.f_bfree));
    e.u64(uint64_t(sfs.f_bavail));
    e.u64(uint64_t(sfs.f_files));
    e.u64(uint64_t(sfs.f_ffree));
#ifdef __APPLE__
    e.u64(uint64_t(uint32_t(sfs.f_fsid.val[0])) | (uint64_t(uint32_t(sfs.f_fsid.val[1])) << 32));
    e.u32(NAME_MAX);
#else
    e.u64(uint64_t(uint32_t(sfs.f_fsid.__val[0])) | (uint64_t(uint32_t(sfs.f_fsid.__val[1])) << 32));
    e.u32(uint32_t(sfs.f_namelen));
#endif
    send_reply(b);
}

// ============================================================ open / create

void Conn::op_lopen(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint32_t dflags = d.u32();
    d.end();

    FidRef f = get_fid(fid);
    std::unique_lock<std::shared_mutex> lk(f->mu);
    if (f->opened || f->xattr) oserr(EINVAL);
    // O_PATH|O_NOFOLLOW gave us the link itself; a client wanting its target
    // must Treadlink and walk there.
    if (f->is_symlink) oserr(ELOOP);

    int flags = translate_open_flags(dflags, cfg_->readonly);
    if (f->is_dir) {
        if ((flags & O_ACCMODE) != O_RDONLY) oserr(EISDIR);
        flags |= O_DIRECTORY;
    }

    f->iofd = reopen_fid(*f, flags);
    f->opened = true;
    f->dir_off = 0;
    logf(3, "[%s] opened %s flags=%#o", peer_.c_str(), f->display().c_str(), unsigned(flags));

    struct stat st = fstat_or_throw(f->pfd.get());
    Bytes &b = reply_buf_;
    begin(b, Rlopen, tag);
    Enc e(b);
    e.qid(qid_of(st));
    e.u32(iounit_for(msize_.load(std::memory_order_acquire)));
    send_reply(b);
}

void Conn::op_lcreate(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    std::string name = d.str();
    uint32_t dflags = d.u32();
    uint32_t mode = d.u32();
    uint32_t gid = d.u32();
    d.end();

    require_writable();
    if (!valid_component(name) || name == ".") oserr(EINVAL);

    FidRef f = get_fid(fid);
    std::unique_lock<std::shared_mutex> lk(f->mu);
    if (!f->is_dir || f->opened || f->xattr) oserr(EINVAL);

    int flags = translate_open_flags(dflags, false) | O_CREAT;
    // O_NOFOLLOW makes an existing symlink at `name` fail rather than letting
    // a planted link redirect the create somewhere else.
    int nfd = ::openat(f->pfd.get(), name.c_str(), flags | O_NOFOLLOW, mode_t(mode & 07777));
    if (nfd < 0) oserr();
    Fd iofd(nfd);

    try_set_gid(f->pfd.get(), name.c_str(), gid);

    Fd npath = walk_one(f->pfd.get(), name);
    struct stat st = fstat_or_throw(npath.get());

    f->path.push_back(name);
    f->pfd = std::move(npath);
    f->iofd = std::move(iofd);
    f->opened = true;
    f->is_dir = false;
    f->is_symlink = false;
    f->dir_off = 0;

    Bytes &b = reply_buf_;
    begin(b, Rlcreate, tag);
    Enc e(b);
    e.qid(qid_of(st));
    e.u32(iounit_for(msize_.load(std::memory_order_acquire)));
    send_reply(b);
}

void Conn::op_mkdir(uint16_t tag, Dec &d) {
    uint32_t dfid = d.u32();
    std::string name = d.str();
    uint32_t mode = d.u32();
    uint32_t gid = d.u32();
    d.end();

    require_writable();
    if (!valid_component(name) || name == ".") oserr(EINVAL);

    FidRef f = get_fid(dfid);
    std::shared_lock<std::shared_mutex> lk(f->mu);
    if (!f->is_dir) oserr(ENOTDIR);

    if (::mkdirat(f->pfd.get(), name.c_str(), mode_t(mode & 07777)) != 0) oserr();
    try_set_gid(f->pfd.get(), name.c_str(), gid);

    Fd np = walk_one(f->pfd.get(), name);
    Bytes &b = reply_buf_;
    begin(b, Rmkdir, tag);
    Enc(b).qid(qid_of(fstat_or_throw(np.get())));
    send_reply(b);
}

void Conn::op_symlink(uint16_t tag, Dec &d) {
    uint32_t dfid = d.u32();
    std::string name = d.str();
    std::string target = d.str();
    uint32_t gid = d.u32();
    d.end();

    require_writable();
    if (!valid_component(name) || name == ".") oserr(EINVAL);
    if (target.empty()) oserr(EINVAL);

    FidRef f = get_fid(dfid);
    std::shared_lock<std::shared_mutex> lk(f->mu);
    if (!f->is_dir) oserr(ENOTDIR);

    // The target is stored verbatim and never resolved by us; because walks
    // never follow symlinks, a link pointing outside the export is inert here
    // and only means anything to a client that chooses to follow it.
    if (::symlinkat(target.c_str(), f->pfd.get(), name.c_str()) != 0) oserr();
    try_set_gid(f->pfd.get(), name.c_str(), gid);

    Fd np = walk_one(f->pfd.get(), name);
    Bytes &b = reply_buf_;
    begin(b, Rsymlink, tag);
    Enc(b).qid(qid_of(fstat_or_throw(np.get())));
    send_reply(b);
}

void Conn::op_mknod(uint16_t tag, Dec &d) {
    uint32_t dfid = d.u32();
    std::string name = d.str();
    uint32_t mode = d.u32();
    uint32_t major = d.u32();
    uint32_t minor = d.u32();
    uint32_t gid = d.u32();
    d.end();

    require_writable();
    if (!valid_component(name) || name == ".") oserr(EINVAL);

    FidRef f = get_fid(dfid);
    std::shared_lock<std::shared_mutex> lk(f->mu);
    if (!f->is_dir) oserr(ENOTDIR);

    // Character and block devices need privilege; the kernel enforces that for
    // us, so an unprivileged export simply cannot be used to create them.
    if (::mknodat(f->pfd.get(), name.c_str(), mode_t(mode), ::makedev(major, minor)) != 0) oserr();
    try_set_gid(f->pfd.get(), name.c_str(), gid);

    Fd np = walk_one(f->pfd.get(), name);
    Bytes &b = reply_buf_;
    begin(b, Rmknod, tag);
    Enc(b).qid(qid_of(fstat_or_throw(np.get())));
    send_reply(b);
}

void Conn::op_link(uint16_t tag, Dec &d) {
    uint32_t dfid = d.u32();
    uint32_t fid = d.u32();
    std::string name = d.str();
    d.end();

    require_writable();
    if (!valid_component(name) || name == ".") oserr(EINVAL);

    FidRef df = get_fid(dfid);
    FidRef f = get_fid(fid);
    TwoFidLock lk(df, f);
    if (!df->is_dir) oserr(ENOTDIR);
    if (f->is_dir) oserr(EPERM);

    // linkat(AT_EMPTY_PATH) needs CAP_DAC_READ_SEARCH; the /proc form is the
    // documented unprivileged equivalent.
#ifdef __APPLE__
    Fd parent = open_parent(*f);
    int rc = ::linkat(parent.get(), f->path.back().c_str(), df->pfd.get(), name.c_str(), 0);
#else
    int rc = ::linkat(f->pfd.get(), "", df->pfd.get(), name.c_str(), AT_EMPTY_PATH);
    if (rc != 0 && (errno == EPERM || errno == ENOENT || errno == EINVAL || errno == EACCES)) {
        std::string p = proc_path(f->pfd.get());
        rc = ::linkat(AT_FDCWD, p.c_str(), df->pfd.get(), name.c_str(), AT_SYMLINK_FOLLOW);
    }
#endif
    if (rc != 0) oserr();
    send_empty(Rlink, tag);
}

// ================================================================ namespace

void Conn::op_rename(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint32_t dfid = d.u32();
    std::string name = d.str();
    d.end();

    require_writable();
    if (!valid_component(name) || name == ".") oserr(EINVAL);

    FidRef f = get_fid(fid);
    FidRef df = get_fid(dfid);
    TwoFidLock lk(f, df);
    if (f->path.empty()) oserr(EBUSY);  // cannot rename the export root itself
    if (!df->is_dir) oserr(ENOTDIR);

    Fd oldparent = open_parent(*f);
    if (::renameat(oldparent.get(), f->path.back().c_str(), df->pfd.get(), name.c_str()) != 0) oserr();

    // The O_PATH descriptor still names the same inode, so only the server's
    // idea of where the fid lives needs updating.
    std::vector<std::string> np = df->path;
    np.push_back(name);
    f->path = std::move(np);

    send_empty(Rrename, tag);
}

void Conn::op_renameat(uint16_t tag, Dec &d) {
    uint32_t olddirfid = d.u32();
    std::string oldname = d.str();
    uint32_t newdirfid = d.u32();
    std::string newname = d.str();
    d.end();

    require_writable();
    if (!valid_component(oldname) || oldname == ".") oserr(EINVAL);
    if (!valid_component(newname) || newname == ".") oserr(EINVAL);

    FidRef od = get_fid(olddirfid);
    FidRef nd = get_fid(newdirfid);
    TwoFidLock lk(od, nd);
    if (!od->is_dir || !nd->is_dir) oserr(ENOTDIR);

    if (::renameat(od->pfd.get(), oldname.c_str(), nd->pfd.get(), newname.c_str()) != 0) oserr();
    send_empty(Rrenameat, tag);
}

void Conn::op_unlinkat(uint16_t tag, Dec &d) {
    uint32_t dfid = d.u32();
    std::string name = d.str();
    uint32_t flags = d.u32();
    d.end();

    require_writable();
    if (!valid_component(name) || name == ".") oserr(EINVAL);

    FidRef f = get_fid(dfid);
    std::shared_lock<std::shared_mutex> lk(f->mu);
    if (!f->is_dir) oserr(ENOTDIR);

    // Only AT_REMOVEDIR is meaningful here; ignore anything else a client
    // might set rather than passing unknown bits to the kernel.
    int at = (flags & 0x200u) ? AT_REMOVEDIR : 0;
    if (::unlinkat(f->pfd.get(), name.c_str(), at) != 0) oserr();
    send_empty(Runlinkat, tag);
}

void Conn::op_remove(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    d.end();

    // 9P requires the fid to be clunked whether or not the removal succeeds.
    FidRef f = take_fid(fid);
    if (cfg_->readonly) oserr(EROFS);
    if (f->path.empty()) oserr(EBUSY);

    Fd parent = open_parent(*f);
    if (::unlinkat(parent.get(), f->path.back().c_str(), f->is_dir ? AT_REMOVEDIR : 0) != 0) oserr();
    send_empty(Rremove, tag);
}

void Conn::op_readlink(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    d.end();

    FidRef f = get_fid(fid);
    std::shared_lock<std::shared_mutex> lk(f->mu);
    if (!f->is_symlink) oserr(EINVAL);

    std::vector<char> buf(PATH_MAX);
    // An empty pathname makes readlinkat operate on the O_PATH|O_NOFOLLOW
    // descriptor itself; older kernels want the parent-plus-name form.
    ssize_t n = ::readlinkat(f->pfd.get(), "", buf.data(), buf.size());
    if (n < 0 && (errno == ENOENT || errno == EINVAL) && !f->path.empty()) {
        Fd parent = open_parent(*f);
        n = ::readlinkat(parent.get(), f->path.back().c_str(), buf.data(), buf.size());
    }
    if (n < 0) oserr();
    if (size_t(n) >= buf.size()) oserr(ENAMETOOLONG);

    Bytes &b = reply_buf_;
    begin(b, Rreadlink, tag);
    Enc(b).str(std::string_view(buf.data(), size_t(n)));
    send_reply(b);
}

// ================================================================ attributes

void Conn::op_getattr(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint64_t request = d.u64();
    d.end();

    FidRef f = get_fid(fid);
    std::shared_lock<std::shared_mutex> lk(f->mu);

    uint64_t valid = GETATTR_BASIC;
    struct stat st;
    uint64_t btime_sec = 0, btime_nsec = 0;

#ifdef __APPLE__
    st = fstat_or_throw(f->pfd.get());
    btime_sec = uint64_t(st.st_birthtimespec.tv_sec);
    btime_nsec = uint64_t(st.st_birthtimespec.tv_nsec);
    valid |= GETATTR_BTIME;
#else
    struct statx stx;
    if (::statx(f->pfd.get(), "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                STATX_BASIC_STATS | STATX_BTIME, &stx) == 0) {
        std::memset(&st, 0, sizeof st);
        st.st_mode = stx.stx_mode;
        st.st_uid = stx.stx_uid;
        st.st_gid = stx.stx_gid;
        st.st_nlink = stx.stx_nlink;
        st.st_rdev = ::makedev(stx.stx_rdev_major, stx.stx_rdev_minor);
        st.st_dev = ::makedev(stx.stx_dev_major, stx.stx_dev_minor);
        st.st_ino = ino_t(stx.stx_ino);
        st.st_size = off_t(stx.stx_size);
        st.st_blksize = blksize_t(stx.stx_blksize);
        st.st_blocks = blkcnt_t(stx.stx_blocks);
        st.st_atim.tv_sec = stx.stx_atime.tv_sec;
        st.st_atim.tv_nsec = stx.stx_atime.tv_nsec;
        st.st_mtim.tv_sec = stx.stx_mtime.tv_sec;
        st.st_mtim.tv_nsec = stx.stx_mtime.tv_nsec;
        st.st_ctim.tv_sec = stx.stx_ctime.tv_sec;
        st.st_ctim.tv_nsec = stx.stx_ctime.tv_nsec;
        if (stx.stx_mask & STATX_BTIME) {
            btime_sec = uint64_t(stx.stx_btime.tv_sec);
            btime_nsec = uint64_t(stx.stx_btime.tv_nsec);
            valid |= GETATTR_BTIME;
        }
    } else {
        st = fstat_or_throw(f->pfd.get());
    }

#endif

    // We report exactly the fields we filled in.  GEN and DATA_VERSION stay
    // out of the mask rather than being faked, so a client can tell that we
    // do not supply them; reporting more than `request` asked for is allowed.
    (void)request;

    Bytes &b = reply_buf_;
    begin(b, Rgetattr, tag);
    Enc e(b);
    e.u64(valid);
    e.qid(qid_of(st));
    e.u32(uint32_t(st.st_mode));
    e.u32(uint32_t(st.st_uid));
    e.u32(uint32_t(st.st_gid));
    e.u64(uint64_t(st.st_nlink));
    e.u64(uint64_t(st.st_rdev));
    e.u64(uint64_t(st.st_size));
    e.u64(uint64_t(st.st_blksize));
    e.u64(uint64_t(st.st_blocks));
    e.u64(uint64_t(st.st_atim.tv_sec));
    e.u64(uint64_t(st.st_atim.tv_nsec));
    e.u64(uint64_t(st.st_mtim.tv_sec));
    e.u64(uint64_t(st.st_mtim.tv_nsec));
    e.u64(uint64_t(st.st_ctim.tv_sec));
    e.u64(uint64_t(st.st_ctim.tv_nsec));
    e.u64(btime_sec);
    e.u64(btime_nsec);
    e.u64(0);  // gen
    e.u64(0);  // data_version
    send_reply(b);
}

void Conn::op_setattr(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint32_t valid = d.u32();
    uint32_t mode = d.u32();
    uint32_t uid = d.u32();
    uint32_t gid = d.u32();
    uint64_t size = d.u64();
    uint64_t atime_sec = d.u64(), atime_nsec = d.u64();
    uint64_t mtime_sec = d.u64(), mtime_nsec = d.u64();
    d.end();

    require_writable();
    FidRef f = get_fid(fid);
    std::unique_lock<std::shared_mutex> lk(f->mu);
    if (f->xattr) oserr(EINVAL);

    // chown before chmod: changing the owner clears the setuid/setgid bits, so
    // doing it the other way round would silently discard a requested mode.
    if (valid & (SETATTR_UID | SETATTR_GID)) {
        uid_t u = (valid & SETATTR_UID) ? uid_t(uid) : uid_t(-1);
        gid_t g = (valid & SETATTR_GID) ? gid_t(gid) : gid_t(-1);
#ifdef __APPLE__
        if (::fchown(f->pfd.get(), u, g) != 0) oserr();
#else
        if (::fchownat(f->pfd.get(), "", u, g, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0) oserr();
#endif
    }

    if (valid & SETATTR_MODE) {
        if (f->is_symlink) oserr(EOPNOTSUPP);  // Linux has no lchmod
#ifdef __APPLE__
        if (::fchmod(f->pfd.get(), mode_t(mode & 07777)) != 0) oserr();
#else
        long rc = ::syscall(SYS_fchmodat2, f->pfd.get(), "", mode_t(mode & 07777), AT_EMPTY_PATH);
        if (rc != 0) {
            std::string p = proc_path(f->pfd.get());
            if (::fchmodat(AT_FDCWD, p.c_str(), mode_t(mode & 07777), 0) != 0) oserr();
        }
#endif
    }

    if (valid & SETATTR_SIZE) {
        if (f->is_dir) oserr(EISDIR);
        if (f->is_symlink) oserr(EINVAL);
        if (f->opened) {
            if (::ftruncate(f->iofd.get(), off_t(size)) != 0) oserr();
        } else {
            Fd w = reopen_fid(*f, O_WRONLY);
            if (::ftruncate(w.get(), off_t(size)) != 0) oserr();
        }
    }

    if (valid & (SETATTR_ATIME | SETATTR_MTIME)) {
        struct timespec ts[2];
        ts[0].tv_sec = 0;
        ts[0].tv_nsec = UTIME_OMIT;
        ts[1].tv_sec = 0;
        ts[1].tv_nsec = UTIME_OMIT;
        if (valid & SETATTR_ATIME) {
            if (valid & SETATTR_ATIME_SET) {
                ts[0].tv_sec = time_t(atime_sec);
                ts[0].tv_nsec = long(atime_nsec);
            } else {
                ts[0].tv_nsec = UTIME_NOW;
            }
        }
        if (valid & SETATTR_MTIME) {
            if (valid & SETATTR_MTIME_SET) {
                ts[1].tv_sec = time_t(mtime_sec);
                ts[1].tv_nsec = long(mtime_nsec);
            } else {
                ts[1].tv_nsec = UTIME_NOW;
            }
        }
        int rc;
        if (f->is_symlink) {
            // /proc/self/fd/N is itself a symlink, so AT_SYMLINK_NOFOLLOW
            // there would time-stamp the wrong thing.  Go via the parent.
            if (f->path.empty()) oserr(EINVAL);
            Fd parent = open_parent(*f);
            rc = ::utimensat(parent.get(), f->path.back().c_str(), ts, AT_SYMLINK_NOFOLLOW);
        } else {
#ifdef __APPLE__
            rc = ::futimens(f->pfd.get(), ts);
#else
            std::string p = proc_path(f->pfd.get());
            rc = ::utimensat(AT_FDCWD, p.c_str(), ts, 0);
#endif
        }
        if (rc != 0) oserr();
    }

    send_empty(Rsetattr, tag);
}

// ==================================================================== xattr

void Conn::op_xattrwalk(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint32_t newfid = d.u32();
    std::string name = d.str();
    d.end();

    if (newfid == fid) oserr(EINVAL);
    FidRef f = get_fid(fid);
    std::shared_lock<std::shared_mutex> lk(f->mu);
    if (f->xattr) oserr(EINVAL);

    std::string p = proc_path(f->pfd.get());
    Bytes buf;
    ssize_t n;
    // An empty name asks for the list of attribute names instead of a value.
    if (name.empty()) {
        n = host_listxattr(f->pfd.get(), p, nullptr, 0);
        if (n < 0) oserr();
        buf.resize(size_t(n));
        if (n > 0) {
            n = host_listxattr(f->pfd.get(), p, reinterpret_cast<char *>(buf.data()), buf.size());
            if (n < 0) oserr();
            buf.resize(size_t(n));
        }
    } else {
        n = host_getxattr(f->pfd.get(), p, name.c_str(), nullptr, 0);
        if (n < 0) oserr();
        buf.resize(size_t(n));
        if (n > 0) {
            n = host_getxattr(f->pfd.get(), p, name.c_str(), buf.data(), buf.size());
            if (n < 0) oserr();
            buf.resize(size_t(n));
        }
    }

    auto nf = std::make_shared<Fid>();
    nf->pfd = Fd(check(::fcntl(f->pfd.get(), F_DUPFD_CLOEXEC, 0)));
    nf->path = f->path;
    nf->is_dir = f->is_dir;
    nf->is_symlink = f->is_symlink;
    nf->xattr = true;
    nf->opened = true;  // an xattr fid is readable straight away
    nf->xattr_name = name;
    nf->xattr_buf = std::move(buf);
    uint64_t sz = nf->xattr_buf.size();
    put_fid(newfid, std::move(nf));

    Bytes &b = reply_buf_;
    begin(b, Rxattrwalk, tag);
    Enc(b).u64(sz);
    send_reply(b);
}

void Conn::op_xattrcreate(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    std::string name = d.str();
    uint64_t attr_size = d.u64();
    uint32_t flags = d.u32();
    d.end();

    require_writable();
    if (name.empty()) oserr(EINVAL);
    // Linux caps an xattr value at 64 KiB; refuse absurd sizes up front rather
    // than letting a client make us buffer them.
    if (attr_size > (1u << 20)) oserr(E2BIG);

    FidRef f = get_fid(fid);
    std::unique_lock<std::shared_mutex> lk(f->mu);
    if (f->opened || f->xattr) oserr(EINVAL);

    f->xattr = true;
    f->xattr_write = true;
    f->opened = true;
    f->xattr_name = name;
    f->xattr_size = attr_size;
    f->xattr_flags = flags;
    f->xattr_buf.clear();
    f->xattr_buf.reserve(size_t(attr_size));

    send_empty(Rxattrcreate, tag);
}

// ==================================================================== I/O

void Conn::op_read(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint64_t offset = d.u64();
    uint32_t count = d.u32();
    d.end();

    FidRef f = get_open_fid(fid);
    std::shared_lock<std::shared_mutex> lk(f->mu);

    uint32_t cap = iounit_for(msize_.load(std::memory_order_acquire));
    if (count > cap) count = cap;

    Bytes &b = reply_buf_;
    begin(b, Rread, tag);
    Enc e(b);
    e.u32(0);  // patched below

    size_t got = 0;
    if (f->xattr) {
        if (f->xattr_write) oserr(EBADF);
        if (offset < f->xattr_buf.size()) {
            got = std::min(size_t(count), f->xattr_buf.size() - size_t(offset));
            e.raw(f->xattr_buf.data() + offset, got);
        }
    } else {
        if (f->is_dir) oserr(EISDIR);  // directories are read with Treaddir
        uint8_t *dst = e.reserve(count);
        ssize_t n = ::pread(f->iofd.get(), dst, count, off_t(offset));
        // FIFOs and sockets in the export are not seekable.
        if (n < 0 && errno == ESPIPE) n = ::read(f->iofd.get(), dst, count);
        if (n < 0) oserr();
        got = size_t(n);
        b.resize(kHeaderLen + 4 + got);
    }
    st32(b.data() + kHeaderLen, uint32_t(got));
    send_reply(b);
}

void Conn::op_write(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint64_t offset = d.u64();
    uint32_t count = d.u32();
    std::span<const uint8_t> data = d.raw(count);
    d.end();

    require_writable();
    FidRef f = get_open_fid(fid);

    // File I/O only needs a shared lock -- pwrite carries its own offset, so
    // concurrent writes to one fid are safe and pipelining stays parallel.
    // Buffering an xattr mutates the fid, so that path takes the lock
    // exclusively and re-checks the state it decided on under the shared one.
    size_t wrote;
    bool is_xattr;
    {
        std::shared_lock<std::shared_mutex> lk(f->mu);
        is_xattr = f->xattr;
        if (!is_xattr) {
            if (f->is_dir) oserr(EISDIR);
            ssize_t n = ::pwrite(f->iofd.get(), data.data(), count, off_t(offset));
            if (n < 0 && errno == ESPIPE) n = ::write(f->iofd.get(), data.data(), count);
            if (n < 0) oserr();
            wrote = size_t(n);
        }
    }
    if (is_xattr) {
        std::unique_lock<std::shared_mutex> lk(f->mu);
        if (!f->xattr || !f->xattr_write) oserr(EBADF);
        // Written in the order given but not applied until clunk, so the
        // attribute appears in one setxattr rather than in fragments.
        // Compared this way round because offset + count could wrap.
        if (offset > f->xattr_size || count > f->xattr_size - offset) oserr(ENOSPC);
        if (f->xattr_buf.size() < offset + count) f->xattr_buf.resize(size_t(offset) + count);
        if (count) std::memcpy(f->xattr_buf.data() + offset, data.data(), count);
        wrote = count;
    }

    Bytes &b = reply_buf_;
    begin(b, Rwrite, tag);
    Enc(b).u32(uint32_t(wrote));
    send_reply(b);
}

void Conn::op_readdir(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint64_t offset = d.u64();
    uint32_t count = d.u32();
    d.end();

    FidRef f = get_open_fid(fid);
    std::unique_lock<std::shared_mutex> lk(f->mu);  // moves the directory cursor
    if (!f->is_dir) oserr(ENOTDIR);
    if (f->xattr) oserr(EINVAL);

    uint32_t cap = iounit_for(msize_.load(std::memory_order_acquire));
    if (count > cap) count = cap;

    struct stat dst = fstat_or_throw(f->pfd.get());

    Bytes &b = reply_buf_;
    begin(b, Rreaddir, tag);
    Enc e(b);
    e.u32(0);
    const size_t body_start = b.size();
    if (!f->dir_stream) {
        Fd scan = reopen_fid(*f, O_RDONLY | O_DIRECTORY);
        DIR *dir = ::fdopendir(scan.get());
        if (!dir) oserr();
        scan.release();
        f->dir_stream.reset(dir);
    }
    if (offset > uint64_t(LONG_MAX)) oserr(EINVAL);
    DIR *dir = f->dir_stream.get();
    if (!offset) ::rewinddir(dir);
    else ::seekdir(dir, long(offset));
    uint64_t last_off = offset;
    bool full = false;
    for (;;) {
        errno = 0;
        auto *de = ::readdir(dir);
        if (!de) { if (errno) oserr(); break; }
        std::string_view name(de->d_name);
        if (b.size() - body_start + readdir_entry_len(name.size()) > count) { full = true; break; }
        Qid q{};
        q.path = qid_path(dst.st_dev, ino_t(de->d_ino));
        uint8_t dtype = de->d_type;
        q.type = qtype_of_dtype(dtype);
        if (dtype == DT_UNKNOWN) {
            struct stat es;
            if (::fstatat(f->pfd.get(), de->d_name, &es, AT_SYMLINK_NOFOLLOW) == 0) {
                q.type = qtype_of_mode(es.st_mode);
                dtype = S_ISDIR(es.st_mode) ? DT_DIR : (S_ISLNK(es.st_mode) ? DT_LNK : DT_REG);
            }
        }
        long cookie = ::telldir(dir);
        if (cookie < 0) oserr();
        encode_dirent(e, q, uint64_t(cookie), dtype, name);
        last_off = uint64_t(cookie);
    }

    // A caller whose count cannot hold even one entry would otherwise spin.
    if (b.size() == body_start && full) oserr(EINVAL);

    f->dir_off = last_off;
    st32(b.data() + kHeaderLen, uint32_t(b.size() - body_start));
    send_reply(b);
}

void Conn::op_fsync(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint32_t datasync = d.u32();
    d.end();

    FidRef f = get_open_fid(fid);
    std::shared_lock<std::shared_mutex> lk(f->mu);
    if (f->xattr) {
        send_empty(Rfsync, tag);
        return;
    }
#ifdef __APPLE__
    (void)datasync;
    int rc = ::fsync(f->iofd.get());
#else
    int rc = datasync ? ::fdatasync(f->iofd.get()) : ::fsync(f->iofd.get());
#endif
    if (rc != 0) oserr();
    send_empty(Rfsync, tag);
}

// =================================================================== locking

void Conn::op_lock(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint8_t type = d.u8();
    uint32_t flags = d.u32();
    uint64_t start = d.u64();
    uint64_t length = d.u64();
    (void)d.u32();  // proc_id: meaningful only to the client
    std::string client_id = d.str();
    d.end();
    (void)client_id;  // identifies the client's lock owner; OFD locks do not need it

    if (flags & ~uint32_t(LOCK_FLAG_BLOCK | LOCK_FLAG_RECLAIM)) oserr(EINVAL);

    FidRef f = get_open_fid(fid);
    std::shared_lock<std::shared_mutex> lk(f->mu);
    if (f->xattr) oserr(EINVAL);

    struct flock fl {};
    switch (type) {
        case LOCK_RDLCK: fl.l_type = F_RDLCK; break;
        case LOCK_WRLCK: fl.l_type = F_WRLCK; break;
        case LOCK_UNLCK: fl.l_type = F_UNLCK; break;
        default: oserr(EINVAL);
    }
    fl.l_whence = SEEK_SET;
    fl.l_start = off_t(start);
    fl.l_len = off_t(length);
    fl.l_pid = 0;  // required to be zero for open-file-description locks

    // OFD locks belong to the descriptor, not the process.  That is what makes
    // this correct for a server holding many clients' locks at once: ordinary
    // POSIX locks would all share the server's pid and silently merge.
    uint8_t status = LOCK_SUCCESS;
    if (::fcntl(f->iofd.get(), F_OFD_SETLK, &fl) != 0) {
        if (errno == EACCES || errno == EAGAIN) {
            // Never block a worker thread: report contention and let the
            // client retry, which is what the Linux v9fs client expects.
            status = LOCK_BLOCKED;
        } else {
            oserr();
        }
    }

    Bytes &b = reply_buf_;
    begin(b, Rlock, tag);
    Enc(b).u8(status);
    send_reply(b);
}

void Conn::op_getlock(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    uint8_t type = d.u8();
    uint64_t start = d.u64();
    uint64_t length = d.u64();
    uint32_t proc_id = d.u32();
    std::string client_id = d.str();
    d.end();

    FidRef f = get_open_fid(fid);
    std::shared_lock<std::shared_mutex> lk(f->mu);
    if (f->xattr) oserr(EINVAL);

    struct flock fl {};
    fl.l_type = (type == LOCK_WRLCK) ? F_WRLCK : F_RDLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = off_t(start);
    fl.l_len = off_t(length);
    fl.l_pid = 0;
    if (::fcntl(f->iofd.get(), F_OFD_GETLK, &fl) != 0) oserr();

    Bytes &b = reply_buf_;
    begin(b, Rgetlock, tag);
    Enc e(b);
    if (fl.l_type == F_UNLCK) {
        e.u8(LOCK_UNLCK);
        e.u64(start);
        e.u64(length);
        e.u32(proc_id);
    } else {
        e.u8(fl.l_type == F_WRLCK ? LOCK_WRLCK : LOCK_RDLCK);
        e.u64(uint64_t(fl.l_start));
        e.u64(uint64_t(fl.l_len));
        e.u32(uint32_t(fl.l_pid));
    }
    e.str(client_id);
    send_reply(b);
}

// ==================================================================== clunk

void Conn::op_clunk(uint16_t tag, Dec &d) {
    uint32_t fid = d.u32();
    d.end();

    FidRef f = take_fid(fid);
    std::unique_lock<std::shared_mutex> lk(f->mu);

    // A pending Txattrcreate is committed here: the value the client streamed
    // in with Twrite becomes visible in one setxattr, or is removed if it
    // asked for a zero-length attribute.
    if (f->xattr && f->xattr_write) {
        std::string p = proc_path(f->pfd.get());
        int rc;
        if (f->xattr_size == 0) {
            rc = host_removexattr(f->pfd.get(), p, f->xattr_name.c_str());
        } else {
            if (f->xattr_buf.size() != f->xattr_size) {
                logf(1, "[%s] xattr %s: client wrote %zu of %llu bytes", peer_.c_str(),
                     f->xattr_name.c_str(), f->xattr_buf.size(),
                     static_cast<unsigned long long>(f->xattr_size));
            }
            rc = host_setxattr(f->pfd.get(), p, f->xattr_name.c_str(), f->xattr_buf.data(),
                            f->xattr_buf.size(), int(f->xattr_flags));
        }
        if (rc != 0) oserr();
    }
    send_empty(Rclunk, tag);
}

}  // namespace npxf::server
