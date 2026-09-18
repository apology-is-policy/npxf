// npxf -- command line client.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "client.hpp"
#include "net.hpp"
#include "ninep.hpp"
#include "util.hpp"

using namespace npxf;
using namespace npxf::client;
using namespace npxf::ninep;

namespace {

struct Opts {
    std::string addr = "localhost:5640";
    Bytes token;
    uint32_t msize = kDefaultMsize;
    int depth = 8;
};

void usage(FILE *out) {
    std::fprintf(out,
                 "usage: npxf [global options] <command> [args]\n"
                 "\n"
                 "Global options:\n"
                 "  -a, --addr HOST:PORT   server address (default localhost:5640)\n"
                 "  -t, --token-file F     file holding the shared token\n"
                 "      --token-env VAR    read the token from environment variable VAR\n"
                 "                         (defaults to NPXF_TOKEN when neither is given)\n"
                 "  -m, --msize N          maximum 9P message size (default %u)\n"
                 "  -d, --depth N          requests kept in flight during a copy (default 8)\n"
                 "  -v, --verbose          repeat for more detail\n"
                 "\n"
                 "Commands:\n"
                 "  ls [-l] [PATH]              list a directory\n"
                 "  stat PATH                   show attributes\n"
                 "  cat PATH                    write a file to stdout\n"
                 "  get [-r] REMOTE [LOCAL]     copy from the server\n"
                 "  put [-r] LOCAL [REMOTE]     copy to the server\n"
                 "  mkdir [-p] PATH             create a directory\n"
                 "  rm [-r] PATH                remove a file or directory\n"
                 "  mv OLD NEW                  rename\n"
                 "  ln -s TARGET LINKPATH       create a symlink\n"
                 "  readlink PATH               print a symlink's target\n"
                 "  df [PATH]                   filesystem statistics\n"
                 "  tunnel [--unix P|--tcp N]   expose plain 9P locally for mount(8)\n",
                 kDefaultMsize);
}

// -------------------------------------------------------------- local files

Bytes read_token_file(const std::string &path) {
    Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd) throw_errno("open " + path);
    struct stat st;
    if (::fstat(fd.get(), &st) != 0) throw_errno("fstat " + path);
    if (st.st_mode & (S_IRWXG | S_IRWXO))
        logf(0, "npxf: warning: %s is readable by other users (mode %04o); chmod 600 it",
             path.c_str(), unsigned(st.st_mode & 07777));

    Bytes buf(4096);
    size_t n = 0;
    for (;;) {
        ssize_t r = ::read(fd.get(), buf.data() + n, buf.size() - n);
        if (r < 0) {
            if (errno == EINTR) continue;
            throw_errno("read " + path);
        }
        if (r == 0) break;
        n += size_t(r);
        if (n == buf.size()) fail("token file " + path + " is too large");
    }
    buf.resize(n);
    trim_token_file(buf);  // util.hpp -- the rule, and why haul must match it
    if (buf.empty()) fail("token file " + path + " is empty");
    return buf;
}

void write_all_at(int fd, const uint8_t *p, size_t n, off_t off) {
    size_t done = 0;
    while (done < n) {
        ssize_t w = ::pwrite(fd, p + done, n - done, off + off_t(done));
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == ESPIPE) {  // stdout to a pipe is not seekable
                w = ::write(fd, p + done, n - done);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    throw_errno("write");
                }
                done += size_t(w);
                continue;
            }
            throw_errno("write");
        }
        done += size_t(w);
    }
}

std::string mode_string(uint32_t mode) {
    static const char *rwx[] = {"---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};
    char t = '-';
    switch (mode & S_IFMT) {
        case S_IFDIR: t = 'd'; break;
        case S_IFLNK: t = 'l'; break;
        case S_IFCHR: t = 'c'; break;
        case S_IFBLK: t = 'b'; break;
        case S_IFIFO: t = 'p'; break;
        case S_IFSOCK: t = 's'; break;
        default: break;
    }
    std::string s(1, t);
    s += rwx[(mode >> 6) & 7];
    s += rwx[(mode >> 3) & 7];
    s += rwx[mode & 7];
    if (mode & S_ISUID) s[3] = (mode & S_IXUSR) ? 's' : 'S';
    if (mode & S_ISGID) s[6] = (mode & S_IXGRP) ? 's' : 'S';
    if (mode & S_ISVTX) s[9] = (mode & S_IXOTH) ? 't' : 'T';
    return s;
}

std::string time_string(int64_t sec) {
    char buf[64];
    std::time_t t = std::time_t(sec);
    struct tm tmv;
    if (!::localtime_r(&t, &tmv)) return "?";
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M", &tmv);
    return buf;
}

std::string basename_of(const std::string &p) {
    auto comps = split_path(p);
    return comps.empty() ? std::string(".") : comps.back();
}

std::string dirname_of(const std::string &p) {
    auto comps = split_path(p);
    if (comps.empty()) return "";
    comps.pop_back();
    std::string s;
    for (const auto &c : comps) {
        if (!s.empty()) s += '/';
        s += c;
    }
    return s;
}

// Holds a fid and clunks it however the scope exits.
struct FidGuard {
    Client &c;
    uint32_t fid;
    bool live = true;
    FidGuard(Client &cl, uint32_t f) : c(cl), fid(f) {}
    FidGuard(const FidGuard &) = delete;
    FidGuard &operator=(const FidGuard &) = delete;
    ~FidGuard() {
        if (!live) return;
        try {
            c.clunk(fid);
        } catch (const std::exception &) {
            // Teardown; the server drops the fid when the session ends anyway.
        }
    }
    void release() { live = false; }
};

// ------------------------------------------------------------- bulk copy

// Pulls one open file into `outfd`, keeping `depth` Treads on the wire at
// once.  Offsets are explicit on both sides, so completions do not have to be
// matched up with any particular position in the output.
uint64_t pull_file(Client &c, uint32_t fid, int outfd, uint64_t size, int depth) {
    const uint32_t chunk = c.iounit();
    std::vector<uint8_t> buf(chunk);
    struct InFlight {
        uint16_t tag;
        uint64_t off;
        uint32_t want;
    };
    std::deque<InFlight> q;
    uint64_t next = 0, total = 0, limit = size;

    while (next < limit || !q.empty()) {
        while (next < limit && q.size() < size_t(depth)) {
            uint32_t want = uint32_t(std::min<uint64_t>(chunk, limit - next));
            q.push_back({c.submit_read(fid, next, want), next, want});
            next += want;
        }
        InFlight f = q.front();
        q.pop_front();
        size_t n = c.complete_read(f.tag, buf.data(), buf.size());
        if (n) {
            write_all_at(outfd, buf.data(), n, off_t(f.off));
            total += n;
        }
        // A short read on a regular file means end of file; stop queueing past
        // it.  Reads already in flight beyond that point return nothing.
        if (n < f.want) limit = std::min(limit, f.off + n);
    }

    // getattr's size is a snapshot; if the file grew meanwhile, finish it off.
    for (;;) {
        size_t n = c.read_at(fid, next, buf.data(), chunk);
        if (n == 0) break;
        write_all_at(outfd, buf.data(), n, off_t(next));
        next += n;
        total += n;
    }
    return total;
}

uint64_t push_file(Client &c, int infd, uint32_t fid, int depth) {
    const uint32_t chunk = c.iounit();
    // One buffer per in-flight request.  A short Rwrite has to be finished off
    // from the original data, so a chunk cannot be recycled until its reply
    // has landed.  Slots are reused in the same order they are drained, so at
    // most `depth` of them exist at once.
    const size_t slots = size_t(depth);
    std::vector<std::vector<uint8_t>> bufs(slots, std::vector<uint8_t>(chunk));
    struct InFlight {
        uint16_t tag;
        uint64_t off;
        uint32_t len;
        size_t slot;
    };
    std::deque<InFlight> q;
    uint64_t off = 0, total = 0;
    size_t slot = 0;

    auto drain = [&] {
        InFlight f = q.front();
        q.pop_front();
        size_t w = c.complete_write(f.tag);
        total += w;
        // Short writes are legal; finish the remainder synchronously rather
        // than disturbing the pipeline behind it.
        while (w < f.len) {
            size_t more = c.write_at(fid, f.off + w, bufs[f.slot].data() + w, f.len - w);
            w += more;
            total += more;
        }
    };

    for (;;) {
        if (q.size() >= slots) drain();
        std::vector<uint8_t> &buf = bufs[slot];
        ssize_t n = ::pread(infd, buf.data(), chunk, off_t(off));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno != ESPIPE) throw_errno("read");
            n = ::read(infd, buf.data(), chunk);  // stdin from a pipe
            if (n < 0) throw_errno("read");
        }
        if (n == 0) break;
        q.push_back({c.submit_write(fid, off, buf.data(), uint32_t(n)), off, uint32_t(n), slot});
        off += uint64_t(n);
        slot = (slot + 1) % slots;
    }
    while (!q.empty()) drain();
    return total;
}

// ------------------------------------------------------------- recursion

void pull_tree(Client &c, const Opts &o, uint32_t dfid, const std::string &local);

void pull_entry(Client &c, const Opts &o, uint32_t parent, const DirEntry &de,
                const std::string &local) {
    uint32_t fid = c.alloc_fid();
    if (c.walk(parent, fid, {de.name}).size() != 1) {
        c.release_fid(fid);
        logf(0, "npxf: %s vanished while copying", de.name.c_str());
        return;
    }
    FidGuard g(c, fid);
    Attrs a = c.getattr(fid);

    if (S_ISDIR(a.mode)) {
        pull_tree(c, o, fid, local);
    } else if (S_ISLNK(a.mode)) {
        std::string target = c.readlink(fid);
        ::unlink(local.c_str());
        if (::symlink(target.c_str(), local.c_str()) != 0) throw_errno("symlink " + local);
    } else if (S_ISREG(a.mode)) {
        c.lopen(fid, L_O_RDONLY);
        Fd out(::open(local.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                      mode_t(a.mode & 07777)));
        if (!out) throw_errno("create " + local);
        uint64_t n = pull_file(c, fid, out.get(), a.size, o.depth);
        logf(1, "  %s (%llu bytes)", local.c_str(), static_cast<unsigned long long>(n));
    } else {
        logf(0, "npxf: skipping %s (not a regular file, directory or symlink)", local.c_str());
    }
}

void pull_tree(Client &c, const Opts &o, uint32_t dfid, const std::string &local) {
    if (::mkdir(local.c_str(), 0755) != 0 && errno != EEXIST) throw_errno("mkdir " + local);
    // Read the whole listing before recursing: the directory fid's cursor is
    // server-side state, and descending mid-scan would disturb it.
    uint32_t scan = c.alloc_fid();
    c.walk(dfid, scan, {});
    FidGuard g(c, scan);
    c.lopen(scan, L_O_RDONLY | L_O_DIRECTORY);
    std::vector<DirEntry> entries = c.readdir(scan);

    for (const auto &de : entries) pull_entry(c, o, dfid, de, local + "/" + de.name);
}

void push_tree(Client &c, const Opts &o, const std::string &local, uint32_t dfid);

void push_entry(Client &c, const Opts &o, const std::string &local, uint32_t dfid,
                const std::string &name) {
    struct stat st;
    if (::lstat(local.c_str(), &st) != 0) throw_errno("lstat " + local);

    if (S_ISDIR(st.st_mode)) {
        uint32_t sub = c.alloc_fid();
        try {
            c.mkdir(dfid, name, uint32_t(st.st_mode & 07777), uint32_t(::getgid()));
        } catch (const RemoteError &e) {
            if (e.err != EEXIST) {
                c.release_fid(sub);
                throw;
            }
        }
        if (c.walk(dfid, sub, {name}).size() != 1) {
            c.release_fid(sub);
            fail("cannot enter " + name + " on the server");
        }
        FidGuard g(c, sub);
        push_tree(c, o, local, sub);
    } else if (S_ISLNK(st.st_mode)) {
        std::vector<char> buf(4096);
        ssize_t n = ::readlink(local.c_str(), buf.data(), buf.size());
        if (n < 0) throw_errno("readlink " + local);
        try {
            c.unlinkat(dfid, name, 0);
        } catch (const RemoteError &) {
            // Not there yet, which is the common case.
        }
        c.symlink(dfid, name, std::string(buf.data(), size_t(n)), uint32_t(::getgid()));
    } else if (S_ISREG(st.st_mode)) {
        Fd in(::open(local.c_str(), O_RDONLY | O_CLOEXEC));
        if (!in) throw_errno("open " + local);
        uint32_t fid = c.alloc_fid();
        c.walk(dfid, fid, {});
        FidGuard g(c, fid);
        c.lcreate(fid, name, L_O_WRONLY | L_O_CREAT | L_O_TRUNC, uint32_t(st.st_mode & 07777),
                  uint32_t(::getgid()));
        uint64_t n = push_file(c, in.get(), fid, o.depth);
        logf(1, "  %s (%llu bytes)", local.c_str(), static_cast<unsigned long long>(n));
    } else {
        logf(0, "npxf: skipping %s (not a regular file, directory or symlink)", local.c_str());
    }
}

void push_tree(Client &c, const Opts &o, const std::string &local, uint32_t dfid) {
    DIR *dir = ::opendir(local.c_str());
    if (!dir) throw_errno("opendir " + local);
    std::vector<std::string> names;
    while (struct dirent *de = ::readdir(dir)) {
        std::string n = de->d_name;
        if (n == "." || n == "..") continue;
        names.push_back(std::move(n));
    }
    ::closedir(dir);
    std::sort(names.begin(), names.end());
    for (const auto &n : names) push_entry(c, o, local + "/" + n, dfid, n);
}

// ------------------------------------------------------------- commands

int cmd_ls(Client &c, const Opts &o, std::vector<std::string> args) {
    bool long_form = false;
    std::string path;
    for (auto &a : args) {
        if (a == "-l")
            long_form = true;
        else if (path.empty())
            path = a;
        else
            fail("ls: too many arguments");
    }

    uint32_t fid = c.walk_path(path);
    FidGuard g(c, fid);
    Attrs a = c.getattr(fid);

    if (!S_ISDIR(a.mode)) {
        if (long_form)
            std::printf("%s %3llu %6u %6u %12llu %s %s\n", mode_string(a.mode).c_str(),
                        static_cast<unsigned long long>(a.nlink), a.uid, a.gid,
                        static_cast<unsigned long long>(a.size), time_string(a.mtime_sec).c_str(),
                        path.c_str());
        else
            std::printf("%s\n", path.c_str());
        return 0;
    }

    // Read the listing through a clone: 9P forbids walking from an open fid,
    // and the long form has to walk to each entry to stat it.
    uint32_t scan = c.alloc_fid();
    c.walk(fid, scan, {});
    FidGuard sg(c, scan);
    c.lopen(scan, L_O_RDONLY | L_O_DIRECTORY);
    std::vector<DirEntry> entries = c.readdir(scan);
    std::sort(entries.begin(), entries.end(),
              [](const DirEntry &x, const DirEntry &y) { return x.name < y.name; });

    for (const auto &de : entries) {
        if (!long_form) {
            std::printf("%s%s\n", de.name.c_str(), de.qid.type & QTDIR ? "/" : "");
            continue;
        }
        uint32_t efid = c.alloc_fid();
        if (c.walk(fid, efid, {de.name}).size() != 1) {
            c.release_fid(efid);
            std::printf("%-10s %3s %6s %6s %12s %-16s %s\n", "??????????", "?", "?", "?", "?", "?",
                        de.name.c_str());
            continue;
        }
        FidGuard eg(c, efid);
        Attrs ea = c.getattr(efid);
        std::string suffix;
        if (S_ISLNK(ea.mode)) {
            try {
                suffix = " -> " + c.readlink(efid);
            } catch (const std::exception &) {
                suffix = " -> ?";
            }
        }
        std::printf("%s %3llu %6u %6u %12llu %s %s%s\n", mode_string(ea.mode).c_str(),
                    static_cast<unsigned long long>(ea.nlink), ea.uid, ea.gid,
                    static_cast<unsigned long long>(ea.size), time_string(ea.mtime_sec).c_str(),
                    de.name.c_str(), suffix.c_str());
    }
    return 0;
}

int cmd_stat(Client &c, const Opts &, std::vector<std::string> args) {
    if (args.size() != 1) fail("stat: expected exactly one path");
    uint32_t fid = c.walk_path(args[0]);
    FidGuard g(c, fid);
    Attrs a = c.getattr(fid);
    std::printf("  path: %s\n", args[0].empty() ? "/" : args[0].c_str());
    std::printf("  mode: %s (%04o)\n", mode_string(a.mode).c_str(), a.mode & 07777);
    std::printf("  size: %llu\n", static_cast<unsigned long long>(a.size));
    std::printf(" links: %llu\n", static_cast<unsigned long long>(a.nlink));
    std::printf(" owner: %u:%u\n", a.uid, a.gid);
    std::printf(" mtime: %s\n", time_string(a.mtime_sec).c_str());
    std::printf(" atime: %s\n", time_string(a.atime_sec).c_str());
    std::printf(" ctime: %s\n", time_string(a.ctime_sec).c_str());
    if (a.valid & GETATTR_BTIME) std::printf(" btime: %s\n", time_string(a.btime_sec).c_str());
    std::printf("   qid: type=%02x version=%u path=%llu\n", a.qid.type, a.qid.version,
                static_cast<unsigned long long>(a.qid.path));
    if (S_ISLNK(a.mode)) std::printf("target: %s\n", c.readlink(fid).c_str());
    return 0;
}

int cmd_cat(Client &c, const Opts &o, std::vector<std::string> args) {
    if (args.size() != 1) fail("cat: expected exactly one path");
    uint32_t fid = c.walk_path(args[0]);
    FidGuard g(c, fid);
    Attrs a = c.getattr(fid);
    if (S_ISDIR(a.mode)) fail("cat: " + args[0] + " is a directory");
    c.lopen(fid, L_O_RDONLY);
    pull_file(c, fid, STDOUT_FILENO, a.size, o.depth);
    return 0;
}

int cmd_get(Client &c, const Opts &o, std::vector<std::string> args) {
    bool recursive = false;
    std::vector<std::string> pos;
    for (auto &a : args) {
        if (a == "-r" || a == "-R")
            recursive = true;
        else
            pos.push_back(a);
    }
    if (pos.empty() || pos.size() > 2) fail("get: expected REMOTE [LOCAL]");
    std::string remote = pos[0];
    std::string local = pos.size() > 1 ? pos[1] : basename_of(remote);

    uint32_t fid = c.walk_path(remote);
    FidGuard g(c, fid);
    Attrs a = c.getattr(fid);

    if (S_ISDIR(a.mode)) {
        if (!recursive) fail("get: " + remote + " is a directory (use -r)");
        pull_tree(c, o, fid, local);
        return 0;
    }
    if (S_ISLNK(a.mode)) {
        std::string t = c.readlink(fid);
        ::unlink(local.c_str());
        if (::symlink(t.c_str(), local.c_str()) != 0) throw_errno("symlink " + local);
        return 0;
    }
    c.lopen(fid, L_O_RDONLY);
    Fd out(::open(local.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode_t(a.mode & 07777)));
    if (!out) throw_errno("create " + local);
    uint64_t n = pull_file(c, fid, out.get(), a.size, o.depth);
    logf(1, "%s -> %s (%llu bytes)", remote.c_str(), local.c_str(),
         static_cast<unsigned long long>(n));
    return 0;
}

int cmd_put(Client &c, const Opts &o, std::vector<std::string> args) {
    bool recursive = false;
    std::vector<std::string> pos;
    for (auto &a : args) {
        if (a == "-r" || a == "-R")
            recursive = true;
        else
            pos.push_back(a);
    }
    if (pos.empty() || pos.size() > 2) fail("put: expected LOCAL [REMOTE]");
    std::string local = pos[0];
    // Trailing slashes would turn into empty path components.
    while (local.size() > 1 && local.back() == '/') local.pop_back();
    std::string remote = pos.size() > 1 ? pos[1] : basename_of(local);

    struct stat st;
    if (::lstat(local.c_str(), &st) != 0) throw_errno("lstat " + local);
    if (S_ISDIR(st.st_mode) && !recursive) fail("put: " + local + " is a directory (use -r)");

    // If REMOTE names an existing directory, copy into it rather than over it.
    std::string parent = dirname_of(remote), name = basename_of(remote);
    try {
        uint32_t probe = c.walk_path(remote);
        FidGuard pg(c, probe);
        Attrs pa = c.getattr(probe);
        if (S_ISDIR(pa.mode) && !S_ISDIR(st.st_mode)) {
            parent = remote;
            name = basename_of(local);
        }
    } catch (const RemoteError &) {
        // Does not exist yet; create it under `parent`.
    }

    uint32_t dfid = c.walk_path(parent);
    FidGuard dg(c, dfid);
    push_entry(c, o, local, dfid, name);
    return 0;
}

int cmd_mkdir(Client &c, const Opts &, std::vector<std::string> args) {
    bool parents = false;
    std::vector<std::string> pos;
    for (auto &a : args) {
        if (a == "-p")
            parents = true;
        else
            pos.push_back(a);
    }
    if (pos.size() != 1) fail("mkdir: expected exactly one path");

    std::vector<std::string> comps = split_path(pos[0]);
    if (comps.empty()) fail("mkdir: refusing to create the export root");

    uint32_t dfid = c.alloc_fid();
    c.walk(c.root(), dfid, {});
    FidGuard g(c, dfid);

    for (size_t i = 0; i < comps.size(); i++) {
        bool last = (i + 1 == comps.size());
        if (!last && !parents) {
            if (c.walk(dfid, dfid, {comps[i]}).size() != 1)
                throw RemoteError(ENOENT, pos[0] + ": " + std::strerror(ENOENT));
            continue;
        }
        try {
            c.mkdir(dfid, comps[i], 0755, uint32_t(::getgid()));
        } catch (const RemoteError &e) {
            if (!(e.err == EEXIST && parents)) throw;
        }
        if (!last && c.walk(dfid, dfid, {comps[i]}).size() != 1)
            throw RemoteError(ENOENT, pos[0] + ": " + std::strerror(ENOENT));
    }
    return 0;
}

void remove_tree(Client &c, uint32_t dfid, const std::string &name) {
    uint32_t fid = c.alloc_fid();
    if (c.walk(dfid, fid, {name}).size() != 1) {
        c.release_fid(fid);
        return;
    }
    bool is_dir;
    {
        FidGuard g(c, fid);
        is_dir = S_ISDIR(c.getattr(fid, GETATTR_MODE).mode);
        if (is_dir) {
            uint32_t scan = c.alloc_fid();
            c.walk(fid, scan, {});
            FidGuard sg(c, scan);
            c.lopen(scan, L_O_RDONLY | L_O_DIRECTORY);
            for (const auto &de : c.readdir(scan)) remove_tree(c, fid, de.name);
        }
    }
    c.unlinkat(dfid, name, is_dir ? uint32_t(AT_REMOVEDIR) : 0u);
}

int cmd_rm(Client &c, const Opts &, std::vector<std::string> args) {
    bool recursive = false;
    std::vector<std::string> pos;
    for (auto &a : args) {
        if (a == "-r" || a == "-R")
            recursive = true;
        else
            pos.push_back(a);
    }
    if (pos.size() != 1) fail("rm: expected exactly one path");
    std::vector<std::string> comps = split_path(pos[0]);
    if (comps.empty()) fail("rm: refusing to remove the export root");

    uint32_t dfid = c.walk_path(dirname_of(pos[0]));
    FidGuard g(c, dfid);
    std::string name = comps.back();

    uint32_t probe = c.alloc_fid();
    if (c.walk(dfid, probe, {name}).size() != 1) {
        c.release_fid(probe);
        throw RemoteError(ENOENT, pos[0] + ": " + std::strerror(ENOENT));
    }
    bool is_dir;
    {
        FidGuard pg(c, probe);
        is_dir = S_ISDIR(c.getattr(probe, GETATTR_MODE).mode);
    }
    if (is_dir && !recursive) {
        c.unlinkat(dfid, name, uint32_t(AT_REMOVEDIR));  // succeeds only if empty
        return 0;
    }
    if (is_dir)
        remove_tree(c, dfid, name);
    else
        c.unlinkat(dfid, name, 0);
    return 0;
}

int cmd_mv(Client &c, const Opts &, std::vector<std::string> args) {
    if (args.size() != 2) fail("mv: expected OLD and NEW");
    std::vector<std::string> oc = split_path(args[0]), nc = split_path(args[1]);
    if (oc.empty() || nc.empty()) fail("mv: refusing to rename the export root");

    uint32_t od = c.walk_path(dirname_of(args[0]));
    FidGuard og(c, od);
    uint32_t nd = c.walk_path(dirname_of(args[1]));
    FidGuard ng(c, nd);
    c.renameat(od, oc.back(), nd, nc.back());
    return 0;
}

int cmd_ln(Client &c, const Opts &, std::vector<std::string> args) {
    std::vector<std::string> pos;
    bool sym = false;
    for (auto &a : args) {
        if (a == "-s")
            sym = true;
        else
            pos.push_back(a);
    }
    if (!sym) fail("ln: only symbolic links are supported (use -s)");
    if (pos.size() != 2) fail("ln: expected TARGET and LINKPATH");
    std::vector<std::string> lc = split_path(pos[1]);
    if (lc.empty()) fail("ln: LINKPATH must name something inside the export");

    uint32_t dfid = c.walk_path(dirname_of(pos[1]));
    FidGuard g(c, dfid);
    c.symlink(dfid, lc.back(), pos[0], uint32_t(::getgid()));
    return 0;
}

int cmd_readlink(Client &c, const Opts &, std::vector<std::string> args) {
    if (args.size() != 1) fail("readlink: expected exactly one path");
    uint32_t fid = c.walk_path(args[0]);
    FidGuard g(c, fid);
    std::printf("%s\n", c.readlink(fid).c_str());
    return 0;
}

int cmd_df(Client &c, const Opts &, std::vector<std::string> args) {
    std::string path = args.empty() ? "" : args[0];
    uint32_t fid = c.walk_path(path);
    FidGuard g(c, fid);
    StatFs s = c.statfs(fid);
    double total = double(s.blocks) * s.bsize;
    double avail = double(s.bavail) * s.bsize;
    double used = total - double(s.bfree) * s.bsize;
    std::printf("block size : %u\n", s.bsize);
    std::printf("total      : %.1f GiB\n", total / (1024 * 1024 * 1024));
    std::printf("used       : %.1f GiB\n", used / (1024 * 1024 * 1024));
    std::printf("available  : %.1f GiB\n", avail / (1024 * 1024 * 1024));
    std::printf("inodes     : %llu total, %llu free\n", static_cast<unsigned long long>(s.files),
                static_cast<unsigned long long>(s.ffree));
    std::printf("name limit : %u\n", s.namelen);
    return 0;
}

// ------------------------------------------------------------------ tunnel

// Relays framed 9P between a local plaintext socket and one encrypted npxf
// session.  Because our records are one-to-one with 9P messages, this is a
// pure framing translation -- the local client negotiates version and msize
// with the real server, straight through.
void relay(Fd local, const Opts &o) {
    Dialed d = dial(o.addr, o.token);
    Channel ch(d.sock.get(), d.keys, o.msize);
    int lfd = local.get(), rfd = d.sock.get();

    std::thread up([&] {
        Bytes msg;
        try {
            for (;;) {
                uint8_t hdr[4];
                if (!net::read_full(lfd, hdr, 4)) break;
                uint32_t size = ld32(hdr);
                if (size < kHeaderLen || size > o.msize) {
                    logf(0, "npxf tunnel: local client sent a %u byte message (msize is %u)", size,
                         o.msize);
                    break;
                }
                msg.resize(size);
                std::memcpy(msg.data(), hdr, 4);
                if (!net::read_full(lfd, msg.data() + 4, size - 4)) break;
                ch.send(msg);
            }
        } catch (const std::exception &e) {
            logf(1, "npxf tunnel: upstream: %s", e.what());
        }
        ::shutdown(rfd, SHUT_RDWR);
        ::shutdown(lfd, SHUT_RDWR);
    });

    try {
        Bytes msg;
        while (ch.recv(msg)) net::write_full(lfd, msg.data(), msg.size());
    } catch (const std::exception &e) {
        logf(1, "npxf tunnel: downstream: %s", e.what());
    }
    ::shutdown(lfd, SHUT_RDWR);
    ::shutdown(rfd, SHUT_RDWR);
    up.join();
}

int cmd_tunnel(const Opts &o, std::vector<std::string> args) {
    std::string unix_path, tcp_port;
    for (size_t i = 0; i < args.size(); i++) {
        if (args[i] == "--unix" && i + 1 < args.size())
            unix_path = args[++i];
        else if (args[i] == "--tcp" && i + 1 < args.size())
            tcp_port = args[++i];
        else
            fail("tunnel: unexpected argument '" + args[i] + "'");
    }
    if (unix_path.empty() && tcp_port.empty())
        unix_path = "/tmp/npxf-" + std::to_string(::getuid()) + ".sock";

    std::vector<Fd> listeners;
    if (!unix_path.empty()) {
        listeners.push_back(net::unix_listen(unix_path));
        std::fprintf(stderr, "npxf tunnel: listening on %s\nmount with:\n", unix_path.c_str());
        std::fprintf(stderr, "  sudo mount -t 9p -o trans=unix,version=9p2000.L,msize=%u %s /mnt\n",
                     o.msize, unix_path.c_str());
    } else {
        // A TCP listener is reachable by every local user; the unix socket
        // above is created 0600 and is the safer default.
        listeners = net::tcp_listen(net::parse_addr("127.0.0.1:" + tcp_port, tcp_port));
        std::fprintf(stderr,
                     "npxf tunnel: listening on 127.0.0.1:%s (any local user can connect)\n"
                     "mount with:\n"
                     "  sudo mount -t 9p -o trans=tcp,port=%s,version=9p2000.L,msize=%u "
                     "127.0.0.1 /mnt\n",
                     tcp_port.c_str(), tcp_port.c_str(), o.msize);
    }

    std::vector<pollfd> pfds;
    for (auto &l : listeners) pfds.push_back(pollfd{l.get(), POLLIN, 0});
    for (;;) {
        int pr = ::poll(pfds.data(), pfds.size(), -1);
        if (pr < 0) {
            if (errno == EINTR) break;
            throw_errno("poll");
        }
        for (auto &pf : pfds) {
            if (!(pf.revents & POLLIN)) continue;
            Fd cs(::accept4(pf.fd, nullptr, nullptr, SOCK_CLOEXEC));
            if (!cs) continue;
            std::thread([sock = std::move(cs), opts = o]() mutable {
                try {
                    relay(std::move(sock), opts);
                } catch (const std::exception &e) {
                    logf(0, "npxf tunnel: %s", e.what());
                }
            }).detach();
        }
    }
    if (!unix_path.empty()) ::unlink(unix_path.c_str());
    return 0;
}

}  // namespace

int main(int argc, char **argv) {
    Opts o;
    std::string token_file, token_env;
    std::vector<std::string> rest;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto want = [&](const char *what) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "npxf: %s needs an argument\n", what);
                std::exit(2);
            }
            return argv[++i];
        };
        if (!rest.empty()) {
            rest.push_back(a);  // everything after the command belongs to it
        } else if (a == "-a" || a == "--addr") {
            o.addr = want("--addr");
        } else if (a == "-t" || a == "--token-file") {
            token_file = want("--token-file");
        } else if (a == "--token-env") {
            token_env = want("--token-env");
        } else if (a == "-m" || a == "--msize") {
            o.msize = uint32_t(std::strtoul(want("--msize").c_str(), nullptr, 10));
        } else if (a == "-d" || a == "--depth") {
            o.depth = std::atoi(want("--depth").c_str());
        } else if (a == "-v" || a == "--verbose") {
            g_verbose++;
        } else if (a == "-h" || a == "--help") {
            usage(stdout);
            return 0;
        } else if (!a.empty() && a[0] == '-' && a != "-") {
            std::fprintf(stderr, "npxf: unknown global option '%s'\n", a.c_str());
            return 2;
        } else {
            rest.push_back(a);
        }
    }

    if (rest.empty()) {
        usage(stderr);
        return 2;
    }
    if (o.depth < 1) o.depth = 1;
    if (o.depth > 256) o.depth = 256;

    try {
        std::string err;
        if (!crypto::self_test(&err)) fail("cryptographic self-test failed: " + err);
        ::signal(SIGPIPE, SIG_IGN);

        if (!token_env.empty()) {
            const char *v = ::getenv(token_env.c_str());
            if (!v || !*v) fail("environment variable " + token_env + " is unset or empty");
            o.token.assign(v, v + std::strlen(v));
        } else if (!token_file.empty()) {
            o.token = read_token_file(token_file);
        } else if (const char *v = ::getenv("NPXF_TOKEN"); v && *v) {
            o.token.assign(v, v + std::strlen(v));
        } else {
            std::fprintf(stderr,
                         "npxf: no token; pass --token-file, --token-env, or set NPXF_TOKEN\n");
            return 2;
        }

        std::string cmd = rest[0];
        std::vector<std::string> args(rest.begin() + 1, rest.end());

        if (cmd == "tunnel") return cmd_tunnel(o, args);

        Client c;
        c.connect(o.addr, byte_span(o.token), o.msize);
        c.attach(::getenv("USER") ? ::getenv("USER") : "npxf");

        int rc;
        if (cmd == "ls")
            rc = cmd_ls(c, o, args);
        else if (cmd == "stat")
            rc = cmd_stat(c, o, args);
        else if (cmd == "cat")
            rc = cmd_cat(c, o, args);
        else if (cmd == "get")
            rc = cmd_get(c, o, args);
        else if (cmd == "put")
            rc = cmd_put(c, o, args);
        else if (cmd == "mkdir")
            rc = cmd_mkdir(c, o, args);
        else if (cmd == "rm")
            rc = cmd_rm(c, o, args);
        else if (cmd == "mv")
            rc = cmd_mv(c, o, args);
        else if (cmd == "ln")
            rc = cmd_ln(c, o, args);
        else if (cmd == "readlink")
            rc = cmd_readlink(c, o, args);
        else if (cmd == "df")
            rc = cmd_df(c, o, args);
        else {
            std::fprintf(stderr, "npxf: unknown command '%s'\n", cmd.c_str());
            usage(stderr);
            return 2;
        }
        c.close();
        return rc;
    } catch (const RemoteError &e) {
        std::fprintf(stderr, "npxf: %s\n", e.what());
        return 1;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "npxf: %s\n", e.what());
        return 1;
    }
}
