#include "client.hpp"

#include <algorithm>
#include <cstring>

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net.hpp"

namespace npxf::client {

using namespace ninep;

namespace {

Dec body_of(const Bytes &msg) { return Dec(parse(byte_span(msg)).body); }

Attrs decode_getattr(Dec &d) {
    Attrs a;
    a.valid = d.u64();
    a.qid = d.qid();
    a.mode = d.u32();
    a.uid = d.u32();
    a.gid = d.u32();
    a.nlink = d.u64();
    a.rdev = d.u64();
    a.size = d.u64();
    a.blksize = d.u64();
    a.blocks = d.u64();
    a.atime_sec = int64_t(d.u64());
    a.atime_nsec = uint32_t(d.u64());
    a.mtime_sec = int64_t(d.u64());
    a.mtime_nsec = uint32_t(d.u64());
    a.ctime_sec = int64_t(d.u64());
    a.ctime_nsec = uint32_t(d.u64());
    a.btime_sec = int64_t(d.u64());
    (void)d.u64();  // btime_nsec
    (void)d.u64();  // gen
    (void)d.u64();  // data_version
    return a;
}

}  // namespace

std::vector<std::string> split_path(const std::string &p) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < p.size()) {
        size_t j = p.find('/', i);
        if (j == std::string::npos) j = p.size();
        std::string c = p.substr(i, j - i);
        if (!c.empty() && c != ".") out.push_back(std::move(c));
        i = j + 1;
    }
    return out;
}

Dialed dial(const std::string &addr, std::span<const uint8_t> token) {
    Dialed out;
    out.sock = net::tcp_connect(net::parse_addr(addr, "5640"));
    net::set_nodelay(out.sock.get());
    net::set_keepalive(out.sock.get());
    client_handshake(out.sock.get(), token, out.keys);
    return out;
}

// ============================================================== lifecycle

Client::~Client() { close(); }

void Client::connect(const std::string &addr, std::span<const uint8_t> token, uint32_t msize) {
    if (msize < kMinMsize) msize = kMinMsize;
    if (msize > kMaxRecordPayload) msize = uint32_t(kMaxRecordPayload);

    Dialed d = dial(addr, token);
    sock_ = std::move(d.sock);
    ch_.emplace(sock_.get(), d.keys, msize);
    reader_ = std::thread([this] { reader_loop(); });

    Bytes r = call(
        Tversion, [&](Enc &e) {
            e.u32(msize);
            e.str(kVersion);
        },
        Rversion);
    Dec dd = body_of(r);
    uint32_t got = dd.u32();
    std::string ver = dd.str();
    if (ver != kVersion) fail("server does not speak " + std::string(kVersion) + " (offered " + ver + ")");
    if (got > msize) fail("server raised msize above what we asked for");
    msize_ = got;
    logf(2, "negotiated %s, msize %u", ver.c_str(), msize_);
}

void Client::attach(const std::string &uname) {
    root_fid_ = alloc_fid();
    call(
        Tattach,
        [&](Enc &e) {
            e.u32(root_fid_);
            e.u32(kNoFid);  // channel-layer auth already happened; no afid
            e.str(uname);
            e.str("");
            e.u32(uint32_t(::getuid()));
        },
        Rattach);
    attached_ = true;
}

void Client::close() {
    if (!ch_) return;
    if (attached_) {
        try {
            clunk(root_fid_);
        } catch (const std::exception &) {
            // Nothing useful to do while tearing down.
        }
        attached_ = false;
    }
    // Wake the reader out of its blocking read, then let it finish.
    if (sock_) ::shutdown(sock_.get(), SHUT_RDWR);
    if (reader_.joinable()) reader_.join();
    ch_.reset();
    sock_.reset();
}

void Client::reader_loop() {
    Bytes msg;
    std::string why;
    try {
        while (ch_->recv(msg)) {
            if (msg.size() < kHeaderLen) {
                why = "runt reply";
                break;
            }
            uint16_t tag = ld16(msg.data() + 5);
            std::lock_guard<std::mutex> lk(mu_);
            auto it = pending_.find(tag);
            if (it == pending_.end()) {
                logf(1, "npxf: reply for unknown tag %u, ignoring", tag);
            } else {
                it->second->msg = std::move(msg);
                it->second->done = true;
            }
            msg = Bytes{};
            cv_.notify_all();
        }
        if (why.empty()) why = "server closed the connection";
    } catch (const std::exception &e) {
        why = e.what();
    }
    std::lock_guard<std::mutex> lk(mu_);
    if (fatal_.empty()) fatal_ = why;
    cv_.notify_all();
}

// ================================================================ plumbing

uint16_t Client::next_tag() {
    std::lock_guard<std::mutex> lk(tag_mu_);
    if (!tag_free_.empty()) {
        uint16_t t = tag_free_.front();
        tag_free_.pop_front();
        return t;
    }
    if (tag_next_ >= kNoTag) fail("ran out of 9P tags");
    return tag_next_++;
}

void Client::free_tag(uint16_t tag) {
    std::lock_guard<std::mutex> lk(tag_mu_);
    tag_free_.push_back(tag);
}

uint32_t Client::alloc_fid() {
    std::lock_guard<std::mutex> lk(fid_mu_);
    if (!fid_free_.empty()) {
        uint32_t f = fid_free_.front();
        fid_free_.pop_front();
        return f;
    }
    if (fid_next_ >= kNoFid) fail("ran out of 9P fids");
    return fid_next_++;
}

void Client::release_fid(uint32_t fid) {
    std::lock_guard<std::mutex> lk(fid_mu_);
    fid_free_.push_back(fid);
}

uint16_t Client::submit(uint8_t type, const std::function<void(Enc &)> &body) {
    uint16_t tag = (type == Tversion) ? kNoTag : next_tag();
    Bytes b;
    begin(b, type, tag);
    {
        Enc e(b);
        body(e);
    }
    finish(b);
    if (b.size() > msize_ && type != Tversion)
        fail("outgoing " + std::string(type_name(type)) + " of " + std::to_string(b.size()) +
             " bytes exceeds msize " + std::to_string(msize_));

    auto p = std::make_shared<Pending>();
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!fatal_.empty()) fail(fatal_);
        pending_[tag] = p;
    }
    try {
        ch_->send(b);
    } catch (...) {
        std::lock_guard<std::mutex> lk(mu_);
        pending_.erase(tag);
        throw;
    }
    return tag;
}

Bytes Client::await(uint16_t tag, uint8_t expect) {
    std::shared_ptr<Pending> p;
    Bytes msg;
    {
        std::unique_lock<std::mutex> lk(mu_);
        auto it = pending_.find(tag);
        if (it == pending_.end()) fail("await() on a tag that was never submitted");
        p = it->second;
        cv_.wait(lk, [&] { return p->done || !fatal_.empty(); });
        pending_.erase(tag);
        if (!p->done) fail(fatal_);
        msg = std::move(p->msg);
    }
    if (tag != kNoTag) free_tag(tag);

    Header h = parse(byte_span(msg));
    if (h.type == Rlerror) {
        Dec d(h.body);
        int e = int(d.u32());
        throw RemoteError(e, std::strerror(e));
    }
    if (h.type != expect)
        fail(std::string("expected ") + type_name(expect) + ", got " + type_name(h.type));
    return msg;
}

// ============================================================== operations

std::vector<Qid> Client::walk(uint32_t fid, uint32_t newfid, const std::vector<std::string> &names) {
    if (names.size() > kMaxWalkNames) fail("walk of more than 16 names");
    Bytes r = call(
        Twalk,
        [&](Enc &e) {
            e.u32(fid);
            e.u32(newfid);
            e.u16(uint16_t(names.size()));
            for (const auto &n : names) e.str(n);
        },
        Rwalk);
    Dec d = body_of(r);
    uint16_t n = d.u16();
    std::vector<Qid> qids;
    qids.reserve(n);
    for (uint16_t i = 0; i < n; i++) qids.push_back(d.qid());
    return qids;
}

uint32_t Client::walk_path(const std::string &path) {
    std::vector<std::string> comps = split_path(path);
    uint32_t fid = alloc_fid();
    walk(root_fid_, fid, {});  // clone the root

    size_t i = 0;
    while (i < comps.size()) {
        // Twalk carries at most sixteen names, so long paths take a few trips.
        size_t n = std::min(kMaxWalkNames, comps.size() - i);
        std::vector<std::string> chunk(comps.begin() + long(i), comps.begin() + long(i + n));
        std::vector<Qid> qids;
        try {
            qids = walk(fid, fid, chunk);
        } catch (...) {
            try {
                clunk(fid);
            } catch (const std::exception &) {
            }
            throw;
        }
        if (qids.size() != n) {
            try {
                clunk(fid);
            } catch (const std::exception &) {
            }
            throw RemoteError(ENOENT, path + ": " + std::strerror(ENOENT));
        }
        i += n;
    }
    return fid;
}

Qid Client::lopen(uint32_t fid, uint32_t flags) {
    Bytes r = call(
        Tlopen,
        [&](Enc &e) {
            e.u32(fid);
            e.u32(flags);
        },
        Rlopen);
    Dec d = body_of(r);
    return d.qid();
}

Qid Client::lcreate(uint32_t dfid, const std::string &name, uint32_t flags, uint32_t mode,
                    uint32_t gid) {
    Bytes r = call(
        Tlcreate,
        [&](Enc &e) {
            e.u32(dfid);
            e.str(name);
            e.u32(flags);
            e.u32(mode);
            e.u32(gid);
        },
        Rlcreate);
    Dec d = body_of(r);
    return d.qid();
}

Qid Client::mkdir(uint32_t dfid, const std::string &name, uint32_t mode, uint32_t gid) {
    Bytes r = call(
        Tmkdir,
        [&](Enc &e) {
            e.u32(dfid);
            e.str(name);
            e.u32(mode);
            e.u32(gid);
        },
        Rmkdir);
    Dec d = body_of(r);
    return d.qid();
}

Qid Client::symlink(uint32_t dfid, const std::string &name, const std::string &target, uint32_t gid) {
    Bytes r = call(
        Tsymlink,
        [&](Enc &e) {
            e.u32(dfid);
            e.str(name);
            e.str(target);
            e.u32(gid);
        },
        Rsymlink);
    Dec d = body_of(r);
    return d.qid();
}

Attrs Client::getattr(uint32_t fid, uint64_t mask) {
    Bytes r = call(
        Tgetattr,
        [&](Enc &e) {
            e.u32(fid);
            e.u64(mask);
        },
        Rgetattr);
    Dec d = body_of(r);
    return decode_getattr(d);
}

void Client::setattr(uint32_t fid, uint32_t valid, uint32_t mode, uint32_t uid, uint32_t gid,
                     uint64_t size, int64_t atime_sec, int64_t atime_nsec, int64_t mtime_sec,
                     int64_t mtime_nsec) {
    call(
        Tsetattr,
        [&](Enc &e) {
            e.u32(fid);
            e.u32(valid);
            e.u32(mode);
            e.u32(uid);
            e.u32(gid);
            e.u64(size);
            e.u64(uint64_t(atime_sec));
            e.u64(uint64_t(atime_nsec));
            e.u64(uint64_t(mtime_sec));
            e.u64(uint64_t(mtime_nsec));
        },
        Rsetattr);
}

std::vector<DirEntry> Client::readdir(uint32_t fid) {
    std::vector<DirEntry> out;
    uint64_t offset = 0;
    uint32_t chunk = iounit();
    for (;;) {
        Bytes r = call(
            Treaddir,
            [&](Enc &e) {
                e.u32(fid);
                e.u64(offset);
                e.u32(chunk);
            },
            Rreaddir);
        Dec d = body_of(r);
        uint32_t count = d.u32();
        if (count == 0) break;
        std::span<const uint8_t> data = d.raw(count);
        Dec ed(data);
        while (ed.left() > 0) {
            DirEntry de;
            de.qid = ed.qid();
            de.offset = ed.u64();
            de.type = ed.u8();
            de.name = ed.str();
            offset = de.offset;
            if (de.name != "." && de.name != "..") out.push_back(std::move(de));
        }
    }
    return out;
}

std::string Client::readlink(uint32_t fid) {
    Bytes r = call(Treadlink, [&](Enc &e) { e.u32(fid); }, Rreadlink);
    Dec d = body_of(r);
    return d.str();
}

StatFs Client::statfs(uint32_t fid) {
    Bytes r = call(Tstatfs, [&](Enc &e) { e.u32(fid); }, Rstatfs);
    Dec d = body_of(r);
    StatFs s;
    s.type = d.u32();
    s.bsize = d.u32();
    s.blocks = d.u64();
    s.bfree = d.u64();
    s.bavail = d.u64();
    s.files = d.u64();
    s.ffree = d.u64();
    s.fsid = d.u64();
    s.namelen = d.u32();
    return s;
}

void Client::renameat(uint32_t odfid, const std::string &oldname, uint32_t ndfid,
                      const std::string &newname) {
    call(
        Trenameat,
        [&](Enc &e) {
            e.u32(odfid);
            e.str(oldname);
            e.u32(ndfid);
            e.str(newname);
        },
        Rrenameat);
}

void Client::unlinkat(uint32_t dfid, const std::string &name, uint32_t flags) {
    call(
        Tunlinkat,
        [&](Enc &e) {
            e.u32(dfid);
            e.str(name);
            e.u32(flags);
        },
        Runlinkat);
}

void Client::fsync(uint32_t fid, bool datasync) {
    call(
        Tfsync,
        [&](Enc &e) {
            e.u32(fid);
            e.u32(datasync ? 1u : 0u);
        },
        Rfsync);
}

void Client::clunk(uint32_t fid) {
    call(Tclunk, [&](Enc &e) { e.u32(fid); }, Rclunk);
    release_fid(fid);
}

// ==================================================================== I/O

uint16_t Client::submit_read(uint32_t fid, uint64_t offset, uint32_t count) {
    if (count > iounit()) count = iounit();
    return submit(Tread, [&](Enc &e) {
        e.u32(fid);
        e.u64(offset);
        e.u32(count);
    });
}

size_t Client::complete_read(uint16_t tag, uint8_t *buf, size_t cap) {
    Bytes r = await(tag, Rread);
    Dec d = body_of(r);
    uint32_t count = d.u32();
    if (count > cap) fail("server returned more data than we asked for");
    std::span<const uint8_t> data = d.raw(count);
    if (count) std::memcpy(buf, data.data(), count);
    return count;
}

uint16_t Client::submit_write(uint32_t fid, uint64_t offset, const uint8_t *p, uint32_t n) {
    if (n > iounit()) n = iounit();
    return submit(Twrite, [&](Enc &e) {
        e.u32(fid);
        e.u64(offset);
        e.u32(n);
        e.raw(p, n);
    });
}

size_t Client::complete_write(uint16_t tag) {
    Bytes r = await(tag, Rwrite);
    Dec d = body_of(r);
    return d.u32();
}

size_t Client::read_at(uint32_t fid, uint64_t offset, uint8_t *buf, size_t n) {
    return complete_read(submit_read(fid, offset, uint32_t(std::min<size_t>(n, iounit()))), buf, n);
}

size_t Client::write_at(uint32_t fid, uint64_t offset, const uint8_t *p, size_t n) {
    size_t done = 0;
    while (done < n) {
        uint32_t chunk = uint32_t(std::min<size_t>(n - done, iounit()));
        size_t w = complete_write(submit_write(fid, offset + done, p + done, chunk));
        if (w == 0) fail("server accepted zero bytes of a write");
        done += w;
    }
    return done;
}

}  // namespace npxf::client
