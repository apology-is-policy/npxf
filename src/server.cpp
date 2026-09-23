#include "platform.hpp"
// npxf-server -- main, listener, and the per-connection message loop.
#include "server.hpp"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <cstdlib>
#include <cstring>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "net.hpp"

namespace npxf::server {

thread_local Bytes Conn::reply_buf_;
thread_local bool Conn::worker_reply_ = false;

namespace {

volatile sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

std::atomic<int> g_live_conns{0};

}  // namespace

// ============================================================ connection

Conn::Conn(std::shared_ptr<const Config> cfg, Fd sock, int rootfd)
    : cfg_(std::move(cfg)), sock_(std::move(sock)), rootfd_(rootfd) {
    peer_ = net::peer_name(sock_.get());
}

Conn::~Conn() { stop_workers(); }

void Conn::serve() {
    net::set_nodelay(sock_.get());
    net::set_keepalive(sock_.get());

    // The lifecycle lines log at the default level: an operator whose mount
    // misbehaves first needs to know whether a connection arrived at all.
    logf(0, "[%s] connected", peer_.c_str());
    SessionKeys keys;
    server_handshake(sock_.get(), byte_span(cfg_->token), keys);
    logf(0, "[%s] authenticated", peer_.c_str());

    ch_.emplace(sock_.get(), keys, cfg_->msize);
    msize_.store(cfg_->msize, std::memory_order_release);
    start_workers();

    Bytes msg;
    while (ch_->recv(msg)) {
        if (msg.size() < ninep::kHeaderLen) fail("runt 9P message");
        uint32_t msize = msize_.load(std::memory_order_acquire);
        if (msg.size() > msize)
            fail("message of " + std::to_string(msg.size()) + " exceeds negotiated msize " +
                 std::to_string(msize));

        uint8_t type = msg[4];
        uint16_t tag = ld16(msg.data() + 5);
        uint32_t declared = ld32(msg.data());
        if (declared != msg.size()) fail("9P size field disagrees with the record length");

        if (g_verbose >= 3)
            logf(3, "[%s] <- %s tag=%u len=%zu", peer_.c_str(), ninep::type_name(type), tag,
                 msg.size());

        // Tversion is a session reset: it must be answered with nothing else
        // in flight, and it invalidates every fid.
        if (type == ninep::Tversion) {
            {
                std::unique_lock<std::mutex> lk(tags_mu_);
                tags_cv_.wait(lk, [&] { return active_tags_.empty(); });
            }
            clear_fids();
            ninep::Dec d(std::span<const uint8_t>(msg).subspan(ninep::kHeaderLen));
            try {
                op_version(tag, d);
            } catch (const Errno &e) {
                send_error(tag, e.e);
            } catch (const ninep::ProtoError &) {
                send_error(tag, EPROTO);
            }
            continue;
        }

        if (!versioned_.load(std::memory_order_acquire)) {
            send_error(tag, EINVAL);  // client must negotiate a version first
            continue;
        }

        if (type == ninep::Tflush) {
            ninep::Dec d(std::span<const uint8_t>(msg).subspan(ninep::kHeaderLen));
            uint16_t oldtag;
            try {
                oldtag = d.u16();
            } catch (const ninep::ProtoError &) {
                send_error(tag, EPROTO);
                continue;
            }
            bool answer_now;
            {
                std::lock_guard<std::mutex> lk(tags_mu_);
                answer_now = !active_tags_.count(oldtag);
                if (!answer_now) flush_waiters_[oldtag].push_back(tag);
            }
            // Spec: Rflush must not precede the flushed request's own reply.
            // If the target is still running we park this tag and let the
            // worker answer it, so the reader thread keeps draining.
            if (answer_now) send_empty(ninep::Rflush, tag);
            continue;
        }

        if (tag == ninep::kNoTag) {
            send_error(tag, EINVAL);  // NOTAG is only legal on Tversion
            continue;
        }
        {
            std::lock_guard<std::mutex> lk(tags_mu_);
            if (!active_tags_.insert(tag).second) {
                send_error(tag, EINVAL);  // tag already in flight
                continue;
            }
        }

        {
            std::lock_guard<std::mutex> lk(q_mu_);
            if (stopping_) break;
            queue_.push_back(Job{type, tag, std::move(msg)});
        }
        q_cv_.notify_one();
        msg = Bytes{};
    }
    logf(0, "[%s] disconnected", peer_.c_str());
}

void Conn::start_workers() {
    int n = cfg_->workers;
    if (n <= 0) {
        unsigned hw = std::thread::hardware_concurrency();
        n = int(hw ? std::min(hw, 8u) : 4u);
    }
    n = std::max(n, 2);
    workers_.reserve(size_t(n));
    for (int i = 0; i < n; i++) workers_.emplace_back([this] { worker_loop(); });
    logf(2, "[%s] %d worker threads", peer_.c_str(), n);
}

void Conn::stop_workers() {
    {
        std::lock_guard<std::mutex> lk(q_mu_);
        if (stopping_ && workers_.empty()) return;
        stopping_ = true;
    }
    q_cv_.notify_all();
    for (auto &t : workers_)
        if (t.joinable()) t.join();
    workers_.clear();
}

void Conn::worker_loop() {
    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lk(q_mu_);
            q_cv_.wait(lk, [&] { return stopping_ || !queue_.empty(); });
            if (queue_.empty()) return;  // stopping and drained
            job = std::move(queue_.front());
            queue_.pop_front();
        }
        try {
            run_job(job);
        } catch (const std::exception &e) {
            // A failure here means the channel itself is gone.  Tear the
            // connection down rather than spinning on a dead socket.
            logf(1, "[%s] fatal: %s", peer_.c_str(), e.what());
            {
                std::lock_guard<std::mutex> lk(q_mu_);
                stopping_ = true;
            }
            ::shutdown(sock_.get(), SHUT_RDWR);
            q_cv_.notify_all();
            return;
        }
    }
}

void Conn::run_job(Job &job) {
    struct ReplyGuard {
        bool &active;
        explicit ReplyGuard(bool &a) : active(a) { active = true; }
        ~ReplyGuard() { active = false; }
    } guard(worker_reply_);
    ninep::Dec d(std::span<const uint8_t>(job.msg).subspan(ninep::kHeaderLen));
    try {
        switch (job.type) {
            case ninep::Tauth: op_auth(job.tag, d); break;
            case ninep::Tattach: op_attach(job.tag, d); break;
            case ninep::Twalk: op_walk(job.tag, d); break;
            case ninep::Tstatfs: op_statfs(job.tag, d); break;
            case ninep::Tlopen: op_lopen(job.tag, d); break;
            case ninep::Tlcreate: op_lcreate(job.tag, d); break;
            case ninep::Tsymlink: op_symlink(job.tag, d); break;
            case ninep::Tmknod: op_mknod(job.tag, d); break;
            case ninep::Trename: op_rename(job.tag, d); break;
            case ninep::Treadlink: op_readlink(job.tag, d); break;
            case ninep::Tgetattr: op_getattr(job.tag, d); break;
            case ninep::Tsetattr: op_setattr(job.tag, d); break;
            case ninep::Txattrwalk: op_xattrwalk(job.tag, d); break;
            case ninep::Txattrcreate: op_xattrcreate(job.tag, d); break;
            case ninep::Treaddir: op_readdir(job.tag, d); break;
            case ninep::Tfsync: op_fsync(job.tag, d); break;
            case ninep::Tlock: op_lock(job.tag, d); break;
            case ninep::Tgetlock: op_getlock(job.tag, d); break;
            case ninep::Tlink: op_link(job.tag, d); break;
            case ninep::Tmkdir: op_mkdir(job.tag, d); break;
            case ninep::Trenameat: op_renameat(job.tag, d); break;
            case ninep::Tunlinkat: op_unlinkat(job.tag, d); break;
            case ninep::Tread: op_read(job.tag, d); break;
            case ninep::Twrite: op_write(job.tag, d); break;
            case ninep::Tclunk: op_clunk(job.tag, d); break;
            case ninep::Tremove: op_remove(job.tag, d); break;
            default:
                logf(1, "[%s] unsupported message type %u", peer_.c_str(), job.type);
                send_error(job.tag, EOPNOTSUPP);
                break;
        }
    } catch (const Errno &e) {
        send_error(job.tag, e.e);
    } catch (const ninep::ProtoError &e) {
        logf(1, "[%s] malformed %s: %s", peer_.c_str(), ninep::type_name(job.type), e.what());
        send_error(job.tag, EPROTO);
    }
    if (worker_reply_) fail("operation completed without a reply");
}

void Conn::publish_reply(Bytes &b) {
    if (!worker_reply_) { ch_->send(b); return; }
    // The client may reuse its tag the instant it receives the reply. Hold
    // admission's mutex across publication AND retirement, so its next request
    // cannot observe a sent reply whose tag is still marked active. Lock order:
    // tags_mu_ -> Channel send mutex; no channel path acquires tags_mu_.
    std::vector<uint16_t> flushes;
    {
        std::lock_guard<std::mutex> lk(tags_mu_);
        ch_->send(b);
        uint16_t tag = ld16(b.data() + 5);
        active_tags_.erase(tag);
        auto it = flush_waiters_.find(tag);
        if (it != flush_waiters_.end()) {
            flushes = std::move(it->second);
            flush_waiters_.erase(it);
        }
        worker_reply_ = false;
    }
    tags_cv_.notify_all();
    for (uint16_t ft : flushes) send_empty(ninep::Rflush, ft);
}

void Conn::send_reply(Bytes &b) {
    ninep::finish(b);
    uint32_t msize = msize_.load(std::memory_order_acquire);
    if (b.size() > msize) {
        // Never send a reply the client is not prepared to receive.
        logf(1, "[%s] reply of %zu bytes exceeds msize %u", peer_.c_str(), b.size(), msize);
        uint16_t tag = ld16(b.data() + 5);
        ninep::begin(b, ninep::Rlerror, tag);
        ninep::Enc(b).u32(uint32_t(platform::wire_errno(EMSGSIZE)));
        ninep::finish(b);
    }
    if (g_verbose >= 3)
        logf(3, "[%s] -> %s tag=%u len=%zu", peer_.c_str(), ninep::type_name(b[4]),
             ld16(b.data() + 5), b.size());
    publish_reply(b);
}

void Conn::send_error(uint16_t tag, int e) {
    Bytes b;
    ninep::begin(b, ninep::Rlerror, tag);
    ninep::Enc(b).u32(uint32_t(platform::wire_errno(e)));
    ninep::finish(b);
    logf(2, "[%s] -> Rlerror tag=%u errno=%d (%s)", peer_.c_str(), tag, e, std::strerror(e));
    publish_reply(b);
}

void Conn::send_empty(uint8_t type, uint16_t tag) {
    Bytes b;
    ninep::begin(b, type, tag);
    ninep::finish(b);
    publish_reply(b);
}

// -------------------------------------------------------------- fid table

FidRef Conn::get_fid(uint32_t id) {
    std::lock_guard<std::mutex> lk(fids_mu_);
    auto it = fids_.find(id);
    if (it == fids_.end()) oserr(EBADF);
    return it->second;
}

FidRef Conn::get_open_fid(uint32_t id) {
    FidRef f = get_fid(id);
    if (!f->opened) oserr(EBADF);
    return f;
}

void Conn::put_fid(uint32_t id, FidRef f) {
    if (id == ninep::kNoFid) oserr(EBADF);
    std::lock_guard<std::mutex> lk(fids_mu_);
    if (!fids_.emplace(id, std::move(f)).second) oserr(EBADF);  // fid already in use
}

FidRef Conn::take_fid(uint32_t id) {
    std::lock_guard<std::mutex> lk(fids_mu_);
    auto it = fids_.find(id);
    if (it == fids_.end()) oserr(EBADF);
    FidRef f = std::move(it->second);
    fids_.erase(it);
    return f;
}

void Conn::clear_fids() {
    std::lock_guard<std::mutex> lk(fids_mu_);
    fids_.clear();
}

// ================================================================== main

namespace {

void usage(FILE *out) {
    std::fprintf(out,
                 "usage: npxf-server [options]\n"
                 "\n"
                 "Serves a directory over 9P2000.L on an authenticated, encrypted channel.\n"
                 "\n"
                 "  -l, --listen ADDR     address to bind (default :5640)\n"
                 "  -r, --root DIR        directory to export (default: cwd)\n"
                 "  -t, --token-file F    file holding the shared token (required, or --token-env)\n"
                 "      --token-env VAR   read the token from environment variable VAR\n"
                 "  -m, --msize N         maximum 9P message size (default %u)\n"
                 "  -j, --workers N       worker threads per connection (default: min(ncpu,8))\n"
                 "  -c, --max-conns N     concurrent connections to accept (default 64)\n"
                 "  -R, --read-only       reject every mutating operation\n"
                 "  -u, --user NAME       drop to this user after binding (requires root)\n"
                 "      --once            serve a single connection, then exit\n"
                 "  -v, --verbose         repeat for more detail\n"
                 "  -h, --help\n",
                 ninep::kDefaultMsize);
}

Bytes read_token_file(const std::string &path) {
    Fd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd) throw_errno("open " + path);

    struct stat st;
    if (::fstat(fd.get(), &st) != 0) throw_errno("fstat " + path);
    if (st.st_mode & (S_IRWXG | S_IRWXO))
        logf(0, "npxf-server: warning: %s is readable by other users (mode %04o); chmod 600 it",
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
    // A token file almost always ends in a newline; do not make that part of
    // the secret, or `echo tok > f` and `printf tok > f` would disagree.
    while (!buf.empty() && (buf.back() == '\n' || buf.back() == '\r')) buf.pop_back();
    if (buf.empty()) fail("token file " + path + " is empty");
    return buf;
}

void drop_privileges(const std::string &user) {
    if (::geteuid() != 0) fail("--user requires starting as root");
    errno = 0;
    struct passwd *pw = ::getpwnam(user.c_str());
    if (!pw) fail("no such user: " + user);
    if (::setgroups(1, &pw->pw_gid) != 0) throw_errno("setgroups");
    if (::setgid(pw->pw_gid) != 0) throw_errno("setgid");
    if (::setuid(pw->pw_uid) != 0) throw_errno("setuid");
    if (::setuid(0) == 0) fail("privilege drop did not stick");
    logf(0, "npxf-server: dropped to %s (uid %u)", user.c_str(), unsigned(pw->pw_uid));
}

bool need_arg(int argc, char **argv, int &i, const char *what, std::string &out) {
    if (i + 1 >= argc) {
        std::fprintf(stderr, "npxf-server: %s needs an argument\n", what);
        return false;
    }
    out = argv[++i];
    return true;
}

}  // namespace

int run(std::shared_ptr<const Config> cfgp) {
    const Config &cfg = *cfgp;
    Fd rootfd(::open(cfg.root.c_str(), platform::path_flags | O_DIRECTORY | O_CLOEXEC));
    if (!rootfd) throw_errno("open export root " + cfg.root);

    // Several operations reopen an O_PATH descriptor through /proc/self/fd,
    // which is the only race-free way to upgrade one.  Check now rather than
    // failing obscurely on the first setattr.
#ifdef __linux__
    if (::access("/proc/self/fd", X_OK) != 0)
        fail("/proc is not mounted; npxf-server needs it to operate on open handles");
#endif

    auto socks = net::tcp_listen(net::parse_addr(cfg.listen, "5640"), cfg.max_conns);

    if (!cfg.drop_user.empty()) drop_privileges(cfg.drop_user);

    logf(0, "npxf-server: exporting %s on %s (msize %u%s)", cfg.root.c_str(), cfg.listen.c_str(),
         cfg.msize, cfg.readonly ? ", read-only" : "");

    std::vector<pollfd> pfds;
    pfds.reserve(socks.size());
    for (auto &s : socks) pfds.push_back(pollfd{s.get(), POLLIN, 0});

    while (!g_stop) {
        int pr = ::poll(pfds.data(), pfds.size(), -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            throw_errno("poll");
        }
        for (auto &pf : pfds) {
            if (!(pf.revents & POLLIN)) continue;
            Fd cs(platform::accept_cloexec(pf.fd));
            if (!cs) {
                if (errno == EINTR || errno == ECONNABORTED || errno == EAGAIN) continue;
                throw_errno("accept");
            }
            if (g_live_conns.load() >= cfg.max_conns) {
                logf(0, "[%s] refused: at the %d connection limit",
                     net::peer_name(cs.get()).c_str(), cfg.max_conns);
                continue;  // cs closes here
            }

            if (cfg.once) {
                Conn c(cfgp, std::move(cs), rootfd.get());
                c.serve();
                return 0;
            }

            g_live_conns.fetch_add(1);
            int rfd = rootfd.get();
            std::thread([cfgp, sock = std::move(cs), rfd]() mutable {
                std::string who = net::peer_name(sock.get());
                try {
                    Conn c(std::move(cfgp), std::move(sock), rfd);
                    c.serve();
                } catch (const std::exception &e) {
                    logf(0, "[%s] %s", who.c_str(), e.what());
                }
                g_live_conns.fetch_sub(1);
            }).detach();
        }
    }
    // Give connections a moment to finish what they are doing.  They hold a
    // reference to the config, so nothing they touch goes away underneath
    // them, but finishing an in-flight write beats cutting it off.
    for (int i = 0; i < 40 && g_live_conns.load() > 0; i++) {
        struct timespec ts {
            0, 50 * 1000 * 1000
        };
        ::nanosleep(&ts, nullptr);
    }
    logf(0, "npxf-server: shutting down (%d connection(s) still open)", g_live_conns.load());
    return 0;
}

}  // namespace npxf::server

int main(int argc, char **argv) {
    using namespace npxf;
    using namespace npxf::server;

    Config cfg;
    std::string token_file, token_env, val;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto want = [&](const char *what) { return need_arg(argc, argv, i, what, val); };
        if (a == "-l" || a == "--listen") {
            if (!want("--listen")) return 2;
            cfg.listen = val;
        } else if (a == "-r" || a == "--root") {
            if (!want("--root")) return 2;
            cfg.root = val;
        } else if (a == "-t" || a == "--token-file") {
            if (!want("--token-file")) return 2;
            token_file = val;
        } else if (a == "--token-env") {
            if (!want("--token-env")) return 2;
            token_env = val;
        } else if (a == "-m" || a == "--msize") {
            if (!want("--msize")) return 2;
            cfg.msize = uint32_t(std::strtoul(val.c_str(), nullptr, 10));
        } else if (a == "-j" || a == "--workers") {
            if (!want("--workers")) return 2;
            cfg.workers = std::atoi(val.c_str());
        } else if (a == "-c" || a == "--max-conns") {
            if (!want("--max-conns")) return 2;
            cfg.max_conns = std::atoi(val.c_str());
        } else if (a == "-R" || a == "--read-only") {
            cfg.readonly = true;
        } else if (a == "-u" || a == "--user") {
            if (!want("--user")) return 2;
            cfg.drop_user = val;
        } else if (a == "--once") {
            cfg.once = true;
        } else if (a == "-v" || a == "--verbose") {
            g_verbose++;
        } else if (a == "-h" || a == "--help") {
            usage(stdout);
            return 0;
        } else {
            std::fprintf(stderr, "npxf-server: unknown option '%s'\n", a.c_str());
            usage(stderr);
            return 2;
        }
    }

    try {
        std::string err;
        if (!crypto::self_test(&err)) fail("cryptographic self-test failed: " + err);

        if (cfg.msize < ninep::kMinMsize) cfg.msize = ninep::kMinMsize;
        if (cfg.msize > kMaxRecordPayload) cfg.msize = uint32_t(kMaxRecordPayload);
        if (cfg.max_conns < 1) cfg.max_conns = 1;

        if (!token_env.empty()) {
            const char *v = ::getenv(token_env.c_str());
            if (!v || !*v) fail("environment variable " + token_env + " is unset or empty");
            cfg.token.assign(v, v + std::strlen(v));
        } else if (!token_file.empty()) {
            cfg.token = read_token_file(token_file);
        } else {
            std::fprintf(stderr, "npxf-server: a token is required (--token-file or --token-env)\n");
            return 2;
        }

        if (cfg.root.empty()) {
            char buf[4096];
            if (!::getcwd(buf, sizeof buf)) throw_errno("getcwd");
            cfg.root = buf;
        }

        // A dead peer must surface as EPIPE from write(), not as a signal.
        ::signal(SIGPIPE, SIG_IGN);
        struct sigaction sa {};
        sa.sa_handler = on_signal;  // deliberately no SA_RESTART, so poll() wakes
        sigemptyset(&sa.sa_mask);
        ::sigaction(SIGINT, &sa, nullptr);
        ::sigaction(SIGTERM, &sa, nullptr);

        return run(std::make_shared<const Config>(std::move(cfg)));
    } catch (const std::exception &e) {
        std::fprintf(stderr, "npxf-server: %s\n", e.what());
        return 1;
    }
}
