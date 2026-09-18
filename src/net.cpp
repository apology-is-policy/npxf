#include "net.hpp"

#include <cstring>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace npxf::net {

Addr parse_addr(std::string_view s, std::string_view default_port) {
    Addr a;
    a.port = std::string(default_port);
    if (s.empty()) return a;

    if (s.front() == '[') {  // [::1]:5640
        size_t close = s.find(']');
        if (close == std::string_view::npos) fail("malformed address: " + std::string(s));
        a.host = std::string(s.substr(1, close - 1));
        std::string_view rest = s.substr(close + 1);
        if (!rest.empty()) {
            if (rest.front() != ':') fail("malformed address: " + std::string(s));
            a.port = std::string(rest.substr(1));
        }
        return a;
    }

    size_t colon = s.rfind(':');
    // No colon at all, or several (a bare IPv6 literal): treat accordingly.
    if (colon == std::string_view::npos) {
        if (s.find_first_not_of("0123456789") == std::string_view::npos) {
            a.port = std::string(s);  // bare port number
        } else {
            a.host = std::string(s);
        }
        return a;
    }
    if (s.find(':') != colon) {  // more than one colon => bare IPv6 literal
        a.host = std::string(s);
        return a;
    }
    a.host = std::string(s.substr(0, colon));
    a.port = std::string(s.substr(colon + 1));
    return a;
}

namespace {

addrinfo *resolve(const Addr &a, bool passive) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = passive ? AI_PASSIVE : 0;
    addrinfo *res = nullptr;
    const char *host = a.host.empty() ? nullptr : a.host.c_str();
    int rc = ::getaddrinfo(host, a.port.c_str(), &hints, &res);
    if (rc != 0)
        fail("cannot resolve " + (a.host.empty() ? std::string("*") : a.host) + ":" + a.port + ": " +
             ::gai_strerror(rc));
    return res;
}

struct AddrInfoGuard {
    addrinfo *p;
    ~AddrInfoGuard() {
        if (p) ::freeaddrinfo(p);
    }
};

// A close-on-exec socket, optionally non-blocking.  Linux sets both flags
// atomically inside socket(2); the BSDs have neither, so there the fcntl round
// trip is the whole of what libc offers -- and it leaves a window in which a
// concurrent fork+exec would inherit the descriptor.  npxf never forks, so the
// window is unreachable here, and keeping the difference in one wrapper is what
// stops it from becoming an #ifdef at every call site.
int socket_ce(int domain, int type, int proto, bool nonblock = false) {
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    return ::socket(domain, type | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), proto);
#else
    int fd = ::socket(domain, type, proto);
    if (fd < 0) return fd;
    auto bail = [&] {
        int e = errno;
        ::close(fd);
        errno = e;
        return -1;
    };
    if (::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) return bail();
    if (nonblock) {
        int fl = ::fcntl(fd, F_GETFL, 0);
        if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return bail();
    }
    return fd;
#endif
}

}  // namespace

std::vector<Fd> tcp_listen(const Addr &a, int backlog) {
    AddrInfoGuard res{resolve(a, true)};
    std::vector<Fd> out;
    std::string last_err;

    for (addrinfo *ai = res.p; ai; ai = ai->ai_next) {
        Fd fd(socket_ce(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (!fd) {
            last_err = std::strerror(errno);
            continue;
        }
        int one = 1;
        ::setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        // Bind v6 sockets v6-only so a dual-stack host gets two clean sockets
        // rather than one that silently shadows the other.
        if (ai->ai_family == AF_INET6) ::setsockopt(fd.get(), IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);

        if (::bind(fd.get(), ai->ai_addr, ai->ai_addrlen) != 0) {
            last_err = std::strerror(errno);
            continue;
        }
        if (::listen(fd.get(), backlog) != 0) {
            last_err = std::strerror(errno);
            continue;
        }
        out.push_back(std::move(fd));
    }
    if (out.empty())
        fail("cannot listen on " + (a.host.empty() ? std::string("*") : a.host) + ":" + a.port + ": " +
             last_err);
    return out;
}

Fd tcp_connect(const Addr &a, int timeout_ms) {
    AddrInfoGuard res{resolve(a, false)};
    std::string last_err = "no addresses";

    for (addrinfo *ai = res.p; ai; ai = ai->ai_next) {
        Fd fd(socket_ce(ai->ai_family, ai->ai_socktype, ai->ai_protocol, true));
        if (!fd) {
            last_err = std::strerror(errno);
            continue;
        }
        int rc = ::connect(fd.get(), ai->ai_addr, ai->ai_addrlen);
        if (rc != 0) {
            if (errno != EINPROGRESS) {
                last_err = std::strerror(errno);
                continue;
            }
            pollfd pf{fd.get(), POLLOUT, 0};
            int pr;
            do {
                pr = ::poll(&pf, 1, timeout_ms);
            } while (pr < 0 && errno == EINTR);
            if (pr == 0) {
                last_err = "timed out";
                continue;
            }
            if (pr < 0) {
                last_err = std::strerror(errno);
                continue;
            }
            int err = 0;
            socklen_t elen = sizeof err;
            if (::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
                last_err = std::strerror(err ? err : errno);
                continue;
            }
        }
        // Back to blocking mode for the rest of the session.
        int fl = ::fcntl(fd.get(), F_GETFL, 0);
        if (fl < 0 || ::fcntl(fd.get(), F_SETFL, fl & ~O_NONBLOCK) < 0) throw_errno("fcntl");
        return fd;
    }
    fail("cannot connect to " + a.host + ":" + a.port + ": " + last_err);
}

namespace {

sockaddr_un make_un(const std::string &path) {
    sockaddr_un sa{};
    sa.sun_family = AF_UNIX;
    if (path.size() >= sizeof sa.sun_path) fail("unix socket path too long: " + path);
    std::memcpy(sa.sun_path, path.c_str(), path.size() + 1);
    return sa;
}

}  // namespace

Fd unix_listen(const std::string &path, int backlog) {
    sockaddr_un sa = make_un(path);
    Fd fd(socket_ce(AF_UNIX, SOCK_STREAM, 0));
    if (!fd) throw_errno("socket(AF_UNIX)");

    // Remove a stale socket left by a previous run, but never anything else.
    struct stat st;
    if (::lstat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) ::unlink(path.c_str());

    // Restrict the socket to its owner at creation time; chmod after bind
    // would leave a window in which anyone could connect.
    mode_t old = ::umask(0177);
    int rc = ::bind(fd.get(), reinterpret_cast<sockaddr *>(&sa), sizeof sa);
    int e = errno;
    ::umask(old);
    if (rc != 0) {
        errno = e;
        throw_errno("bind " + path);
    }
    if (::listen(fd.get(), backlog) != 0) throw_errno("listen " + path);
    return fd;
}

Fd unix_connect(const std::string &path) {
    sockaddr_un sa = make_un(path);
    Fd fd(socket_ce(AF_UNIX, SOCK_STREAM, 0));
    if (!fd) throw_errno("socket(AF_UNIX)");
    if (::connect(fd.get(), reinterpret_cast<sockaddr *>(&sa), sizeof sa) != 0)
        throw_errno("connect " + path);
    return fd;
}

void set_nodelay(int fd) {
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

void set_timeout(int fd, int ms) {
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

void set_keepalive(int fd) {
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
}

bool read_full(int fd, uint8_t *p, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = ::read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            throw_errno("read");
        }
        if (r == 0) {
            if (got == 0) return false;  // clean EOF on a message boundary
            fail("connection closed mid-message");
        }
        got += size_t(r);
    }
    return true;
}

void write_full(int fd, const uint8_t *p, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = ::write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            throw_errno("write");
        }
        sent += size_t(w);
    }
}

std::string peer_name(int fd) {
    sockaddr_storage ss{};
    socklen_t len = sizeof ss;
    if (::getpeername(fd, reinterpret_cast<sockaddr *>(&ss), &len) != 0) return "?";
    if (ss.ss_family == AF_UNIX) return "unix";
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (::getnameinfo(reinterpret_cast<sockaddr *>(&ss), len, host, sizeof host, serv, sizeof serv,
                      NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        return "?";
    if (ss.ss_family == AF_INET6) return std::string("[") + host + "]:" + serv;
    return std::string(host) + ":" + serv;
}

}  // namespace npxf::net
