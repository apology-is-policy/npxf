// Host differences stay outside the 9P wire contract (Linux errno/flags).
#pragma once
#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
namespace npxf::platform {
#ifdef __APPLE__
inline constexpr int path_flags = O_EVTONLY | O_SYMLINK | O_NONBLOCK;
#else
inline constexpr int path_flags = O_PATH;
#endif
inline int accept_cloexec(int fd) {
#ifdef __linux__
    return ::accept4(fd, nullptr, nullptr, SOCK_CLOEXEC);
#else
    int child = ::accept(fd, nullptr, nullptr);
    if (child >= 0 && ::fcntl(child, F_SETFD, FD_CLOEXEC) < 0) {
        int e = errno; ::close(child); errno = e; return -1;
    }
    return child;
#endif
}
// These are protocol numbers, never native constants on Darwin.
inline constexpr int error_pairs[][2] = {
    {EPERM,1},{ENOENT,2},{ESRCH,3},{EINTR,4},{EIO,5},{ENXIO,6},
    {E2BIG,7},{ENOEXEC,8},{EBADF,9},{ECHILD,10},{EAGAIN,11},{ENOMEM,12},
    {EACCES,13},{EFAULT,14},{EBUSY,16},{EEXIST,17},{EXDEV,18},{ENODEV,19},
    {ENOTDIR,20},{EISDIR,21},{EINVAL,22},{ENFILE,23},{EMFILE,24},{ENOTTY,25},
    {ETXTBSY,26},{EFBIG,27},{ENOSPC,28},{ESPIPE,29},{EROFS,30},{EMLINK,31},
    {EPIPE,32},{EDOM,33},{ERANGE,34},{EDEADLK,35},{ENAMETOOLONG,36},
    {EPROTO,71},{ENOLCK,37},{ENOSYS,38},{ENOTEMPTY,39},{ELOOP,40},{EOVERFLOW,75},
    {EILSEQ,84},{ENOTSOCK,88},{EMSGSIZE,90},{EPROTOTYPE,91},
    {ENOPROTOOPT,92},{EPROTONOSUPPORT,93},{EOPNOTSUPP,95},{EAFNOSUPPORT,97},
    {EADDRINUSE,98},{EADDRNOTAVAIL,99},{ENETDOWN,100},{ENETUNREACH,101},
    {ECONNABORTED,103},{ECONNRESET,104},{ENOBUFS,105},{EISCONN,106},
    {ENOTCONN,107},{ETIMEDOUT,110},{ECONNREFUSED,111},{EHOSTUNREACH,113},
    {EALREADY,114},{EINPROGRESS,115},{ESTALE,116},{EDQUOT,122},{ECANCELED,125},
#ifdef __APPLE__
    {ENOATTR,61},{ENOTSUP,95},
#else
    {ENODATA,61},
#endif
};
inline int wire_errno(int e) {
#ifdef __APPLE__
    for (auto &pair : error_pairs) if (pair[0] == e) return pair[1];
    return 5;
#else
    return e;
#endif
}
inline int host_errno(int e) {
#ifdef __APPLE__
    for (auto &pair : error_pairs) if (pair[1] == e) return pair[0];
    return EIO;
#else
    return e;
#endif
}
}
