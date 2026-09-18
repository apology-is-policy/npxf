"""A minimal 9P2000.L client, used to exercise npxf-server directly.

This deliberately does not go through the npxf client: it drives the wire
protocol so the test suite can reach operations the CLI never issues, and so
the server is validated against something other than its own counterpart.
Speaks plaintext 9P to `npxf tunnel`, exactly as the kernel's v9fs client does.
"""

import errno as host_errno
import sys
import os
import socket
import struct

NOFID = 0xFFFFFFFF
NOTAG = 0xFFFF

T = {
    "statfs": 8, "lopen": 12, "lcreate": 14, "symlink": 16, "mknod": 18,
    "rename": 20, "readlink": 22, "getattr": 24, "setattr": 26,
    "xattrwalk": 30, "xattrcreate": 32, "readdir": 40, "fsync": 50,
    "lock": 52, "getlock": 54, "link": 70, "mkdir": 72, "renameat": 74,
    "unlinkat": 76, "version": 100, "auth": 102, "attach": 104, "flush": 108,
    "walk": 110, "read": 116, "write": 118, "clunk": 120, "remove": 122,
}
R = {v: k for k, v in T.items()}
RLERROR = 7

# Tgetattr request masks.
GETATTR_BASIC = 0x000007FF
GETATTR_ALL = 0x00003FFF

# Tsetattr valid bits.
SET_MODE, SET_UID, SET_GID, SET_SIZE = 1, 2, 4, 8
SET_ATIME, SET_MTIME, SET_CTIME = 0x10, 0x20, 0x40
SET_ATIME_SET, SET_MTIME_SET = 0x80, 0x100

# 9P2000.L open flags (they match Linux on x86, but name them anyway).
O_RDONLY, O_WRONLY, O_RDWR = 0, 1, 2
O_CREAT, O_EXCL, O_TRUNC = 0o100, 0o200, 0o1000
O_APPEND, O_DIRECTORY = 0o2000, 0o200000

LOCK_RDLCK, LOCK_WRLCK, LOCK_UNLCK = 0, 1, 2
LOCK_SUCCESS, LOCK_BLOCKED, LOCK_ERROR, LOCK_GRACE = 0, 1, 2, 3

AT_REMOVEDIR = 0x200


class Rlerror(Exception):
    def __init__(self, errno):
        if sys.platform == "darwin":
            errno = {11: host_errno.EAGAIN, 35: host_errno.EDEADLK,
                     36: host_errno.ENAMETOOLONG, 37: host_errno.ENOLCK,
                     38: host_errno.ENOSYS, 39: host_errno.ENOTEMPTY,
                     40: host_errno.ELOOP, 61: host_errno.ENODATA,
                     75: host_errno.EOVERFLOW, 95: host_errno.EOPNOTSUPP,
                     116: host_errno.ESTALE}.get(errno, errno)
        super().__init__("Rlerror %d (%s)" % (errno, os.strerror(errno)))
        self.errno = errno


class Unexpected(Exception):
    pass


def s9(text):
    b = text.encode() if isinstance(text, str) else text
    return struct.pack("<H", len(b)) + b


class Buf:
    """Reads 9P body fields, checking that nothing runs off the end."""

    def __init__(self, data):
        self.d = data
        self.i = 0

    def take(self, n):
        if self.i + n > len(self.d):
            raise Unexpected("reply truncated (wanted %d, have %d)" % (n, len(self.d) - self.i))
        v = self.d[self.i:self.i + n]
        self.i += n
        return v

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def qid(self):
        t = self.u8()
        return (t, self.u32(), self.u64())

    def string(self):
        return self.take(self.u16()).decode()

    def rest(self):
        return self.take(len(self.d) - self.i)


class Client:
    def __init__(self, path, msize=65536, timeout=15):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(timeout)
        self.s.connect(path)
        self.tag = 1
        self.next_fid = 1
        self.msize = msize
        self.version(msize)

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    # ---------------------------------------------------------- transport

    def _read(self, n):
        b = b""
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c:
                raise Unexpected("server closed the connection")
            b += c
        return b

    def send(self, type_, body, tag=None):
        if tag is None:
            tag = self.tag
            self.tag = (self.tag + 1) % 0xFFFE or 1
        self.s.sendall(struct.pack("<IBH", 7 + len(body), type_, tag) + body)
        return tag

    def recv(self):
        size, t, tag = struct.unpack("<IBH", self._read(7))
        if size < 7:
            raise Unexpected("runt reply, size=%d" % size)
        return t, tag, self._read(size - 7)

    def call(self, name, body, tag=None):
        want = T[name] + 1
        self.send(T[name], body, tag)
        t, _, data = self.recv()
        if t == RLERROR:
            raise Rlerror(struct.unpack("<I", data[:4])[0])
        if t != want:
            raise Unexpected("expected R%s, got %s" % (name, R.get(t - 1, t)))
        return Buf(data)

    def fid(self):
        f = self.next_fid
        self.next_fid += 1
        return f

    # --------------------------------------------------------- operations

    def version(self, msize):
        b = self.call("version", struct.pack("<I", msize) + s9("9P2000.L"), tag=NOTAG)
        self.msize = b.u32()
        v = b.string()
        if v != "9P2000.L":
            raise Unexpected("server offered version %r" % v)
        return self.msize

    def attach(self, fid=0, uname="tester"):
        b = self.call("attach", struct.pack("<II", fid, NOFID) + s9(uname) + s9("") +
                      struct.pack("<I", os.getuid()))
        return b.qid()

    def walk(self, fid, newfid, names):
        body = struct.pack("<IIH", fid, newfid, len(names))
        for n in names:
            body += s9(n)
        b = self.call("walk", body)
        return [b.qid() for _ in range(b.u16())]

    def walk_to(self, root, path):
        f = self.fid()
        names = [c for c in path.split("/") if c and c != "."]
        got = self.walk(root, f, names)
        if len(got) != len(names):
            raise Rlerror(2)
        return f

    def lopen(self, fid, flags):
        b = self.call("lopen", struct.pack("<II", fid, flags))
        return b.qid(), b.u32()

    def lcreate(self, fid, name, flags, mode, gid=None):
        gid = os.getgid() if gid is None else gid
        b = self.call("lcreate", struct.pack("<I", fid) + s9(name) +
                      struct.pack("<III", flags, mode, gid))
        return b.qid(), b.u32()

    def mkdir(self, dfid, name, mode=0o755, gid=None):
        gid = os.getgid() if gid is None else gid
        return self.call("mkdir", struct.pack("<I", dfid) + s9(name) +
                         struct.pack("<II", mode, gid)).qid()

    def symlink(self, dfid, name, target, gid=None):
        gid = os.getgid() if gid is None else gid
        return self.call("symlink", struct.pack("<I", dfid) + s9(name) + s9(target) +
                         struct.pack("<I", gid)).qid()

    def mknod(self, dfid, name, mode, major=0, minor=0, gid=None):
        gid = os.getgid() if gid is None else gid
        return self.call("mknod", struct.pack("<I", dfid) + s9(name) +
                         struct.pack("<IIII", mode, major, minor, gid)).qid()

    def link(self, dfid, fid, name):
        self.call("link", struct.pack("<II", dfid, fid) + s9(name))

    def rename(self, fid, dfid, name):
        self.call("rename", struct.pack("<II", fid, dfid) + s9(name))

    def renameat(self, odfid, oldname, ndfid, newname):
        self.call("renameat", struct.pack("<I", odfid) + s9(oldname) +
                  struct.pack("<I", ndfid) + s9(newname))

    def unlinkat(self, dfid, name, flags=0):
        self.call("unlinkat", struct.pack("<I", dfid) + s9(name) + struct.pack("<I", flags))

    def remove(self, fid):
        self.call("remove", struct.pack("<I", fid))

    def readlink(self, fid):
        return self.call("readlink", struct.pack("<I", fid)).string()

    def getattr(self, fid, mask=GETATTR_ALL):
        b = self.call("getattr", struct.pack("<IQ", fid, mask))
        a = {"valid": b.u64(), "qid": b.qid(), "mode": b.u32(), "uid": b.u32(), "gid": b.u32(),
             "nlink": b.u64(), "rdev": b.u64(), "size": b.u64(), "blksize": b.u64(),
             "blocks": b.u64()}
        for k in ("atime", "mtime", "ctime", "btime"):
            a[k + "_sec"] = b.u64()
            a[k + "_nsec"] = b.u64()
        a["gen"] = b.u64()
        a["data_version"] = b.u64()
        return a

    def setattr(self, fid, valid, mode=0, uid=0, gid=0, size=0,
                atime_sec=0, atime_nsec=0, mtime_sec=0, mtime_nsec=0):
        self.call("setattr", struct.pack("<IIIIIQQQQQ", fid, valid, mode, uid, gid, size,
                                         atime_sec, atime_nsec, mtime_sec, mtime_nsec))

    def statfs(self, fid):
        b = self.call("statfs", struct.pack("<I", fid))
        return {"type": b.u32(), "bsize": b.u32(), "blocks": b.u64(), "bfree": b.u64(),
                "bavail": b.u64(), "files": b.u64(), "ffree": b.u64(), "fsid": b.u64(),
                "namelen": b.u32()}

    def read(self, fid, offset, count):
        b = self.call("read", struct.pack("<IQI", fid, offset, count))
        return b.take(b.u32())

    def write(self, fid, offset, data):
        b = self.call("write", struct.pack("<IQI", fid, offset, len(data)) + data)
        return b.u32()

    def readdir(self, fid, offset, count):
        """Returns (entries, next_offset); entries are (qid, offset, type, name)."""
        b = self.call("readdir", struct.pack("<IQI", fid, offset, count))
        data = Buf(b.take(b.u32()))
        out = []
        while data.i < len(data.d):
            q = data.qid()
            off = data.u64()
            typ = data.u8()
            out.append((q, off, typ, data.string()))
        return out, (out[-1][1] if out else offset)

    def readdir_all(self, fid, count=None):
        count = count or (self.msize - 24)
        entries, off = [], 0
        while True:
            batch, off = self.readdir(fid, off, count)
            if not batch:
                return entries
            entries += batch

    def fsync(self, fid, datasync=0):
        self.call("fsync", struct.pack("<II", fid, datasync))

    def clunk(self, fid):
        self.call("clunk", struct.pack("<I", fid))

    def flush(self, oldtag):
        self.send(T["flush"], struct.pack("<H", oldtag))
        t, _, _ = self.recv()
        if t != T["flush"] + 1:
            raise Unexpected("expected Rflush, got %s" % R.get(t - 1, t))

    def lock(self, fid, type_, start, length, flags=0, proc_id=0, client_id="npxf-test"):
        b = self.call("lock", struct.pack("<IBIQQI", fid, type_, flags, start, length, proc_id) +
                      s9(client_id))
        return b.u8()

    def getlock(self, fid, type_, start, length, proc_id=0, client_id="npxf-test"):
        b = self.call("getlock", struct.pack("<IBQQI", fid, type_, start, length, proc_id) +
                      s9(client_id))
        return {"type": b.u8(), "start": b.u64(), "length": b.u64(), "proc_id": b.u32(),
                "client_id": b.string()}

    def xattrwalk(self, fid, newfid, name):
        return self.call("xattrwalk", struct.pack("<II", fid, newfid) + s9(name)).u64()

    def xattrcreate(self, fid, name, size, flags=0):
        self.call("xattrcreate", struct.pack("<I", fid) + s9(name) +
                  struct.pack("<QI", size, flags))
