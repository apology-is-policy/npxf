"""Protocol-level coverage for the 9P2000.L operations the npxf CLI never issues.

Run as:  ops.py <tunnel-socket> <export-dir>

Prints one `ok NAME` or `FAIL NAME: detail` line per check, which test.sh folds
into its own tally.  The export directory is passed in so checks can confirm
the server actually touched the filesystem, not just that it answered politely.
"""

import errno
import host_xattr  # supplies native Darwin checks where Python omits them
import os
import stat
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p9  # noqa: E402

SOCK = sys.argv[1]
EXPORT = sys.argv[2]

failures = 0


def ok(name):
    print("ok %s" % name)


def bad(name, detail):
    global failures
    failures += 1
    print("FAIL %s: %s" % (name, detail))


def check(name, want, got):
    if want == got:
        ok(name)
    else:
        bad(name, "expected %r, got %r" % (want, got))


def truthy(name, cond, detail="condition was false"):
    if cond:
        ok(name)
    else:
        bad(name, detail)


def expect_errno(name, want, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except p9.Rlerror as e:
        if e.errno == want:
            ok(name)
        else:
            bad(name, "expected %s, got %s" % (os.strerror(want), os.strerror(e.errno)))
        return
    except Exception as e:  # noqa: BLE001
        bad(name, "expected %s, raised %r" % (os.strerror(want), e))
        return
    bad(name, "expected %s, call succeeded" % os.strerror(want))


def run(c, root):
    scratch = "ops"
    try:
        c.unlinkat(root, scratch, p9.AT_REMOVEDIR)
    except p9.Rlerror:
        pass
    c.mkdir(root, scratch, 0o755)
    d = c.walk_to(root, scratch)
    base = os.path.join(EXPORT, scratch)

    # A client can reuse a tag immediately after receiving its reply. This
    # exposed a publication/retirement race under real concurrent transfers.
    for _ in range(1000):
        c.call("getattr", struct.pack("<IQ", d, p9.GETATTR_BASIC), tag=50000)
    ok("a reply permits immediate reuse of its tag (1000 requests)")

    # A Darwin fid cannot be upgraded through /proc/self/fd. Its safe reopen
    # must reject a substituted inode BEFORE applying O_TRUNC. Linux may still
    # open the pinned old inode; neither host may truncate the replacement.
    stale_path = os.path.join(base, "stale.txt")
    with open(stale_path, "wb") as out:
        out.write(b"original")
    stale = c.walk_to(d, "stale.txt")
    os.rename(stale_path, stale_path + ".old")
    with open(stale_path, "wb") as out:
        out.write(b"replacement-must-survive")
    try:
        c.lopen(stale, p9.O_WRONLY | p9.O_TRUNC)
        if sys.platform == "darwin":
            bad("stale fid reopen", "accepted a replacement inode")
    except p9.Rlerror as e:
        if e.errno != errno.ESTALE:
            raise
    with open(stale_path, "rb") as inp:
        check("stale fid never truncates a replacement", b"replacement-must-survive", inp.read())
    c.clunk(stale)
    os.unlink(stale_path)
    os.unlink(stale_path + ".old")

    # ------------------------------------------------------------- setattr
    f = c.fid()
    c.walk(d, f, [])
    c.lcreate(f, "attr.txt", p9.O_WRONLY | p9.O_CREAT, 0o644)
    c.write(f, 0, b"0123456789")
    c.clunk(f)
    local = os.path.join(base, "attr.txt")

    f = c.walk_to(d, "attr.txt")
    c.setattr(f, p9.SET_MODE, mode=0o600)
    check("setattr sets the mode", 0o600, stat.S_IMODE(os.stat(local).st_mode))

    c.setattr(f, p9.SET_SIZE, size=4)
    check("setattr truncates", 4, os.stat(local).st_size)
    check("getattr sees the new size", 4, c.getattr(f)["size"])

    when = int(time.time()) - 86400
    c.setattr(f, p9.SET_MTIME | p9.SET_MTIME_SET, mtime_sec=when)
    check("setattr sets mtime", when, int(os.stat(local).st_mtime))
    check("getattr reports that mtime", when, c.getattr(f)["mtime_sec"])

    c.setattr(f, p9.SET_ATIME, atime_sec=0)  # ATIME without ATIME_SET means "now"
    truthy("setattr with no ATIME_SET means now",
           abs(os.stat(local).st_atime - time.time()) < 30)

    a = c.getattr(f)
    check("getattr reports the owner", (os.getuid(), os.getgid()), (a["uid"], a["gid"]))
    truthy("getattr reports nlink", a["nlink"] == 1, "nlink=%d" % a["nlink"])
    truthy("getattr sets the basic valid bits",
           a["valid"] & p9.GETATTR_BASIC == p9.GETATTR_BASIC, "valid=%#x" % a["valid"])
    truthy("getattr does not claim gen or data_version",
           not a["valid"] & 0x3000, "valid=%#x" % a["valid"])
    c.clunk(f)

    # ---------------------------------------------------------------- link
    src = c.walk_to(d, "attr.txt")
    c.link(d, src, "hardlink.txt")
    check("link creates a hard link", 2, os.stat(local).st_nlink)
    check("the link shares an inode",
          os.stat(local).st_ino, os.stat(os.path.join(base, "hardlink.txt")).st_ino)
    ln = c.walk_to(d, "hardlink.txt")
    check("both names report the same qid.path", c.getattr(src)["qid"][2],
          c.getattr(ln)["qid"][2])
    c.clunk(ln)
    expect_errno("link refuses a directory", errno.EPERM, c.link, d, d, "dirlink")
    c.clunk(src)

    # -------------------------------------------------------------- rename
    # Trename (fid + new parent), as distinct from Trenameat used by the CLI.
    f = c.walk_to(d, "hardlink.txt")
    c.rename(f, d, "renamed.txt")
    truthy("rename moves the file",
           os.path.exists(os.path.join(base, "renamed.txt")) and
           not os.path.exists(os.path.join(base, "hardlink.txt")))
    # The fid must still work, and know where it now lives.
    check("the fid survives its own rename", 4, c.getattr(f)["size"])
    c.rename(f, d, "renamed2.txt")
    truthy("a renamed fid can be renamed again",
           os.path.exists(os.path.join(base, "renamed2.txt")))
    c.clunk(f)

    # -------------------------------------------------------------- remove
    f = c.fid()
    c.walk(d, f, [])
    c.lcreate(f, "doomed.txt", p9.O_WRONLY | p9.O_CREAT, 0o644)
    c.clunk(f)
    f = c.walk_to(d, "doomed.txt")
    c.remove(f)
    truthy("remove unlinks the file", not os.path.exists(os.path.join(base, "doomed.txt")))
    # Tremove clunks the fid even on failure, so reusing it must fail.
    expect_errno("remove clunks its fid", errno.EBADF, c.getattr, f)

    # --------------------------------------------------------------- mknod
    try:
        c.mknod(d, "fifo", stat.S_IFIFO | 0o644)
        truthy("mknod creates a FIFO", stat.S_ISFIFO(os.lstat(os.path.join(base, "fifo")).st_mode))
    except p9.Rlerror as e:
        bad("mknod creates a FIFO", "Rlerror %s" % os.strerror(e.errno))

    # --------------------------------------------------------------- fsync
    f = c.fid()
    c.walk(d, f, [])
    c.lcreate(f, "sync.txt", p9.O_WRONLY | p9.O_CREAT, 0o644)
    c.write(f, 0, b"durable")
    c.fsync(f, 0)
    c.fsync(f, 1)
    ok("fsync and fdatasync both succeed")
    c.clunk(f)

    # -------------------------------------------------------------- statfs
    s = c.statfs(d)
    truthy("statfs reports a sane block size", s["bsize"] in (512, 1024, 2048, 4096, 8192, 16384,
                                                             32768, 65536),
           "bsize=%d" % s["bsize"])
    truthy("statfs reports a name limit", 0 < s["namelen"] <= 4096, "namelen=%d" % s["namelen"])
    truthy("statfs reports total blocks", s["blocks"] > 0)

    # --------------------------------------------------------------- flush
    c.flush(0xBEEF)  # nothing outstanding under that tag: answer immediately
    ok("flush of an unknown tag is answered")
    check("the session still works after a flush", 4, c.getattr(c.walk_to(d, "attr.txt"))["size"])

    # ------------------------------------------------------- lock / getlock
    a_fid = c.walk_to(d, "attr.txt")
    b_fid = c.walk_to(d, "attr.txt")
    c.lopen(a_fid, p9.O_RDWR)
    c.lopen(b_fid, p9.O_RDWR)

    check("an exclusive lock is granted", p9.LOCK_SUCCESS,
          c.lock(a_fid, p9.LOCK_WRLCK, 0, 10))
    # Open file description locks belong to the descriptor, so a second fid on
    # the same file conflicts even though it is the same server process.
    check("a conflicting lock reports BLOCKED", p9.LOCK_BLOCKED,
          c.lock(b_fid, p9.LOCK_WRLCK, 0, 10))
    g = c.getlock(b_fid, p9.LOCK_WRLCK, 0, 10)
    check("getlock reports the holder's type", p9.LOCK_WRLCK, g["type"])
    check("getlock reports the range", (0, 10), (g["start"], g["length"]))
    check("a lock past the range is granted", p9.LOCK_SUCCESS,
          c.lock(b_fid, p9.LOCK_WRLCK, 100, 10))
    check("unlocking succeeds", p9.LOCK_SUCCESS, c.lock(a_fid, p9.LOCK_UNLCK, 0, 10))
    check("the range is free once unlocked", p9.LOCK_UNLCK,
          c.getlock(b_fid, p9.LOCK_WRLCK, 0, 10)["type"])
    check("the lock can now be taken", p9.LOCK_SUCCESS, c.lock(b_fid, p9.LOCK_WRLCK, 0, 10))
    c.clunk(a_fid)
    c.clunk(b_fid)

    # --------------------------------------------------------------- xattr
    f = c.walk_to(d, "attr.txt")
    xw = c.fid()
    try:
        c.xattrcreate(f, "user.npxf", 5, 0)
        c.write(f, 0, b"hello")
        c.clunk(f)  # the value is applied here, in one setxattr
        supported = True
    except p9.Rlerror as e:
        supported = e.errno not in (errno.EOPNOTSUPP, errno.ENOTSUP, errno.EPERM)
        if supported:
            bad("xattrcreate stores a value", "Rlerror %s" % os.strerror(e.errno))
        else:
            print("xattrs unsupported on this filesystem (%s); skipping"
                  % os.strerror(e.errno))
        try:
            c.clunk(f)
        except p9.Rlerror:
            pass

    if supported:
        check("xattrcreate stores a value", b"hello", os.getxattr(local, "user.npxf"))
        f = c.walk_to(d, "attr.txt")
        n = c.xattrwalk(f, xw, "user.npxf")
        check("xattrwalk reports the value length", 5, n)
        # An xattr fid is readable straight away, with no Tlopen.
        check("reading an xattr fid returns the value", b"hello", c.read(xw, 0, 100))
        c.clunk(xw)

        names = c.fid()
        total = c.xattrwalk(f, names, "")
        listing = c.read(names, 0, 4096) if total else b""
        truthy("an empty xattrwalk name lists the attributes",
               b"user.npxf\x00" in listing, "listing=%r" % listing)
        c.clunk(names)

        missing = c.fid()
        expect_errno("xattrwalk of a missing attribute fails", errno.ENODATA,
                     c.xattrwalk, f, missing, "user.nope")

        # A zero declared size means "remove the attribute".
        c.xattrcreate(f, "user.npxf", 0, 0)
        c.clunk(f)
        truthy("a zero-size xattrcreate removes the attribute",
               "user.npxf" not in os.listxattr(local))

    # -------------------------------------------- readdir cursor / paging
    many = c.fid()
    c.walk(d, many, [])
    c.mkdir(d, "many", 0o755)
    md = c.walk_to(d, "many")
    expected = set()
    for i in range(200):
        name = "entry-%03d%s" % (i, "-padding" * (i % 4))
        expected.add(name)
        nf = c.fid()
        c.walk(md, nf, [])
        c.lcreate(nf, name, p9.O_WRONLY | p9.O_CREAT, 0o644)
        c.clunk(nf)

    # Paging with a tiny count is the real exercise of the server's directory
    # cursor: it has to stop mid-batch and resume from exactly the right offset.
    for count in (128, 200, 512, 4096):
        sd = c.fid()
        c.walk(md, sd, [])
        c.lopen(sd, p9.O_RDONLY | p9.O_DIRECTORY)
        seen, calls, off = [], 0, 0
        while True:
            batch, off = c.readdir(sd, off, count)
            calls += 1
            if not batch:
                break
            seen += [e[3] for e in batch]
            if calls > 2000:
                break
        c.clunk(sd)
        names = [n for n in seen if n not in (".", "..")]
        if len(names) != len(set(names)):
            dupes = sorted({n for n in names if names.count(n) > 1})[:5]
            bad("readdir with count=%d returns each entry once" % count, "duplicates: %s" % dupes)
        elif set(names) != expected:
            bad("readdir with count=%d returns every entry" % count,
                "missing %d, extra %d" % (len(expected - set(names)), len(set(names) - expected)))
        else:
            ok("readdir pages correctly with count=%d (%d calls)" % (count, calls))

    # Rewinding to offset 0 must restart the scan.
    sd = c.fid()
    c.walk(md, sd, [])
    c.lopen(sd, p9.O_RDONLY | p9.O_DIRECTORY)
    first, _ = c.readdir(sd, 0, 256)
    again, _ = c.readdir(sd, 0, 256)
    check("readdir at offset 0 rewinds", [e[3] for e in first], [e[3] for e in again])
    c.clunk(sd)

    dirents = c.fid()
    c.walk(md, dirents, [])
    c.lopen(dirents, p9.O_RDONLY | p9.O_DIRECTORY)
    entries = c.readdir_all(dirents)
    truthy("readdir reports a regular-file type",
           all(e[2] == 8 for e in entries if e[3].startswith("entry-")),
           "types=%s" % sorted({e[2] for e in entries}))
    c.clunk(dirents)

    # ------------------------------------------------------ protocol rules
    expect_errno("auth is declined", errno.EOPNOTSUPP,
                 c.call, "auth", p9.struct.pack("<I", 90) + p9.s9("u") + p9.s9("") +
                 p9.struct.pack("<I", 0))
    expect_errno("attach with an afid is refused", errno.EOPNOTSUPP, c.call, "attach",
                 p9.struct.pack("<II", 91, 92) + p9.s9("u") + p9.s9("") + p9.struct.pack("<I", 0))
    expect_errno("an unknown fid is EBADF", errno.EBADF, c.getattr, 90210)

    # newfid == fid is the legal in-place walk, which repoints the fid.
    # newfid naming some *other* live fid is not allowed.
    inplace = c.walk_to(d, ".")
    c.walk(inplace, inplace, ["attr.txt"])
    check("walking a fid onto itself replaces it", 4, c.getattr(inplace)["size"])
    c.clunk(inplace)

    live = c.walk_to(d, "attr.txt")
    expect_errno("walking onto another live fid is refused", errno.EBADF,
                 c.walk, d, live, ["attr.txt"])
    c.clunk(live)

    expect_errno("walking more than 16 names is refused", errno.EINVAL,
                 c.walk, d, c.fid(), ["x"] * 17)

    of = c.walk_to(d, "attr.txt")
    c.lopen(of, p9.O_RDONLY)
    expect_errno("walking from an open fid is refused", errno.EBADF, c.walk, of, c.fid(), [])
    expect_errno("opening an already-open fid is refused", errno.EINVAL, c.lopen, of, p9.O_RDONLY)
    c.clunk(of)

    expect_errno("read of an unopened fid is EBADF", errno.EBADF, c.read, md, 0, 10)
    od = c.walk_to(d, "many")
    c.lopen(od, p9.O_RDONLY | p9.O_DIRECTORY)
    # Directories are read with Treaddir; plain Tread on one must be refused.
    expect_errno("read of an open directory is EISDIR", errno.EISDIR, c.read, od, 0, 10)
    c.clunk(od)

    dw = c.walk_to(d, "many")
    expect_errno("opening a directory for writing is EISDIR", errno.EISDIR,
                 c.lopen, dw, p9.O_WRONLY)
    c.clunk(dw)

    c.symlink(d, "loop", "attr.txt")
    sl = c.walk_to(d, "loop")
    expect_errno("opening a symlink is ELOOP", errno.ELOOP, c.lopen, sl, p9.O_RDONLY)
    check("readlink returns the target", "attr.txt", c.readlink(sl))
    c.clunk(sl)

    nf = c.fid()
    expect_errno("a walk name containing a slash is refused", errno.EINVAL,
                 c.walk, d, nf, ["a/b"])
    nf = c.fid()
    expect_errno("an empty walk name is refused", errno.EINVAL, c.walk, d, nf, [""])

    # A partial walk yields a short Rwalk and creates no fid.
    pf = c.fid()
    got = c.walk(d, pf, ["many", "nope", "deeper"])
    check("a partial walk returns only the qids it reached", 1, len(got))
    expect_errno("a partial walk creates no fid", errno.EBADF, c.getattr, pf)

    expect_errno("creating over an existing name with O_EXCL fails", errno.EEXIST,
                 c.lcreate, c.walk_to(d, "."), "attr.txt",
                 p9.O_WRONLY | p9.O_CREAT | p9.O_EXCL, 0o644)
    expect_errno("removing a non-empty directory without AT_REMOVEDIR fails", (errno.EPERM if sys.platform == "darwin" else errno.EISDIR),
                 c.unlinkat, d, "many", 0)

    c.clunk(md)
    c.clunk(many)
    c.clunk(d)


def main():
    c = p9.Client(SOCK)
    root = 0
    c.attach(root)
    try:
        run(c, root)
    except Exception as e:  # noqa: BLE001
        import traceback
        bad("ops suite completed", "%r" % e)
        traceback.print_exc(file=sys.stderr)
    c.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
