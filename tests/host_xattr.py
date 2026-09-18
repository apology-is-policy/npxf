"""Independent native xattr checks when Darwin Python omits os.*xattr."""
import ctypes
import os
import sys

if sys.platform == "darwin" and not hasattr(os, "getxattr"):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                             ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.getxattr.restype = ctypes.c_ssize_t
    libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.listxattr.restype = ctypes.c_ssize_t

    def checked(n):
        if n < 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e))
        return n

    def getxattr(path, name):
        args = os.fsencode(path), os.fsencode(name)
        n = checked(libc.getxattr(*args, None, 0, 0, 0))
        buf = ctypes.create_string_buffer(n)
        got = checked(libc.getxattr(*args, buf, n, 0, 0))
        return buf.raw[:got]

    def listxattr(path):
        path = os.fsencode(path)
        n = checked(libc.listxattr(path, None, 0, 0))
        buf = ctypes.create_string_buffer(n)
        got = checked(libc.listxattr(path, buf, n, 0))
        return [os.fsdecode(s) for s in buf.raw[:got].split(b'\0') if s]

    os.getxattr = getxattr
    os.listxattr = listxattr
