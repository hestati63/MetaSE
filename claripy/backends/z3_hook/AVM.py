from cffi import FFI
import tempfile


class Executor():
    def __init__(self):
        self.ffi = FFI()

    def cdef(self, fundef):
        self.ffi.cdef(fundef)

    def new(self, t, val):
        return self.ffi.new(t, val)

    def open(self, filename):
        self.dll = self.ffi.dlopen(filename)

    def sym(self, fun):
        return getattr(self.dll, fun)

    def close(self):
        self.ffi.dlclose(self.dll)


def doAVM(codes):
    f = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".c")
    f.write('''#include <stdint.h>
#define abs(x) (x) > 0 ? (x) : -(x)
''')
    for _, _, code in codes:
        print code
        f.write(code + '\n')
    f.close()
    print f.name
    #f.write
    exit(0)
    raise Exception("todo: search")
