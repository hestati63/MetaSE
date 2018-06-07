from cffi import FFI

import os
import tempfile
import subprocess


class Executor():
    def __init__(self, dll):
        self.ffi = FFI()
        self.dl_name = dll
        self.dll = self.ffi.dlopen(dll)

    def __str__(self):
        return '<Executor: %s>' % self.dl_name

    def __del__(self):
        self.ffi.dlclose(self.dll)

    def float(self, val):
        pass

    def double(self, val):
        pass

    def char(self, val):
        pass

    def short(self, val):
        pass

    def int(self, val):
        pass

    def longlong(self, val):
        pass

    def run(self, func, *args):
        fun = getattr(self.dll, func)
        pass

    def cdef(self, fundef):
        self.ffi.cdef(fundef)

    def new(self, t, val):
        return self.ffi.new(t, val)

    def sym(self, fun):
        return getattr(self.dll, fun)

    def close(self):
        self.ffi.dlclose(self.dll)


def createLibrary(codes):
    f = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".c")
    f.write('''#include <stdint.h>
#define abs(x) (x) > 0 ? (x) : -(x)
''')
    for _, _, code, _ in codes:
        f.write(code + '\n')
    f.close()
    name = f.name[:-2]
    subprocess.check_call(['gcc', '-O3', '-c', '-fpic',
                           name + '.c', '-o', name + '.o'])
    subprocess.check_call(['gcc', '-shared', '-o', name + '.so', name + '.o'])
    os.unlink(name + '.o')
    os.unlink(name + '.c')
    return name + '.so'


def doAVM(codes):
    library = createLibrary(codes)
    executor = Executor(library)
    
    os.unlink(library + '.so')
    raise Exception("todo: search")
