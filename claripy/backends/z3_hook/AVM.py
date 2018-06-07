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

    def run(self, _id, *args):
        fun = getattr(self.dll, 'fitness_{}'.format(_id))
        pass

    def cdef(self, fundef):
        self.ffi.cdef(fundef)

    def new(self, t, val=None):
        return self.ffi.new(t, val)


def createLibrary(codes):
    f = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".c")
    f.write(r'''#include <stdint.h>
#define abs(x) ((x) > 0 ? (x) : -(x))
#define extract(value, start, length) \
    (((value) >> (start)) & (~0ULL >> (sizeof(value) * 8) - (length)))
''')
    for _, _, code, _ in codes:
        f.write(code + '\n')
    f.close()
    name = f.name[:-2]
    subprocess.check_call(['gcc', '-O3', '-c', '-Wno-pointer-to-int-cast',
                          '-fpic', name + '.c', '-o', name + '.o'])
    subprocess.check_call(['gcc', '-shared', '-o', name + '.so', name + '.o'])
    os.unlink(name + '.o')
    os.unlink(name + '.c')
    return name + '.so'


def get_arg_constructor(size, executor):
    if size == 8:
        return executor.char
    elif size == 16:
        return executor.short
    elif size == 32:
        return executor.int
    elif size == 64:
        return executor.longlong


def doAVM(codes):
    library = createLibrary(codes)
    executor = Executor(library)

    allfv = set()
    funcs = []
    for idx, (op, fv, code, uuid) in enumerate(codes):
        branch_distance = len(codes) - idx - 1
        funcs.append((uuid, op, branch_distance))
        executor.cdef(code.split('\n')[0] + ';')
        allfv |= fv

    args = {name: get_arg_constructor(size, executor)
            for size, name in allfv}
    # initialize all argument to zero
    args_value = {name: func(0) for name, func in args.items()}

    # TODO: Write AVM codes
    # XXX: now play with args_value and funcs and do AVM
    # XXX: funcs consist of three values: uuid, op, branch_distance
    # XXX: op is comparison operator
    # XXX: you can get fitness of function by calling
    # XXX: executor.run(uuid, args)
    # XXX: this function should return dictionary: name: value

    os.unlink(library)
    raise Exception("todo: search")
