from cffi import FFI

import os
import tempfile
import subprocess

ffi = FFI()


class Executor():
    def __init__(self, dll):
        self.dl_name = dll
        self.dll = ffi.dlopen(dll)

    def __str__(self):
        return '<Executor: %s>' % self.dl_name

    def cdef(self, fundef):
        ffi.cdef(fundef)

    def float(self, val):
        return ffi.cast('float', val)

    def double(self, val):
        return ffi.cast('double', val)

    def char(self, val):
        return ffi.cast('char', val)

    def short(self, val):
        return ffi.cast('short', val)

    def int(self, val):
        return ffi.cast('int', val)

    def long(self, val):
        return ffi.cast('long', val)

    def run(self, _id, args):
        fun = getattr(self.dll, 'fitness_{}'.format(_id))
        arg = ffi.new('void **')
        for i, val in enumerate(args):
            arg[i] = ffi.cast('void *', val)
        return fun(arg)


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
        return executor.long


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
    args_value = {name: func(0x37) for name, func in args.items()}
    # TODO: Write AVM codes
    # XXX: now play with args_value and funcs and do AVM
    # XXX: funcs consist of three values: uuid, op, branch_distance
    # XXX: op is comparison operator
    # XXX: you can get fitness of function by calling
    # XXX: executor.run(uuid, args)
    # XXX: this function should return dictionary: name: value
    # XXX: Example
    # XXX: executor.run(funcs[0][0], args_value.values())


    os.unlink(library)
    raise Exception("todo: search")
