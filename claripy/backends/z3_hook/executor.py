import os
import tempfile
import subprocess

from cffi import FFI


ffi = FFI()


class Executor():
    def __init__(self, codes):
        self.funcs, defs, self.fvs, name = self.__preprocess(codes)
        self.dl_name = self.__compile(name)
        self.dll = ffi.dlopen(self.dl_name)
        for i in defs:
            ffi.cdef(i)

    def __preprocess(self, codes):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".c") as f:
            name = f.name[:-2]
            f.write(r'''#include <stdint.h>
        #define abs(x) ((x) > 0 ? (x) : -(x))
        #define extract(value, start, length) \
            (((value) >> (start)) & (~0ULL >> (sizeof(value) * 8) - (length)))
            ''')
            defs = []
            funcs = []
            fv_set = set()
            for idx, (op, fv, code, uuid) in enumerate(codes):
                f.write(code + '\n')
                defs.append(code.split('\n')[0] + ';')
                funcs.append((uuid, fv, op, len(codes) - idx - 1))
                fv_set |= fv
            fvs = {name: size for size, name in fv_set}
        return funcs, defs, fvs, name

    def __compile(self, name):
        subprocess.check_call(['gcc', '-O3', '-c', '-Wno-pointer-to-int-cast',
                              '-fpic', name + '.c', '-o', name + '.o'])
        subprocess.check_call(['gcc', '-shared', '-o',
                               name + '.so', name + '.o'])
        os.unlink(name + '.o')
        os.unlink(name + '.c')
        return name + '.so'

    def __str__(self):
        return '<Executor: %s>' % self.dl_name

    def __del__(self):
        os.unlink(self.dl_name)

    def __call__(self, _id, args):
        fun = getattr(self.dll, 'fitness_{}'.format(_id))
        arg = ffi.new('void **')
        for i, val in enumerate(args):
            arg[i] = ffi.cast('void *', val)
        return fun(arg)

    def get_arg_constructor(self, val, size):
        if size == 8:
            return ffi.cast('char', val)
        elif size == 16:
            return ffi.cast('short', val)
        elif size == 32:
            return ffi.cast('int', val)
        elif size == 64:
            return ffi.cast('long', val)
        else:
            raise ValueError('Unknown size')
