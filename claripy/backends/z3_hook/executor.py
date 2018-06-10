import os
import tempfile
import subprocess

from cffi import FFI


ffi = FFI()


class BV():
    def __init__(self, val, size):
        self.val = val
        self.size = size

    def valid(self):
        return 0 <= self.val <= (1L << self.size) - 1

    def __str__(self):
        return "{}(BV{})".format(self.val, self.size)

    def __repr__(self):
        return "{}(BV{})".format(self.val, self.size)

    def __call__(self):
        return self.val

    def __add__(self, o):
        return BV(self.val + o, self.size)

    def __sub__(self, o):
        return BV(self.val - o, self.size)

    def __mul__(self, o):
        return BV(self.val * o, self.size)

    def __div__(self, o):
        return BV(self.val / o, self.size)

    def random_move(self):
        # TODO: How to random move?
        return self


class Executor():
    def __init__(self, codes):
        self.funcs, defs, self.fvs, name = self.__preprocess(codes)
        self.dl_name = self.__compile(name)
        self.dll = ffi.dlopen(self.dl_name)
        for i in defs:
            ffi.cdef(i, override=True)

    def __preprocess(self, codes):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".c") as f:
            name = f.name[:-2]
            f.write(r'''#include <stdint.h>
        #define abs(x) ((x) > 0 ? (x) : -(x))
        #define extract(value, start, length) \
            (((value) >> (start)) & (~0ULL >> (sizeof(value) * 8) - (length)))
            ''')

            def helper(chunk, bd, defs, funcs, fv_set):
                if isinstance(chunk, list):
                    or_funcs = []
                    for c in chunk:
                        helper(c, bd, defs, or_funcs, fv_set)
                    funcs.append(or_funcs)
                else:
                    op, fv, code, uuid = chunk
                    f.write(code + '\n')
                    defs.append(code.split('\n')[0] + ';')
                    funcs.append((uuid, fv, op, bd))
                    fv_set |= fv

            defs = []
            funcs = []
            fv_set = set()
            for idx, code in enumerate(codes):
                helper(code, len(codes) - idx - 1, defs, funcs, fv_set)
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
            arg[i] = ffi.cast('void *', val())
        return fun(arg)
