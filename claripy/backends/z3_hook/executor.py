import os
import tempfile
import subprocess

from cffi import FFI


def leq(x):
    return x <= 0


def lt(x):
    return x < 0


def eq(x):
    return x == 0


def get_checker_by_sat(op):
    if op in ['ge', 'le']:
        return leq
    elif op in ['gt', 'lt', 'neq']:
        return lt
    elif op in ['eq']:
        return eq
    else:
        raise ValueError("Unknown op")


ffi = FFI()


class BV():
    def __init__(self, val, size):
        self.val = val
        self.size = size
        self.ffikind = ffi.cast('void *', val)
        # FIXME: optimize
        self.valid = 0 <= self.val <= (1L << self.size) - 1

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

    def __ne__(self, o):
        return self.val != o

    def __eq__(self, o):
        return self.val == o

    def random_move(self):
        # TODO: How to random move?
        return self


class Executor():
    def __init__(self, codes):
        self.funcs, defs, self.fvs, name = self.__preprocess(codes)
        self.dl_name = self.__compile(name)
        self.dll = ffi.dlopen(self.dl_name)

    def __preprocess(self, codes):
        defs = []
        funcs = []
        builded = []
        fv_set = set()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".c") as f:
            name = f.name[:-2]
            f.write(r'''#include <math.h>
#include <stdint.h>
#define abs(x) ((x) > 0 ? (x) : -(x))
#define extract(value, start, length) \
(((value) >> (start)) & (~0ULL >> (sizeof(value) * 8) - (length)))
''')

            for idx, code in enumerate(codes):
                bd = len(codes) - idx - 1
                if isinstance(code, list):
                    ors = []
                    for c in code:
                        op, fv, code, uuid, tp = c
                        ors.append((uuid, fv, get_checker_by_sat(op)))
                        if uuid not in builded:
                            fdef = r'{} fitness_{}(void **);'.format(tp, uuid)
                            ffi.cdef(fdef, override=True)
                            builded.append(uuid)
                            f.write(code + '\n')
                            fv_set |= fv
                    funcs.append((bd, ors, ))
                else:
                    op, fv, code, uuid, tp = code
                    if uuid not in builded:
                        fdef = r'{} fitness_{}(void **);'.format(tp, uuid)
                        ffi.cdef(fdef, override=True)
                        builded.append(uuid)
                        f.write(code + '\n')
                        fv_set |= fv
                    funcs.append((bd, (uuid, fv, get_checker_by_sat(op)), ))
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
            arg[i] = val.ffikind
        return fun(arg)
