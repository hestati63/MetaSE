import os
import tempfile
import subprocess
import struct

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

max_mantissa_64 = 2 ** 52
max_mantissa_32 = 2 ** 23
max_exp_64 = 2 ** 11 - 1
max_exp_32 = 2 ** 8 - 1
ffi = FFI()

class FP():
    def __init__(self, val, size, m=None, exp=None, sign=True):
        if m is not None:
            self.sign = sign
            self.mantissa = m
            self.exponent = exp
        else:
            if size == 32:
                bits = ''.join(bin(ord(c))[2:].rjust(8, '0')
                               for c in struct.pack('!f', val))
                self.sign = int(bits[0], 2)
                self.exponent = int(bits[1:9], 2)
                self.mantissa = int(bits[9:], 2)
            elif size == 64:
                bits = ''.join(bin(ord(c))[2:].rjust(8, '0')
                               for c in struct.pack('!d', val))
                self.sign = int(bits[0], 2)
                self.exponent = int(bits[1:12], 2)
                self.mantissa = int(bits[12:], 2)
            else:
                raise ValueError
        if size == 32:
            self.val = (self.sign << 31L)
            self.val |= (self.exponent << 23L) | self.mantissa
            self.valid = self.exponent <= max_exp_32
        else:
            self.val = (self.sign << 63L)
            self.val |= (self.exponent << 52L) | self.mantissa
            self.valid = self.exponent <= max_exp_64

        self.size = size
        self.ffikind = ffi.cast('void *', self.val)

    def __str__(self):
        return "{:x}(FP{})".format(self.val, self.size)

    def __repr__(self):
        return "{:x}(FP{})".format(self.val, self.size)

    def __call__(self):
        return self.val

    def __add__(self, o):
        mantissa = self.mantissa + o
        exponent = self.exponent
        max_mantissa = max_mantissa_32 if self.size == 32 else max_mantissa_64
        max_exp = max_exp_32 if self.size == 32 else max_exp_64
        while mantissa >= max_mantissa:
            mantissa -= max_mantissa
            exponent += 1
            if exponent == max_exp:
                print hex(exponent)
                mantissa = 0
                break

        return FP(None, self.size, m=mantissa, exp=exponent, sign=self.sign)

    def __sub__(self, o):
        mantissa = self.mantissa - o
        exponent = self.exponent
        max_mantissa = max_mantissa_32 if self.size == 32 else max_mantissa_64
        max_exp = max_exp_32 if self.size == 32 else max_exp_64
        while mantissa < max_mantissa:
            mantissa += max_mantissa
            exponent -= 1
        return FP(None, self.size, m=mantissa, exp=exponent, sign=self.sign)

    def random_move(self):
        # TODO: How to random move?
        return self


class BV():
    def __init__(self, val, size):
        mask = (1L << size) - 1
        self.val = val
        self.size = size
        self.ffikind = ffi.cast('void *', val)
        # FIXME: optimize
        self.valid = 0 <= self.val <= mask

    def __str__(self):
        return "{:x}(BV{})".format(self.val, self.size)

    def __repr__(self):
        return "{:x}(BV{})".format(self.val, self.size)

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
#define inf INFINITY
#define nan NAN
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
        fvs = {name: (size, isfp) for size, name, isfp in fv_set}
        return funcs, defs, fvs, name

    def __compile(self, name):
        '''
        with open(name + '.c') as f: print f.read()
        raw_input()
        '''
        subprocess.check_call(['gcc', '-O3', '-c', '-Wno-pointer-to-int-cast',
                              '-w', '-fpic', name + '.c', '-o', name + '.o'])
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
        arg = ffi.new('void *[%d]' % len(args))
        for i, val in enumerate(args):
            arg[i] = val.ffikind
        return fun(arg)
