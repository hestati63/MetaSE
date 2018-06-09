from cffi import FFI

import os
import tempfile
import subprocess


class Found(Exception):
    pass


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


def sat(op, fitness):
    if op in ['ge', 'le']:
        return fitness <= 0
    elif op in ['gt', 'lt', 'neq']:
        return fitness < 0
    elif op in ['eq']:
        return fitness == 0
    else:
        raise Exception("Unknown op")


def get_fitness(executor, funcs, args):
    for uuid, fv, op, bd in funcs:
        cargs = [args[name] for _, name in fv]
        fitness = executor.run(uuid, cargs)
        if not sat(op, fitness):
            return bd, fitness
    return bd, fitness


def isImproved(cur, prev):
    if cur[0] > prev[0]:
        return True
    elif cur[0] == prev[0]:
        return cur[1] > prev[1]
    else:
        return False


def doAVM(codes):
    library = createLibrary(codes)
    executor = Executor(library)

    allfv = set()
    funcs = []
    for idx, (op, fv, code, uuid) in enumerate(codes):
        branch_distance = len(codes) - idx - 1
        funcs.append((uuid, fv, op, branch_distance))
        executor.cdef(code.split('\n')[0] + ';')
        allfv |= fv

    args = {name: get_arg_constructor(size, executor)
            for size, name in allfv}
    # initialize all argument to zero
    args_value = {name: 0 for name, _ in args.items()}
    arglen = len(args_value)
    for _ in range(100):
        try:
            improvement = 1
            while improvement != 0:
                idx = 0
                improvement = 0
                while idx < arglen:
                    packed = {k: args[k](v) for k, v in args_value.items()}
                    cur = get_fitness(executor, funcs, packed)
                    k = args_value.keys()[idx]
                    move_type = 1
                    improved = False
                    while True:
                        if move_type:
                            if args_value[k] == 0:
                                args_value[k] = 1
                            else:
                                args_value[k] = args_value[k] * 2
                        else:
                            args_value[k] = args_value[k] + 1

                        packed = {k: args[k](v) for k, v in args_value.items()}
                        now = get_fitness(executor, funcs, packed)
                        if isImproved(now, cur):
                            improved = True
                            cur = now
                        else:
                            if move_type:
                                move_type = 0
                                args_value[k] /= 2
                            else:
                                improvement = improvement + improved
                                break
                    idx += 1
        except Found:
            break
        # Change arg_value with random initializer
    else:
        args_value = None

    if args_value:
        args_value = {(name, size,): args_value[name] for size, name in allfv}
    os.unlink(library)
    return args_value
