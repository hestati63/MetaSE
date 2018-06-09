from .executor import Executor


class Found(Exception):
    pass


def sat(op, fitness):
    if op in ['ge', 'le']:
        return fitness <= 0
    elif op in ['gt', 'lt', 'neq']:
        return fitness < 0
    elif op in ['eq']:
        return fitness == 0
    else:
        raise ValueError("Unknown op")


def get_fitness(executor, args):
    for uuid, fv, op, bd in executor.funcs:
        cargs = [executor.get_arg_constructor(args[name], size)
                 for size, name in fv]
        fitness = executor(uuid, cargs)
        if not sat(op, fitness):
            return bd, fitness
    return bd, fitness


def is_improved(cur, prev):
    if cur[0] == prev[0]:
        return cur[1] > prev[1]
    else:
        return cur[0] > prev[0]


def fetch(v, mT):
    return v * 2 if v != 0 and not mT else v + 1


def doAVM(codes):
    executor = Executor(codes)

    # initialize all argument to zero
    args_value = {name: 0 for name in executor.fvs.keys()}
    arglen = len(args_value)
    for _ in range(100):
        try:
            while True:
                idx = 0
                improvement = 0
                while idx < arglen:
                    cur = get_fitness(executor, args_value)
                    k = args_value.keys()[idx]
                    st = cur
                    while True:
                        args_value[k] = fetch(args_value[k], 0)
                        now = get_fitness(executor, args_value)
                        if is_improved(now, cur):
                            cur = now
                        else:
                            args_value[k] = args_value[k] / 2
                            break

                    while True:
                        args_value[k] = fetch(args_value[k], 1)
                        now = get_fitness(executor, args_value)
                        if is_improved(now, cur):
                            cur = now
                        else:
                            if is_improved(now, st):
                                improvement = improvement + 1
                            break
                    idx += 1
                if improvement == 0:
                    break
        except Found:
            break
        # TODO: Change arg_value with random initializer
    else:
        return None

    return {(name, size,): args_value[name]
            for name, size in executor.fvs}
