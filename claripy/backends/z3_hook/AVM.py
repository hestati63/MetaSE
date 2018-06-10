from .executor import Executor, BV


inf = float('inf')


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
        cargs = [args[name] for _, name in fv]
        if all(arg.valid() for arg in cargs):
            fitness = executor(uuid, cargs)
            if not sat(op, fitness):
                return bd, fitness
        else:
            return inf, inf
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
    print executor.fvs
    args_value = {name: BV(0, size) for name, size in executor.fvs.items()}
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
                    # Pattern Move
                    while True:
                        args_value[k] = \
                                args_value[k] if args_value[k] != 0 else 1
                        now = get_fitness(executor, args_value)
                        if is_improved(now, cur):
                            cur = now
                        else:
                            args_value[k] = args_value[k] / 2
                            break
                    # get direction
                    backup = args_value[k]
                    args_value[k] = backup + 1
                    inc = get_fitness(executor, args_value)
                    direction = is_improved(inc, cur)
                    if not direction:
                        args_value[k] = backup - 1
                        dec = get_fitness(executor, args_value)
                        direction = -is_improved(dec, cur)
                    args_value[k] = backup
                    # Exploratory Move
                    while direction:
                        args_value[k] = args_value[k] + direction
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
        args_value = {n: v.random_move() for n, v in args_value.items()}
    else:
        return None

    return {(name, size,): args_value[name]
            for name, size in executor.fvs}
