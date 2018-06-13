from .executor import Executor, BV, FP


inf = float('inf')


def get_fitness(executor, args):
    if not all(arg.valid for arg in args.values()):
        return inf, inf
    for bd, funcs in executor.funcs:
        if isinstance(funcs, list):
            res = []
            for i in funcs:
                uuid, fv, sat = i
                cargs = [args[name] for _, name, _ in fv]
                fitness = executor(uuid, cargs)
                if not sat(fitness):
                    res.append(fitness)
                else:
                    res = None
                    break
            if res:
                return bd, min(res)
        else:
            uuid, fv, sat = funcs
            cargs = [args[name] for _, name, _ in fv]
            fitness = executor(uuid, cargs)
            if not sat(fitness):
                return bd, fitness


def pack_result(args_value, executor):
    return {(name, size,): args_value[name]
            for name, size in executor.fvs.items()}


def doAVM(codes):
    executor = Executor(codes)

    # initialize all argument to zero
    args_value = {name: FP(0, size) if isfp else BV(0, size)
                  for name, (size, isfp) in executor.fvs.items()}
    arglen = len(args_value)
    for _ in range(100):
        while True:
            idx = 0
            improvement = 0
            while idx < arglen:
                cur = get_fitness(executor, args_value)
                st = cur
                if cur is None:
                    return pack_result(args_value, executor)
                k = args_value.keys()[idx]

                # get direction
                backup = args_value[k]
                args_value[k] = backup + 1
                inc = get_fitness(executor, args_value)
                if inc is None:
                    return pack_result(args_value, executor)
                direction = inc < cur
                if not direction:
                    args_value[k] = backup - 1
                    dec = get_fitness(executor, args_value)
                    if dec is None:
                        return pack_result(args_value, executor)
                    direction = - (dec < cur)

                # Pattern Move
                if direction:
                    delta = 2 * direction
                    while True:
                        pv = args_value[k]
                        args_value[k] = pv + delta
                        delta = 2 * delta
                        now = get_fitness(executor, args_value)
                        if now is None:
                            return pack_result(args_value, executor)
                        if now <= cur:
                            cur = now
                        else:
                            improvement += st > cur
                            args_value[k] = pv
                            break
                idx += 1
            if improvement == 0:
                break
        args_value = {n: v.random_move() for n, v in args_value.items()}
