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
        cargs = [executor.get_arg_constructor(size)(args[name])
                 for size, name in fv]
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
    executor = Executor(codes)

    # initialize all argument to zero
    args_value = {name: 0 for name in executor.fvs.keys()}
    arglen = len(args_value)
    for _ in range(100):
        try:
            improvement = 1
            while improvement != 0:
                idx = 0
                improvement = 0
                while idx < arglen:
                    cur = get_fitness(executor, args_value)
                    k = args_value.keys()[idx]
                    move_type = 1
                    improved = False
                    while True:
                        v = args_value[k]
                        if move_type:
                            args_value[k] = v * 2 if v != 0 else 1
                        else:
                            args_value[k] = v + 1

                        now = get_fitness(executor, args_value)
                        if isImproved(now, cur):
                            improved = True
                            cur = now
                        else:
                            if move_type:
                                move_type = 0
                                args_value[k] = v / 2
                            else:
                                improvement = improvement + improved
                                break
                    idx += 1
        except Found:
            break
        # Change arg_value with random initializer
    else:
        return None

    return {(name, size,): args_value[name]
            for name, size in executor.fvs}
