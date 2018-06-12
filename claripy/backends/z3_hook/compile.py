import random
import string
from ...ast.bv import BV
from ...ast.bool import Bool
from ...ast.fp import FP


fvPool = string.uppercase + string.lowercase
relops = [
    '__eq__', 'fpEQ',
    '__ne__', 'fpNEQ',
    '__ge__', 'fpGE',
    '__le__', 'fpLE',
    '__gt__', 'fpGT',
    '__lt__', 'fpLT',
]


def sort2type(sort):
    return sort.name.lower()


def size2type(size):
    if size == 8:
        return 'uint8_t'
    elif size == 16:
        return 'uint16_t'
    elif size == 32:
        return 'uint32_t'
    elif size == 64:
        return 'uint64_t'
    else:
        raise ValueError("Unknown size: %d" % size)


def getType(ast):
    if isinstance(ast, BV):
        return size2type(ast.size())
    elif isinstance(ast, FP):
        return sort2type(ast.sort)
    else:
        raise TypeError("Unknown type: %s" % ast)


def genFpPrecond(ids, asts, exprs):
    stmt_args = zip([sort2type(ast.sort) for ast in asts], ids, exprs)
    return'\n'.join('{st} {id} = {expr};'.
                    format(st=st, id=id, expr=expr)
                    for st, id, expr in stmt_args) + '\n'


def genBvPrecond(ids, asts, exprs):
    stmt_args = zip([size2type(ast.size()) for ast in asts], ids, exprs)
    return'\n'.join('{st} {id} = {expr};'.
                    format(st=st, id=id, expr=expr)
                    for st, id, expr in stmt_args) + '\n'


def normalize_op(op, negate=False):
    if op == '__eq__' or op == 'fpEQ':
        return 'neq' if negate else 'eq'
    elif op == '__ne__' or op == 'fpNEQ':
        return 'eq' if negate else 'neq'
    elif op == '__ge__' or op == 'fpGE':
        return 'lt' if negate else 'ge'
    elif op == '__le__' or op == 'fpLE':
        return 'gt' if negate else 'le'
    elif op == '__gt__' or op == 'fpGT':
        return 'le' if negate else 'gt'
    elif op == '__lt__' or op == 'fpLT':
        return 'ge' if negate else 'lt'
    else:
        raise ValueError("Unknown Op: %s" % op)


def get_f(op):
    if op == 'eq':
        return 'abs(({b}) - ({a}))'
    elif op == 'neq':
        return '-abs(({b}) - ({a}))'
    elif op == 'ge':
        return '({b}) - ({a})'
    elif op == 'le':
        return '({a}) - ({b})'
    elif op == 'gt':
        return '({b}) - ({a})'
    elif op == 'lt':
        return '({a}) - ({b})'
    else:
        raise ValueError("Unknown Op: %s" % op)


class CompileService(object):
    boundId = set()
    defs = ''
    code_template = '''{type} fitness_{id}(void **args)
    {{
        {unpack}
        {defs}
        return {code};
    }}
    '''

    def __init__(self, ast):
        self.ast = ast

    def getFreeId(self):
        ID = ''.join(random.choice(fvPool) for _ in range(10))
        while ID in self.boundId:
            ID = ''.join(random.choice(fvPool) for _ in range(10))
        self.boundId.add(ID)
        return ID

    def compile(self):
        return self.handle_Top_Bool(self.ast)

    def handle_Top_Bool(self, ast, negate=False):
        if ast.op == 'Not':
            return self.handle_Top_Bool(ast.args[0], negate=not negate)
        elif ast.op == 'Or':
            res = []
            for _ast in ast.args:
                r = self.handle_Top_Bool(_ast)
                if isinstance(r, list):
                    res.extend(r)
                else:
                    res.append(r)
            return res

        elif ast.op in relops:
            op = normalize_op(ast.op, negate=negate)
            args = ast.args
            fv1, pr1, code1 = self._compile(args[0])
            fv2, pr2, code2 = self._compile(args[1])
            fv = fv1 | fv2
            precond = pr1 + pr2
            unpack = '\n'.join('{tp} {name} = ({tp}) args[{idx}];'.
                               format(name=n, tp=size2type(sz), idx=idx)
                               for idx, (sz, n) in enumerate(fv))
        else:
            raise NotImplementedError('%s %s %s'
                                      % (ast.op, len(ast.args), ast))

        fit = get_f(op).format(a=code1, b=code2)
        tp = getType(args[0])
        return op, fv, self.code_template.format(type=tp,
                                                 id=ast.ana_uuid,
                                                 unpack=unpack,
                                                 defs=precond,
                                                 code=fit), ast.ana_uuid, tp

    def _compile(self, ast):
        func = getattr(self, 'handle_{}'.format(ast.__class__.__name__))
        return func(ast)

    def handle_FP(self, ast):
        if ast.op == 'fpToFP':
            if len(ast.args) == 3:
                mode, expr, _type = ast.args
                assert mode == 'RNE'
            elif len(ast.args) == 2:
                expr, _type = ast.args
            else:
                raise ValueError
            _type = _type.name.lower()
            fv, precond, code = self._compile(expr)
            if isinstance(expr, FP):
                code = '({tp})({expr})'.format(tp=_type, expr=code)
            elif isinstance(expr, BV):
                _id = self.getFreeId()
                tp = size2type(expr.size())
                precond += '{tp} {id} = {v};\n'.format(tp=tp, id=_id, v=code)
                code = '({tp})({id})'.format(tp=_type, id=_id)
            else:
                raise TypeError
            return fv, precond, code
        elif ast.op == 'fpAdd':
            mode, op1, op2 = ast.args
            assert mode == 'RNE'
            id1, id2 = self.getFreeId(), self.getFreeId()
            fv1, pr1, expr1 = self._compile(op1)
            fv2, pr2, expr2 = self._compile(op2)
            precond = pr1 + pr2
            precond += genFpPrecond([id1, id2],
                                    [op1, op2], [expr1, expr2])
            expr = '({n})+({d})'.format(n=id1, d=id2)
            return (fv1 | fv2), precond, expr
        elif ast.op == 'fpSub':
            mode, op1, op2 = ast.args
            assert mode == 'RNE'
            id1, id2 = self.getFreeId(), self.getFreeId()
            fv1, pr1, expr1 = self._compile(op1)
            fv2, pr2, expr2 = self._compile(op2)
            precond = pr1 + pr2
            precond += genFpPrecond([id1, id2],
                                    [op1, op2], [expr1, expr2])
            expr = '({n})-({d})'.format(n=id1, d=id2)
            return (fv1 | fv2), precond, expr
        elif ast.op == 'fpMul':
            mode, op1, op2 = ast.args
            assert mode == 'RNE'
            id1, id2 = self.getFreeId(), self.getFreeId()
            fv1, pr1, expr1 = self._compile(op1)
            fv2, pr2, expr2 = self._compile(op2)
            precond = pr1 + pr2
            precond += genFpPrecond([id1, id2],
                                    [op1, op2], [expr1, expr2])
            expr = '({n})*({d})'.format(n=id1, d=id2)
            return (fv1 | fv2), precond, expr
        elif ast.op == 'fpDiv':
            mode, op1, op2 = ast.args
            assert mode == 'RNE'
            id1, id2 = self.getFreeId(), self.getFreeId()
            fv1, pr1, expr1 = self._compile(op1)
            fv2, pr2, expr2 = self._compile(op2)
            precond = pr1 + pr2
            precond += genFpPrecond([id1, id2],
                                    [op1, op2], [expr1, expr2])
            expr = '({n})/({d})'.format(n=id1, d=id2)
            return (fv1 | fv2), precond, expr
        elif ast.op == 'fpNeg':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genFpPrecond([ID], [op], [expr])
            expr = '-({id})'.format(id=ID)
            return fv, precond, expr
        elif ast.op == 'FPV':
            _id = self.getFreeId()
            precond = '{type} {id} = {val};\n'.format(type=sort2type(ast.sort),
                                                      id=_id, val=ast.args[0])
            return set(), precond, _id
        else:
            raise NotImplementedError('Unhandled %s %s %s'
                                      % (ast.sort, ast.op, ast.args))

    def handle_BV(self, ast):
        if ast.op == '__add__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')+('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__sub__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')-('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__mul__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')*('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__div__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')/('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'BVV':
            _id = self.getFreeId()
            val, size = ast.args
            if size <= 32:
                precond = 'uint32_t {id} = {val};\n'.format(id=_id, val=val)
            else:
                precond = 'uint64_t {id} = {val};\n'.format(id=_id, val=val)
            return set(), precond, _id
        elif ast.op == 'Concat':
            res = [(self._compile(at), at.size()) for at in ast.args]
            fvs = set()
            precond = ''
            exprs = []
            for (fv, pr, expr), sz in res:
                fvs |= fv
                precond += pr
                exprs.append((expr, sz))
            exprs.reverse()
            now = 0
            codes = []
            for expr, sz in exprs:
                codes.append('(({expr} & {size}) * {now})'.
                             format(expr=expr, size=(1 << sz) - 1,
                                    now=2 ** now))
                now += sz
            return fvs, precond, '|'.join(codes)
        elif ast.op == 'Extract':
            st, ed, expr = ast.args
            fv, pr, expr = self._compile(expr)
            code = 'extract({exp}, {st}, {ed})'.format(exp=expr, st=st, ed=ed)
            return fv, pr, code
        elif ast.op == 'BVS':
            size = ast.size()
            name = ast.args[0]
            return set([(size, name)]), '', name
        elif ast.op == '__invert__':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            code = '~({id})'.format(id=ID)
            return fv, precond, code
        elif ast.op == 'fpToIEEEBV':
            pass
        elif ast.op == 'fpToSBV':
            mode, op, size = ast.args
            assert mode == 'RTZ'
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            if size == 32:
                code = '(int32_t)truncf({id})'.format(id=ID)
            elif size == 64:
                code = '(int64_t)trunc({id})'.format(id=ID)
            else:
                raise ValueError(size)
            return fv, precond, code
        elif ast.op == 'fpToUBV':
            mode, op, size = ast.args
            assert mode == 'RTZ'
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            if size == 32:
                code = '(uint32_t)truncf({id})'.format(id=ID)
            elif size == 64:
                code = '(uint64_t)trunc({id})'.format(id=ID)
            else:
                raise ValueError(size)
            return fv, precond, code
        else:
            raise NotImplementedError('Unhandled BV %s %s' % (ast.op, ast))

    def handle_Bool(self, ast, negate=False):
        if ast.op == 'Not':
            return self.handle_Bool(ast.args[0], negate=not negate)


class Compiler(object):
    cache = dict()

    def compile(self, ast):
        stmts = self.__try_divide(ast)
        stmts = stmts if isinstance(stmts, list) else [stmts]
        for stmt in stmts:
            _hash = stmt._hash
            r = self.cache.get(_hash, False) or CompileService(stmt).compile()
            self.cache[_hash] = r
            yield r

    def __try_divide(self, ast):
        assert isinstance(ast, Bool)
        op = ast.op
        if op == 'And':
            # in this case, we can divide them into three parts
            return [self.__try_divide(arg) for arg in ast.args]
        else:
            return ast
