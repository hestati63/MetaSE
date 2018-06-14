import random
import string
from ...ast.bv import BV
from ...ast.bool import Bool
from ...ast.fp import FP


fvPool = string.uppercase + string.lowercase
relops_eq = ['__eq__', 'fpEQ']
relops_ne = ['__ne__', 'fpNEQ']
relops_ge = ['__ge__', 'fpGE', 'UGE', 'SGE']
relops_le = ['__le__', 'fpLE', 'ULE', 'SLE']
relops_gt = ['__gt__', 'fpGT', 'UGT', 'SGT']
relops_lt = ['__lt__', 'fpLT', 'ULT', 'SLT']
relops = sum([relops_eq, relops_ne, relops_ge, relops_le, relops_gt, relops_lt], [])


def sort2type(sort):
    global size
    name = sort.name.lower()
    if name == 'float':
        size = 32
    elif name == 'double':
        size = 64
    else:
        raise ValueError
    return name


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
    if op in relops_eq:
        return 'neq' if negate else 'eq'
    elif op in relops_ne:
        return 'eq' if negate else 'neq'
    elif op in relops_ge:
        return 'lt' if negate else 'ge'
    elif op in relops_le:
        return 'gt' if negate else 'le'
    elif op in relops_gt:
        return 'le' if negate else 'gt'
    elif op in relops_lt:
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
                               for idx, (sz, n, _) in enumerate(fv))
        elif ast.op == 'BoolV':
            op, = ast.args
            return ('eq',
                    set(),
                    self.code_template.format(type='float',
                                              id=ast.ana_uuid,
                                              unpack='',
                                              defs='',
                                              code=1-op),
                    ast.ana_uuid,
                    'float')
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
        global size
        if ast.op == 'fpToFP':
            if len(ast.args) == 3:
                mode, expr, _type = ast.args
                assert mode == 'RNE'
            elif len(ast.args) == 2:
                mode = None
                expr, _type = ast.args
            else:
                raise ValueError
            _type = _type.name.lower()
            fv, precond, code = self._compile(expr)
            if isinstance(expr, FP):
                code = '({tp})({expr})'.format(tp=_type, expr=code)
            elif isinstance(expr, BV) and mode:
                _id = self.getFreeId()
                tp = size2type(expr.size())
                precond += '{tp} {id} = {v};\n'.format(tp=tp, id=_id, v=code)
                code = '({tp})({id})'.format(tp=_type, id=_id)
            elif isinstance(expr, BV) and mode is None:
                _id = self.getFreeId()
                tp = size2type(expr.size())
                if expr.op == 'BVS':
                    a, b, c = list(fv)[0]
                    fv = set([(a, b, True)])
                precond += '{tp} {id} = {v};\n'.format(tp=tp, id=_id, v=code)
                code = '*({tp}*)(&{id})'.format(tp=_type, id=_id)
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
        elif ast.op == 'fpAbs':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genFpPrecond([ID], [op], [expr])
            expr = 'abs' + ' f'[size == 32] + '({id})'.format(id=ID)
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
        global size
        if ast.op == 'SGE':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')>=('.join('(int' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'SLE':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')<=('.join('(int' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'SGT':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')>('.join('(int' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'SLT':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')<('.join('(int' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'UGE':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')>=('.join('(uint' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'ULE':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')<=('.join('(uint' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'UGT':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')>('.join('(uint' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'ULT':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')<('.join('(uint' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'And':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')&('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'Or':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')|('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'Not':
            assert len(ast.args) == 1
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '~({id})'.format(ID[0])
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'Concat':
            res = [(self._compile(at), at.size()) for at in ast.args]
            fvs = set()
            precond = ''
            exprs = []
            for (fv, pr, expr), sz in res:
                fvs |= fv
                precond += pr
                exprs.append((expr, sz))
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
        elif ast.op == 'BVV':
            _id = self.getFreeId()
            val, size = ast.args
            if size <= 32:
                precond = 'uint32_t {id} = {val}U;\n'.format(id=_id, val=val)
            else:
                precond = 'uint64_t {id} = {val}UL;\n'.format(id=_id, val=val)
            return set(), precond, _id
        elif ast.op == 'BoolS':
            pass
        elif ast.op == 'BVS':
            size = ast.size()
            name = ast.args[0]
            return set([(size, name, False)]), '', name
        elif ast.op == 'SDiv':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')/('.join('(int' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'SMod':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')%('.join('(int' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__add__':
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
        elif ast.op == '__pow__':
            assert len(ast.args) == 2
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = 'lround(pow(({id1}), ({id2})))'.format(id1=ID[0], id2=ID[1])
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__mod__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')%('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__neg__':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            code = '-({id})'.format(id=ID)
            return fv, precond, code
        elif ast.op == '__pos__':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            code = '+({id})'.format(id=ID)
            return fv, precond, code
        elif ast.op == '__abs__':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            code = 'lround(abs(({id})))'.format(id=ID)
            return fv, precond, code
        elif ast.op == '__and__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')&('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__or__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')|('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__xor__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')^('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__eq__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')==('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__ne__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')!=('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__ge__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')>=('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__le__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')<=('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__gt__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')>('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__lt__':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')<('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__lshift__':    #XXX
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')<<('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__rshift__':    #XXX
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')>>('.join(ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == '__invert__':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            code = '~({id})'.format(id=ID)
            return fv, precond, code
        elif ast.op == 'fpToIEEEBV':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            code = '*({type}*)&({id})'.format(type='uint'+str(size)+'_t',
                                              id=ID)
            return fv, precond, code
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
        elif ast.op == 'SignExt':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            code = '(int{size}_t)({id})'.format(id=ID, size=size)   #XXX
            return fv, precond, code
        elif ast.op == 'ZeroExt':
            op, = ast.args
            ID = self.getFreeId()
            fv, precond, expr = self._compile(op)
            precond += genBvPrecond([ID], [op], [expr])
            code = '(uint{size}_t)({id})'.format(id=ID, size=size)  #XXX
            return fv, precond, code
        elif ast.op == 'LShR':
            ID = [self.getFreeId() for _ in ast.args]
            fv, pr, expr = zip(*map(self._compile, ast.args))
            precond = ''.join(pr)
            precond += genBvPrecond(ID, ast.args, expr)
            code = '(' + ')>>('.join('(uint' + str(size) + '_t)' + ID) + ')'
            return reduce(set.__or__, fv), precond, code
        elif ast.op == 'RotateLeft':
            pass
        elif ast.op == 'RotateRight':
            pass
        elif ast.op == 'Reverse':
            pass
        else:
            raise NotImplementedError('Unhandled BV %s %s' % (ast.op, ast))

    def handle_Bool(self, ast, negate=False):
        if ast.op == 'Not':
            return self.handle_Bool(ast.args[0], negate=not negate)


class Compiler(object):
    cache = dict()

    def compile(self, ast):
        rs =[]
        stmts = self.__try_divide(ast)
        stmts = stmts if isinstance(stmts, list) else [stmts]
        for stmt in stmts:
            _hash = stmt._hash
            r = self.cache.get(_hash, False) or CompileService(stmt).compile()
            self.cache[_hash] = r
            rs.append(r)
        return rs

    def __try_divide(self, ast):
        assert isinstance(ast, Bool)
        op = ast.op
        if op == 'And':
            # in this case, we can divide them into three parts
            return [self.__try_divide(arg) for arg in ast.args]
        else:
            return ast
