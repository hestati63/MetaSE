import z3
from .AVM import doAVM
from .compile import Compiler


def isFP(ast):
    if ast.sort_kind() == z3.Z3_FLOATING_POINT_SORT:
        return True
    else:
        return any(isFP(child) for child in ast.children())


class Solver(z3.Solver):
    def __init__(self, *args, **kwargs):
        backendobj = kwargs.pop('backendobj')
        z3.Solver.__init__(self, *args, **kwargs)
        self.fpKind = False           # Whether this solver hold fp
        self.backendobj = backendobj  # backend object to call _abstract
        self.push_rec = []            # push record
        self.compiler = Compiler()

    def push(self):
        z3.Solver.push(self)
        self.push_rec.append(self.fpKind)

    def pop(self):
        z3.Solver.pop(self)
        self.fpKind = self.push_rec.pop()

    def check(self):
        if self.fpKind:
            self.answer = self.__search()
            return z3.sat if self.answer else z3.unsat
            #if self.answer is None:
            #    r = z3.Solver.check(self)
            #    self.fpKind = False
            #    if r == z3.sat:
            #        print self.assertions()
            #        print z3.Solver.model(self)
            #        print 'wrong result'
            #        raw_input()
            #    else:
            #        print 'not wrong'
            #    return r
            #else:
            #    return z3.sat
        else:
            return z3.Solver.check(self)

    def model(self):
        if self.fpKind:
            s = z3.Solver()
            for key, value in self.answer.items():
                s.add(z3.BitVec(key[0], key[1][0]) == value.val)
            assert (s.check() == z3.sat)
            return s.model()
        else:
            return z3.Solver.model(self)

    def __search(self):
        codes = []
        for expr in self.assertions():
            codes.extend(list(self.compiler.compile(
                self.backendobj.simplify(self.backendobj._abstract(expr)))))
        return doAVM(codes)

    def add(self, *x):
        self.fpKind = self.fpKind or any([isFP(expr) for expr in x])
        z3.Solver.add(self, *x)
