import z3
from .ast import compileAST


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

    def push(self):
        z3.Solver.push(self)
        self.push_rec.append(self.fpKind)

    def pop(self):
        z3.Solver.pop(self)
        self.fpKind = self.push_rec.pop()

    def check(self):
        if self.fpKind:
            return self.__search()
        else:
            return z3.Solver.check(self)

    def __search(self):
        codes = [compileAST(self.backendobj._abstract(expr))
                 for expr in self.assertions()]
        raise Exception("todo: search")

    def add(self, *x):
        self.fpKind = self.fpKind or any([isFP(expr) for expr in x])
        z3.Solver.add(self, *x)
