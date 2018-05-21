import z3

from jit import JIT


class Solver(z3.Solver):
    def __init__(self, *args, **kwargs):
        z3.Solver.__init__(self, *args, **kwargs)

    def check(self):
        assertions = self.assertions()
        a = assertions[len(assertions) - 1]
        print(a.sexpr())
        expr = JIT.parse_sexpr(a.sexpr())[0]
        JIT().compile_expr(expr)
        return z3.Solver.check(self)
