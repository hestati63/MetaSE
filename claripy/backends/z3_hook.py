import z3


class Solver(z3.Solver):
    def __init__(self, *args, **kwargs):
        z3.Solver.__init__(self, *args, **kwargs)

    def check(self):
        assertions = self.assertions()
        print assertions
        return z3.Solver.check(self)
