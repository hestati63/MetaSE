from ...ast.base import Base
from ...ast.bv import BV, BVV
from ...ast.bool import BoolV, Bool
from ...ast.fp import FP, FPV


def negate_op(op):
    if op == '__eq__':
        return '__ne__'
    elif op == '__ne__':
        return '__eq__'
    elif op == '__ge__':
        return '__lt__'
    elif op == '__le__':
        return '__gt__'
    elif op == '__gt__':
        return '__le__'
    elif op == '__lt__':
        return '__ge__'
    elif op == 'fpLT':
        return 'fpGE'
    else:
        print "Cannot negate: %s" % op
        exit(0)


class Compiler(object):
    cache = dict()
    code_template = '''{type} fitness_{id}(void **args) {{
        {unpack}
        return {code};
    }}
    '''

    def compile(self, ast):
        stmts = self.__try_divide(ast)
        stmts = stmts if isinstance(stmts, list) else [stmts]
        for stmt in stmts:
            self.handle_Top_Bool(stmt)
        exit(0)


    def __try_divide(self, ast):
        assert isinstance(ast, Bool)
        op = ast.op
        if op == 'And':
            # in this case, we can divide them into three parts
            return [self.__try_divide(arg) for arg in ast.args]
        elif op == 'Not':
            return ast
        else:
            print op
            exit(0)

    # return: set of free variable, code
    def _compile(self, ast):
        # TODO
        func = getattr(self, 'handle_{}'.format(ast.__class__.__name__))
        func(ast)


    def handle_Top_Bool(self, ast, negate=False):
        if ast.op =='Not':
            return self.handle_Top_Bool(ast.args[0], negate=not negate)
        elif ast.op == 'fpLT':
            op = negate_op(ast.op) if negate else ast.op
            args = ast.args
            fv1, code1 = self._compile(args[0])
            fv2, code2 = self._compile(args[1])
            fv = fv1 | fv2
            # type??
            unpack = '\n'.join('uint64_t {name} = (uint64_t *)args[{idx}];'.\
                        format(name=n, idx=idx) for idx, n in enumerate(fv))
            fitness ='({}) - ({})'.format(code1, code2)
            return op, fv, self.code_template(type='float',
                                              id=ast.ana_uuid,
                                              unpack=unpack,
                                              code=fitness)
        else:
            print ast
            print ast.op
            print len(ast.args)
            for i in ast.args:
                print i
            exit(0)


    def handle_Bool(self, ast, negate=False, hot=False):
        if ast.op =='Not':
            return self.handle_Bool(ast.args[0], negate=True, hot=hot)

