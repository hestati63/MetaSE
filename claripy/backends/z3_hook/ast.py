from ...ast.base import Base
from ...ast.bv import BV, BVV
from ...ast.bool import BoolV, Bool
from ...ast.fp import FP, FPV


def compile_bool(ast):
    # operator: ast.op
    # args: ast.args

    for i in ast.args:
        compileAST(i)
    exit(0)

def compile_BV(ast):
    if ast.op == 'BVV':
        ''' ast.args[0] hold value
            ast.args[1] hold bit_length '''
        return "TODO"
    else:
        for i in ast.args:
            compileAST(i)

    #print ast.op
    #print ast.args

def compile_int(ast):
    if ast.bit_length == 64:
        #print ast.numerator
        #print dir(ast)
        pass

AST_action_map = {
        Bool: compile_bool,
        BV: compile_BV,
        int: compile_int,
}


def compileAST(ast):
    for obj, func in AST_action_map.items():
        if isinstance(ast, obj):
            return func(ast)
    raise Exception("todo: compile {}".format(ast.__class__.__name__))
