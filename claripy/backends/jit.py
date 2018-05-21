from ..errors import ClaripyOperationError
from ..fp import FSORT_DOUBLE, FSORT_FLOAT


class JIT():
    def __init__(self):
        self._xmm = [False] * 16
        self._rm = None
        self._sort = None
        self._suffix = None

    @staticmethod
    def parse_sexpr(sexpr):
        expr = [[]]
        word = ''
        for c in sexpr:
            if c in ' \n\t':
                if word:
                    expr[-1].append(word)
                    word = ''
            elif c == '(':
                expr.append([])
            elif c == ')':
                if word:
                    expr[-1].append(word)
                    word = ''
                temp = expr.pop()
                expr[-1].append(temp)
            else:
                word += c
        return expr[0]

    def _emit(self, instr):
        #TODO
        print(instr)

    def _ralloc(self):
        try:
            i = self._xmm.index(False)
        except ValueError:
            raise ClaripyOperationError('out of registers')
        self._xmm[i] = True
        return i

    def _free(self, i):
        self._xmm[i] = False

    def _encode_rm(self, rm):
        if rm == 'roundNearestTiesToEven':
            return 0
        elif rm == 'roundTowardNegative':
            return 1
        elif rm == 'roundTowardPositive':
            return 2
        elif rm == 'roundTowardZero':
            return 3

    def _set_rm(self, rm):
        if rm != self._rm:
            self._emit('push 0')
            self._emit('stmxcsr [rsp]')
            self._emit('and word [rsp], 0x9fff')
            encoded_rm = self._encode_rm(rm)
            if encoded_rm:
                self._emit('or word [rsp]. 0x%x' % (rm * 0x2000))
            self._emit('ldmxcsr [rsp]')
            self._rm = rm

    def _set_size(self, size):
        if size == 32:
            self._sort = FSORT_FLOAT
            self._suffix = 's'
        elif size == 64:
            self._sort = FSORT_DOUBLE
            self._suffix = 'd'

    def compile_expr(self, expr):
        def iter(expr):
            if expr[0] == 'fp.eq':
                xmm1 = iter(expr[1])
                xmm2 = iter(expr[2])
                self._emit('cmps%s xmm%d, xmm%d, 0' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.lt':
                xmm1 = iter(expr[1])
                xmm2 = iter(expr[2])
                self._emit('cmps%s xmm%d, xmm%d, 1' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.le':
                xmm1 = iter(expr[1])
                xmm2 = iter(expr[2])
                self._emit('cmps%s xmm%d, xmm%d, 2' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.ne':
                xmm1 = iter(expr[1])
                xmm2 = iter(expr[2])
                self._emit('cmps%s xmm%d, xmm%d, 4' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.ge':
                xmm1 = iter(expr[1])
                xmm2 = iter(expr[2])
                self._emit('cmps%s xmm%d, xmm%d, 5' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.gt':
                xmm1 = iter(expr[1])
                xmm2 = iter(expr[2])
                self._emit('cmps%s xmm%d, xmm%d, 6' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.abs':
                xmm1 = iter(expr[1])
                xmm2 = self._ralloc()
                if self._suffix == 's':
                    self._emit('push 0x7fffffff')
                else:
                    self._emit('mov rax, 0x7fffffffffffffff')
                    self._emit('push rax')
                self._emit('movs%s xmm%d, [rsp]' % (self._suffix, xmm2))
                self._emit('andp%s xmm%d, xmm%d' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.neg':
                xmm1 = iter(expr[1])
                xmm2 = self._ralloc()
                if self._suffix == 's':
                    self._emit('push 0x80000000')
                else:
                    self._emit('mov rax, 0x8000000000000000')
                    self._emit('push rax')
                self._emit('movs%s xmm%d, [rsp]' % (self._suffix, xmm2))
                self._emit('xorp%s xmm%d, xmm%d' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.add':
                xmm1 = iter(expr[2])
                xmm2 = iter(expr[3])
                self._set_rm(expr[1])
                self._emit('adds%s xmm%d, xmm%d' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.sub':
                xmm1 = iter(expr[2])
                xmm2 = iter(expr[3])
                self._set_rm(expr[1])
                self._emit('subs%s xmm%d, xmm%d' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.mul':
                xmm1 = iter(expr[2])
                xmm2 = iter(expr[3])
                self._set_rm(expr[1])
                self._emit('muls%s xmm%d, xmm%d' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp.div':
                xmm1 = iter(expr[2])
                xmm2 = iter(expr[3])
                self._set_rm(expr[1])
                self._emit('divs%s xmm%d, xmm%d' % (self._suffix, xmm1, xmm2))
                self._free(xmm2)
                return xmm1
            elif expr[0] == 'fp':
                xmm1 = self._ralloc()
                imm = eval(expr[1].replace('#', '0'))
                imm <<= self._sort.exp
                imm |= eval(expr[2].replace('#', '0'))
                imm <<= self._sort.mantissa - 1
                imm |= eval(expr[3].replace('#', '0'))
                self._emit('mov rax, 0x%x' % imm)
                self._emit('push rax')
                self._emit('movs%s xmm%d, [rsp]' % (self._suffix, xmm1))
                return xmm1
            elif expr[0] == 'let':
                xmm1 = iter(expr[1][0][1])
                if xmm1 is not None:
                    self._free(xmm1)
                return iter(expr[2])
            elif expr[0] == 'concat':
                return None
            elif isinstance(expr[0], list):
                if expr[0][0] == '_':
                    if expr[0][1] == 'to_fp':
                        self._set_size(int(expr[0][2]) + int(expr[0][3]))
                        xmm1 = iter(expr[2])
                        encoded_rm = self._encode_rm(expr[1])
                        self._emit('rounds%s xmm%d, xmm%d, %d' % (self._suffix, xmm1, xmm1, encoded_rm))
                        return xmm1
                    elif expr[0][1] == 'zero_extend':
                        #TODO
                        return iter(expr[1])
            elif isinstance(expr, list):
                if expr[0] == '_':
                    if expr[1] == '+zero':
                        self._set_size(int(expr[2]) + int(expr[3]))
                        xmm1 = self._ralloc()
                        self._emit('xor rax, rax')
                        self._emit('push rax')
                        self._emit('movs%s xmm%d, [rsp]' % (self._suffix, xmm1))
                        return xmm1
                    elif expr[1] == '-zero':
                        self._set_size(int(expr[2]) + int(expr[3]))
                        xmm1 = self._ralloc()
                        if self._suffix == 's':
                            self._emit('push 0x80000000')
                        else:
                            self._emit('mov rax, 0x8000000000000000')
                            self._emit('push rax')
                        self._emit('movs%s xmm%d, [rsp]' % (self._suffix, xmm1))
                        return xmm1
                elif expr[0] == 'ite':
                    #TODO
                    iter(expr[1])
                    iter(expr[2])
                    return iter(expr[3])
                elif len(expr) > 2:
                    #TODO
                    return self._ralloc()
            elif expr.startswith('FP_'):
                #TODO
                self._set_size(int(expr[-2:]))
                xmm1 = self._ralloc()
                return xmm1
            else:
                return self._ralloc()

        self._emit('mov rbp, rsp')
        ret = iter(expr)
        if ret:
            self._emit('mov xmm0, xmm%d' % ret)
