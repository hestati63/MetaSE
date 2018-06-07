from cffi import FFI


class Executor():
    def __init__(self):
        self.ffi = FFI()

    def cdef(self, fundef):
        self.ffi.cdef(fundef)

    def new(self, t, val):
        return self.ffi.new(t, val)

    def open(self, filename):
        self.dll = self.ffi.dlopen(filename)

    def sym(self, fun):
        return getattr(self.dll, fun)

    def close(self):
        self.ffi.dlclose(self.dll)


if __name__ == "__main__":
    '''Test.'''
    dl = Executor()
    dl.cdef('int printf(const char *, ...);')
    dl.open('libc.so.6')
    printf = dl.sym('printf')
    printf('%s, %s\n', dl.new('char []', 'hello'), dl.new('char []', 'world'))
    dl.close()
