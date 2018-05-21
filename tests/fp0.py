#!/usr/bin/env python

import claripy

a = claripy.FPS("a", claripy.FSORT_FLOAT)
b = claripy.FPV(1.0, claripy.FSORT_FLOAT)
s = claripy.Solver()
s.add(a - 1 == b)
print s.eval(b, 1)
print s.eval(a, 1)
