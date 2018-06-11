#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cProfile
import os
import angr
import time
import claripy
import sys


def main(arg):
    cwd = '/'.join(os.path.abspath(__file__).split('/')[:-1])
    path = os.path.join(cwd, "targets/%s" % arg)
    proj = angr.Project(path, load_options={'auto_load_libs': False})

    # define argument
    sym_arg = claripy.BVS('sym_arg', 8)
    argv = [proj.filename, sym_arg]

    # create state
    state = proj.factory.entry_state(args=argv)
    sm = proj.factory.simulation_manager(state)

    # run
    start_time = time.time()
    sm.run()

    for state in sm.deadended:
        print 'found:', state.solver.eval(argv[1])
    print ('=== %s seconds to find result ===' % (time.time() - start_time))


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print "Usage: %s <prog>" % sys.argv[0]
    elif len(sys.argv) == 2:
        main(sys.argv[1])
    elif sys.argv[1] == 'profile':
        cProfile.run("main('{}')".format(sys.argv[2]))
