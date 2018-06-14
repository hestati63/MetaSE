#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cProfile
import os
import angr
import time
import claripy
import sys
import pwn


def main():
    cwd = '/'.join(os.path.abspath(__file__).split('/')[:-1])
    path = os.path.join(cwd, "targets/GlobalOptimizer")
    proj = angr.Project(path, load_options={'auto_load_libs': True})
    func = pwn.ELF(path).symbols

    def test(name, *args):
        # create state
        state = proj.factory.call_state(func[name], *args)
        sm = proj.factory.simulation_manager(state)

        # run
        start_time = time.time()
        sm.explore(find=lambda s: 'Global' in s.posix.dumps(1))

        for state in sm.found:
            print 'found:', state.solver.eval(args)
        print ('=== %s seconds to find result ===' % (time.time() - start_time))

    # define argument
    arg1 = claripy.BVS('arg1', 8)
    test('_Z11testFireflyc', arg1)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        main()
    elif sys.argv[1] == 'profile':
        cProfile.run("main()")
