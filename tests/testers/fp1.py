import os
import angr
import time
import claripy


def main():
    path = os.path.abspath(__file__)
    path = os.path.join('/'.join(path.split('/')[:-1]),  "../targets/fp1")
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
    main()
