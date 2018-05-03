MetaSE
=====
Symbolic Execution with Metaheuristic search

How to Run
-----
```bash
$ . hook
$ python code.py
```


Work Flow
-----
1. Make function that compiles predicates to X86 native code.
2. Write function that run and get fitness with [unicorn](https://github.com/unicorn-engine/unicorn).
3. Based on **step 2**, write AVM
4. Adopt **step 3** to [angr](https://github.com/angr/angr)'s [claripy](https://github.com/angr/claripy).

Role
-----
| Name          | WorkFlow       |
|---------------|----------------|
| Hyeonwoo Kang | **#1**, **#2** |
| Bilgehan      | **#2**, **#3** |
| Minkyu Jung   | **#4**         |

Related work
-----
* [FloPSy - Search-Based Floating Point Constraint Solving for Symbolic Execution](https://link.springer.com/chapter/10.1007%2F978-3-642-16573-3_11)
* [Symbolic Execution with Interval Solving and Meta-heuristic Search](https://dl.acm.org/citation.cfm?id=2224897)
