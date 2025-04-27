import angr
from time import time
from IPython import embed

def print_state(state:angr.SimState):
    print(f"*************{hex(state.addr)}**************")
    try:
        state.block().pp()
    except:
        print(f"could not print block at {state.addr}")
    print("***************************")

def get_list_hex(l):
    return "[{}]".format(", ".join(hex(x) for x in l))

def get_end_divider():
    return "###################################################"

def get_start_divider():
    return "***************************************************"

def compare_history(state_a: angr.SimState , state_b: angr.SimState) -> angr.SimState:
    return state_a


def timer_func(func):
    # This function shows the execution time of
    # the function object passed
    def wrap_func(*args, **kwargs):
        t1 = time()
        result = func(*args, **kwargs)
        t2 = time()
        print(f"Function {func.__name__!r} executed in {(t2-t1):.4f}s")
        return result

    return wrap_func


def analyze_found_state(state: angr.SimState):
    all_args = {}
    for ac in state.history.actions:
        if isinstance(ac, angr.state_plugins.SimActionConstraint):
            ac: angr.state_plugins.SimActionConstraint
            for arg in ac.constraint.to_claripy().args:
                for leaf_ast in arg.leaf_asts():
                    if not leaf_ast.concrete and leaf_ast not in all_args:
                        all_args[leaf_ast] = []
    for arg in all_args:
        try:
            all_args[arg] = state.solver.eval_atleast(arg, 1)
        except:
            print("lolol")
    embed()
