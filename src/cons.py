from enum import Enum

# LOOP STATUS
class LOOP_STATUS:
    NOT_ANALYZED = 0
    STEM_FOUND = 1
    STEM_NOT_FOUND = 2

# WORKER TYPE
class WORKER_TYPE(Enum):
    LOOP_FINDER = "loop-finder" # generates loop in database
    STEM_FINDER = "stem-finder" # finds stems for loops in database
    LASSO_VERIFIER = "lasso-verifier" # verifies lasso in database
    CONS_VERIFIER = "cons-verifier" # verifies constraint for lasso in database
    BENCHMARK = "benchmark" # runs in benchmark mode
    TARGET = "target" # targets particular function or marked lassos in database
    SPAWN = "spawn" # spawns a IPython after creating a finder and verifier

    def __str__(self) -> str:
        return self.value


class RUNNING_MODE(Enum):
    REGULAR = "regular" # Regular mode
    CALL_RESOLVER = "call-resolver" # Call resolver mode for symbolic execution only

    def __str__(self) -> str:
        return self.value


class STEM_STATUS:
    DEFAULT = 0
    ABORT = 1


class LOOP_FIELDS:
    MAPPING = {
        "loop" : 0,
        "status" : 1,
        "func_names" : 2
    }
    LOOP = "loop"
    STATUS = "status"
    FUNC_NAMES = "func_names"

class STEM_FIELDS:
    STEM = "stem"
    STATUS = "status"
    FUNC_NAMES = "func_names"
    MAPPING = {STEM : 0, STATUS: 1, FUNC_NAMES : 2}

class LASSOS_FIELDS:
    LOOP = "loop"
    STEM = "stem"
    LOOP_HEAD = "loop_head"
    STATUS = "status"
    DATA = "data"
    STEM_FINDING_START = "stem_finding_start"
    STEM_EXECUTION_START = "stem_execution_start"
    LOOP_EXECUTION_START = "loop_execution_start"
    ITERATION_VERIFIED = "iteration_verified"
    STEM_FINDING_FINISH = "stem_finding_finish"
    STEM_EXECUTION_FINISH = "stem_execution_finish"
    LOOP_EXECUTION_FINISH = "loop_execution_finish"
    MAPPING = {
        LOOP: 0,
        STEM: 1,
        LOOP_HEAD: 2,
        STATUS: 3,
        DATA: 4,
        "stem_finding_start": 5,
        "stem_finding_finish": 6,
        "stem_execution_start": 7,
        "stem_execution_finish": 8,
        "loop_execution_start": 9,
        "loop_execution_finish": 10,
        "iteration_verified": 11,
    }


class LASSO_STATUS:
    NOT_ANALYZED = 0
    LOOP_NOT_SEEN = 1
    STEM_ABORTED = 2
    LOOP_VERIFIED = 3
    STEM_EXECUTED = 4
    TIMEOUT = 5
    LOOP_NOT_VERIFIED = 6
    CONS_NOT_VERIFIED = 7
    STEM_EXECUTED = 8
    CONS_VERIFIED = 9
    TARGET = 10
    LIMIT_CROSS = 11
    ANGR_ERRORED = 12
    RUNTIME = 13
