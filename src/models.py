from init import *

import networkx as nx
from functools import lru_cache
from constraint_simplifier import unique_constraint_snapshot, unique_constraint_snapshots
import json
import time

class Stem():

    def __init__(self, 
                    cfg, 
                    stem : list, 
                    status : int = STEM_STATUS.DEFAULT,
                 ) -> None:
        self.stem : list = stem
        self.status : int = status
        self.stem_funcs : list = []
        if cfg:
            self.cfg = cfg
            for addr in self.stem:
                self.stem_funcs.append(self.cfg.functions.get_by_addr(addr))
            self.func_names = self.stem_func_names
            logger.debug(f"Found new stem {self}")
        db.add_stem(self)

    @property
    @lru_cache
    def stem_str(self):
        return json.dumps(self.stem)

    @property
    @lru_cache
    def stem_func_names(self):
        if len(self.stem_funcs) == 0:
            return ""
        result = ""
        for func in self.stem_funcs:
            result += func.name + "->"
        return result[:-2]

    @classmethod
    def create_from_db(cls, cfg, db_row):
        return cls(
            cfg,
            json.loads(db_row[STEM_FIELDS.MAPPING[STEM_FIELDS.STEM]]),
            db_row[STEM_FIELDS.MAPPING[STEM_FIELDS.STATUS]],
        )

    def update_status(self, status):
        self.status = status
        db.update_stem_status(self)

    def get_db_row(self):
        return self.stem_str, self.status, self.func_names

    def __repr__(self) -> str:
        return self.stem_func_names


class Loop:

    def __init__(
        self,
        cfg: angr.analyses.cfg.cfg_fast.CFGFast,
        loop: list,
        status: int = LOOP_STATUS.NOT_ANALYZED,
    ) -> None:
        """A lasso is a program execution path that consists of a stem and then a loop ----O like that
        Args:
            cfg (angr.analyses.cfg.cfg_fast.CFGFast): the cfgfast of this project
            stems (set): a list of list of addresses that starts form a entry point to the start of the lasso
            loop (list): a list of addresses of the functions that creates the loop
            loop_start (int): address of where the loop starts
        """
        self.loop = loop
        self.loop_funcs = []
        self.status = status
        if cfg:
            self.cfg = cfg
            for addr in self.loop:
                self.loop_funcs.append(self.cfg.functions.get_by_addr(addr))
            self.func_names : str = self.loop_func_names
            logger.debug(f"Found new loop {self}")
        db.add_loop(self)

    @classmethod
    def create_from_db(
        cls, cfg: angr.analyses.cfg.cfg_fast.CFGFast, row: tuple
    ):
        loop, status = (
            row[LOOP_FIELDS.MAPPING[LOOP_FIELDS.LOOP]],
            row[LOOP_FIELDS.MAPPING[LOOP_FIELDS.STATUS]],
        )
        return cls(cfg, json.loads(loop), status)

    def update_simgr(self, simgr, snapshots=None):
        self.simgr = simgr
        self.snapshots = snapshots

    def update_status(self, status: int):
        self.status = status
        db.update_loop_status(self)

    @property
    @lru_cache
    def loop_str(self):
        return json.dumps(self.loop)

    @property
    @lru_cache
    def loop_func_names(self):
        if len(self.loop_funcs) == 0:
            return ""
        result = ""
        for func in self.loop_funcs:
            result += func.name + "->"
        return result[:-2]

    def __repr__(self) -> str:
        return self.loop_func_names


class Lasso():

    def __init__(
        self,
        cfg,
        loop: Loop,
        stem: Stem,
        loop_head: int,
        status: int = LASSO_STATUS.NOT_ANALYZED,
        data=None,
        stem_finding_start: float = 0.0,
        stem_finding_finish: float = 0.0,
        stem_execution_start: float = 0.0,
        stem_execution_finish: float = 0.0,
        loop_execution_start: float = 0.0,
        loop_execution_finish: float = 0.0,
        iteration_verified: int = 0,
    ) -> None:
        self.cfg = cfg
        self.stem = stem
        self.loop = loop
        self.loop_head = loop_head
        self.status = status
        self.data = data
        self.stem_finding_start = stem_finding_start
        self.stem_finding_finish = stem_finding_finish
        self.stem_execution_start = stem_execution_start
        self.stem_execution_finish = stem_execution_finish
        self.loop_execution_start = loop_execution_start
        self.loop_execution_finish = loop_execution_finish
        self.iteration_verified = iteration_verified
        self.call_stack = []
        logger.debug(f"Found new lasso {self}")
        db.add_lasso(self)

    @classmethod
    def create_from_db(cls, cfg, db_row):
        db_stem = db.get_stem(db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.STEM]])
        db_loop = db.get_loop(db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.LOOP]])
        if db_stem is None or db_loop is None:
            raise Exception(f"Could not get stem/loop from db for creating lasso :( {db_row}")
        stem = Stem.create_from_db(cfg, db_stem)
        loop = Loop.create_from_db(cfg, db_loop)
        return cls(
            cfg,
            loop,
            stem,
            db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.LOOP_HEAD]],
            db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.STATUS]],
            json.loads(db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.DATA]]),
            db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.STEM_FINDING_START]],
            db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.STEM_FINDING_FINISH]],
            db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.STEM_EXECUTION_START]],
            db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.STEM_EXECUTION_FINISH]],
            db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.LOOP_EXECUTION_START]],
            db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.LOOP_EXECUTION_FINISH]],
            db_row[LASSOS_FIELDS.MAPPING[LASSOS_FIELDS.ITERATION_VERIFIED]],
        )

    def get_db_row(self):
        return  (
                self.loop.loop_str, 
                self.stem.stem_str, 
                self.loop_head, 
                self.status, 
                json.dumps(self.data),
                self.stem_finding_start,
                self.stem_finding_finish,
                self.stem_execution_start,
                self.stem_execution_finish,
                self.loop_execution_start,
                self.loop_execution_finish,
                self.iteration_verified,
                )

    def update_call_stack(self, state):
        runtime = False
        if self.cfg:
            history_funcs = ""
            for addr in state.history.bbl_addrs:
                try:
                    func = self.cfg.functions.get_by_addr(addr)
                    if func and func.name:
                        self.call_stack.append(func)
                        if "runtime" in func.name:
                            runtime = True
                        history_funcs += func.name + "->"
                except:
                    pass
            self.update_data(history_funcs[:-2])
            return runtime

    def loop_verified(self, simgr, state, snapshots):
        self.simgr = simgr
        self.snapshots = snapshots
        runtime = self.update_call_stack(state)
        self.update_loop_execution_finish()
        if not runtime:
            self.update_status(LASSO_STATUS.LOOP_VERIFIED)
        else:
            self.update_status(LASSO_STATUS.RUNTIME)

    def update_stem_finding_start(self, value = time.time()):
        db._update_lasso(self, "stem_finding_start", value)

    def update_stem_finding_finish(self, value = time.time()):
        db._update_lasso(self, "stem_finding_finish", value)

    def update_stem_execution_start(self):
        db._update_lasso(self, "stem_execution_start", time.time())

    def update_stem_execution_finish(self):
        db._update_lasso(self, "stem_execution_finish", time.time())

    def update_loop_execution_start(self):
        db._update_lasso(self, "loop_execution_start", time.time())

    def update_loop_execution_finish(self):
        db._update_lasso(self, "loop_execution_finish", time.time())

    def update_iteration_verified(self, iteration_verified):
        db._update_lasso(self, "iteration_verified", iteration_verified)

    def update_status(self, status, simgr = None, state = None, snapshots = None):
        # if self.status == LASSO_STATUS.TARGET:
        #     return
        self.status = status
        db.update_lasso_status(self)
        if status == LASSO_STATUS.STEM_EXECUTED:
            self.update_stem_execution_finish()
            self.update_loop_execution_start()
            self.update_call_stack(state)
        elif status == LASSO_STATUS.LOOP_NOT_SEEN:
            if simgr is None or state is None or snapshots is None:
                raise Exception("Loop not seen without necessary args to analyze")
            self.simgr = simgr
            self.state = state
            self.snapshots = snapshots
        elif status == LASSO_STATUS.STEM_ABORTED:
            self.stem.update_status(STEM_STATUS.ABORT)

    @property
    def data_str(self):
        return json.dumps(self.data)

    def update_data(self, data):
        self.data = data
        db.update_lasso_data(self)

    def __repr__(self) -> str:
        result = f"stem {self.stem}\t loop {self.loop}"
        return result
