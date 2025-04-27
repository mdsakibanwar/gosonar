import networkx
from init import *


class VerifierTech(angr.ExplorationTechnique):
    def __init__(self, lasso: Lasso, recursion_limit, cfg, stop_addresses = []):
        super().__init__()
        self._lasso : Lasso = lasso
        self._loop : Loop = lasso.loop
        self._stem : Stem = lasso.stem
        self.cfg = cfg
        self._complete = False
        self._recursion_limit = recursion_limit
        self.deferred_stash = "gohome_stash"
        self._snapshots = {}
        self._loop_not_seen = False
        self.graph = networkx.DiGraph()
        self.stop_addresses = stop_addresses

    def setup(self, simgr):
        self._lasso.update_stem_execution_start()
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []
            simgr.stashes["found"] = []

    def step(self, simgr:angr.SimulationManager, stash="active", **kwargs):
        simgr = simgr.step(stash, **kwargs)
        # logger.debug(util.get_start_divider())
        if len(simgr.active) == 0:
            logger.error("Could not find a path :( trying others!")
            if len(simgr.stashes[self.deferred_stash]) > 0:
                simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop())
            else:
                self._complete = True
            return
        for state in simgr.active:
            if type(state.addr) is int and self.stop_addresses and hex(state.addr) in self.stop_addresses:
                embed()
            if state.addr == self._lasso.loop_head:
                stem_seen, loop_seen = True, True
                bbl_addrs = list(state.history.bbl_addrs)
                count = bbl_addrs.count(state.addr)
                for addr in self._stem.stem[:-1]:
                    if addr not in bbl_addrs:
                        stem_seen = False
                        break
                if count == 0 and stem_seen:
                    self._lasso.update_status(LASSO_STATUS.STEM_EXECUTED, state=state)
                if count > 0 and stem_seen:
                    self._lasso.update_iteration_verified(count)
                for addr in self._loop.loop:
                    if addr not in bbl_addrs:
                        loop_seen = False
                        break
                if stem_seen and count == self._recursion_limit and not loop_seen:
                    logger.debug(f"Found {count} of loop head but stem_seen: {stem_seen} and loop_seen: {loop_seen}")
                    self._lasso.update_status(LASSO_STATUS.LOOP_NOT_SEEN, simgr=simgr, state=state, snapshots=self._snapshots)
                    self._complete = True
                    continue
                logger.debug(f"Finished {count} recursions! {util.get_list_hex(list(state.history.bbl_addrs))}")
                self._snapshots[count] = state
                if count >= self._recursion_limit:
                    self._complete = True
                    self._lasso.loop_verified(simgr, state, self._snapshots)
                    simgr.stashes['found'] = [state]
                    break
                else:
                    simgr.move("active", self.deferred_stash, filter_func= lambda s: s.addr != self._lasso.loop_head)
                    break
            else:
                try:
                    func = self.cfg.functions.get_by_addr(state.addr)
                    caller = None
                    if func:
                        for addr in state.history.bbl_addrs:
                            try:
                                caller = self.cfg.functions.get_by_addr(addr)
                                if caller:
                                    break
                            except:
                                pass
                    if caller:
                        self.graph.add_node(caller.name)
                        self.graph.add_node(func.name)
                        self.graph.add_edge(caller.name, func.name)
                except:
                    pass
        # logger.debug(util.get_end_divider())

        return

    def complete(self, simgr):
        return self._complete
