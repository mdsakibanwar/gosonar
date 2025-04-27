from cons import *
from init import *
import time
from functools import lru_cache


class CandidateFinder():

    def __init__(self, proj, cfg, args, use_entry = False) -> None:
        self._proj = proj
        self._cfg:angr.analyses.cfg.cfg_fast.CFGFast = cfg
        self._args = args
        self._graph_handler = args.graph_handler
        self._use_entry = use_entry

    @property
    def graph_handler(self):
        return self._graph_handler

    def get_function_name(self, node_name):
        if "+" in node_name:
            return node_name.split("+")[0]
        else:
            return node_name

    def get_all_public_callers(self, target_node, maximum_depth = 5):
        if maximum_depth == 0:
            return []
        if target_node:
            results = set()
            for node in target_node.predecessors:
                if node and node.name and "." in node.name:
                    # fmt.fmt.fmtQc+0x3e
                    last_part = node.name.split(".")[-1]
                    structure_name = node.name.split(".")[-2]
                    if "+" in last_part:
                        last_part = last_part.split("+")[0]
                    if last_part[0].istitle() and (
                        structure_name.startswith("z2") or structure_name[0].istitle()
                    ):
                        name = self.get_function_name(node.name)
                        if name:
                            logger.trace(f"Found new public caller function: {name}")
                            results.add(self._cfg.functions.get(name))
                        else:
                            logger.error(f"could not find function name from node {node.name}")
                    func = None
                    try:
                        name = self.get_function_name(node.name)
                        if name:
                            func = self._cfg.functions.get(name)
                    except:
                        logger.error(f"could not find function from node {node.name}")
                    if (
                        func
                        and func.name
                        and func.addr
                        and not func.name.startswith("sub")
                        and func.name not in target_node.name
                    ):
                        func_node = self._cfg.get_any_node(func.addr)
                        prev = self.get_all_public_callers(func_node, maximum_depth = maximum_depth - 1)
                        for p in prev:
                            results.add(p)
        return results

    def find_stem_to_loop(self, cg_cycle):
        logger.info(f"Finding Stem from cycle {cg_cycle}")
        stems_loop_head = []
        path = []
        for func_addr in cg_cycle:
            if self._use_entry:
                path = self._graph_handler.find_shortest_path_in_cg(
                    self._proj.entry, func_addr
                )
                if len(path) > 0:
                    stem = Stem(self._cfg, path)
                    stems_loop_head.append((stem, func_addr))
                continue

            func = self._cfg.functions.get_by_addr(func_addr)
            if func is None:
                continue
            if func.name and "." in func.name:
                last_part = func.name.split(".")[-1]
                structure_name = func.name.split(".")[-2]
                if last_part[0].istitle() and (structure_name.startswith("z2") or structure_name[0].istitle()):
                    stems_loop_head.append((Stem(self._cfg, [func_addr]), func_addr))
            func_node = self._cfg.get_any_node(func_addr)
            results = set()
            if func_node:
                try:
                    results = self.get_all_public_callers(func_node)
                except Exception as e:
                    pass
                if len(results) > 0:
                    # bro you are still finding one path
                    for func in results:
                        path = self._graph_handler.find_shortest_path_in_cg(
                            func.addr, func_addr
                        )
                        if len(path) > 0 and str(path) not in db.skipped_stems:
                            stem = Stem(self._cfg, path)
                            stems_loop_head.append((stem, func_addr))
        return stems_loop_head

    def find_stems_gather_lassos(self, loop_obj: Loop):
        logger.debug(f"Finding stem for loop : {loop_obj.loop_func_names}")
        stem_finding_start = time.time()
        stems_loop_heads = self.find_stem_to_loop(loop_obj.loop)
        stem_finding_finish = time.time()
        lassos = []
        if len(stems_loop_heads) > 0:
            loop_obj.update_status(LOOP_STATUS.STEM_FOUND)
            for stem, loop_head in stems_loop_heads:
                lasso = Lasso(self._cfg, loop_obj, stem, loop_head, stem_finding_start=stem_finding_start, stem_finding_finish=stem_finding_finish)
                lassos.append(lasso)
            return lassos
        loop_obj.update_status(LOOP_STATUS.STEM_NOT_FOUND)
        return lassos

    def generate_loops(self, cycle_limit = None):
        # find the cycles in the call graph and convert them from addr to funcs
        logger.info("Starting to find loops")
        for cg_cycle in self._graph_handler.generate_cycles_in_cg():
            if cycle_limit and len(cg_cycle) > cycle_limit:
                continue
            package_function_in_loop = False
            funcs = []
            for addr in cg_cycle:
                func = self._cfg.functions.get(addr)
                if func and func.name and "." in func.name:
                    funcs.append(func.name)
                    package = func.name.split(".")[0]
                    if package == self._args.package:
                        package_function_in_loop  = True
                        break
            if package_function_in_loop or self._args.worker_type == WORKER_TYPE.BENCHMARK:
                loop = Loop(self._cfg, cg_cycle)
                yield loop
            else:
                logger.warning(f"Not including loop because no function from target package {self._args.package} loop {funcs}")

    def find_n_limit_loops(self, cycle_size_limit = None, find_stem = False):
        for loop in self.generate_loops(cycle_limit = cycle_size_limit):
            if find_stem:
                self.find_stems_gather_lassos(loop)

    def find_and_gather_lassos(self, limit=None):
        lassos = []
        for loop in self.generate_loops(cycle_limit=limit):
            new_lassos = self.find_stems_gather_lassos(loop)
            if not len(new_lassos) > 0:
                continue
            lassos.extend(new_lassos)
        return lassos
