from operator import call
from init import *
import ctypes
from signal import SIGABRT
from verifier_tech import VerifierTech




current_lasso = None
already_analyzed = {}


@ctypes.CFUNCTYPE(None, ctypes.c_int)
def sigabrt_handler(signal):
    global current_lasso
    print("SIGABRT received. Exiting gracefully.")
    # Your cleanup code here
    if current_lasso:
        current_lasso.update_status(LASSO_STATUS.STEM_ABORTED)

class Verifier():
    def __init__(self, proj, cfg, args) -> None:
        self.proj = proj
        self.cfg = cfg
        self.args = args
        c_globals = ctypes.CDLL(None)  # POSIX
        c_globals.signal(SIGABRT, sigabrt_handler)
        pass

    def verify_recursion(
        self,
        lasso : Lasso, 
        TIMEOUT: int = 300,
        RECURSION_LIMIT: int = 3
    ):
        global current_lasso, skipper
        loop : Loop = lasso.loop
        stem : Stem = lasso.stem
        if str(stem.stem) in db.skipped_stems:
            lasso.update_status(LASSO_STATUS.STEM_ABORTED)
            return lasso
        current_lasso = lasso
        starting_addr = stem.stem[0]
        logger.debug(
            f"Verifying recursion for lasso with stem: {util.get_list_hex(stem.stem)} and loop {util.get_list_hex(loop.loop)}"
        )
        logger.info(
            f"Verifying recursion for lasso with stem: {stem.stem_func_names} and loop: {loop.loop_func_names}"
        )
        simgr = None
        for i in range(5):
            logger.info(f"Trying to verify for {i}th time")
            call_state: angr.sim_state.SimState = self.proj.factory.call_state(starting_addr)
            call_state.options.SIMPLIFY_CONSTRAINTS = True
            call_state.options.UNDER_CONSTRAINED_SYMEXEC = True
            call_state.globals['counter'] = i
            try:
                simgr: angr.SimulationManager = self.proj.factory.simulation_manager(call_state)
                tech = VerifierTech(
                    lasso, RECURSION_LIMIT, self.cfg, self.args.stop_addresses
                )
                simgr.use_technique(angr.exploration_techniques.Timeout(TIMEOUT))
                simgr.use_technique(tech)
                simgr = simgr.run()
            except ValueError as e:
                if i == 5:
                    raise e
            if lasso.status == LASSO_STATUS.LOOP_VERIFIED:
                return lasso
        # either due to timeout or having no path to explore
        if simgr: 
            if len(simgr.errored) > 0:
                lasso.update_status(LASSO_STATUS.ANGR_ERRORED)
                return lasso 
        if tech._complete:
            lasso.update_status(LASSO_STATUS.LOOP_NOT_VERIFIED)
        else:
            lasso.update_status(LASSO_STATUS.TIMEOUT)
            lasso.update_data({"timeout" : TIMEOUT})
        return lasso

    def compare_equal_to_constant(self, constraint):
        if len(constraint.args) == 2 and constraint.op == "__eq__":
            return True
        return False

    def get_contraint(self, mismatch, cons_1_map, cons_2_map):
        if mismatch in cons_1_map:
            return cons_1_map[mismatch]
        elif mismatch in cons_2_map:
            return cons_2_map[mismatch]
        else: 
            raise Exception("Could not find constraint in any map")

    def same_con(self, c1, c2):
        _, _, cc1 = c1.constraint.ast.canonicalize()
        _, _, cc2 = c2.constraint.ast.canonicalize()
        cc1_set = set()
        cc2_set = set()
        for child in cc1.children_asts():
            if self.compare_equal_to_constant(child):
                cc1_set.add(str(child))
        for child in cc2.children_asts():
            if self.compare_equal_to_constant(child):
                cc2_set.add(str(child))
        missed = list(cc1_set ^ cc2_set)
        if (
            len(missed) > 0
            or not len(cc1.args) == len(cc2.args)
            or not len(list(cc1.children_asts())) == len(list(cc2.children_asts()))
            or not len(list(cc1.leaf_asts())) == len(list(cc2.leaf_asts()))
        ):
            return False 
        return True

    def remove_similar_cons(self, mismatches : list, cons_1_map, cons_2_map):
        mismatch_cons = {}
        for mismatch in mismatches:
            mismatch_constraint = self.get_contraint(mismatch, cons_1_map, cons_2_map)
            mismatch_cons[mismatch_constraint] = mismatch

        for mc in mismatch_cons.keys():
            if self.compare_equal_to_constant(mc.constraint):
                mismatches.remove(mismatch_cons[mc])
                continue
            for mc2 in mismatch_cons.keys():
                if self.same_con(mc, mc2):
                    if mismatch_cons[mc] in mismatches:
                        mismatches.remove(mismatch_cons[mc])
                    if mismatch_cons[mc2] in mismatches:
                        mismatches.remove(mismatch_cons[mc2])
        return mismatches

    def compare_cons(self, cons_1, cons_2):
        cons_1_map = {}
        for con in cons_1:
            mapc, countc, canon_cc = con.constraint.ast.canonicalize()
            cons_1_map[str(canon_cc)] = con

        cons_2_map = {}
        for con in cons_2:
            mapc, countc, canon_cc = con.constraint.ast.canonicalize()
            cons_2_map[str(canon_cc)] = con

        con_1_set = set(cons_1_map.keys())
        con_2_set = set(cons_2_map.keys())
        mismatches = list(con_1_set ^ con_2_set)
        self.remove_similar_cons(mismatches, cons_1_map, cons_2_map)
        if len(mismatches) > 0:
            embed()
            return False
        return True

    def verify_constraints(self, lasso: Lasso):
        if lasso.status != LASSO_STATUS.LOOP_VERIFIED:
            logger.error("Trying to verify constraint for lasso with loop not verified")
            return False
        histories = []
        logger.debug(f"Verifying constraints for lasso")
        if lasso.snapshots is None:
            return False
        for index in lasso.snapshots:
            snapshot = lasso.snapshots[index]
            histories.append(snapshot.history)
        prev = None
        all_new_cons = []
        for his in histories:
            new_cons = []
            if prev is not None:
                cur_cons = list(his.actions)
                prev_cons = list(prev.actions)
                for ac in cur_cons:
                    if ac not in prev_cons:
                        new_cons.append(ac)
            all_new_cons.append(new_cons)
            prev = his
        if len(all_new_cons[-1]) == 0 and len(all_new_cons[-2]) == 0:
            lasso.update_status(LASSO_STATUS.CONS_VERIFIED)
            return True
        if len(all_new_cons[-1]) == len(all_new_cons[-2]) and self.compare_cons(all_new_cons[-1], all_new_cons[-2]):
        # if self.compare_cons(all_new_cons[-1], all_new_cons[-2]):            
            lasso.update_status(LASSO_STATUS.CONS_VERIFIED)
            return True
        lasso.update_status(LASSO_STATUS.CONS_NOT_VERIFIED)
        return False
