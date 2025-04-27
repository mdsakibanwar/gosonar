import angr
import result_state_info_store

def subset(full_list, sub_list):
    if(all(x in full_list for x in sub_list)):
        return True
    else:
        return False

def unique_constraint_snapshot(snapshot: angr.SimulationManager):
    constraints_map = result_state_info_store.get_snapshot_constraint(snapshot)
    cons_list = []
    cons_list.append(constraints_map['cons'])
    return unique_constraint_set(cons_list)


def unique_constraint_snapshots(snapshots: list):
    cons_list = []
    for snapshot in snapshots:
        constraints_map = result_state_info_store.get_snapshot_constraint(snapshot)
        cons_list.append(constraints_map['cons'])
    return unique_constraint_set(cons_list)


def unique_constraint_set(constraint_lists):
    result = []
    if len(constraint_lists) > 0:
        result = [constraint_lists[0]]
    for cons in constraint_lists:
        add = True
        for re in result:
            if subset(re, cons) or subset(cons, re):
                add = False
                break
        if add:
            result.append(cons)
    return result
