#!../.venv/bin/python

import angr
import networkx as nx
import json


def get_snapshot_constraint(snapshot: angr.SimState, con_str: bool = False):
    """ Get all the constraint for found states of a simulation manager.
    

    Args:
        snapshot (angr.SimulationManager): The simulation manager whose constraint you want
        con_str (bool, optional): If the constraints should be converted to string. Defaults to False.

    Returns:
        dict: dict[state_number][cons/blocks]   
    """
    result = {}
    result["cons"] = []
    blocks = []
    for bbl_addr in snapshot.history.bbl_addrs:
        blocks.append(bbl_addr)
    result["blocks"] = blocks
    for ac in snapshot.history.actions:
        if con_str:
            result["cons"].append(ac.__repr__())
        else:
            result["cons"].append(ac)
    return result


def dump_snapshot_constraint(snapshot: angr.SimState, prefix: str):
    result = get_snapshot_constraint(snapshot, True)
    with open(f"constraints/snapshot_{prefix}.json", "w+") as fp:
        json.dump(result, fp, indent= 4)
