import os
import sqlite3
import angr
from cons import *
import claripy
from pathlib import Path

import argparse
from loguru import logger
from datetime import datetime
from db_handler import DB_Handler
import util
db = DB_Handler()

from indirect_jump_concritizer_logic import IndirectJumpConcritizer
from models import Loop, Stem, Lasso
from verifier import Verifier
from graph_handler import GraphHandler
from finder import CandidateFinder


counter = 0
debug =  True
forbiddens = ["stub", "thumb", "sub", "thunk", "eq", "import", "runtime"]
musts = ["."]
project_root = Path(__file__).resolve().parent.parent

class RuntimeHook(angr.SimProcedure):
    def run(self):
        return


class AtoiHook(angr.SimProcedure):
    def run(self, input):
        global counter
        counter += 1
        return claripy.BVS(f"atoi_input_{counter}", 64, uninitialized=True)


def init(args: argparse.Namespace):
    filename = args.binary.split("/")[-1].replace("/", "_")
    if args.worker_type:
        filename += "_" + str(args.worker_type) + "_" + str(args.mode)
    logger.add(
        f"{project_root}/logs/{filename}_{str(datetime.now()).replace(' ', '_')}.log", level="TRACE"
    )
    proj = angr.Project(args.binary, load_options={"auto_load_libs": False})
    indirect_concritizer = IndirectJumpConcritizer(args)
    cfg_fast = proj.analyses.CFGFast()
    logger.info("Finished making CFG Fast")
    if not indirect_concritizer.setup_done:
        indirect_concritizer.setup(proj, cfg_fast)

    if args.mode != RUNNING_MODE.REGULAR:
        for fun in cfg_fast.kb.functions.values():
            if fun.name.startswith("runtime"):
                proj.hook(fun.addr, hook=RuntimeHook())
    
    if args.worker_type == WORKER_TYPE.BENCHMARK:
        for fun in cfg_fast.kb.functions.values():
            if "atoi" in fun.name:
                proj.hook(fun.addr, hook=AtoiHook())

    cg = cfg_fast.functions.callgraph.copy()
    if not args.no_prune_callgraph:
        nodes_to_remove = []
        for node in cg.nodes:
            func = cfg_fast.functions.get_by_addr(node)
            for forbidden in forbiddens:
                if forbidden in func.name:
                    nodes_to_remove.append(node)
            for must in musts:
                if not must in func.name:
                    nodes_to_remove.append(node)
        cg.remove_nodes_from(nodes_to_remove)
        edges_to_remove = []
        for addr, edge_dict in cg.adjacency():
            for to_addr, edges in edge_dict.items():
                for index, edge_type in edges.items():
                    if(edge_type['type'] != "call"):
                        edges_to_remove.append((addr, to_addr))
        cg.remove_edges_from(edges_to_remove)
    args.cg = cg
    args.graph_handler = GraphHandler(cg)
    return proj, cfg_fast


def clo_init() -> argparse.Namespace:
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--package",
        "-p",
        dest="package",
        required=False,
        help="Package to target, all cycles must contain one function under package",
    )
    parser.add_argument(
        "--mode",
        "-m",
        dest="mode",
        type=RUNNING_MODE,
        choices=list(RUNNING_MODE),
        default=RUNNING_MODE.REGULAR,
        required=False,
        help="Running Mode [default = regular]",
    )
    parser.add_argument(
        "-log",
        "--loglevel",
        dest="loglevel",
        default="TRACE",
        help="Provide logging level. Example --loglevel debug, [default = TRACE]",
    )
    parser.add_argument(
        "--worker-type",
        "-w",
        dest="worker_type",
        required=True,
        type=WORKER_TYPE,
        choices=list(WORKER_TYPE),
        help="Worker Type",
    )

    parser.add_argument(
        "--target-func",
        dest="target_func",
        required=False,
        help="Function to target in targeted mode",
    )
    parser.add_argument(
        "--binary",
        dest="binary",
        required=False,
        help="Binary to Analyze",
    )
    parser.add_argument(
        "--stop-addresses",
        "-s",
        dest="stop_addresses",
        nargs="*",
        required=False,
        help="Addresses to stop execution at when active under simulation manager",
    )
    parser.add_argument(
        "--cycle-size",
        dest="cycle_size",
        type=int,
        required=False,
        default=5,
        help="Limit for cycle size [default = 5]",
    )
    parser.add_argument(
        "--db",
        dest="database",
        default=None,
        required=False,
        help="Database to use",
    )
    parser.add_argument(
        "--recursion-limit",
        dest="recursion_limit",
        required=False,
        default=3,
        type=int,
        help="Recursion Limit [default = 3]",
    )
    parser.add_argument(
        "--db-id-start",
        dest="db_id_start",
        required=False,
        default=0,
        type=int,
        help="Rowid for starting working with DB [default = 0]",
    )
    parser.add_argument(
        "--db-amount",
        dest="db_amount",
        required=False,
        default=250,
        type=int,
        help="Number of rows this worker should analyze [default = 250]",
    )

    parser.add_argument(
        "--no-prune-callgraph",
        dest="no_prune_callgraph",
        required=False,
        default=False,
        action="store_true",
        help="If indirect call resolver should be bypassed [default = False]",
    )
    parser.add_argument(
        "--bypass-db",
        dest="bypass_db",
        required=False,
        default=False,
        action="store_true",
        help="If all db access should be bypassed [default = False]",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        required=False,
        type=int,
        default=600,
        help="Timeout [default = 600]",
    )
    args = parser.parse_args()

    if args.worker_type == WORKER_TYPE.BENCHMARK:
        args.bypass_db = True
        args.no_prune_callgraph = True
        args.package = None
        
    if not args.package and not args.binary:
        logger.error("At least one of --package or --binary must be provided.")

    
    bins_path, db_path = project_root / 'bins', project_root / 'db'
    
    if not db_path.exists():
        db_path.mkdir(parents=True, exist_ok=True)

    if not args.binary:
        args.binary = f"{bins_path}/go_stdlib/{args.package}"

    filename = args.binary.split("/")[-1]
    if not args.bypass_db and args.database is None:
        suffix = "reg"
        if args.mode == RUNNING_MODE.CALL_RESOLVER:
            suffix = "call"
        db_name = f"{db_path}/{filename}_{suffix}.db"
        logger.warning(f"Database not provided creating/using one at {db_name}")
        if not os.path.exists(db_name):
            with open(db_name, "w"):
                logger.info(f"Created new database at {db_name}")
            db.build_tables(db_name)
        args.database = db_name
    db.setup_db(args.database, args.bypass_db)
    return args
