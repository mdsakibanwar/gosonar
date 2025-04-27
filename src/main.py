from init import *

def verify_cons(proj, cfg, args):
    verifier = Verifier(proj, cfg, args)
    rows = db.get_n_lassos_by_status(
        status=LASSO_STATUS.LOOP_VERIFIED, count=args.db_amount, start=args.db_id_start
    )
    lassos = []
    for row in rows:
        lasso = Lasso.create_from_db(cfg, row)
        lasso = verifier.verify_recursion(lasso, args.timeout, args.recursion_limit)
        lassos.append(lasso)
        if verifier.verify_constraints(lasso):
            logger.debug(f"Found violating lasso {lasso}")

def verify_lasso(proj, cfg, args):
    verifier = Verifier(proj, cfg, args)
    rows = db.get_n_lassos_by_status(status = LASSO_STATUS.NOT_ANALYZED, count=args.db_amount, start=args.db_id_start)
    for row in rows:
        lasso = Lasso.create_from_db(cfg, row)
        try:
            lasso = verifier.verify_recursion(lasso, args.timeout, args.recursion_limit)
        except ValueError as e:
            logger.exception(e)
            lasso.update_status(LASSO_STATUS.STEM_ABORTED)
        if lasso.status == LASSO_STATUS.LOOP_VERIFIED:
            verifier.verify_constraints(lasso)


def analyze_targeted_lassos(proj, cfg, args):
    target_func = None
    if args.target_func is not None:
        target_func = args.target_func
    verifier = Verifier(proj, cfg, args)
    if target_func:
        rows = db.get_all_targeted_func_in_loop_lasso(target_func)
    else:
        rows = db.get_n_lassos_by_status(
            status=LASSO_STATUS.TARGET, count=args.db_amount, start=args.db_id_start
        )
    for row in rows:
        lasso = Lasso.create_from_db(cfg, row)
        if not target_func or (target_func in lasso.loop.loop_func_names):    
            try:
                lasso = verifier.verify_recursion(lasso, args.timeout, args.recursion_limit)
                if lasso.status == LASSO_STATUS.LOOP_VERIFIED:
                    verifier.verify_constraints(lasso)
            except ValueError as e:
                logger.exception(e)
                lasso.update_status(LASSO_STATUS.STEM_ABORTED)


def find_stem(proj, cfg, args):
    finder = CandidateFinder(proj, cfg, args)
    rows = db.get_n_loops_by_status(status = LOOP_STATUS.NOT_ANALYZED, count = args.db_amount, start = args.db_id_start)
    for row in rows:
        loop = Loop.create_from_db(cfg, row)
        lassos = finder.find_stems_gather_lassos(loop)
        logger.debug(f"Found {len(lassos)} lassos from loop: {loop.loop_func_names}")

def generate_loops(proj, cfg, args):
    finder = CandidateFinder(proj, cfg, args)
    finder.find_n_limit_loops(cycle_size_limit=args.cycle_size, find_stem=False)

def benchmark(proj, cfg, args):
    try:
        finder = CandidateFinder(proj, cfg, args, use_entry= True)
        verifier = Verifier(proj, cfg, args)
        lassos = finder.find_and_gather_lassos()
        for lasso in lassos:
            lasso = verifier.verify_recursion(lasso)
            if verifier.verify_constraints(lasso):
                logger.debug(f"Found violating lasso {lasso}")
    except Exception as e:
        logger.exception(e)


if __name__ == "__main__":
    args = clo_init()
    proj, cfg_fast = init(args)
    
    match args.worker_type:
        case WORKER_TYPE.STEM_FINDER:
            find_stem(proj, cfg_fast, args)
        case WORKER_TYPE.LASSO_VERIFIER:
            verify_lasso(proj, cfg_fast, args)
        case WORKER_TYPE.LOOP_FINDER:
            generate_loops(proj, cfg_fast, args) 
        case WORKER_TYPE.BENCHMARK:
            benchmark(proj, cfg_fast, args)
        case  WORKER_TYPE.CONS_VERIFIER:
            verify_cons(proj, cfg_fast, args)
        case WORKER_TYPE.TARGET:
            analyze_targeted_lassos(proj, cfg_fast, args)
        case WORKER_TYPE.SPAWN:
            finder = CandidateFinder(proj, cfg_fast, args)
            verifier = Verifier(proj, cfg_fast, args)
            embed()
        case _:
            logger.info("Nothing done")
