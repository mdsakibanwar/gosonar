from . import MemoryMixin
from IPython import embed
import angr
import capstone
import sys
from loguru import logger

sys.path.append("/home/ubuntu/gosonar/src")

from indirect_jump_concritizer_logic import IndirectJumpConcritizer

def resolve_call(state, size, ins, arch_byte_width):
    concritizer = IndirectJumpConcritizer()
    value = state.solver.BVS(f"gohome_{hex(ins.address)}", size = size * arch_byte_width)
    concrete_addrs = concritizer.get_called_functions(
        ins.address
    )
    if not concrete_addrs:
        return None
    elif len(concrete_addrs) > 1:
        constraint_options = [
            value == concrete_addr for concrete_addr in concrete_addrs
        ]
        conditional_constraint = state.solver.Or(*constraint_options)
    else:
        conditional_constraint = value == concrete_addrs[0]
    state.add_constraints(conditional_constraint)
    return value


class IndirectCallConcritizationMixin(MemoryMixin):
    def load(self, addr, size=None, condition=None, **kwargs):
        if (
            type(addr) is not int
            and self.state.solver.symbolic(addr)
            and addr.uninitialized
        ):
            state: angr.SimState = self.state
            blk = state.block()
            insns = list(blk.disassembly.insns)
            first_insn = insns[0]
            if first_insn.mnemonic == "call":
                result = resolve_call(state, size, first_insn, state.arch.byte_width)
                return  result if result is not None else super().load(addr, size=size, condition=condition, **kwargs)
            elif first_insn.mnemonic == "mov":
                last_insn = insns[-1]
                if last_insn.mnemonic == "call":
                    if len(last_insn.operands) == 1:
                        if last_insn.operands[0].type == capstone.x86.X86_OP_IMM:
                            return super().load(
                                addr, size=size, condition=condition, **kwargs
                            )
                    else:
                        logger.warning(f"matching for more than 1 operands with string matching {last_insn.op_str}")
                    call_target = last_insn.op_str
                    if call_target in first_insn.op_str:
                        for ins in insns[1:-1]:
                            if "mov" in ins.mnemonic and ins.op_str.startswith(call_target):
                                return super().load(addr, size=size, condition=condition, **kwargs)
                        result = resolve_call(
                            state, size, last_insn, state.arch.byte_width
                        )
                        return  result if result is not None else super().load(addr, size=size, condition=condition, **kwargs)
        return super().load(addr, size=size, condition=condition, **kwargs)
