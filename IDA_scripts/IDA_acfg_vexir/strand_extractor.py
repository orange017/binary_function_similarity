from collections import defaultdict
import hashlib


class StrandHash:

    def __init__(self, exp_tree):
        self.HASH_MASK = ((1 << 10) - 1)
        self.raw_hash = hashlib.md5(str(exp_tree).encode('utf-8'))

    def hexdigest(self):
        return self.raw_hash.hexdigest()
    
    def shash(self):
        return int.from_bytes(self.raw_hash.digest()[:2], byteorder='little') & self.HASH_MASK


class StrandsExtractor():
    """
    This class is responsible for extracting strands from a VEX block and computing 
    their hashes. The main method is `extract_strands`, which returns a list of 
    strands, where
    """
    
    def __init__(self, vex_block):
        self.statements = vex_block.statements
        self.pyvex_arch = vex_block.arch
        self.tmp2exp = {}
        self.reg2exp = defaultdict(list)
        self.normalized_register_names = {}

    def reset_normalized_register_names(self):
        """
        Reset the normalized register names mapping and index. This should be called at the 
        beginning of the extraction of each strand, to ensure that the same register offset 
        gets the same normalized name across different strands, but different strands can 
        have different normalized names for the same register offset.
        """
        self.normalized_register_names.clear()

    def get_normalized_register_name(self, reg):
        """
        Returns a normalized name for the given register offset. The same offset will always 
        get the same normalized name.
        """
        norm_reg_name = self.normalized_register_names.get(reg, None)
        if norm_reg_name is None:
            reg_name_idx = len(self.normalized_register_names) + 1
            norm_reg_name = f't{reg_name_idx}'
            self.normalized_register_names[reg] = norm_reg_name
        return norm_reg_name

    def extract_strands(self):
        """
        We first start doing a linear scan of the VEX block and we update the
        following data structures:
        - candidates: list of statement indexes that should be consider as
          starting point of a strand.
        - tmp2exp = {tmp_reg_idx : (IRExpr, stmt_idx)}
            - for each tmp register, store the expression that defines it and
              the index of the statement of such expression
        - reg2exp = {
            reg_offset : [ (IRExpr, stmt_idx), (IRExpr, stmt_idx), ... ]
          }
        """
        candidates = self.collect_candidate_statement_idxs()
        stmt_idx_to_exp_tree = {}
        while len(candidates) > 0:
            stmt_idx = candidates.pop()
            exp_tree = self.extract_strand(stmt_idx)
            stmt_idx_to_exp_tree[stmt_idx] = exp_tree
            candidates -= self.curr_strand_idxs
        return stmt_idx_to_exp_tree

    def extract_strand(self, stmt_idx):
        '''Returns: the list of used '''
        self.reset_normalized_register_names()
        stmt = self.statements[stmt_idx]
        self.curr_strand_idxs = set()
        self.computed_exp_trees = {}
        exp_tree = None
        if stmt.tag == 'Ist_Put':
            exp_tree_l = self.get_normalized_register_name(stmt.offset)
            exp_tree_r = self.extract_strand_from_exp(stmt.data, stmt_idx)
            exp_tree = ('=', (exp_tree_l, exp_tree_r))
        elif stmt.tag == 'Ist_PutI':
            exp_tree_l = self.extract_strand_from_exp(stmt.ix, stmt_idx)
            exp_tree_r = self.extract_strand_from_exp(stmt.data, stmt_idx)
            exp_tree = ('=', (exp_tree_l, exp_tree_r))
        elif stmt.tag == 'Ist_Store':
            exp_addr = self.extract_strand_from_exp(stmt.addr, stmt_idx)
            exp_data = self.extract_strand_from_exp(stmt.data, stmt_idx)
            exp_tree = ('memstore', (exp_addr, exp_data))
        elif stmt.tag == 'Ist_StoreG':
            exp_guard = self.extract_strand_from_exp(stmt.guard, stmt_idx)
            exp_addr = self.extract_strand_from_exp(stmt.addr, stmt_idx)
            exp_data = self.extract_strand_from_exp(stmt.data, stmt_idx)
            exp_tree = ('guardedmemstore', (exp_guard, exp_addr, exp_data))
        elif stmt.tag == 'Ist_Exit':
            assert stmt.guard is not None
            exp_tree = self.extract_strand_from_exp(stmt.guard, stmt_idx)
        else:
            raise Exception(f'starting stmt {stmt.tag} not supported')
        assert exp_tree is not None
        assert type(exp_tree) == tuple
        return exp_tree

    def extract_strand_from_exp(self, exp, stmt_idx):
        self.curr_strand_idxs.add(stmt_idx)
        if (exp, stmt_idx) in self.computed_exp_trees.keys():
            return self.computed_exp_trees[(exp, stmt_idx)]
        exp_tree = None
        if type(exp) == str:
            exp_tree = exp
        elif exp.tag == 'Iex_RdTmp':
            tmp = exp.tmp
            def_exp, def_exp_idx = self.tmp2exp[tmp]
            exp_tree = self.extract_strand_from_exp(def_exp, def_exp_idx)
        elif exp.tag == 'Iex_Get':
            for put_exp, put_exp_idx in reversed(self.reg2exp[exp.offset]):
                if put_exp_idx < stmt_idx:
                    exp_tree = self.extract_strand_from_exp(
                        put_exp, put_exp_idx)
                    break
            else:
                exp_tree = self.get_normalized_register_name(exp.offset)
        elif exp.tag == 'Iex_Binop':
            norm_op = op_to_norm_op(exp.op)
            if norm_op is None:
                raise Exception(f'unsupported {exp.tag} op {exp.op}')
            cexp1_tree = self.extract_strand_from_exp(
                exp.child_expressions[0], stmt_idx)
            cexp2_tree = self.extract_strand_from_exp(
                exp.child_expressions[1], stmt_idx)
            if norm_op in '+*&|^':
                if type(cexp1_tree) == str and type(cexp2_tree) == str:
                    exp_tree = (norm_op, tuple(
                        sorted((cexp1_tree, cexp2_tree))))
                else:
                    exp_tree = (norm_op, tuple((cexp1_tree, cexp2_tree)))
            else:
                exp_tree = (norm_op, tuple((cexp1_tree, cexp2_tree)))
        elif exp.tag == 'Iex_Unop':
            norm_op = op_to_norm_op(exp.op)
            if norm_op is None:
                raise Exception(f'unsupported {exp.tag} op {exp.op}')
            cexp = self.extract_strand_from_exp(
                exp.child_expressions[0], stmt_idx)
            if norm_op == 'cast':
                # ignore casts for now
                exp_tree = cexp
            else:
                exp_tree = (norm_op, (cexp, ))
        elif exp.tag in ['Iex_Triop', 'Iex_Qop']:
            norm_op = op_to_norm_op(exp.op)
            if norm_op is None:
                raise Exception(f'unsupported {exp.tag} op {exp.op}')
            cexp_trees = []
            for cexp in exp.child_expressions:
                cexp_tree = self.extract_strand_from_exp(cexp, stmt_idx)
                cexp_trees.append(cexp_tree)
            exp_tree = (norm_op, tuple(cexp_trees))
        elif exp.tag in ['Iex_CCall', 'Iex_ITE', 'Iex_GetI']:
            cexp_trees = []
            for cexp in exp.child_expressions:
                cexp_tree = self.extract_strand_from_exp(cexp, stmt_idx)
                cexp_trees.append(cexp_tree)
            exp_tree = (exp.tag, tuple(cexp_trees))
        elif exp.tag in ['Iex_Const']:
            exp_tree = str(exp.con.value)
        elif exp.tag == 'Iex_Load':
            exp_addr = self.extract_strand_from_exp(exp.addr, stmt_idx)
            exp_tree = ('memload', ((exp_addr, )))
        elif exp.tag == 'Iex_Custom':
            cexp_trees = []
            for cexp in exp.child_expressions:
                cexp_tree = self.extract_strand_from_exp(cexp, stmt_idx)
                cexp_trees.append(cexp_tree)
            exp_tree = (exp.op, tuple(cexp_trees))
        else:
            raise Exception(f'exp {exp.tag} not supported')
        assert exp_tree is not None
        self.computed_exp_trees[(exp, stmt_idx)] = exp_tree
        return exp_tree

    def reg_offset_to_name(self, offset):
        return self.pyvex_arch.translate_register_name(offset)

    def should_skip_reg(self, offset):
        reg_name = self.reg_offset_to_name(offset)
        if reg_name in ['eip', 'rip', 'pc']:
            return True
        if reg_name.startswith('cc_'):
            return True
        return False

    def collect_candidate_statement_idxs(self):
        candidates = set()
        for stmt_idx, stmt in enumerate(self.statements):
            # print(f"Processing stmt idx {stmt_idx} with tag {stmt.tag}")
            if stmt.tag == 'Ist_WrTmp':
                self.tmp2exp[stmt.tmp] = (stmt.data, stmt_idx)
            elif stmt.tag == 'Ist_Put':
                if not self.should_skip_reg(stmt.offset):
                    self.reg2exp[stmt.offset].append((stmt.data, stmt_idx))
                    candidates.add(stmt_idx)
            elif stmt.tag == 'Ist_PutI':
                candidates.add(stmt_idx)
            elif stmt.tag == 'Ist_Store':
                candidates.add(stmt_idx)
            elif stmt.tag == 'Ist_Dirty':
                self.tmp2exp[stmt.tmp] = ('dirty', stmt_idx)
            elif stmt.tag == 'Ist_CAS':
                self.tmp2exp[stmt.oldLo] = (CustomExpr(
                    'CAS', [stmt.addr, stmt.expdLo]), stmt_idx)
            elif stmt.tag == 'Ist_LLSC':
                if stmt.storedata is not None:
                    self.tmp2exp[stmt.result] = (CustomExpr(
                        'LLSC', [stmt.addr, stmt.storedata]), stmt_idx)
                else:
                    self.tmp2exp[stmt.result] = (
                        CustomExpr('LLSC', [stmt.addr]), stmt_idx)
            elif stmt.tag == 'Ist_LoadG':
                self.tmp2exp[stmt.dst] = (CustomExpr(
                    'Ist_LoadG', [stmt.guard, stmt.addr, stmt.alt]), stmt_idx)
            elif stmt.tag == 'Ist_StoreG':
                candidates.add(stmt_idx)
            elif stmt.tag in ['Ist_IMark', 'Ist_AbiHint', 'Ist_MBE']:
                pass
            elif stmt.tag == 'Ist_Exit':
                if stmt.guard is not None:
                    candidates.add(stmt_idx)
            else:
                raise Exception(f'stmt {stmt.tag} not supported')
        return candidates

def op_to_norm_op(op, only_known_ops: bool = False):
    norm_op = op_to_norm_op_map.get(op, None)
    if norm_op is not None:
        return norm_op
    for op_prefix, op_norm in op_prefixes_to_norm_op_map.items():
        if op.startswith(op_prefix):
            return op_norm
    if only_known_ops:
        return op
    return None

class CustomExpr():
    """
    Dummy binop expression useful to store references to two expressions
    instead of just one. Useful for CAS and LLSC statements.
    """

    def __init__(self, op, child_expressions):
        self.tag = 'Iex_Custom'
        self.op = op
        self.child_expressions = child_expressions[:]


op_to_norm_op_map = {
    # binop
    'Iop_Add64': '+',
    'Iop_Add32': '+',
    'Iop_Add16': '+',
    'Iop_Add8': '+',
    'Iop_Add64x2': '+',
    'Iop_Add32x4': '+',
    'Iop_Add16x8': '+',
    'Iop_Add8x16': '+',
    'Iop_Add64F0x2': '+',
    'Iop_Add32F0x4': '+',
    'Iop_Sub64': '-',
    'Iop_Sub32': '-',
    'Iop_Sub16': '-',
    'Iop_Sub8': '-',
    'Iop_Sub32x4': '-',
    'Iop_QSub8Ux16': '-',
    'Iop_Mul64': '*',
    'Iop_Mul64F0x2': '*',
    'Iop_Mul32': '*',
    'Iop_MullU64': '*',
    'Iop_MullS64': '*',
    'Iop_MullU32': '*',
    'Iop_MullS32': '*',
    'Iop_DivU64': '/',
    'Iop_DivModS64to64': '/',
    'Iop_DivModU128to64': '/',
    'Iop_DivModU64to32': '/',
    'Iop_Shr64': '>>',
    'Iop_Shr32': '>>',
    'Iop_Shr16': '>>',
    'Iop_Shr8': '>>',
    'Iop_Shl64': '<<',
    'Iop_Shl32': '<<',
    'Iop_Shl16': '<<',
    'Iop_Shl8': '<<',
    'Iop_Sar64': '>>',
    'Iop_Sar32': '>>',
    'Iop_Sar16': '>>',
    'Iop_Sar8': '>>',
    'Iop_AndV128': '&',
    'Iop_And64': '&',
    'Iop_And32': '&',
    'Iop_And16': '&',
    'Iop_And8': '&',
    'Iop_OrV128': '|',
    'Iop_Or64': '|',
    'Iop_Or32': '|',
    'Iop_Or16': '|',
    'Iop_Or8': '|',
    'Iop_XorV128': '^',
    'Iop_Xor64': '^',
    'Iop_Xor32': '^',
    'Iop_Xor16': '^',
    'Iop_Xor8': '^',
    'Iop_CasCmpNE64': '!=',
    'Iop_CasCmpNE32': '!=',
    'Iop_CasCmpNE16': '!=',
    'Iop_CasCmpNE8': '!=',
    'Iop_CmpNE64': '!=',
    'Iop_CmpNE32': '!=',
    'Iop_CmpNE16': '!=',
    'Iop_CmpNE8': '!=',
    'Iop_CmpEQ64': '==',
    'Iop_CmpEQ32': '==',
    'Iop_CmpEQ16': '==',
    'Iop_CmpEQ8': '==',
    'Iop_CmpEQ64x2': '==',
    'Iop_CmpEQ32x4': '==',
    'Iop_CmpEQ16x8': '==',
    'Iop_CmpEQ8x16': '==',
    'Iop_CmpEQ8x16': '==',
    'Iop_CmpEQ64F0x2': '==',
    'Iop_CmpEQ32F0x4': '==',
    'Iop_CmpLE64U': '<=',
    'Iop_CmpLE64S': '<=',
    'Iop_CmpLE32U': '<=',
    'Iop_CmpLE32S': '<=',
    'Iop_CmpLT64U': '<',
    'Iop_CmpLT64S': '<',
    'Iop_CmpLT32U': '<',
    'Iop_CmpLT32S': '<',
    'Iop_CmpF64': 'comp',
    'Iop_CmpF32': 'comp',
    'Iop_64HLtoV128': 'combine',
    'Iop_64HLto128': 'combine',
    'Iop_32HLto64': 'combine',
    'Iop_16HLto32': 'combine',
    'Iop_8HLto16': 'combine',
    # unop
    'Iop_SetV128lo64': 'cast',
    'Iop_V128to64': 'cast',
    'Iop_V128HIto64': 'cast',
    'Iop_128to64': 'cast',
    'Iop_128HIto64': 'cast',
    'Iop_128to32': 'cast',
    'Iop_128to16': 'cast',
    'Iop_128to8': 'cast',
    'Iop_128to1': 'bool',
    'Iop_64StoV128': 'cast',
    'Iop_64UtoV128': 'cast',
    'Iop_64Sto128': 'cast',
    'Iop_64Uto128': 'cast',
    'Iop_64to32': 'cast',
    'Iop_64HIto32': 'cast',
    'Iop_64to16': 'cast',
    'Iop_64to8': 'cast',
    'Iop_64to1': 'bool',
    'Iop_32StoV128': 'cast',
    'Iop_32UtoV128': 'cast',
    'Iop_32to64': 'cast',
    'Iop_32Sto64': 'cast',
    'Iop_32Uto64': 'cast',
    'Iop_32to16': 'cast',
    'Iop_32HIto16': 'cast',
    'Iop_32to8': 'cast',
    'Iop_32to1': 'cast',
    'Iop_32to1': 'bool',
    'Iop_16Sto64': 'cast',
    'Iop_16Uto64': 'cast',
    'Iop_16Sto32': 'cast',
    'Iop_16Uto32': 'cast',
    'Iop_16to8': 'cast',
    'Iop_16HIto8': 'cast',
    'Iop_16to1': 'bool',
    'Iop_8Sto64': 'cast',
    'Iop_8Uto64': 'cast',
    'Iop_8Sto32': 'cast',
    'Iop_8Uto32': 'cast',
    'Iop_8Sto16': 'cast',
    'Iop_8Uto16': 'cast',
    'Iop_8to1': 'bool',
    'Iop_1Sto64': 'int',
    'Iop_1Uto64': 'int',
    'Iop_1Sto32': 'int',
    'Iop_1Uto32': 'int',
    'Iop_1Sto16': 'int',
    'Iop_1Uto16': 'int',
    'Iop_1Sto8': 'int',
    'Iop_1Uto8': 'int',
    'Iop_ReinterpI64asF64': 'float',
    'Iop_ReinterpF64asI64': 'int',
    'Iop_ReinterpI32asF32': 'float',
    'Iop_ReinterpF32asI32': 'int',
    'Iop_F64toF32': 'cast',
    'Iop_F64toI64S': 'int',
    'Iop_F64toI64U': 'int',
    'Iop_F64toI32S': 'int',
    'Iop_F64toI32U': 'int',
    'Iop_I64StoF64': 'float',
    'Iop_I64UtoF64': 'float',
    'Iop_I64StoF32': 'float',
    'Iop_I64UtoF32': 'float',
    'Iop_I32StoF64': 'float',
    'Iop_I32UtoF64': 'float',
    'Iop_I32StoF32': 'float',
    'Iop_I32UtoF32': 'float',
    'Iop_F32toF64': 'float',
    'Iop_F32toF64S': 'float',
    'Iop_F32toI64S': 'int',
    'Iop_NotV128': '!',
    'Iop_Not128': '!',
    'Iop_Not64': '!',
    'Iop_Not32': '!',
    'Iop_Not16': '!',
    'Iop_Not8': '!',
    'Iop_Not1': '!',
    'Iop_NegF64': 'neg',
    'Iop_NegF32': 'neg',
    'Iop_Neg64Fx2': 'neg',
    'Iop_Clz64': 'countzero',
    'Iop_Clz32': 'countzero',
    'Iop_Ctz64': 'countzero',
    'Iop_Ctz32': 'countzero',
    'Iop_MAddF64': 'muladd',
    'Iop_MSubF64': 'mulsub',
}

op_prefixes_to_norm_op_map = {
    'Iop_Add': '+',
    'Iop_Sub': '-',
    'Iop_Mul': '*',
    'Iop_Div': '/',
    'Iop_And': '&',
    'Iop_Or': '|',
    'Iop_Xor': '^',
    'Iop_Not': '!',
    'Iop_CmpNE': '!=',
    'Iop_CmpEQ': '==',
    'Iop_CmpLT': '<',
    'Iop_CmpLE': '<=',
    'Iop_CmpGT': '>',
    'Iop_CmpGE': '>=',
    'Iop_ExpCmpNE': '!=',
    'Iop_ExpCmpEQ': '==',
    'Iop_ExpCmpLT': '<',
    'Iop_ExpCmpLE': '<=',
    'Iop_ExpCmpGT': '>',
    'Iop_ExpCmpGE': '>=',
    'Iop_Cat': 'combine',
    'Iop_Interleave': 'combine',
    'Iop_Max': 'max',
    'Iop_Min': 'min',
    'Iop_Perm': 'perm',
    'Iop_Round': 'round',
    'Iop_Sar': '>>',
    'Iop_Shr': '>>',
    'Iop_Shl': '<<',
    'Iop_Sh': '<<',
    'Iop_Rsh': '>>',
    'Iop_Sqrt': 'sqrt',
    'Iop_Cnt': 'count',
    'Iop_Neg': 'neg',
    'Iop_Reinterp': 'cast',
    'Iop_Zero': 'cast',
    'Iop_Abs': 'abs',
    'Iop_NarrowUn': 'cast',
    'Iop_QNarrow': 'cast',
    'Iop_Reverse': 'reverse',
    'Iop_Slice': 'slice',
    'Iop_GetMSB': 'conv',
    'Iop_Scale': 'scale',
}