
#include "HSSAGen.h"
#include <assert.h>
#include <algorithm>
#include "HSSA.h"

namespace holodec {

	struct HSSAGenDef {
		HId id;//for Regdef -> registerId, for stack and tmp -> index
		uint64_t offset;
		uint64_t size;
		HId ssaId;
	};
	struct HSSAGenRegDef {
		HId parentRegId;
		bool cleared;
		HList<HSSAGenDef> defs;
	};
	struct HSSAGenBasicBlock {
		HList<HSSAGenRegDef> inputs;
		HList<HSSAGenRegDef> outputs;
	};
	struct HSSAGenStck {
		HString name;
		HList<HSSAGenDef> defs;//size - stck_index
	};
	struct HSSAGenTmp {
		HList<HSSAGenDef> defs;
	};
	//uint64_t index = 0;
	//snprintf(buffer, "%s%%d", stack.name);
	//if(sscanf(reg, buffer,&index) < 1){
	// return 0;
	//}
	//return index;

	bool operator< (HSSAGenDef& lhs, HSSAGenDef& rhs) {
		return lhs.offset < rhs.offset;
	}

	struct HSSAGenState {
		HArchitecture* arch;
		HIdGenerator gen;

		HMap<HString, HSSAGenStck> stacks;
		HList<HSSAGenRegDef> regDefs;
		HSSAGenBasicBlock genBB;//per basic block
		HSSAGenTmp tmp;//per instruction

		HInstruction* instr;
		HId lastOp;

		HSSAFunction ssaFunction;
		HId activeBasicBlock;

		HId generateNewBasicBlock() {
			HSSABasicBlock bb;
			return activeBasicBlock = ssaFunction.basicblocks.add (bb);
		}
		void activateBasicBlock (HId id) {
			activeBasicBlock = id;
		}
		void addExpression (HSSAExpression expr) {
			ssaFunction.basicblocks.get (activeBasicBlock)->expressions.add (expr);
		}
		HSSAExpression* getExpression (HId id) {
			HSSAExpression* expr = ssaFunction.basicblocks.get (activeBasicBlock)->expressions.get (id);
			if (expr)
				return expr;
			for (HSSABasicBlock& bb : ssaFunction.basicblocks.list) {
				expr = bb.expressions.get (id);
				if (expr)
					return expr;
			}
			return nullptr;
		}


		HSSAGenDef createValOrInput (HSSAGenRegDef* regdef, HRegister* reg, uint64_t lowerbound, uint64_t upperbound) {
			if (lowerbound < upperbound) {
				if (regdef->cleared) {
					HId id = gen.next();
					printf ("%d = Value(0x0,%d)\n", id, upperbound - lowerbound);
					return {reg->id, lowerbound, upperbound - lowerbound, id};
				} else {
					HId input;
					HSSAGenRegDef* foundregdef = nullptr;
					for (HSSAGenRegDef& regdef : genBB.inputs) {
						if (regdef.parentRegId == reg->parentId) {
							foundregdef = &regdef;
							break;
						}
					}
					if (foundregdef) {
						for (HSSAGenDef& def : foundregdef->defs) {
							if (def.id == reg->id) {
								return def;
							}
						}
					}
					input = gen.next();
					printf ("%d = Input(%s,%d)\n", input, reg->name.cstr(), upperbound - lowerbound);
					HSSAGenDef def = {reg->id, lowerbound, upperbound - lowerbound, input};
					if (foundregdef) {
						foundregdef->defs.push_back (def);
					} else {
						genBB.inputs.push_back ({reg->parentId, false, {def}});
					}
					return def;
				}
			}
			return {0, 0, 0, 0};
		}

		HId getDefForUse (HId regId, uint64_t offset = 0, uint64_t size = 0) {
			return getDefForUse (arch->getRegister (regId), offset, size);
		}
		HId getDefForUse (HRegister* reg, uint64_t offset = 0, uint64_t size = 0) {
			offset += reg->offset;//adjust for parent register
			size = size == 0 ? reg->size - offset : size;
			for (HSSAGenRegDef& regdef : regDefs) {
				if (regdef.parentRegId == reg->parentId) {
					int localdefcount = 0;
					HSSAGenDef localdefs[20];
					for (auto it = regdef.defs.begin(); it != regdef.defs.end();) {
						HSSAGenDef& def = *it;
						if (def.offset == offset && def.size == size) //perfect match
							return def.ssaId;
						if (offset < (def.offset + def.size) && def.offset < (offset + size)) { //start after
							uint64_t newoffset = 0, newsize = def.size;
							if (def.offset < offset) {//split of lower nibble
								newoffset += offset - def.offset;
								newsize -= newoffset;
							}
							if (def.offset + def.size > offset + size) {//split of upper nibble
								newsize -= (def.offset + def.size) - (offset + size);
							}
							HId newSSA = gen.next();
							printf ("%d = Split(%d,%d,%d);\n", newSSA, def.ssaId, newoffset, newsize);
							localdefs[localdefcount++] = {def.id, def.offset + newoffset, newsize, newSSA};
						}
						it++;
					}
					//sort defs by offset
					std::sort (localdefs, localdefs + localdefcount);
					bool sort = false;
					if (localdefcount > 0) {//checks integrity
						uint64_t newlocaldefcount = localdefcount;
						uint64_t input = 0;
						uint64_t lastupperBound = offset;
						for (int i = 0; i < localdefcount; i++) {
							if (lastupperBound != localdefs[i].offset) {
								localdefs[newlocaldefcount++] = createValOrInput (&regdef, reg, lastupperBound, localdefs[i].offset);
								sort = true;
							}
							lastupperBound = localdefs[i].offset + localdefs[i].size;
						}
						if (lastupperBound != offset + size) {
							localdefs[newlocaldefcount++] = createValOrInput (&regdef, reg, lastupperBound, offset + size);
							sort = true;
						}
						localdefcount = newlocaldefcount;
					}
					if (sort) //sort anew
						std::sort (localdefs, localdefs + localdefcount);

					if (localdefcount == 0) {
						return createValOrInput (&regdef, reg, offset, offset + size).ssaId;
					} else if (localdefcount == 1) { //this case is the most likely
						assert (localdefs[0].offset == offset && localdefs[0].size == size);
						return localdefs[0].ssaId;
					} else {
						HId id = gen.next();
						printf ("%d = Extend(", id);

						uint64_t resultsize = 0;
						uint64_t lastupperBound = offset;
						for (int i = 0; i < localdefcount; i++) {
							assert (lastupperBound == localdefs[i].offset);
							if (i)
								printf (", ");
							printf ("%d", localdefs[i]);
							resultsize += localdefs[i].size;
							lastupperBound = localdefs[i].offset + localdefs[i].size;
						}
						printf (")\n");
						assert (resultsize == size);
						return id;
					}
				}
			}
			HSSAGenRegDef regdef = {reg->parentId, false, {}};
			return createValOrInput (&regdef, reg, offset, offset + size).ssaId;
		}
		HId createDef (HId regId, HId ssaId) {
			HRegister* reg = arch->getRegister (regId);
			//printf ("Add Reg Def\n");
			//printf ("%d = P:%s - R:%s Offset: %d Size: %d\n", ssaId, arch->getRegister (reg->parentId)->name.cstr(), arch->getRegister (reg->id)->name.cstr(), reg->offset, reg->size);
			for (HSSAGenRegDef& regdef : regDefs) {
				if (regdef.parentRegId == reg->parentId) {
					if (reg->clearParentOnWrite) {//clears whole register
						regdef.cleared = true;
						regdef.defs.clear();
					} else {
						for (auto it = regdef.defs.begin(); it != regdef.defs.end();) {
							HSSAGenDef& defit = *it;
							if (reg->offset < (defit.offset + defit.size) && defit.offset < (reg->offset + reg->size)) { //if there is an intersection
								int count = 0;
								HSSAGenDef def[2];

								if (defit.offset < reg->offset) { //if starts before
									HId splitId = gen.next();
									printf ("%d = LowerSplit(%d,%d,%d);\n", splitId, defit.ssaId, 0, (reg->offset - defit.offset));
									def[count++] = {defit.id, defit.offset, reg->offset - defit.offset, splitId};
								}
								if ( (reg->offset + reg->size) < (defit.offset + defit.size)) {//if ends after
									HId splitId = gen.next();
									printf ("%d = UpperSplit(%d,%d,%d);\n", splitId, defit.ssaId, reg->offset + reg->size, (defit.offset + defit.size) - (reg->offset + reg->size));
									def[count++] = {defit.id, reg->offset + reg->size, (defit.offset + defit.size) - (reg->offset + reg->size), splitId};
								}
								if (count) {
									defit = def[0];
									if (count == 2)
										regdef.defs.push_back (def[1]);
								} else {
									regdef.defs.erase (it);
									continue;
								}
							}
							++it;
						}
					}
					HSSAGenDef def = {reg->id, reg->offset, reg->size, ssaId };
					regdef.defs.push_back (def);
					return ssaId;
				}
			}
			regDefs.push_back ({reg->parentId, reg->clearParentOnWrite, {{reg->id, reg->offset, reg->size, ssaId }}});
			return ssaId;
		}

		HId getTempDef (HId id, uint64_t offset = 0, uint64_t size = 0) {
			for (HSSAGenDef& def : tmp.defs) {
				if (def.id == id) {
					if (!offset && (!size || def.size == size)) {
						return def.ssaId;
					} else {
						HId id = gen.next();
						printf ("%d = Split(%d,%d,%d)", id, def.ssaId, offset, size ? size : def.size);
						return id;
					}
				}
			}
			assert (false);
			return 0;
		}
		HId createTempDef (HId id, uint64_t size) {
			for (auto it = tmp.defs.begin(); it != tmp.defs.end(); it++) {
				if ( (*it).id == id) {
					HId ssaId = gen.next();
					*it = {id, 0, size, ssaId};
					return ssaId;
				}
			}
			HId ssaId = gen.next();
			tmp.defs.push_back ({id, 0, size, ssaId});
			return ssaId;
		}

		void print (int indent = 0) {
			printf ("Reg Defs -------------\n");
			for (HSSAGenRegDef& regdef : regDefs) {
				printIndent (indent);
				printf ("Parent Reg: %s Cleared? %d\n", arch->getParentRegister (regdef.parentRegId)->name.cstr(), regdef.cleared);
				for (HSSAGenDef& def : regdef.defs) {

					printIndent (indent + 1);
					printf ("Id: %d R:%s Offset: %d Size: %d\n", def.ssaId, arch->getRegister (def.id)->name.cstr(), def.offset, def.size);
				}
			}
			printf ("Inputs\n");
			for (HSSAGenRegDef& regdef : genBB.inputs) {
				printIndent (indent);
				printf ("Parent Reg: %s Cleared? %d\n", arch->getParentRegister (regdef.parentRegId)->name.cstr(), regdef.cleared);
				for (HSSAGenDef& def : regdef.defs) {

					printIndent (indent + 1);
					printf ("Id: %d R:%s Offset: %d Size: %d\n", def.ssaId, arch->getRegister (def.id)->name.cstr(), def.offset, def.size);
				}
			}
		}
	};


	struct HSSAConstData {
		bool isConst;
		uint64_t val;
	};

	HId parseIRtoSSA (HId nodeid, HSSAGenState* state);
	HId parseIRtoSSAExpr (HId nodeid, HSSAGenState* state);
	HId parseIRtoSSAVal (HId nodeid, HSSAGenState* state);
	HId parseIROptoSSA (HIRExpression* expr, HSSAGenState* state);
	HId parseIRAssigntoSSA (HIRExpression* expr, HSSAGenState* state);
	HId parseIRArgExprtoSSA (HIRExpression* expr, HInstArgument* arg, HSSAGenState* state);
	HId parseIRArgValtoSSA (HIRExpression* expr, HInstArgument* arg, HSSAGenState* state);
	HId parseIRSizetoSSA (HIRExpression* expr, HSSAGenState* state);
	HId parseIRExtendtoSSA (HIRExpression* expr, HSSAGenState* state);
	HId parseIRFlagtoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAConstData getIRExprConst (HId nodeId, HSSAGenState* state);

	HId parseIRtoSSA (HId rootId, HSSAGenState* state) {
		return parseIRtoSSAExpr (rootId, state);
	}
	HId parseIRtoSSAExpr (HId nodeid, HSSAGenState* state) {
		if (!nodeid)
			assert (false);
		HIRExpression* expr = state->arch->getIrExpr (nodeid);
		if (!expr)
			assert (false);
		HId returnId = parseIRtoSSAVal (nodeid, state);
		if (expr->type == HIR_EXPR_ARG) {//if it is a memory access load the from memory
			uint64_t i = expr->mod.var_index;
			assert (i && i <= state->instr->opcount);
			if (state->instr->operands[i - 1].type.type == H_LOCAL_TYPE_MEM) {
				HId src = returnId;
				returnId = state->gen.next();
				printf ("%d = #ld(%d,%d)\n", returnId, src, state->instr->operands[i - 1].type.size);
			}
		}
		return returnId;
	}
	HId genOp (const char* str, HIRExpression* expr, HSSAGenState* state, uint64_t offset = 0) {
		if ( (expr->subexprcount - offset) == 1)
			return parseIRtoSSAExpr (expr->subexpressions[offset], state);
		HId ids[3] = {0, 0, 0};
		ids[0] = parseIRtoSSAExpr (expr->subexpressions[offset], state);
		ids[1] = genOp (str, expr, state, offset + 1);
		ids[2] = state->gen.next();
		printf ("%d = %s(%d,%d)\n", ids[2], str, ids[0], ids[1]);
		state->lastOp = ids[2];
		return ids[2];
	}
	HId genOp (const char* str1, const char* str2, HIRExpression* expr, HSSAGenState* state, uint64_t offset = 0) {
		if ( (expr->subexprcount - offset) == 1)
			return parseIRtoSSAExpr (expr->subexpressions[offset], state);
		HId ids[3] = {0, 0, 0};
		ids[0] = parseIRtoSSAExpr (expr->subexpressions[offset], state);
		ids[1] = genOp (str2, expr, state, offset + 1);
		ids[2] = state->gen.next();
		printf ("%d = %s(%d,%d)\n", ids[2], str1, ids[0], ids[1]);
		state->lastOp = ids[2];
		return ids[2];
	}
	HId parseIROptoSSA (HIRExpression* expr, HSSAGenState* state) {
		switch (expr->token) {
		case HIR_TOKEN_ADD:
			return genOp ("+", expr, state);
		case HIR_TOKEN_SADD:
			return genOp ("#sadd", expr, state);
		case HIR_TOKEN_FADD:
			return genOp ("#fadd", expr, state);
		case HIR_TOKEN_SUB:
			return genOp ("-", "+", expr, state);
		case HIR_TOKEN_SSUB:
			return genOp ("#ssub", "#sadd", expr, state);
		case HIR_TOKEN_FSUB:
			return genOp ("#fsub", "#fadd", expr, state);
		case HIR_TOKEN_MUL:
			return genOp ("*", expr, state);
		case HIR_TOKEN_SMUL:
			return genOp ("#smul", expr, state);
		case HIR_TOKEN_FMUL:
			return genOp ("#fmul", expr, state);
		case HIR_TOKEN_DIV:
			return genOp ("#div", "*", expr, state);
		case HIR_TOKEN_SDIV:
			return genOp ("#sdiv", "#smul", expr, state);
		case HIR_TOKEN_FDIV:
			return genOp ("#fdiv", "#fmul", expr, state);
		case HIR_TOKEN_MOD:
			return genOp ("#mod", "*", expr, state);
		case HIR_TOKEN_SMOD:
			return genOp ("#smod", "#smul", expr, state);
		case HIR_TOKEN_FMOD:
			return genOp ("#fmod", "#fmul", expr, state);
		case HIR_TOKEN_NEG:
			return genOp ("#neg", expr, state);
		case HIR_TOKEN_FNEG:
			return genOp ("#fneg", expr, state);
		//Comparison
		case HIR_TOKEN_CMP_E:
			return genOp ("#cmp_eq", expr, state);
		case HIR_TOKEN_CMP_NE:
			return genOp ("#cmp_neq", expr, state);
		case HIR_TOKEN_CMP_L:
			return genOp ("#cmp_l", expr, state);
		case HIR_TOKEN_CMP_LE:
			return genOp ("#cmp_le", expr, state);
		case HIR_TOKEN_CMP_G:
			return genOp ("#cmp_g", expr, state);
		case HIR_TOKEN_CMP_GE:
			return genOp ("#cmp_ge", expr, state);
		case HIR_TOKEN_CMP_NOT:
			return genOp ("#cmp_not", expr, state);
		//
		case HIR_TOKEN_AND:
			return genOp ("#and", expr, state);
		case HIR_TOKEN_OR:
			return genOp ("#or", expr, state);
		case HIR_TOKEN_XOR:
			return genOp ("#xor", expr, state);
		//Bit Operators
		case HIR_TOKEN_BAND:
			return genOp ("#band", expr, state);
		case HIR_TOKEN_BOR:
			return genOp ("#bor", expr, state);
		case HIR_TOKEN_BXOR:
			return genOp ("#bxor", expr, state);
		case HIR_TOKEN_BNOT:
			return genOp ("#bnot", expr, state);
		//Shifts - Rotates
		case HIR_TOKEN_SHR:
			return genOp ("#shr", expr, state);
		case HIR_TOKEN_SHL:
			return genOp ("#shl", expr, state);
		case HIR_TOKEN_SAR:
			return genOp ("#sar", expr, state);
		case HIR_TOKEN_SAL:
			return genOp ("#sal", expr, state);
		case HIR_TOKEN_ROR:
			return genOp ("#ror", expr, state);
		case HIR_TOKEN_ROL:
			return genOp ("#rol", expr, state);
		default:
			assert (false);

		}
		//TODO properly handle instructions
		printf ("Op...\n");
		return 0;
	}
	HId parseIRArgValtoSSA (HIRExpression* expr, HInstArgument* arg, HSSAGenState* state) {
		HId id = 0;
		switch (arg->type.type) {
		case H_LOCAL_TYPE_REGISTER:
			return state->getDefForUse (arg->reg, expr->mod.index, expr->mod.size);
		case H_LOCAL_TYPE_STACK:
			//TODO
			break;
		case H_LOCAL_TYPE_MEM: {
			HId base = arg->mem.base ? state->getDefForUse (arg->mem.base) : 0;
			HId index = arg->mem.index ? state->getDefForUse (arg->mem.index) : 0;
			id = state->gen.next();
			printf ("%d = ", id);
			printf ("[");
			bool pre = false;
			if (base) {
				printf ("%d", base);
				pre = true;
			}
			if (index && arg->mem.scale) {
				if (pre)
					printf (" + ");
				printf ("%d*0x%x", index, arg->mem.scale);
				pre = true;
			}
			if (arg->mem.disp) {
				if (pre)
					printf (" + ");
				printf ("%s0x%x", arg->mem.disp < 0 ? "-" : "", arg->mem.disp < 0 ? - (unsigned) arg->mem.disp : arg->mem.disp);
			}
			printf ("]\n");
			break;
		}
		case H_LOCAL_TYPE_IMM_SIGNED:
		case H_LOCAL_TYPE_IMM_UNSIGNED:
			id = state->gen.next();
			printf ("%d = Value(0x%x, %d)\n", id, arg->ival, arg->type.size);
			break;
		case H_LOCAL_TYPE_IMM_FLOAT:
			id = state->gen.next();
			printf ("%d = FValue(%f, %d)\n", id, arg->fval, arg->type.size);
			break;
		}
		return id;
	}
	HId parseIRFlagtoSSA (HIRExpression* expr, HSSAGenState* state) {
		HId id = state->gen.next();
		switch (expr->token) {
		case HIR_TOKEN_FLAG_C:
			printf ("%d = Flag_Carry(%d)\n", id, state->lastOp);
			return id;
		case HIR_TOKEN_FLAG_A:
			printf ("%d = Flag_HalfCarry(%d)\n", id, state->lastOp);
			return id;
		case HIR_TOKEN_FLAG_P:
			printf ("%d = Flag_Parity(%d)\n", id, state->lastOp);
			return id;
		case HIR_TOKEN_FLAG_O:
			printf ("%d = Flag_Overflow(%d)\n", id, state->lastOp);
			return id;
		case HIR_TOKEN_FLAG_Z:
			printf ("%d = Flag_Zero(%d)\n", id, state->lastOp);
			return id;
		case HIR_TOKEN_FLAG_S:
			printf ("%d = Flag_Signed(%d)\n", id, state->lastOp);
			return id;
		default:
			assert (false);
		}
		return 0;
	}
	HId parseIRAssigntoSSA (HIRExpression* expr, HSSAGenState* state) {

		HId targetId = parseIRtoSSAExpr (expr->subexpressions[1], state);
		HIRExpression* targetExpr = state->arch->getIrExpr (expr->subexpressions[0]);
		if (targetExpr) {
			switch (targetExpr->type) {
			case HIR_EXPR_TMP: {
				//TODO get Size of targetId
				return state->createTempDef (targetExpr->mod.var_index, 0);
			}
			break;
			case HIR_EXPR_ARG: {
				uint64_t i = targetExpr->mod.var_index;
				assert (i && i <= state->instr->opcount);
				HInstArgument& arg = state->instr->operands[i - 1];
				switch (arg.type.type) {
				case H_LOCAL_TYPE_REGISTER: {
					assert (!targetExpr->mod.index && !targetExpr->mod.size);
					state->createDef (arg.reg, targetId);
					return targetId;
				}
				case H_LOCAL_TYPE_STACK:
					//TODO
					break;
				case H_LOCAL_TYPE_MEM: {
					HId val = parseIRArgValtoSSA (targetExpr, &arg, state);
					HId id = state->gen.next();
					printf ("%d = #st(%d,%d)\n", id, val, targetId);
					return id;
				}
				default:
					assert (false);
				}
			}
			break;
			case HIR_EXPR_STCK:
				//TODO
				break;
			case HIR_EXPR_REG: {
				assert (!targetExpr->mod.index && !targetExpr->mod.size);
				return state->createDef (targetExpr->regacces, targetId);
			}
			default://can not write to other expressions
				break;
			}
			assert (false);
		}
		printf ("Assign\n");
	}
	HId parseIRSizetoSSA (HIRExpression* expr, HSSAGenState* state) {
		HId id = state->gen.next();
		HIRExpression* subexpr = state->arch->getIrExpr (expr->subexpressions[0]);
		uint64_t size = 0;
		if (subexpr->mod.size) {
			size = subexpr->mod.size;
		} else {
			if (subexpr->mod.var_index) {
				uint64_t i = subexpr->mod.var_index;
				assert (i && i <= state->instr->opcount);
				size = state->instr->operands[i - 1].type.size;
			}
			if (subexpr->regacces) {
				HRegister* reg = state->arch->getRegister (subexpr->regacces);
				if (reg)
					size = reg->size;
			}
		}
		if (expr->type == HIR_EXPR_SIZE)
			printf ("%d = Value(0x%x, 0)\n", id, subexpr->mod.size / state->arch->wordbase);
		else if (expr->type == HIR_EXPR_BSIZE)
			printf ("%d = Value(0x%x, 0)\n", id, subexpr->mod.size);
		else
			assert (false);
		return id;
	}
	HId parseIRExtendtoSSA (HIRExpression* expr, HSSAGenState* state) {
		HId ids[expr->subexprcount] = {0};
		for (size_t i = 0; i < expr->subexprcount; i++) {
			ids[i] = parseIRtoSSAExpr (expr->subexpressions[i], state);
		}
		HId id = state->gen.next();
		printf ("%d = Extend(%d", id, ids[0]);
		for (size_t i = 1; i < expr->subexprcount; i++) {
			printf (", %d", ids[i]);
		}
		printf (")\n");
		return id;
	}
	HId parseIRtoSSAVal (HId nodeid, HSSAGenState* state) {
		if (!nodeid)
			assert (false);
		HIRExpression* expr = state->arch->getIrExpr (nodeid);
		if (!expr)
			assert (false);

		HId id = 0;
		switch (expr->type) {
		case HIR_EXPR_UNDEF:
			//TODO
			return 0;
		case HIR_EXPR_OP:
			return parseIROptoSSA (expr, state);
		case HIR_EXPR_NOP:
			printf ("Nop\n");
			break;
		case HIR_EXPR_ASSIGN:
			return parseIRAssigntoSSA (expr, state);
		case HIR_EXPR_FLOAT:
			id = state->gen.next();
			printf ("%d = FValue(%f, %d)\n", id, expr->fvalue, expr->mod.size);
			break;
		case HIR_EXPR_NUMBER:
			id = state->gen.next();
			printf ("%d = Value(%d, %d)\n", id, expr->value, expr->mod.size);
			break;
		case HIR_EXPR_SEQUENCE:
			for (int i = 0; i < expr->subexprcount; i++) {
				parseIRtoSSAExpr (expr->subexpressions[i], state);
			}
			break;
		case HIR_EXPR_SIZE:
		case HIR_EXPR_BSIZE:
			return parseIRSizetoSSA (expr, state);
		case HIR_EXPR_LOOP:
			printf ("jmp(CND)\n");
			printf ("START:\n");
			for (int i = 1; i < expr->subexprcount; i++) {
				parseIRtoSSAExpr (expr->subexpressions[i], state);
			}
			printf ("CND:\n");
			printf ("jnz(START,%d);\n", parseIRtoSSAExpr (expr->subexpressions[0], state));
			printf ("END:\n");
			break;
		case HIR_EXPR_IF: {
			HSSAConstData constDate = getIRExprConst (expr->subexpressions[0], state);
			if (constDate.isConst) {
				assert (expr->subexprcount >= 2); //no expressions
				assert (! (constDate.val && expr->subexprcount == 2)); //only branch for zero, but value is not zero

				uint64_t selectVal = constDate.val + 1;
				if (selectVal >= expr->subexprcount) selectVal = expr->subexprcount - 1;
				return parseIRtoSSAExpr (expr->subexpressions[selectVal], state);
			} else {
				HId cond = parseIRtoSSAExpr (expr->subexpressions[0], state);
				if (expr->subexprcount == 2) {
					printf ("jz(%d,L)\n", cond);
					parseIRtoSSAExpr (expr->subexpressions[1], state);
					printf ("L:\n");
				} else {
					printf ("br(%d", cond);
					int i;
					for (i = 1; i < HIR_LOCAL_SUBEXPRESSION_COUNT; i++) {
						if (!expr->subexpressions[i]) break;
						printf (",L%d", i);
					}
					printf (")\n");
					for (i = 1; i < HIR_LOCAL_SUBEXPRESSION_COUNT; i++) {
						if (!expr->subexpressions[i]) break;
						printf ("L%d:", i);
						parseIRtoSSAExpr (expr->subexpressions[i], state);
						printf ("jmp(END)\n");
					}
					printf ("END:\n");
				}
			}
		}
		break;
		case HIR_EXPR_APPEND: {
			id = state->gen.next();
			printf ("%d = Extend(", id);
			printf ("%d", parseIRtoSSAExpr (expr->subexpressions[0], state));
			for (int i = 1; i < expr->subexprcount; i++) {
				printf (", %d", parseIRtoSSAExpr (expr->subexpressions[i], state));
			}
			printf (");\n", id);
		}
		break;

		case HIR_EXPR_EXTEND:
		case HIR_EXPR_SEXTEND:
		case HIR_EXPR_FEXTEND:
			return parseIRExtendtoSSA (expr, state);

		case HIR_EXPR_TMP:
			return state->getTempDef (expr->mod.var_index, expr->mod.index, expr->mod.size);
		case HIR_EXPR_ARG: {
			uint64_t i = expr->mod.var_index;
			assert (i && i <= state->instr->opcount);
			return parseIRArgValtoSSA (expr, &state->instr->operands[i - 1], state);
		}
		case HIR_EXPR_STCK:
			//TODO
			break;
		case HIR_EXPR_REG:
			return state->getDefForUse (expr->regacces, expr->mod.index, expr->mod.size);
		case HIR_EXPR_FLAG:
			return parseIRFlagtoSSA (expr, state);

		case HIR_EXPR_REC:
			printf ("Rec %s\n", expr->mod.name_index.cstr());
			//TODO
			break;
		case HIR_EXPR_CUSTOM:
			//TODO
			break;

		case HIR_EXPR_JMP:
			printf ("jmp(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state));
			break;
		case HIR_EXPR_RJMP:
			printf ("rjmp(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state));
			break;
		case HIR_EXPR_CALL:
			printf ("call(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state));
			break;
		case HIR_EXPR_RET:
			printf ("ret(%d)\n", state->getDefForUse (state->arch->getRegister ("rax")));
			break;
		case HIR_EXPR_SYSCALL:
			printf ("syscall(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state));
			break;
		case HIR_EXPR_TRAP:
			printf ("trap(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state));
			break;

		case HIR_EXPR_VAL:
			return parseIRtoSSAVal (expr->subexpressions[0], state);

		case HIR_EXPR_CAST2F:
			id = parseIRtoSSAExpr (expr->subexpressions[0], state);
			printf ("%d = Cast_to_Float(%d)\n", id, expr->subexpressions[0]);
			break;
		case HIR_EXPR_CAST2I:
			id = parseIRtoSSAExpr (expr->subexpressions[0], state);
			printf ("%d = Cast_to_Int(%d)\n", id, expr->subexpressions[0]);
			break;

		case HIR_EXPR_PUSH:
			//TODO
			break;
		case HIR_EXPR_POP:
			//TODO
			break;

		case HIR_EXPR_STORE: {
			printf ("#st(%d,%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state), parseIRtoSSAExpr (expr->subexpressions[1], state));
		}
		break;
		case HIR_EXPR_LOAD: {
			HId temp = parseIRtoSSAExpr (expr->subexpressions[0], state);
			id = state->gen.next();
			printf ("%d = #ld(%d)\n", id, temp);
		}
		break;
		}
		return id;
	}

	HSSAConstData getIRExprConst (HId nodeId, HSSAGenState* state) {
		HIRExpression* expr = state->arch->getIrExpr (nodeId);

		switch (expr->type) {
		case HIR_EXPR_OP: {
			/*HSSAConstData consts[expr->subexprcount];
			for (int i = 0; i < expr->subexprcount; i++) {
				consts[i] = getIRExprConst (expr->subexpressions[i], state);
				if (!consts[i].isConst)
					return {false, HSSA_CONST_INVALID, 0};
			}
			switch (expr->token) {
			case HIR_TOKEN_ADD:
			case HIR_TOKEN_SADD: {
				uint64_t val = 0;
				for (int i = 0; i < expr->subexprcount; i++) {
					if (consts[i].constType != HSSA_CONST_INT)
						return {false, HSSA_CONST_INVALID, 0};
					val += consts[i].val;
				}
				return {true, HSSA_CONST_INT, val};
			}
			case HIR_TOKEN_FADD: {
				double val = 0;
				for (int i = 0; i < expr->subexprcount; i++) {
					if (consts[i].constType != HSSA_CONST_FLOAT)
						return {false, HSSA_CONST_INVALID, 0};
					val += consts[i].fval;
				}
				return {true, HSSA_CONST_INT, 0, val};
			}
			case HIR_TOKEN_SUB:
			case HIR_TOKEN_SSUB: {
				if (consts[0].constType != HSSA_CONST_INT)
					return {false, HSSA_CONST_INVALID, 0};
				uint64_t val = consts[0].val;
				for (int i = 1; i < expr->subexprcount; i++) {
					if (consts[i].constType != HSSA_CONST_INT)
						return {false, HSSA_CONST_INVALID, 0};
					val -= consts[i].val;
				}
				return {true, HSSA_CONST_INT, val};
			}
			case HIR_TOKEN_FSUB: {
				if (consts[0].constType != HSSA_CONST_FLOAT)
					return {false, HSSA_CONST_INVALID, 0};
				double val = consts[0].fval;
				for (int i = 1; i < expr->subexprcount; i++) {
					if (consts[i].constType != HSSA_CONST_FLOAT)
						return {false, HSSA_CONST_INVALID, 0};
					val -= consts[i].fval;
				}
				return {true, HSSA_CONST_INT, 0, val};
			}
			default:
				return {false, HSSA_CONST_INVALID, 0};
			}*/
		}
		case HIR_EXPR_NOP:
			return {true, 0};
		case HIR_EXPR_FLOAT:
			return {false, 0};
		case HIR_EXPR_NUMBER:
			return {true, expr->value};
		case HIR_EXPR_SIZE: {
			HIRExpression* subexpr = state->arch->getIrExpr (expr->subexpressions[0]);
			if (subexpr->mod.size) {
				return {true, subexpr->mod.size};
			} else {
				uint64_t i = subexpr->mod.var_index;
				assert (i && i <= state->instr->opcount);
				return {true, state->instr->operands[i - 1].type.size};
			}
		}
		case HIR_EXPR_BSIZE: {
			HIRExpression* subexpr = state->arch->getIrExpr (expr->subexpressions[0]);
			if (subexpr->mod.size) {
				return {true, subexpr->mod.size / state->arch->wordbase};
			} else {
				uint64_t i = subexpr->mod.var_index;
				assert (i && i <= state->instr->opcount);
				return {true, state->instr->operands[i - 1].type.size / state->arch->wordbase};
			}
		}
		/*case HIR_EXPR_APPEND:
		case HIR_EXPR_EXTEND:
		case HIR_EXPR_SEXTEND:
		case HIR_EXPR_FEXTEND:
		case HIR_EXPR_TMP:
		case HIR_EXPR_ARG:
		case HIR_EXPR_STCK:
		case HIR_EXPR_VAL:
		case HIR_EXPR_MEM:
		case HIR_EXPR_CAST2F:
		case HIR_EXPR_CAST2I:*/
		default:
			return {false, 0};
		}
		return {false, 0};
	}


	bool HSSAGenerator::parseFunction (HFunction * function) {
		HSSAGenState state;
		state.arch = arch;

		for (HBasicBlock& bb : function->basicblocks) {
			printf ("Basic Block ------------------------------\n");

			for (HInstruction& instr : bb.instructions) {
				HIRRepresentation ir = instr.instrdef->il_string[instr.opcount];
				if (ir) {
					instr.print (arch);
					printf ("SSA------------------\n");
					state.instr = &instr;
					HId end = parseIRtoSSA (ir.rootExpr, &state);
				}
				//parseInstruction (&instr);
			}
		}
		state.print (1);
	}
}
