
#include "HSSAGen.h"
#include <assert.h>
#include <algorithm>

namespace holodec {

	struct HSSARegDef {
		HId parentRegId;
		HId regId;//can be 0
		uint64_t offset;
		uint64_t size;
		HId ssaId;
	};
	struct HSSAStckDef {
		HId id;
		uint64_t size;
		HId ssaId;
	};
	struct HSSATmpDef {
		HId id;
		uint64_t size;
		HId ssaId;
	};

	bool operator< (HSSARegDef& lhs, HSSARegDef& rhs) {
		return lhs.offset < rhs.offset;
	}


	struct HSSAGenState {
		HArchitecture* arch;
		HId flag_gen = 0;
		HMap<HId, HId> map;//TODO remove and change into something faster
		HIdGenerator gen;
		HList<HSSARegDef> regDefs;
		HList<HSSAStckDef> stackDefs;
		HList<HSSATmpDef> tempDefs;
		HInstruction* instr;
		HId lastOp;

		void addRegDef (HSSARegDef newdef) {
			//printf ("Add Reg Def\n");
			//printf ("Id: %d P:%s - R:%s Offset: %d Size: %d\n", newdef.ssaId, arch->getRegister (newdef.parentRegId)->name.cstr(), arch->getRegister (newdef.regId)->name.cstr(), newdef.offset, newdef.size);
			HRegister* reg = arch->getRegister (newdef.regId);
			if (newdef.size == 0)
				newdef.size = reg->size - newdef.offset;
			for (auto it = regDefs.begin(); it != regDefs.end();) {
				HSSARegDef& defit = *it;
				if (reg->clearParentOnWrite) {//if parent is reset on write
					if (newdef.parentRegId && newdef.parentRegId == defit.parentRegId) {//TODO don't clear everything but only things outside of register we are writing to
						regDefs.erase (it);
						continue;
					}
				} else {
					if (newdef.parentRegId && newdef.parentRegId == defit.parentRegId) {//if same parent reg
						if (newdef.offset < (defit.offset + defit.size) && defit.offset < (newdef.offset + newdef.size)) { //if there is an intersection
							int count = 0;
							HSSARegDef def[2];
							if (defit.offset < newdef.offset) { //if starts before
								HId splitId = gen.next();
								printf ("%d = LowerSplit(%d,%d,%d);\n", splitId, defit.ssaId, 0, (newdef.offset - defit.offset));
								def[count++] = {defit.parentRegId, defit.regId, defit.offset, newdef.offset - defit.offset, splitId};
							}
							if ( (newdef.offset + newdef.size) < (defit.offset + defit.size)) {//if ends after
								HId splitId = gen.next();
								printf ("%d = UpperSplit(%d,%d,%d);\n", splitId, defit.ssaId, newdef.offset + newdef.size, (defit.offset + defit.size) - (newdef.offset + newdef.size));
								def[count++] = {defit.parentRegId, defit.regId, newdef.offset + newdef.size, (defit.offset + defit.size) - (newdef.offset + newdef.size), splitId};
							}
							if (count) {
								defit = def[0];
								if (count == 2)
									regDefs.push_back (def[1]);
							} else {
								regDefs.erase (it);
								continue;
							}
						}
					}
				}
				it++;
			}
			regDefs.push_back (newdef);
			if (reg->clearParentOnWrite) {//if parent is reset on write
				HRegister* parentReg = arch->getParentRegister (reg->id);
				if (parentReg->id != reg->id) {
					if (reg->offset) {
						HSSARegDef def = {parentReg->id, parentReg->id, 0, reg->offset, gen.next() };
						regDefs.push_back (def);
						printf ("%d = Value(0, %d);\n", def.ssaId, reg->offset);
					}
					if ( (reg->offset + reg->size) < (parentReg->offset + parentReg->size)) {
						HSSARegDef def = {parentReg->id, parentReg->id, (parentReg->offset + parentReg->size), (parentReg->offset + parentReg->size) - (reg->offset + reg->size), gen.next() };
						regDefs.push_back (def);
						printf ("%d = Value(0, %d);\n", def.ssaId, (parentReg->offset + parentReg->size) - (reg->offset + reg->size));
					}
				}
			}
		}
		HId addRegDef (HId regId, uint64_t offset, uint64_t size) {
			HRegister* parentreg = arch->getParentRegister (regId);
			HRegister* reg = arch->getRegister (regId);
			HSSARegDef def = {parentreg->id, regId, reg->offset + offset, size, gen.next() };
			addRegDef (def);
			return def.ssaId;
		}

		HSSARegDef getRegUseDef (HRegister* reg, uint64_t offset, uint64_t size) {
			if (size == 0)
				size = reg->size - offset;
			HRegister* parentreg = arch->getParentRegister (reg->id);
			if (!parentreg) {
				return {0, 0, 0, 0, 0};
			}
			int localdefcount = 0;
			HSSARegDef localdefs[20];
			for (auto it = regDefs.begin(); it != regDefs.end();) {
				HSSARegDef& def = *it;
				if (def.parentRegId == parentreg->id) {
					if (def.offset == offset && def.size == size) //perfect match
						return def;
					if (def.offset >= offset) { //start after
						if (def.offset < offset + size) { //but before end
							//merge target
							localdefs[localdefcount++] = def;
							regDefs.erase (it);
							continue;
						}
					} else if (def.offset + def.size > offset) { //start before but intersect
						//merge target
						localdefs[localdefcount++] = def;
						regDefs.erase (it);
						continue;
					}
				}
				it++;
			}
			//first split if needed
			for (int i = 0; i < localdefcount; i++) {
				HSSARegDef& def = localdefs[i];
				if (def.offset < offset) {//split of lower nibble
					HId lowerId = gen.next(), higherId = gen.next();
					uint64_t lowersize = offset - def.offset;
					printf ("%d = Split(%d,%d,%d)\n", lowerId, def.ssaId, 0, lowersize);
					printf ("%d = Split(%d,%d,%d)\n", higherId, def.ssaId, lowersize, def.size - lowersize);
					regDefs.push_back ({def.parentRegId, 0, def.offset, lowersize, lowerId});
					def.ssaId = higherId;
					def.offset += lowersize;
					def.size -= lowersize;
					def.regId = 0;
				}
				if (def.offset + def.size > offset + size) {//split of upper nibble
					HId lowerId = gen.next(), higherId = gen.next();
					uint64_t highersize = (def.offset + def.size) - (offset + size);
					printf ("%d = Split(%d,%d,%d)\n", lowerId, def.ssaId, 0, def.size - highersize);
					printf ("%d = Split(%d,%d,%d)\n", higherId, def.ssaId, def.size - highersize, highersize);
					regDefs.push_back ({def.parentRegId, 0, def.offset + def.size - highersize, highersize, higherId});
					def.ssaId = lowerId;
					def.size -= highersize;
					def.regId = 0;
				}
			}
			//then merge if needed
			if (localdefcount == 1) { //this case is the most likely
				if (localdefs[0].offset == offset && localdefs[0].size == size)
					return localdefs[0];
				else {
					//TODO
					printf ("Extend with 0s missing\n");
					return localdefs[0];
				}
			}
			//assert(localdefcount);
			if (!localdefcount) { //this case is the most likely
				return {0, 0, 0, 0, 0xFFFFFFF};
			}

			//sort defs by offset
			std::sort (localdefs, localdefs + localdefcount);

			HId id = gen.next();
			printf ("%d = Extend(", id);
			uint64_t resultsize = localdefs[0].size;
			uint64_t lastupperBound = localdefs[0].offset + localdefs[0].size;
			printf ("%d", localdefs[0]);

			for (int i = 1; i < localdefcount; i++) {
				if (lastupperBound != localdefs[i].offset) {
					printf ("Bound-Error %d - %d\n", lastupperBound, localdefs[i].offset);
				}
				printf (", %d", localdefs[i]);
				resultsize += localdefs[i].size;
				lastupperBound = localdefs[i].offset + localdefs[i].size;
			}
			printf (")\n");
			return {parentreg->id, 0, offset, resultsize, id};
		};
		HSSARegDef getRegUseDef (HRegister* reg) {
			for (HSSARegDef& def : regDefs) {
				if (def.regId == reg->id)
					return def;
			}
			return getRegUseDef (reg, reg->offset, reg->size);
		};
		HSSARegDef getRegUseDef (HId reg, uint64_t offset, uint64_t size) {
			return getRegUseDef (arch->getRegister (reg), offset, size);
		};
		HSSARegDef getRegUseDef (HId reg) {
			return getRegUseDef (arch->getRegister (reg));
		};
		HId getTempUseDef (HId id, uint64_t offset = 0, uint64_t size = 0) {
			for (HSSATmpDef& def : tempDefs) {
				if (def.id == id) {
					if (!offset && !size) {
						return def.ssaId;
					} else {
						HId id = gen.next();
						printf ("%d = Split(%d,%d,%d)", id, def.ssaId, offset, size ? size : def.size);
					}
				}
			}
		}
		void addTempDef (HSSATmpDef newdef) {
			for (auto it = tempDefs.begin(); it != tempDefs.end(); it++) {
				if ( (*it).id == newdef.id) {
					*it = newdef;
					return;
				}
			}
			tempDefs.push_back (newdef);
		}

		void print (int indent = 0) {
			printf ("Reg Defs -------------\n");
			for (HSSARegDef& def : regDefs) {
				printIndent (indent);
				printf ("Id: %d P:%s - R:%s Offset: %d Size: %d\n", def.ssaId, arch->getRegister (def.parentRegId)->name.cstr(), arch->getRegister (def.regId)->name.cstr(), def.offset, def.size);
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
			return 0;
		HIRExpression* expr = state->arch->getIrExpr (nodeid);
		if (!expr)
			return 0;
		HId returnId = parseIRtoSSAVal (nodeid, state);
		if (expr->type == HIR_EXPR_ARG) {
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
			return state->getRegUseDef (arg->reg, expr->mod.index, expr->mod.size).ssaId;
		case H_LOCAL_TYPE_STACK:
			//TODO
			break;
		case H_LOCAL_TYPE_MEM: {
			HId base = arg->mem.base ? state->getRegUseDef (arg->mem.base).ssaId : 0;
			HId index = arg->mem.index ? state->getRegUseDef (arg->mem.index).ssaId : 0;
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
			return id;
		}
		case H_LOCAL_TYPE_IMM_SIGNED:
			id = state->gen.next();
			printf ("%d = Value(%d, %d)\n", id, arg->ival, arg->type.size);
			return id;
		case H_LOCAL_TYPE_IMM_UNSIGNED:
			id = state->gen.next();
			printf ("%d = Value(0x%x, %d)\n", id, arg->ival, arg->type.size);
			return id;
		case H_LOCAL_TYPE_IMM_FLOAT:
			id = state->gen.next();
			printf ("%d = FValue(%f, %d)\n", id, arg->fval, arg->type.size);
			return id;
		}
		return 0;
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
				HSSATmpDef tmpDef = {targetExpr->mod.var_index, 0, targetId};
				state->addTempDef (tmpDef);
				return targetId;
			}
			break;
			case HIR_EXPR_ARG: {
				uint64_t i = targetExpr->mod.var_index;
				assert (i && i <= state->instr->opcount);
				HInstArgument& arg = state->instr->operands[i - 1];
				switch (arg.type.type) {
				case H_LOCAL_TYPE_REGISTER: {
					HRegister* reg = state->arch->getRegister (arg.reg);
					HSSARegDef regdef = {reg->parentId, reg->id, reg->offset + expr->mod.index, expr->mod.size, targetId};
					state->addRegDef (regdef);
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
			case HIR_EXPR_REG:
				return state->addRegDef (targetExpr->regacces, targetExpr->mod.index, targetExpr->mod.size);
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
			uint64_t i = subexpr->mod.var_index;
			assert (i && i <= state->instr->opcount);
			size = state->instr->operands[i - 1].type.size;
		}
		if (expr->type == HIR_EXPR_SIZE)
			printf ("%d = Value(0x%x, 0)\n", id, subexpr->mod.size / state->arch->bitbase);
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
			return 0;
		HIRExpression* expr = state->arch->getIrExpr (nodeid);
		if (!expr)
			return 0;

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
			//TODO
			break;
		case HIR_EXPR_IF: {
			HSSAConstData constDate = getIRExprConst (expr->subexpressions[0], state);
			if (constDate.isConst) {
				if (expr->subexprcount < 2) //no expressions
					return 0;
				if (constDate.val && expr->subexprcount == 2) //only branch for zero, but value is not zero
					return 0;
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
		case HIR_EXPR_APPEND:
			//TODO
			break;

		case HIR_EXPR_EXTEND:
		case HIR_EXPR_SEXTEND:
		case HIR_EXPR_FEXTEND:
			return parseIRExtendtoSSA (expr, state);

		case HIR_EXPR_TMP:
			return state->getTempUseDef (expr->mod.var_index, expr->mod.index, expr->mod.size);
		case HIR_EXPR_ARG: {
			uint64_t i = expr->mod.var_index;
			assert (i && i <= state->instr->opcount);
			return parseIRArgValtoSSA (expr, &state->instr->operands[i - 1], state);
		}
		case HIR_EXPR_STCK:
			//TODO
			break;
		case HIR_EXPR_REG:
			return state->getRegUseDef (expr->regacces, expr->mod.index, expr->mod.size).ssaId;
		case HIR_EXPR_FLAG:
			return parseIRFlagtoSSA (expr, state);

		case HIR_EXPR_REC:
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
			printf ("ret(%d)\n", state->getRegUseDef (state->arch->getRegister ("rax")));
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
			return id;
		case HIR_EXPR_CAST2I:
			id = parseIRtoSSAExpr (expr->subexpressions[0], state);
			printf ("%d = Cast_to_Int(%d)\n", id, expr->subexpressions[0]);
			return id;

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
			return id;
		}
		}
		return 0;
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
				return {true, subexpr->mod.size / state->arch->bitbase};
			} else {
				uint64_t i = subexpr->mod.var_index;
				assert (i && i <= state->instr->opcount);
				return {true, state->instr->operands[i - 1].type.size / state->arch->bitbase};
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
		printf ("Set Register Defines");
		for (HRegister& reg : arch->registers.list) {
			state.addRegDef (reg.id, reg.offset, reg.size);
		}

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
