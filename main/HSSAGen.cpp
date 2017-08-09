
#include "HSSAGen.h"
#include <assert.h>
#include <algorithm>
#include "HSSA.h"

namespace holodec {

	enum HSSAGenArgType {
		HSSAGEN_TYPE_ARG_SSA,//temporary value
		HSSAGEN_TYPE_ARG_MEM,//memory location
		HSSAGEN_TYPE_ARG_REG,//register
		HSSAGEN_TYPE_ARG_STCK,//stack
		HSSAGEN_TYPE_ARG_VAL,//value
		HSSAGEN_TYPE_ARG_FVAL,//floating point value
	};

	struct HSSAGenArgument {
		HSSAGenArgType type;

		HSSAId ssaId;
		struct {
			HId base, index;//regs
			int64_t scale, disp;
		} mem;
		HId reg;
		HId stackid;
		HId stackindex;
		uint64_t value;
		double fvalue;

		uint64_t size;

		HSSAGenArgument() = default;

		HSSAGenArgument (HInstArgument arg) {
			switch (arg.type) {
			case H_LOCAL_TYPE_REGISTER:
				type = HSSAGEN_TYPE_ARG_REG;
				reg = arg.reg;
				break;
			case H_LOCAL_TYPE_STACK:
				type = HSSAGEN_TYPE_ARG_STCK;
				stackid = arg.stack.id;
				stackindex = arg.stack.index;
				break;
			case H_LOCAL_TYPE_MEM:
				type = HSSAGEN_TYPE_ARG_MEM;
				mem.base = arg.mem.base;
				mem.index = arg.mem.index;
				mem.scale = arg.mem.scale;
				mem.disp = arg.mem.disp;
				break;
			case H_LOCAL_TYPE_IMM_SIGNED:
				type = HSSAGEN_TYPE_ARG_VAL;
				value = arg.ival;
				break;
			case H_LOCAL_TYPE_IMM_UNSIGNED:
				type = HSSAGEN_TYPE_ARG_VAL;
				value = arg.ival;
				break;
			case H_LOCAL_TYPE_IMM_FLOAT:
				type = HSSAGEN_TYPE_ARG_FVAL;
				fvalue = arg.fval;
				break;
			}
			size = arg.size;
		}
	};

	struct HSSAGenDef {
		HId id;//for Regdef -> registerId, for stack and tmp -> index
		uint64_t offset;
		uint64_t size;
		HSSAId ssaId;
	};
	struct HSSAGenRegDef {
		HId parentRegId;
		bool cleared;
		HList<HSSAGenDef> defs;
	};
	struct HSSAGenBasicBlock {
		HId id;
		HList<HSSAGenRegDef> inputs;
		HList<HSSAGenRegDef> outputs;
		HList<HSSAExpression> exprs;
	};
	struct HSSAGenStck {
		HString name;
		HList<HSSAId> defs;//size - stck_index
	};
	struct HSSAGenTmp {
		HList<HSSAGenDef> defs;
	};

	bool operator< (HSSAGenDef& lhs, HSSAGenDef& rhs) {
		return lhs.offset < rhs.offset;
	}

	struct HSSAGenState {
		HArchitecture* arch;
		HIdGenerator gen;


		HIdList<HSSAGenBasicBlock> bbs;

		HSSAGenTmp tmp;//per instruction

		//HInstruction* instr;
		HSSAId lastOp;

		HList<HSSAGenStck> stackDefs;

		HList<HSSAGenArgument> args;

		HId activeBasicBlock;

		HId genNewBasicBlock() {
			HSSAGenBasicBlock bb = HSSAGenBasicBlock();
			HId id = bbs.add (bb);
			activeBasicBlock = id;
			return id;
		}
		HSSAGenBasicBlock* getActiveBasicBlock() {
			for (HSSAGenBasicBlock& bb : bbs) {
				if (bb.id == activeBasicBlock) {
					return &bb;
				}
			}
			return nullptr;
		}
		HSSAId addSSAExpression (HSSAExpression expr) {
			for (HSSAGenBasicBlock& bb : bbs) {
				if (bb.id == activeBasicBlock) {
					expr.id = gen.next();
					bb.exprs.push_back (expr);
					return {expr.id, activeBasicBlock};
				}
			}
			assert (false);
			return {0, 0};
		}
		HSSAExpression* getSSAExpression (HSSAId id) {
			for (HSSAGenBasicBlock& bb : bbs) {
				if (bb.id == id.bbid) {
					for (HSSAExpression& expr : bb.exprs) {
						if (id.id == expr.id)
							return &expr;
					}
					break;
				}
			}
			return nullptr;
		}


		HSSAGenDef createValOrInput (HSSAGenRegDef* regdef, HRegister* reg, uint64_t lowerbound, uint64_t upperbound) {
			if (lowerbound < upperbound) {
				if (regdef->cleared) {
					HSSAId id = addSSAExpression ({0, HSSA_EXPR_VALUE, HSSA_OP_INVALID, HSSA_TYPE_UINT, upperbound - lowerbound, 0, {HSSAArg::createArg (upperbound - lowerbound) }});
					printf ("%d = Value(0x0,%d)\n", id.id, upperbound - lowerbound);
					return {reg->id, lowerbound, upperbound - lowerbound, id};
				} else {
					HSSAId input;
					HSSAGenRegDef* foundregdef = nullptr;
					for (HSSAGenRegDef& regdef : getActiveBasicBlock()->inputs) {
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
					input = addSSAExpression ({0, HSSA_EXPR_INPUT, HSSA_OP_INVALID, HSSA_TYPE_UINT, upperbound - lowerbound, 0, {}});
					printf ("%d = Input(%s,%d)\n", input.id, reg->name.cstr(), upperbound - lowerbound);
					HSSAGenDef def = {reg->id, lowerbound, upperbound - lowerbound, input};
					if (foundregdef) {
						foundregdef->defs.push_back (def);
					} else {
						getActiveBasicBlock()->inputs.push_back ({reg->parentId, false, {def}});
					}
					return def;
				}
			}
			return {0, 0, 0, 0};
		}

		void removeDef (HId regId) {
			HRegister* reg = arch->getRegister (regId);
			HSSAId id = addSSAExpression ({0, HSSA_EXPR_UNDEF, HSSA_OP_INVALID, HSSA_TYPE_UINT, reg->size, 0, {}});
			printf ("%d = undef();\n", id.id);
			createDef (regId, id);
		}
		HSSAId getDefForUse (HId regId, uint64_t offset = 0, uint64_t size = 0) {
			return getDefForUse (arch->getRegister (regId), offset, size);
		}
		HSSAId getDefForUse (HRegister* reg, uint64_t offset = 0, uint64_t size = 0) {
			size = size == 0 ? reg->size - offset : size;
			offset += reg->offset;//adjust for parent register
			for (HSSAGenRegDef& regdef : getActiveBasicBlock()->outputs) {
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
							if (newoffset == 0 && newsize == def.size) {
								localdefs[localdefcount++] = def;
							} else {
								HSSAId newSSA = addSSAExpression ({0, HSSA_EXPR_SPLIT, HSSA_OP_INVALID, HSSA_TYPE_UINT, newsize, 0, {HSSAArg::createArg (def.ssaId), HSSAArg::createArg (def.offset + newoffset), HSSAArg::createArg (newsize) }});
								localdefs[localdefcount++] = {def.id, def.offset + newoffset, newsize, newSSA};
							}
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
						HSSAId id = addSSAExpression ({0, HSSA_EXPR_APPEND, HSSA_OP_INVALID, HSSA_TYPE_UINT, size, 0, {}});
						HSSAExpression* expr = getSSAExpression (id);
						printf ("%d = Append(", id.id);

						uint64_t resultsize = 0;
						uint64_t lastupperBound = offset;
						for (int i = 0; i < localdefcount; i++) {
							assert (lastupperBound == localdefs[i].offset);
							if (i)
								printf (", ");
							expr->subExpressions.add (HSSAArg::createArg (localdefs[i].ssaId));
							printf ("%d", localdefs[i].ssaId.id);
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
		HSSAId createDef (HId regId, HSSAId ssaId) {
			HRegister* reg = arch->getRegister (regId);
			//printf ("Add Reg Def\n");
			//printf ("%d = P:%s - R:%s Offset: %d Size: %d\n", ssaId, arch->getRegister (reg->parentId)->name.cstr(), arch->getRegister (reg->id)->name.cstr(), reg->offset, reg->size);
			for (HSSAGenRegDef& regdef : getActiveBasicBlock()->outputs) {
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
									uint64_t offset = 0;
									uint64_t size = reg->offset - defit.offset;
									HSSAId splitId = addSSAExpression ({0, HSSA_EXPR_SPLIT, HSSA_OP_INVALID, HSSA_TYPE_UINT, size, 0, {HSSAArg::createArg (defit.ssaId), HSSAArg::createArg (offset), HSSAArg::createArg (size) }});
									printf ("%d = Split(%d,%d,%d);\n", splitId.id, defit.ssaId.id, 0, (reg->offset - defit.offset));
									def[count++] = {defit.id, defit.offset, reg->offset - defit.offset, splitId};
								}
								if ( (reg->offset + reg->size) < (defit.offset + defit.size)) {//if ends after
									uint64_t offset = reg->offset + reg->size;
									uint64_t size = (defit.offset + defit.size) - (reg->offset + reg->size);
									HSSAId splitId = addSSAExpression ({0, HSSA_EXPR_SPLIT, HSSA_OP_INVALID, HSSA_TYPE_UINT, size, 0, {HSSAArg::createArg (defit.ssaId), HSSAArg::createArg (offset), HSSAArg::createArg (size) }});
									printf ("%d = Split(%d,%d,%d);\n", splitId.id, defit.ssaId.id, offset, size);
									def[count++] = {defit.id, offset, size, splitId};
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
			getActiveBasicBlock()->outputs.push_back ({reg->parentId, reg->clearParentOnWrite, {{reg->id, reg->offset, reg->size, ssaId }}});
			return ssaId;
		}
		HSSAGenStck* getStckGen (HStack* stack) {
			HSSAGenStck* stckgenptr = nullptr;
			for (HSSAGenStck& stckgen : stackDefs) {
				if (stckgen.name == stack->name) {
					stckgenptr = &stckgen;
					break;
				}
			}
			if (!stckgenptr) {
				stackDefs.push_back ({stack->name, {}});
				stckgenptr = &stackDefs.back();
			}
			return stckgenptr;
		}

		void createPush (HId stckId, HSSAId id, uint64_t words = 1) {
			HStack* stack = arch->getStack (stckId);
			assert (stack);
			HSSAGenStck* genStck = getStckGen (stack);

			uint64_t stacksize = genStck->defs.size();
			HSSAGenDef def;
			switch (stack->type) {
			case H_STACK_REGISTER: {
				switch (stack->policy) {
				case H_STACKPOLICY_TOP:
					genStck->defs.push_back (id);
					createDef (stack->regs[stacksize].id, id);
					break;
				case H_STACKPOLICY_BOTTOM:
					genStck->defs.insert (genStck->defs.begin(), id);
					for (int i = 0; i < genStck->defs.size(); i++) {
						createDef (stack->regs[i].id, genStck->defs[i]);
					}
					break;
				}
			}
			break;
			case H_STACK_BUILTIN: {
				switch (stack->policy) {
				case H_STACKPOLICY_TOP:
					genStck->defs.push_back (id);
					break;
				case H_STACKPOLICY_BOTTOM:
					genStck->defs.insert (genStck->defs.begin(), id);
					break;
				}
			}
			break;
			case H_STACK_MEMORY:
				assert (stack->trackingReg);
				HRegister* reg = arch->getRegister (stack->trackingReg);
				assert (reg);

				HSSAId useId = getDefForUse (reg);
				HSSAId newstckptr;
				switch (stack->policy) {
				case H_STACKPOLICY_TOP:
					newstckptr = addSSAExpression ({0, HSSA_EXPR_OP, HSSA_OP_ADD, HSSA_TYPE_UINT, words * arch->wordbase, 0, {HSSAArg::createArg (useId), HSSAArg::createArg (words * arch->wordbase) }});
					printf ("%d = +(%d,0x%x);\n", newstckptr.id, useId.id, words);
					break;
				case H_STACKPOLICY_BOTTOM:
					newstckptr = addSSAExpression ({0, HSSA_EXPR_OP, HSSA_OP_SUB, HSSA_TYPE_UINT, words * arch->wordbase, 0, {HSSAArg::createArg (useId), HSSAArg::createArg (words * arch->wordbase) }});
					printf ("%d = -(%d,0x%x);\n", newstckptr.id, useId.id, words);
					break;
				}
				HSSAId defId = addSSAExpression ({0, HSSA_EXPR_STORE, HSSA_OP_INVALID, HSSA_TYPE_MEM, 0, 0, {HSSAArg::createArg (newstckptr), HSSAArg::createArg (id) }});
				printf ("%d = st(%d,%d);\n", defId.id, newstckptr.id, id);
				createDef (stack->trackingReg, newstckptr);
			}
		}

		HSSAId createPop (HId stckId, uint64_t words = 1) {
			HStack* stack = arch->getStack (stckId);
			assert (stack);
			HSSAGenStck* genStck = getStckGen (stack);

			HSSAId defId;
			switch (stack->type) {
			case H_STACK_REGISTER: {
				switch (stack->policy) {
				case H_STACKPOLICY_TOP:
					defId = genStck->defs.back();
					genStck->defs.pop_back();
					break;
				case H_STACKPOLICY_BOTTOM:
					defId = genStck->defs.front();
					genStck->defs.erase (genStck->defs.begin());
					for (int i = 0; i < genStck->defs.size(); i++) {
						createDef (stack->regs[i].id, genStck->defs[i]);
					}
					break;
				}
				removeDef (stack->regs[genStck->defs.size()].id); //undef previously last element
			}
			break;
			case H_STACK_BUILTIN: {
				switch (stack->policy) {
				case H_STACKPOLICY_TOP:
					defId = genStck->defs.back();
					genStck->defs.pop_back();
					break;
				case H_STACKPOLICY_BOTTOM:
					defId = genStck->defs.front();
					genStck->defs.erase (genStck->defs.begin());
					break;
				}
			}
			break;
			case H_STACK_MEMORY: {
				assert (stack->trackingReg);
				HRegister* reg = arch->getRegister (stack->trackingReg);
				assert (reg);
				HSSAId useId = getDefForUse (reg, 0, 0);
				defId = addSSAExpression ({0, HSSA_EXPR_LOAD, HSSA_OP_INVALID, HSSA_TYPE_UINT, words * arch->wordbase, 0, {HSSAArg::createArg (useId), HSSAArg::createArg (words) }});
				printf ("%d = ld(%d,%d);\n", defId.id, useId.id, words);
				HSSAId newstckptr;
				switch (stack->policy) {
				case H_STACKPOLICY_TOP:
					newstckptr = addSSAExpression ({0, HSSA_EXPR_OP, HSSA_OP_SUB, HSSA_TYPE_UINT, words * arch->wordbase, 0, {HSSAArg::createArg (useId), HSSAArg::createArg (words) }});
					printf ("%d = -(%d,0x%x);\n", newstckptr.id, useId.id, words);
					break;
				case H_STACKPOLICY_BOTTOM:
					newstckptr = addSSAExpression ({0, HSSA_EXPR_OP, HSSA_OP_ADD, HSSA_TYPE_UINT, words * arch->wordbase, 0, {HSSAArg::createArg (useId), HSSAArg::createArg (words) }});
					printf ("%d = +(%d,0x%x);\n", newstckptr.id, useId.id, words);
					break;
				}
				createDef (stack->trackingReg, newstckptr);
			}
			break;
			}
			return defId;
		}
		HSSAId getTempDef (HId id, uint64_t offset = 0, uint64_t size = 0) {
			for (HSSAGenDef& def : tmp.defs) {
				if (def.id == id) {
					if (!offset && (!size || def.size == size)) {
						return def.ssaId;
					} else {
						HSSAId id = addSSAExpression ({0, HSSA_EXPR_SPLIT, HSSA_OP_INVALID, HSSA_TYPE_UINT, size ? size : def.size, 0, {HSSAArg::createArg (def.ssaId), HSSAArg::createArg (offset), HSSAArg::createArg (size ? size : def.size) }});
						printf ("%d = Split(%d,%d,%d);\n", id.id, def.ssaId.id, offset, size ? size : def.size);
						return id;
					}
				}
			}
			assert (false);
			return {0, 0};
		}
		HSSAId createTempDef (HId id, HSSAId ssaId, uint64_t size) {
			for (auto it = tmp.defs.begin(); it != tmp.defs.end(); it++) {
				if ( (*it).id == id) {
					*it = {id, 0, size, ssaId};
					return ssaId;
				}
			}
			tmp.defs.push_back ({id, 0, size, ssaId});
			return ssaId;
		}

		void print (int indent = 0) {
			for (HSSAGenBasicBlock& bb : bbs) {
				printf ("Inputs\n");
				for (HSSAGenRegDef& regdef : bb.inputs) {
					printIndent (indent);
					printf ("Parent Reg: %s Cleared? %d\n", arch->getParentRegister (regdef.parentRegId)->name.cstr(), regdef.cleared);
					for (HSSAGenDef& def : regdef.defs) {

						printIndent (indent + 1);
						printf ("Id: %d R:%s Offset: %d Size: %d\n", def.ssaId, arch->getRegister (def.id)->name.cstr(), def.offset, def.size);
					}
				}
				printf ("Outputs\n");
				for (HSSAGenRegDef& regdef : bb.outputs) {
					printIndent (indent);
					printf ("Parent Reg: %s Cleared? %d\n", arch->getParentRegister (regdef.parentRegId)->name.cstr(), regdef.cleared);
					for (HSSAGenDef& def : regdef.defs) {

						printIndent (indent + 1);
						printf ("Id: %d R:%s Offset: %d Size: %d\n", def.ssaId, arch->getRegister (def.id)->name.cstr(), def.offset, def.size);
					}
				}
				printf ("Vals\n");
				for (HSSAExpression& expr : bb.exprs) {
					expr.print (indent + 1);
				}
			}
		}
	};


	struct HSSAConstData {
		bool isConst;
		uint64_t val;
	};

	HSSAId parseIRtoSSA (HId nodeid, HSSAGenState* state);
	HSSAId parseIRtoSSAExpr (HId nodeid, HSSAGenState* state);
	HSSAId parseIRtoSSAVal (HId nodeid, HSSAGenState* state);
	HSSAId parseIROptoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAId parseIRAssigntoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAId parseIRArgValtoSSA (HIRExpression* expr, HSSAGenArgument* arg, HSSAGenState* state);
	HSSAId parseIRSizetoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAId parseIRExtendtoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAId parseIRFlagtoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAConstData getIRExprConst (HId nodeId, HSSAGenState* state);

	HSSAId parseIRtoSSA (HId rootId, HSSAGenState* state) {
		return parseIRtoSSAExpr (rootId, state);
	}
	HSSAId parseIRtoSSAExpr (HId nodeid, HSSAGenState* state) {
		if (!nodeid)
			assert (false);
		HIRExpression* expr = state->arch->getIrExpr (nodeid);
		if (!expr)
			assert (false);
		HSSAId returnId = parseIRtoSSAVal (nodeid, state);
		if (expr->type == HIR_EXPR_ARG) {//if it is a memory access load the from memory
			uint64_t i = expr->mod.var_index;
			if (state->args[i - 1].type == HSSAGEN_TYPE_ARG_MEM) {
				HSSAId src = returnId;
				returnId = state->addSSAExpression ({0, HSSA_EXPR_LOAD, HSSA_OP_INVALID, HSSA_TYPE_INT, state->args[i - 1].size, 0, {HSSAArg::createArg (src), HSSAArg::createArg (state->args[i - 1].size) }});
			}
		}
		return returnId;
	}
	HSSAId genOp (HSSAOperatorType opType, HSSAType type, HIRExpression* expr, HSSAGenState* state, uint64_t offset = 0) {
		if ( (expr->subexprcount - offset) == 1)
			return parseIRtoSSAExpr (expr->subexpressions[offset], state);
		HSSAId ids[3] = {0, 0, 0};
		ids[0] = parseIRtoSSAExpr (expr->subexpressions[offset], state);
		ids[1] = genOp (opType, type, expr, state, offset + 1);
		ids[2] = state->addSSAExpression ({0, HSSA_EXPR_OP, opType, type, 0, 0, {HSSAArg::createArg (ids[0]), HSSAArg::createArg (ids[1]) }});
		state->lastOp = ids[2];
		return ids[2];
	}
	HSSAId genOp (HSSAOperatorType opType1, HSSAType type1, HSSAOperatorType opType2, HSSAType type2, HIRExpression* expr, HSSAGenState* state, uint64_t offset = 0) {
		if ( (expr->subexprcount - offset) == 1)
			return parseIRtoSSAExpr (expr->subexpressions[offset], state);
		HSSAId ids[3] = {0, 0, 0};
		ids[0] = parseIRtoSSAExpr (expr->subexpressions[offset], state);
		ids[1] = genOp (opType2, type2, expr, state, offset + 1);
		ids[2] = state->addSSAExpression ({0, HSSA_EXPR_OP, opType1, type1, 0, 0, {HSSAArg::createArg (ids[0]), HSSAArg::createArg (ids[1]) }});
		state->lastOp = ids[2];
		return ids[2];
	}
	HSSAId genSOp (HSSAOperatorType opType, HSSAType type, HIRExpression* expr, HSSAGenState* state, uint64_t offset = 0) {
		if ( (expr->subexprcount - offset) != 1)
			assert (false);
		HSSAId ids[2] = {0, 0};
		ids[0] = parseIRtoSSAExpr (expr->subexpressions[offset], state);
		ids[1] = state->addSSAExpression ({0, HSSA_EXPR_OP, opType, type, 0, 0, {HSSAArg::createArg (ids[0]) }});
		state->lastOp = ids[1];
		return ids[1];
	}
	HSSAId parseIROptoSSA (HIRExpression* expr, HSSAGenState* state) {
		switch (expr->token) {
		case HIR_TOKEN_ADD:
			return genOp (HSSA_OP_ADD, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SADD:
			return genOp (HSSA_OP_ADD, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FADD:
			return genOp (HSSA_OP_ADD, HSSA_TYPE_FLOAT, expr, state);
		case HIR_TOKEN_SUB:
			return genOp (HSSA_OP_SUB, HSSA_TYPE_UINT, HSSA_OP_ADD, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SSUB:
			return genOp (HSSA_OP_SUB, HSSA_TYPE_INT, HSSA_OP_ADD, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FSUB:
			return genOp (HSSA_OP_SUB, HSSA_TYPE_FLOAT, HSSA_OP_ADD, HSSA_TYPE_FLOAT, expr, state);
		case HIR_TOKEN_MUL:
			return genOp (HSSA_OP_MUL, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SMUL:
			return genOp (HSSA_OP_MUL, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FMUL:
			return genOp (HSSA_OP_MUL, HSSA_TYPE_FLOAT, expr, state);
		case HIR_TOKEN_DIV:
			return genOp (HSSA_OP_DIV, HSSA_TYPE_UINT, HSSA_OP_MUL, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SDIV:
			return genOp (HSSA_OP_DIV, HSSA_TYPE_INT, HSSA_OP_MUL, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FDIV:
			return genOp (HSSA_OP_DIV, HSSA_TYPE_FLOAT, HSSA_OP_MUL, HSSA_TYPE_FLOAT, expr, state);
		case HIR_TOKEN_MOD:
			return genOp (HSSA_OP_MOD, HSSA_TYPE_UINT, HSSA_OP_MUL, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SMOD:
			return genOp (HSSA_OP_MOD, HSSA_TYPE_INT, HSSA_OP_MUL, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FMOD:
			return genOp (HSSA_OP_MOD, HSSA_TYPE_FLOAT, HSSA_OP_MUL, HSSA_TYPE_FLOAT, expr, state);
		case HIR_TOKEN_NEG:
			return genOp (HSSA_OP_BNOT, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_FNEG:
			return genOp (HSSA_OP_BNOT, HSSA_TYPE_FLOAT, expr, state);
		//Comparison
		case HIR_TOKEN_CMP_E:
			return genOp (HSSA_OP_E, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_CMP_NE:
			return genOp (HSSA_OP_NE, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_CMP_L:
			return genOp (HSSA_OP_L, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_CMP_LE:
			return genOp (HSSA_OP_LE, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_CMP_G:
			return genOp (HSSA_OP_G, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_CMP_GE:
			return genOp (HSSA_OP_GE, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_CMP_NOT:
			return genSOp (HSSA_OP_NOT, HSSA_TYPE_UINT, expr, state);
		//
		case HIR_TOKEN_AND:
			return genOp (HSSA_OP_AND, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_OR:
			return genOp (HSSA_OP_OR, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_XOR:
			return genOp (HSSA_OP_XOR, HSSA_TYPE_UINT, expr, state);
		//Bit Operators
		case HIR_TOKEN_BAND:
			return genOp (HSSA_OP_BAND, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_BOR:
			return genOp (HSSA_OP_BOR, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_BXOR:
			return genOp (HSSA_OP_BXOR, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_BNOT:
			return genSOp (HSSA_OP_BNOT, HSSA_TYPE_UINT, expr, state);
		//Shifts - Rotates
		case HIR_TOKEN_SHR:
			return genOp (HSSA_OP_SHR, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SHL:
			return genOp (HSSA_OP_SHL, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SAR:
			return genOp (HSSA_OP_SAR, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SAL:
			return genOp (HSSA_OP_SAL, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_ROR:
			return genOp (HSSA_OP_ROR, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_ROL:
			return genOp (HSSA_OP_ROL, HSSA_TYPE_UINT, expr, state);
		default:
			assert (false);

		}
		return {0, 0};
	}
	HSSAId parseIRArgValtoSSA (HIRExpression* expr, HSSAGenArgument* arg, HSSAGenState* state) {
		switch (arg->type) {
		case HSSAGEN_TYPE_ARG_REG:
			return state->getDefForUse (arg->reg, expr->mod.index, expr->mod.size);
		case HSSAGEN_TYPE_ARG_STCK:
			//TODO
			break;
		case HSSAGEN_TYPE_ARG_MEM: {
			HSSAId base = {0, 0};
			base = arg->mem.base ? state->getDefForUse (arg->mem.base) : base;
			HSSAId index = {0, 0};
			index = arg->mem.index ? state->getDefForUse (arg->mem.index) : index;
			HSSAId id = state->addSSAExpression ({0, HSSA_EXPR_MEM, HSSA_OP_INVALID, HSSA_TYPE_UINT, state->arch->bitbase, 0, {}});
			HSSAExpression* ssaExpr = state->getSSAExpression (id);
			bool pre = false;
			if (base) {
				ssaExpr->subExpressions.add (HSSAArg::createArg (base));
			} else {
				ssaExpr->subExpressions.add (HSSAArg::createArg ( (uint64_t) 0));
			}
			if (index && arg->mem.scale) {
				ssaExpr->subExpressions.add (HSSAArg::createArg (index));
				ssaExpr->subExpressions.add (HSSAArg::createArg (arg->mem.scale));
			} else {
				ssaExpr->subExpressions.add (HSSAArg::createArg ( (uint64_t) 0));
				ssaExpr->subExpressions.add (HSSAArg::createArg ( (uint64_t) 0));
			}
			if (arg->mem.disp) {
				ssaExpr->subExpressions.add (HSSAArg::createArg (arg->mem.disp));
			} else {
				ssaExpr->subExpressions.add (HSSAArg::createArg ( (int64_t) 0));
			}
			return id;
		}
		case HSSAGEN_TYPE_ARG_VAL:
			return state->addSSAExpression ({0, HSSA_EXPR_VALUE, HSSA_OP_INVALID, HSSA_TYPE_UINT, arg->size, 0, {HSSAArg::createArg (arg->value) }});
			break;
		case HSSAGEN_TYPE_ARG_FVAL:
			return state->addSSAExpression ({0, HSSA_EXPR_VALUE, HSSA_OP_INVALID, HSSA_TYPE_FLOAT, arg->size, 0, {HSSAArg::createArg (arg->value) }});
			break;
		case HSSAGEN_TYPE_ARG_SSA:
			return arg->ssaId;
			break;
		}
		assert (false);
		return {0, 0};
	}
	HSSAId parseIRFlagtoSSA (HIRExpression* expr, HSSAGenState* state) {
		HSSAId id;
		switch (expr->token) {
		case HIR_TOKEN_FLAG_C:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_C, HSSA_OP_INVALID, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_A:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_A, HSSA_OP_INVALID, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_P:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_P, HSSA_OP_INVALID, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_O:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_O, HSSA_OP_INVALID, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_Z:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_Z, HSSA_OP_INVALID, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_S:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_S, HSSA_OP_INVALID, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		}
		assert (false);
		return {0, 0};
	}
	HSSAId parseIRAssigntoSSA (HIRExpression* expr, HSSAGenState* state) {

		HSSAId targetId = parseIRtoSSAExpr (expr->subexpressions[1], state);
		HIRExpression* targetExpr = state->arch->getIrExpr (expr->subexpressions[0]);
		if (targetExpr) {
			switch (targetExpr->type) {
			case HIR_EXPR_TMP: {
				return state->createTempDef (targetExpr->mod.var_index, targetId, 0);
			}
			break;
			case HIR_EXPR_ARG: {
				uint64_t i = targetExpr->mod.var_index;
				HSSAGenArgument& arg = state->args[i - 1];
				switch (arg.type) {
				case HSSAGEN_TYPE_ARG_REG: {
					state->createDef (arg.reg, targetId);
					return targetId;
				}
				case HSSAGEN_TYPE_ARG_STCK:
					//should not be able to assign onto stack
					assert (false);
					break;
				case HSSAGEN_TYPE_ARG_MEM: {
					HSSAId val = parseIRArgValtoSSA (targetExpr, &arg, state);
					return state->addSSAExpression ({0, HSSA_EXPR_STORE, HSSA_OP_INVALID, HSSA_TYPE_MEM, 0, 0, {HSSAArg::createArg (val), HSSAArg::createArg (targetId) }});
				}
				case HSSAGEN_TYPE_ARG_SSA:
					return arg.ssaId;
				default:
					assert (false);
				}
			}
			break;
			case HIR_EXPR_STCK:
				//should not be able to assign onto stack
				assert (false);
				break;
			case HIR_EXPR_REG: {
				assert (!targetExpr->mod.index && !targetExpr->mod.size);
				return state->createDef (targetExpr->reg, targetId);
			}
			default://can not write to other expressions
				break;
			}
		}
		assert (false);
	}
	HSSAId parseIRSizetoSSA (HIRExpression* expr, HSSAGenState* state) {
		HSSAId id;
		HIRExpression* subexpr = state->arch->getIrExpr (expr->subexpressions[0]);
		uint64_t size = 0;
		if (subexpr->mod.size) {
			size = subexpr->mod.size;
		} else {
			if (subexpr->mod.var_index) {
				uint64_t i = subexpr->mod.var_index;
				size = state->args[i - 1].size;
			}
			if (subexpr->reg) {
				HRegister* reg = state->arch->getRegister (subexpr->reg);
				if (reg)
					size = reg->size;
			}
		}
		if (expr->type == HIR_EXPR_SIZE) {
			return state->addSSAExpression ({0, HSSA_EXPR_VALUE, HSSA_OP_INVALID, HSSA_TYPE_UINT, state->arch->bitbase, 0, {HSSAArg::createArg (subexpr->mod.size / state->arch->wordbase) }});
		} else if (expr->type == HIR_EXPR_BSIZE) {
			return state->addSSAExpression ({0, HSSA_EXPR_VALUE, HSSA_OP_INVALID, HSSA_TYPE_UINT, state->arch->bitbase, 0, {HSSAArg::createArg (subexpr->mod.size) }});
		}
		assert (false);
		return {0, 0};
	}
	HSSAId parseIRExtendtoSSA (HIRExpression* expr, HSSAGenState* state) {
		HSSAConstData constData = getIRExprConst (expr->subexpressions[1], state);

		if (constData.isConst) {
			HSSAId sourceId = parseIRtoSSAExpr (expr->subexpressions[0], state);
			HSSAId id;
			switch (expr->type) {
			case HIR_EXPR_EXTEND:
				return state->addSSAExpression ({0, HSSA_EXPR_EXTEND, HSSA_OP_INVALID, HSSA_TYPE_UINT, constData.val, 0, {HSSAArg::createArg (sourceId) }});
			case HIR_EXPR_SEXTEND:
				return state->addSSAExpression ({0, HSSA_EXPR_EXTEND, HSSA_OP_INVALID, HSSA_TYPE_INT, constData.val, 0, {HSSAArg::createArg (sourceId) }});
			case HIR_EXPR_FEXTEND:
				return state->addSSAExpression ({0, HSSA_EXPR_EXTEND, HSSA_OP_INVALID, HSSA_TYPE_FLOAT, constData.val, 0, {HSSAArg::createArg (sourceId) }});
			}
			return id;
		} else {
			assert (false);
			assert (expr->subexprcount == 2);
			HSSAId ids[2];
			for (size_t i = 0; i < expr->subexprcount; i++) {
				ids[i] = parseIRtoSSAExpr (expr->subexpressions[i], state);
			}
			return state->addSSAExpression ({0, HSSA_EXPR_EXTEND, HSSA_OP_INVALID, HSSA_TYPE_UINT, constData.val, 0, {HSSAArg::createArg (ids[0]) }});
		}
	}
	HSSAId parseIRtoSSAVal (HId nodeid, HSSAGenState* state) {
		if (!nodeid)
			assert (false);
		HIRExpression* expr = state->arch->getIrExpr (nodeid);
		if (!expr)
			assert (false);

		switch (expr->type) {
		case HIR_EXPR_UNDEF:
			for (int i = 0; i < expr->subexprcount; i++) {
				HIRExpression* subexpr = state->arch->getIrExpr (expr->subexpressions[i]);
				if (subexpr->type == HIR_EXPR_REG)
					state->removeDef (subexpr->reg);
				else if (subexpr->type == HIR_EXPR_ARG)
					state->removeDef (state->args[subexpr->mod.var_index - 1].reg);
				else
					assert (false);
			}
			return {0, 0};
		case HIR_EXPR_OP:
			return parseIROptoSSA (expr, state);
		case HIR_EXPR_NOP:
			break;
		case HIR_EXPR_ASSIGN:
			return parseIRAssigntoSSA (expr, state);
		case HIR_EXPR_FLOAT:
			return state->addSSAExpression ({0, HSSA_EXPR_VALUE, HSSA_OP_INVALID, HSSA_TYPE_FLOAT, expr->mod.size, 0, {HSSAArg::createArg (expr->fvalue) }});
		case HIR_EXPR_NUMBER:
			return state->addSSAExpression ({0, HSSA_EXPR_VALUE, HSSA_OP_INVALID, HSSA_TYPE_FLOAT, expr->mod.size, 0, {HSSAArg::createArg (expr->value) }});
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
			printf ("jnz(%d,START);\n", parseIRtoSSAExpr (expr->subexpressions[0], state));
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
				HSSAId cond = parseIRtoSSAExpr (expr->subexpressions[0], state);
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
			break;
		}
		case HIR_EXPR_APPEND: {
			HSSAId id = state->addSSAExpression ({0, HSSA_EXPR_APPEND, HSSA_OP_INVALID, HSSA_TYPE_FLOAT, expr->mod.size, 0, {}});
			printf ("%d = Append(", id.id);
			printf ("%d", parseIRtoSSAExpr (expr->subexpressions[0], state));
			HSSAId ids[expr->subexprcount];
			for (int i = 1; i < expr->subexprcount; i++) {
				ids[i] = parseIRtoSSAExpr (expr->subexpressions[i], state);
				printf (", %d", ids[i].id);
			}
			printf (");\n", id);
			HSSAExpression* ssaExpr = state->getSSAExpression (id);
			for (int i = 1; i < expr->subexprcount; i++) {
				ssaExpr->subExpressions.add (HSSAArg::createArg (ids[i]));
			}
			break;
		}

		case HIR_EXPR_EXTEND:
		case HIR_EXPR_SEXTEND:
		case HIR_EXPR_FEXTEND:
			return parseIRExtendtoSSA (expr, state);

		case HIR_EXPR_TMP:
			return state->getTempDef (expr->mod.var_index, expr->mod.index, expr->mod.size);
		case HIR_EXPR_ARG: {
			uint64_t i = expr->mod.var_index;
			return parseIRArgValtoSSA (expr, &state->args[i - 1], state);
		}
		case HIR_EXPR_STCK:
			//shouldn't happen
			assert (false);
			break;
		case HIR_EXPR_REG:
			return state->getDefForUse (expr->reg, expr->mod.index, expr->mod.size);
		case HIR_EXPR_FLAG:
			return parseIRFlagtoSSA (expr, state);

		case HIR_EXPR_REC: {
			HList<HSSAGenArgument> argList;

			for (int i = 0; i < expr->subexprcount; i++) {
				HIRExpression* subexpr = state->arch->getIrExpr (expr->subexpressions[i]);
				switch (subexpr->type) {
				case HIR_EXPR_REG: {
					HSSAGenArgument arg;
					arg.type = HSSAGEN_TYPE_ARG_REG;
					arg.reg = expr->reg;
					argList.push_back (arg);
				}
				break;
				case HIR_EXPR_STCK: {
					HSSAGenArgument arg;
					arg.type = HSSAGEN_TYPE_ARG_STCK;
					arg.stackid = expr->stck;
					arg.stackindex = expr->mod.var_index;
					argList.push_back (arg);
				}
				break;
				case HIR_EXPR_ARG:
					argList.push_back (state->args[subexpr->mod.var_index - 1]);
					break;
				default:
					HSSAGenArgument arg;
					arg.type = HSSAGEN_TYPE_ARG_SSA;
					arg.ssaId = parseIRtoSSAExpr (expr->subexpressions[i], state);
					argList.push_back (arg);
					break;
				}
			}

			HList<HSSAGenArgument> cacheList = state->args;
			HSSAGenTmp cacheTmp = state->tmp;
			state->tmp.defs.clear();
			state->args = argList;
			HInstrDefinition* def = state->arch->getInstrDef (expr->mod.name_index);
			assert (def);
			parseIRtoSSA (def->il_string[expr->subexprcount].rootExpr, state);
			state->tmp = cacheTmp;
			state->args = cacheList;
		}
		break;
		case HIR_EXPR_CUSTOM: {
			HStack* stack = state->arch->getStack (expr->mod.name_index);
			assert (stack);
			HSSAGenStck* genStck = state->getStckGen (stack);
			assert (genStck);
			assert (expr->mod.var_index && expr->mod.var_index <= genStck->defs.size());//we do not want to access a stack rare
			return genStck->defs[expr->mod.var_index - 1];
		}
		break;

		case HIR_EXPR_JMP:
			printf ("jmp(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state).id);
			break;
		case HIR_EXPR_RJMP:
			printf ("rjmp(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state).id);
			break;
		case HIR_EXPR_CALL:
			printf ("call(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state).id);
			break;
		case HIR_EXPR_RET:
			//TODO
			printf ("ret(%d)\n", state->getDefForUse (state->arch->getRegister ("rax")->id).id);
			//state->genNewBasicBlock();
			break;
		case HIR_EXPR_SYSCALL:
			printf ("syscall(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state).id);
			break;
		case HIR_EXPR_TRAP:
			printf ("trap(%d)\n", parseIRtoSSAExpr (expr->subexpressions[0], state).id);
			break;

		case HIR_EXPR_VAL:
			return parseIRtoSSAVal (expr->subexpressions[0], state);

		case HIR_EXPR_CAST2F: {
			HSSAId sid = parseIRtoSSAExpr (expr->subexpressions[0], state);
			return state->addSSAExpression ({0, HSSA_EXPR_CAST, HSSA_OP_INVALID, HSSA_TYPE_FLOAT, expr->mod.size, 0, {HSSAArg::createArg (sid) }});
		}
		break;
		case HIR_EXPR_CAST2I: {
			HSSAId sid = parseIRtoSSAExpr (expr->subexpressions[0], state);
			return state->addSSAExpression ({0, HSSA_EXPR_CAST, HSSA_OP_INVALID, HSSA_TYPE_UINT, expr->mod.size, 0, {HSSAArg::createArg (sid) }});
		}
		break;

		case HIR_EXPR_PUSH: {
			HSSAId id = parseIRtoSSAExpr (expr->subexpressions[1], state);
			HIRExpression* target = state->arch->getIrExpr (expr->subexpressions[0]);
			assert (target->type == HIR_EXPR_STCK);
			state->createPush (target->stck, id);
		}
		break;
		case HIR_EXPR_POP: {
			HSSAConstData constdata = getIRExprConst (expr->subexpressions[1], state);
			assert (constdata.isConst);

			HIRExpression* target = state->arch->getIrExpr (expr->subexpressions[0]);
			assert (target->type == HIR_EXPR_STCK);
			return state->createPop (target->stck, constdata.val);
		}

		case HIR_EXPR_STORE: {
			HSSAId target = parseIRtoSSAExpr (expr->subexpressions[0], state);
			HSSAId value = parseIRtoSSAExpr (expr->subexpressions[1], state);
			return state->addSSAExpression ({0, HSSA_EXPR_STORE, HSSA_OP_INVALID, HSSA_TYPE_MEM, 0, 0, {HSSAArg::createArg (target), HSSAArg::createArg (value) }});
		}
		break;
		case HIR_EXPR_LOAD: {
			HSSAId temp = parseIRtoSSAExpr (expr->subexpressions[0], state);
			HSSAConstData constData = getIRExprConst (expr->subexpressions[1], state);
			assert (constData.isConst);
			return state->addSSAExpression ({0, HSSA_EXPR_LOAD, HSSA_OP_INVALID, HSSA_TYPE_UINT, constData.val, 0, {HSSAArg::createArg (temp) }});
		}
		break;
		}
		return {0, 0};
	}

	HSSAConstData getIRExprConst (HId nodeId, HSSAGenState * state) {
		HIRExpression* expr = state->arch->getIrExpr (nodeId);

		switch (expr->type) {
		case HIR_EXPR_NOP:
			return {true, 0};
		case HIR_EXPR_NUMBER:
			return {true, expr->value};
		case HIR_EXPR_SIZE: {
			HIRExpression* subexpr = state->arch->getIrExpr (expr->subexpressions[0]);
			if (subexpr->mod.size) {
				return {true, subexpr->mod.size / state->arch->wordbase};
			} else {
				switch (subexpr->type) {
				case HIR_EXPR_ARG: {
					uint64_t i = subexpr->mod.var_index;
					return {true, state->args[i - 1].size / state->arch->wordbase};
				}
				break;
				case HIR_EXPR_TMP: {
					//TODO
				}
				break;
				case HIR_EXPR_REG: {
					HRegister* reg = state->arch->getRegister (subexpr->reg);
					assert (reg);
					return {true, reg->size / state->arch->wordbase};
				}
				case HIR_EXPR_STCK: {
					HStack* stack = state->arch->getStack (subexpr->stck);
					assert (stack);
					return {true, stack->wordbitsize / state->arch->wordbase};
				}
				break;
				}
			}
		}
		break;
		case HIR_EXPR_BSIZE: {
			HIRExpression* subexpr = state->arch->getIrExpr (expr->subexpressions[0]);
			if (subexpr->mod.size) {
				return {true, subexpr->mod.size};
			} else {
				switch (subexpr->type) {
				case HIR_EXPR_ARG: {
					uint64_t i = subexpr->mod.var_index;
					return {true, state->args[i - 1].size};
				}
				break;
				case HIR_EXPR_TMP: {
					//TODO
				}
				break;
				case HIR_EXPR_REG: {
					HRegister* reg = state->arch->getRegister (subexpr->reg);
					assert (reg);
					return {true, reg->size};
				}
				case HIR_EXPR_STCK: {
					HStack* stack = state->arch->getStack (subexpr->stck);
					assert (stack);
					return {true, stack->wordbitsize};
				}
				break;
				}
			}
		}
		break;
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

		for (HStack& stack : arch->stacks) {
			state.stackDefs.push_back ({stack.name, {}});
		}
		for (HBasicBlock& bb : function->basicblocks) {
			printf ("Basic Block ------------------------------\n");
			state.genNewBasicBlock();

			for (HInstruction& instr : bb.instructions) {
				HIRRepresentation ir = instr.instrdef->il_string[instr.opcount];
				if (ir) {
					instr.print (arch);
					//printf ("SSA------------------\n");

					state.args.clear();

					for (int i = 0; i < instr.opcount; i++) {
						state.args.emplace_back (instr.operands[i]);
					}

					HId end = parseIRtoSSA (ir.rootExpr, &state);
				}
				//parseInstruction (&instr);
			}
		}
		state.print (1);
	}
}
