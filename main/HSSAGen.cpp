
#include "HSSAGen.h"
#include <assert.h>
#include <algorithm>
#include "HSSA.h"

//TODO replace HSSAId with HSSAArg in algorithm to make some kind of Constant Propagation




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

		HSSAArg def;
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
		HSSAArg def;//TODO HSSAId -> HSSAArg
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
		HIdList<HSSAExpression> exprs;
	};
	struct HSSAGenStck {
		HString name;
		HList<HSSAArg> defs;//size - stck_index
	};

	bool operator< (HSSAGenDef& lhs, HSSAGenDef& rhs) {
		return lhs.offset < rhs.offset;
	}

	struct HSSAGenState {
		HArchitecture* arch;

		HIdList<HSSAGenBasicBlock> bbs;

		HList<HSSAGenDef> tmpdefs;//per instruction

		//HInstruction* instr;
		HSSAId lastOp;

		HList<HSSAGenStck> stackDefs;
		HList<HSSAGenArgument> args;

		HId activeBasicBlock;

		HId genNewBasicBlock() {
			HSSAGenBasicBlock* block = getActiveBasicBlock();
			if (block && !block->exprs.list.size())
				addSSAExpression ({0, HSSA_EXPR_NOP, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, 0, 0, {}});
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
		HSSAArg addSSAExpression (HSSAExpression expr) {
			for (HSSAGenBasicBlock& bb : bbs) {
				if (bb.id == activeBasicBlock) {
					bb.exprs.add (expr);
					return HSSAArg::createArg ({expr.id, activeBasicBlock});
				}
			}
			assert (false);
			return HSSAArg::createArg();
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
					HSSAArg arg = HSSAArg::createArg ( (uint64_t) 0, upperbound - lowerbound);
					return {reg->id, lowerbound, upperbound - lowerbound, arg};
				} else {
					HSSAArg input;
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
					input = addSSAExpression ({0, HSSA_EXPR_INPUT, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, upperbound - lowerbound, 0, {}});
					HSSAGenDef def = {reg->id, lowerbound, upperbound - lowerbound, input};
					if (foundregdef) {
						foundregdef->defs.push_back (def);
					} else {
						getActiveBasicBlock()->inputs.push_back ({reg->parentId, false, {def}});
					}
					return def;
				}
			}
			assert (false);
			return {0, 0, 0, HSSAArg::createArg() };
		}

		void removeDef (HId regId) {
			HRegister* reg = arch->getRegister (regId);
			HSSAArg arg = addSSAExpression ({0, HSSA_EXPR_UNDEF, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, reg->size, 0, {}});
			createDef (regId, arg);
		}
		HSSAArg getDefForUse (HId regId, uint64_t offset = 0, uint64_t size = 0) {
			return getDefForUse (arch->getRegister (regId), offset, size);
		}
		HSSAArg getDefForUse (HRegister* reg, uint64_t offset = 0, uint64_t size = 0) {
			size = size == 0 ? reg->size - offset : size;
			offset += reg->offset;//adjust for parent register
			for (HSSAGenRegDef& regdef : getActiveBasicBlock()->outputs) {
				if (regdef.parentRegId == reg->parentId) {
					int localdefcount = 0;
					HSSAGenDef localdefs[20];
					for (auto it = regdef.defs.begin(); it != regdef.defs.end();) {
						HSSAGenDef& def = *it;
						if (def.offset == offset && def.size == size) //perfect match
							return def.def;
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
								HSSAArg newSSA = addSSAExpression ({0, HSSA_EXPR_SPLIT, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, newsize, 0, {def.def, HSSAArg::createArg (def.offset + newoffset, 0), HSSAArg::createArg (newsize, 0) }});
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
						return createValOrInput (&regdef, reg, offset, offset + size).def;
					} else if (localdefcount == 1) { //this case is the most likely
						assert (localdefs[0].offset == offset && localdefs[0].size == size);
						return localdefs[0].def;
					} else {
						HSSAArg arg = addSSAExpression ({0, HSSA_EXPR_APPEND, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, size, 0, {}});
						HSSAExpression* expr = getSSAExpression (arg.ssaId);

						uint64_t resultsize = 0;
						uint64_t lastupperBound = offset;
						for (int i = 0; i < localdefcount; i++) {
							assert (lastupperBound == localdefs[i].offset);
							expr->subExpressions.add (localdefs[i].def);
							resultsize += localdefs[i].size;
							lastupperBound = localdefs[i].offset + localdefs[i].size;
						}
						assert (resultsize == size);
						return arg;
					}
				}
			}
			HSSAGenRegDef regdef = {reg->parentId, false, {}};
			return createValOrInput (&regdef, reg, offset, offset + size).def;
		}
		HSSAArg createDef (HId regId, HSSAArg arg) {
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
									HSSAArg splitId = addSSAExpression ({0, HSSA_EXPR_SPLIT, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, size, 0, {defit.def, HSSAArg::createArg (offset, arch->bitbase), HSSAArg::createArg (size, arch->bitbase) }});
									def[count++] = {defit.id, defit.offset, reg->offset - defit.offset, splitId};
								}
								if ( (reg->offset + reg->size) < (defit.offset + defit.size)) {//if ends after
									uint64_t offset = reg->offset + reg->size;
									uint64_t size = (defit.offset + defit.size) - (reg->offset + reg->size);
									HSSAArg splitId = addSSAExpression ({0, HSSA_EXPR_SPLIT, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, size, 0, {defit.def, HSSAArg::createArg (offset, arch->bitbase), HSSAArg::createArg (size, arch->bitbase) }});
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
					HSSAGenDef def = {reg->id, reg->offset, reg->size, arg };
					regdef.defs.push_back (def);
					return arg;
				}
			}
			getActiveBasicBlock()->outputs.push_back ({reg->parentId, reg->clearParentOnWrite, {{reg->id, reg->offset, reg->size, arg }}});
			return arg;
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

		void createPush (HId stckId, HSSAArg arg, HSSAArg words) {
			assert (words.type == HSSA_ARG_UINT);
			HStack* stack = arch->getStack (stckId);
			assert (stack);
			HSSAGenStck* genStck = getStckGen (stack);

			uint64_t stacksize = genStck->defs.size();
			HSSAGenDef def;
			switch (stack->type) {
			case H_STACK_REGISTER: {
				switch (stack->policy) {
				case H_STACKPOLICY_TOP:
					genStck->defs.push_back (arg);
					createDef (stack->regs[stacksize].id, arg);
					break;
				case H_STACKPOLICY_BOTTOM:
					genStck->defs.insert (genStck->defs.begin(), arg);
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
					genStck->defs.push_back (arg);
					break;
				case H_STACKPOLICY_BOTTOM:
					genStck->defs.insert (genStck->defs.begin(), arg);
					break;
				}
			}
			break;
			case H_STACK_MEMORY:
				assert (stack->trackingReg);
				HRegister* reg = arch->getRegister (stack->trackingReg);
				assert (reg);

				HSSAArg useId = getDefForUse (reg);
				HSSAArg newstckptr;
				switch (stack->policy) {
				case H_STACKPOLICY_TOP:
					newstckptr = addSSAExpression ({0, HSSA_EXPR_OP, HSSA_OP_ADD, HSSA_COND_NONE, HSSA_TYPE_UINT, words.uval * arch->wordbase, 0, {useId, HSSAArg::createArg (words.uval * arch->wordbase, words.size) }});
					break;
				case H_STACKPOLICY_BOTTOM:
					newstckptr = addSSAExpression ({0, HSSA_EXPR_OP, HSSA_OP_SUB, HSSA_COND_NONE, HSSA_TYPE_UINT, words.uval * arch->wordbase, 0, {useId, HSSAArg::createArg (words.uval * arch->wordbase,  words.size) }});
					break;
				}
				HSSAArg defId = addSSAExpression ({0, HSSA_EXPR_STORE, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_MEM, 0, 0, {newstckptr, arg }});
				createDef (stack->trackingReg, newstckptr);
			}
		}

		HSSAArg createPop (HId stckId, HSSAArg words) {
			assert (words.type == HSSA_ARG_UINT);
			HStack* stack = arch->getStack (stckId);
			assert (stack);
			HSSAGenStck* genStck = getStckGen (stack);

			HSSAArg defId;
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
				HSSAArg useId = getDefForUse (reg, 0, 0);
				defId = addSSAExpression ({0, HSSA_EXPR_LOAD, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, words.uval * arch->wordbase, 0, {useId, HSSAArg::createArg (words.uval, arch->bitbase) }});
				HSSAArg newstckptr;
				switch (stack->policy) {
				case H_STACKPOLICY_TOP:
					newstckptr = addSSAExpression ({0, HSSA_EXPR_OP, HSSA_OP_SUB, HSSA_COND_NONE, HSSA_TYPE_UINT, words.uval * arch->wordbase, 0, {useId, HSSAArg::createArg (words.uval, arch->bitbase) }});
					break;
				case H_STACKPOLICY_BOTTOM:
					newstckptr = addSSAExpression ({0, HSSA_EXPR_OP, HSSA_OP_ADD, HSSA_COND_NONE, HSSA_TYPE_UINT, words.uval * arch->wordbase, 0, {useId, HSSAArg::createArg (words.uval, arch->bitbase) }});
					break;
				}
				createDef (stack->trackingReg, newstckptr);
			}
			break;
			}
			return defId;
		}
		HSSAArg getTempDef (HId id, uint64_t offset = 0, uint64_t size = 0) {
			for (HSSAGenDef& def : tmpdefs) {
				if (def.id == id) {
					if (!offset && (!size || def.size == size)) {
						return def.def;
					} else {
						return addSSAExpression ({0, HSSA_EXPR_SPLIT, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, size ? size : def.size, 0, {def.def, HSSAArg::createArg (offset, arch->bitbase), HSSAArg::createArg (size ? size : def.size, arch->bitbase) }});
					}
				}
			}
			assert (false);
			return HSSAArg::createArg();
		}
		HId createTempDef (HId id, HSSAArg arg, uint64_t size) {
			for (auto it = tmpdefs.begin(); it != tmpdefs.end(); it++) {
				if ( (*it).id == id) {
					*it = {id, 0, size, arg};
					return arg;
				}
			}
			tmpdefs.push_back ({id, 0, size, arg});
			return id;
		}

		void print (int indent = 0) {
			for (HSSAGenBasicBlock& bb : bbs) {
				printf ("Inputs\n");
				for (HSSAGenRegDef& regdef : bb.inputs) {
					printIndent (indent);
					printf ("Parent Reg: %s Cleared? %d\n", arch->getParentRegister (regdef.parentRegId)->name.cstr(), regdef.cleared);
					for (HSSAGenDef& def : regdef.defs) {

						printIndent (indent + 1);
						printf ("Id: ");
						switch (def.def.type) {
						case HSSA_ARG_INT:
							printf ("%d", def.def.val);
							break;
						case HSSA_ARG_UINT:
							printf ("%x", def.def.uval);
							break;
						case HSSA_ARG_FLOAT:
							printf ("%d", def.def.fval);
							break;
						case HSSA_ARG_SSA:
							printf ("%d:%d", def.def.ssaId.id, def.def.ssaId.bbid);
							break;
						}
						printf (" R:%s Offset: %d Size: %d\n", arch->getRegister (def.id)->name.cstr(), def.offset, def.size);
					}
				}
				printf ("Outputs\n");
				for (HSSAGenRegDef& regdef : bb.outputs) {
					printIndent (indent);
					printf ("Parent Reg: %s Cleared? %d\n", arch->getParentRegister (regdef.parentRegId)->name.cstr(), regdef.cleared);
					for (HSSAGenDef& def : regdef.defs) {

						printIndent (indent + 1);
						printf ("Id: ");
						switch (def.def.type) {
						case HSSA_ARG_INT:
							printf ("%d", def.def.val);
							break;
						case HSSA_ARG_UINT:
							printf ("%x", def.def.uval);
							break;
						case HSSA_ARG_FLOAT:
							printf ("%d", def.def.fval);
							break;
						case HSSA_ARG_SSA:
							printf ("%d:%d", def.def.ssaId.id, def.def.ssaId.bbid);
							break;
						}
						printf (" R:%s Offset: %d Size: %d\n", arch->getRegister (def.id)->name.cstr(), def.offset, def.size);
					}
				}
				printf ("Vals\n");
				for (HSSAExpression& expr : bb.exprs) {
					expr.print (bb.id, indent + 1);
				}
			}
		}
	};


	struct HSSAConstData {
		bool isConst;
		uint64_t val;
	};

	HSSAArg parseIRtoSSA (HId nodeid, HSSAGenState* state);
	HSSAArg parseIRtoSSAExpr (HId nodeid, HSSAGenState* state);
	HSSAArg parseIRtoSSAVal (HId nodeid, HSSAGenState* state);
	HSSAArg parseIROptoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAArg parseIRAssigntoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAArg parseIRArgValtoSSA (HIRExpression* expr, HSSAGenArgument* arg, HSSAGenState* state);
	HSSAArg parseIRSizetoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAArg parseIRExtendtoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAArg parseIRFlagtoSSA (HIRExpression* expr, HSSAGenState* state);
	HSSAConstData getIRExprConst (HId nodeId, HSSAGenState* state);

	HSSAArg parseIRtoSSA (HId rootId, HSSAGenState* state) {
		return parseIRtoSSAExpr (rootId, state);
	}
	HSSAArg parseIRtoSSAExpr (HId nodeid, HSSAGenState* state) {
		if (!nodeid)
			assert (false);
		HIRExpression* expr = state->arch->getIrExpr (nodeid);
		if (!expr)
			assert (false);
		HSSAArg returnId = parseIRtoSSAVal (nodeid, state);
		if (expr->type == HIR_EXPR_ARG) {//if it is a memory access load the from memory
			uint64_t i = expr->mod.var_index;
			if (state->args[i - 1].type == HSSAGEN_TYPE_ARG_MEM) {
				returnId = state->addSSAExpression ({0, HSSA_EXPR_LOAD, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_INT, state->args[i - 1].size, 0, {returnId, HSSAArg::createArg (state->args[i - 1].size, state->arch->bitbase) }});
			}
		}
		return returnId;
	}
	HSSAArg genOp (HSSAOperatorType opType, HSSAType type, HIRExpression* expr, HSSAGenState* state, uint64_t offset = 0) {
		if ( (expr->subexprcount - offset) == 1)
			return parseIRtoSSAExpr (expr->subexpressions[offset], state);
		HSSAArg ids[3];
		ids[0] = parseIRtoSSAExpr (expr->subexpressions[offset], state);
		ids[1] = genOp (opType, type, expr, state, offset + 1);
		ids[2] = state->addSSAExpression ({0, HSSA_EXPR_OP, opType, HSSA_COND_NONE, type, 0, 0, {ids[0], ids[1]}});
		state->lastOp = ids[2].ssaId;
		return ids[2];
	}
	HSSAArg genOp (HSSAOperatorType opType1, HSSAOperatorType opType2, HSSAType type, HIRExpression* expr, HSSAGenState* state, uint64_t offset = 0) {
		if ( (expr->subexprcount - offset) == 1)
			return parseIRtoSSAExpr (expr->subexpressions[offset], state);
		HSSAArg ids[3];;
		ids[0] = parseIRtoSSAExpr (expr->subexpressions[offset], state);
		ids[1] = genOp (opType2, type, expr, state, offset + 1);
		ids[2] = state->addSSAExpression ({0, HSSA_EXPR_OP, opType1, HSSA_COND_NONE, type, 0, 0, {ids[0], ids[1] }});
		state->lastOp = ids[2].ssaId;
		return ids[2];
	}
	HSSAArg genSOp (HSSAOperatorType opType, HSSAType type, HIRExpression* expr, HSSAGenState* state, uint64_t offset = 0) {
		if ( (expr->subexprcount - offset) != 1)
			assert (false);
		HSSAArg id;
		id = parseIRtoSSAExpr (expr->subexpressions[offset], state);
		id = state->addSSAExpression ({0, HSSA_EXPR_OP, opType, HSSA_COND_NONE, type, 0, 0, {id}});
		state->lastOp = id.ssaId;
		return id;
	}
	HSSAArg parseIROptoSSA (HIRExpression* expr, HSSAGenState* state) {
		switch (expr->token) {
		case HIR_TOKEN_ADD:
			return genOp (HSSA_OP_ADD, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SADD:
			return genOp (HSSA_OP_ADD, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FADD:
			return genOp (HSSA_OP_ADD, HSSA_TYPE_FLOAT, expr, state);
		case HIR_TOKEN_SUB:
			return genOp (HSSA_OP_SUB, HSSA_OP_ADD, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SSUB:
			return genOp (HSSA_OP_SUB, HSSA_OP_ADD, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FSUB:
			return genOp (HSSA_OP_SUB, HSSA_OP_ADD, HSSA_TYPE_FLOAT, expr, state);
		case HIR_TOKEN_MUL:
			return genOp (HSSA_OP_MUL, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SMUL:
			return genOp (HSSA_OP_MUL, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FMUL:
			return genOp (HSSA_OP_MUL, HSSA_TYPE_FLOAT, expr, state);
		case HIR_TOKEN_DIV:
			return genOp (HSSA_OP_DIV, HSSA_OP_MUL, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SDIV:
			return genOp (HSSA_OP_DIV, HSSA_OP_MUL, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FDIV:
			return genOp (HSSA_OP_DIV, HSSA_OP_MUL, HSSA_TYPE_FLOAT, expr, state);
		case HIR_TOKEN_MOD:
			return genOp (HSSA_OP_MOD, HSSA_OP_MUL, HSSA_TYPE_UINT, expr, state);
		case HIR_TOKEN_SMOD:
			return genOp (HSSA_OP_MOD, HSSA_OP_MUL, HSSA_TYPE_INT, expr, state);
		case HIR_TOKEN_FMOD:
			return genOp (HSSA_OP_MOD, HSSA_OP_MUL, HSSA_TYPE_FLOAT, expr, state);
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
		assert (false);
		return HSSAArg::createArg();
	}
	HSSAArg parseIRArgValtoSSA (HIRExpression* expr, HSSAGenArgument* arg, HSSAGenState* state) {
		switch (arg->type) {
		case HSSAGEN_TYPE_ARG_REG:
			return state->getDefForUse (arg->reg, expr->mod.index, expr->mod.size);
		case HSSAGEN_TYPE_ARG_STCK:
			//TODO
			break;
		case HSSAGEN_TYPE_ARG_MEM: {
			HSSAArg base = arg->mem.base ? state->getDefForUse (arg->mem.base) : HSSAArg::createArg ( (uint64_t) 0, state->arch->bitbase);
			HSSAArg index = arg->mem.index ? state->getDefForUse (arg->mem.index) : HSSAArg::createArg ( (uint64_t) 0, state->arch->bitbase);
			HSSAArg id = state->addSSAExpression ({0, HSSA_EXPR_MEM, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, state->arch->bitbase, 0, {}});
			HSSAExpression* ssaExpr = state->getSSAExpression (id.ssaId);
			bool pre = false;
			ssaExpr->subExpressions.add (base);
			ssaExpr->subExpressions.add (index);
			ssaExpr->subExpressions.add (HSSAArg::createArg (arg->mem.scale, state->arch->bitbase));
			ssaExpr->subExpressions.add (HSSAArg::createArg (arg->mem.disp, state->arch->bitbase));
			return id;
		}
		case HSSAGEN_TYPE_ARG_VAL:
			return HSSAArg::createArg (arg->value, arg->size);
			break;
		case HSSAGEN_TYPE_ARG_FVAL:
			return HSSAArg::createArg (arg->fvalue, arg->size);
			break;
		case HSSAGEN_TYPE_ARG_SSA:
			return arg->def;
			break;
		}
		assert (false);
		return HSSAArg::createArg();
	}
	HSSAArg parseIRFlagtoSSA (HIRExpression* expr, HSSAGenState* state) {
		HSSAArg id;
		switch (expr->token) {
		case HIR_TOKEN_FLAG_C:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_C, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_A:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_A, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_P:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_P, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_O:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_O, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_Z:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_Z, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		case HIR_TOKEN_FLAG_S:
			return state->addSSAExpression ({0, HSSA_EXPR_FLAG_S, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, 1, 0, {HSSAArg::createArg (state->lastOp) }});
		}
		assert (false);
		return HSSAArg::createArg();
	}
	HSSAArg parseIRAssigntoSSA (HIRExpression* expr, HSSAGenState* state) {

		HSSAArg targetId = parseIRtoSSAExpr (expr->subexpressions[1], state);
		HIRExpression* targetExpr = state->arch->getIrExpr (expr->subexpressions[0]);
		if (targetExpr) {
			switch (targetExpr->type) {
			case HIR_EXPR_TMP: {
				state->createTempDef (targetExpr->mod.var_index, targetId, 0);
				return targetId;
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
					return state->addSSAExpression ({0, HSSA_EXPR_STORE, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_MEM, 0, 0, { parseIRArgValtoSSA (targetExpr, &arg, state), targetId }});
				}
				case HSSAGEN_TYPE_ARG_SSA:
					return arg.def;
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
		return HSSAArg::createArg();
	}
	HSSAArg parseIRSizetoSSA (HIRExpression* expr, HSSAGenState* state) {
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
			return HSSAArg::createArg (subexpr->mod.size / state->arch->wordbase, state->arch->bitbase);
		} else if (expr->type == HIR_EXPR_BSIZE) {
			return HSSAArg::createArg (subexpr->mod.size, state->arch->bitbase);
		}
		assert (false);
		return HSSAArg::createArg();
	}
	HSSAArg parseIRExtendtoSSA (HIRExpression* expr, HSSAGenState* state) {
		HSSAArg size = parseIRtoSSAExpr (expr->subexpressions[1], state);
		assert (size.type == HSSA_TYPE_UINT);

		HSSAArg sourceId = parseIRtoSSAExpr (expr->subexpressions[0], state);
		HSSAArg id;
		switch (expr->type) {
		case HIR_EXPR_EXTEND:
			return state->addSSAExpression ({0, HSSA_EXPR_EXTEND, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, size.uval, 0, {sourceId }});
		case HIR_EXPR_SEXTEND:
			return state->addSSAExpression ({0, HSSA_EXPR_EXTEND, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_INT, size.uval, 0, {sourceId }});
		case HIR_EXPR_FEXTEND:
			return state->addSSAExpression ({0, HSSA_EXPR_EXTEND, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_FLOAT, size.uval, 0, {sourceId }});
		}
		return id;
	}
	HSSAArg parseIRtoSSAVal (HId nodeid, HSSAGenState* state) {
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
			return HSSAArg::createArg();
		case HIR_EXPR_OP:
			return parseIROptoSSA (expr, state);
		case HIR_EXPR_NOP:
			break;
		case HIR_EXPR_ASSIGN:
			return parseIRAssigntoSSA (expr, state);
		case HIR_EXPR_FLOAT:
			return HSSAArg::createArg (expr->fvalue, expr->mod.size);
		case HIR_EXPR_NUMBER:
			return HSSAArg::createArg (expr->value, expr->mod.size);
		case HIR_EXPR_SEQUENCE:
			for (int i = 0; i < expr->subexprcount; i++) {
				parseIRtoSSAExpr (expr->subexpressions[i], state);
			}
			break;
		case HIR_EXPR_SIZE:
		case HIR_EXPR_BSIZE:
			return parseIRSizetoSSA (expr, state);
		case HIR_EXPR_LOOP: {
			HSSAArg jmpId = state->addSSAExpression ({0, HSSA_EXPR_JMP, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_PC, state->arch->bitbase, 0, {}});
			HId loopCondId = state->genNewBasicBlock();
			HSSAArg condId = parseIRtoSSAExpr (expr->subexpressions[0], state);
			HSSAArg condJmpId = state->addSSAExpression ({0, HSSA_EXPR_JMP, HSSA_OP_INVALID, HSSA_COND_NZERO, HSSA_TYPE_PC, state->arch->bitbase, 0, {}});
			HId loopBodyId = state->genNewBasicBlock();
			for (int i = 1; i < expr->subexprcount; i++) {
				parseIRtoSSAExpr (expr->subexpressions[i], state);
			}
			state->addSSAExpression ({0, HSSA_EXPR_JMP, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_PC, state->arch->bitbase, 0, {HSSAArg::createArg ({0, loopCondId}) }});
			state->getSSAExpression (jmpId.ssaId)->subExpressions.add (HSSAArg::createArg ({0, loopCondId}));
			HSSAExpression* condJumpExpr = state->getSSAExpression (condJmpId.ssaId);
			condJumpExpr->subExpressions.add (HSSAArg::createArg ({0, loopBodyId}));
			condJumpExpr->subExpressions.add (condId);

		}
		break;
		case HIR_EXPR_IF: {

			HSSAArg cond = parseIRtoSSAExpr (expr->subexpressions[0], state);
			if (cond.type == HSSA_TYPE_UINT) {
				assert (expr->subexprcount >= 2); //no expressions
				assert (! (cond.val && expr->subexprcount == 2)); //only branch for zero, but value is not zero

				uint64_t selectVal = cond.val + 1;
				if (selectVal >= expr->subexprcount) selectVal = expr->subexprcount - 1;
				return parseIRtoSSAExpr (expr->subexpressions[selectVal], state);
			} else {
				assert (expr->subexprcount >= 2);
				if (expr->subexprcount == 2) {
					HSSAArg jmpId = state->addSSAExpression ({0, HSSA_EXPR_JMP, HSSA_OP_INVALID, HSSA_COND_ZERO, HSSA_TYPE_PC, state->arch->bitbase, 0, {}});
					state->genNewBasicBlock();
					HSSAArg arg = parseIRtoSSAExpr (expr->subexpressions[1], state);
					HId blockId = state->genNewBasicBlock();
					HSSAExpression* jumpexpr = state->getSSAExpression (jmpId.ssaId);
					jumpexpr->subExpressions.add (HSSAArg::createArg ({0, blockId}));
					jumpexpr->subExpressions.add (cond);
					return arg;
				} else {
					HSSAArg branchId = state->addSSAExpression ({0, HSSA_EXPR_BRANCH, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_PC, state->arch->bitbase, 0, {cond }});

					HId blockIds[expr->subexprcount];
					HSSAArg blockExpr[expr->subexprcount];
					HSSAArg jumpIds[expr->subexprcount];
					int i;
					for (i = 1; i < expr->subexprcount; i++) {
						blockIds[i] = state->genNewBasicBlock();
						blockExpr[i] = parseIRtoSSAExpr (expr->subexpressions[i], state);
						jumpIds[i] = state->addSSAExpression ({0, HSSA_EXPR_JMP, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_PC, state->arch->bitbase, 0, {}});
					}
					HSSAArg endBlockId = HSSAArg::createArg ({0, state->genNewBasicBlock() });
					HSSAExpression* branchExpr = state->getSSAExpression (branchId.ssaId);
					for (i = 1; i < expr->subexprcount; i++) {
						HSSAArg blockId = HSSAArg::createArg ({0, blockIds[i]});
						branchExpr->subExpressions.add (blockId);//add parameter to branch
						state->getSSAExpression (jumpIds[i].ssaId)->subExpressions.add (endBlockId);
					}
					//return phi node?
				}
			}
			break;
		}
		case HIR_EXPR_APPEND: {
			HSSAArg id = state->addSSAExpression ({0, HSSA_EXPR_APPEND, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_FLOAT, expr->mod.size, 0, {}});
			HSSAArg ids[expr->subexprcount];
			for (int i = 0; i < expr->subexprcount; i++) {
				ids[i] = parseIRtoSSAExpr (expr->subexpressions[i], state);
			}
			HSSAExpression* ssaExpr = state->getSSAExpression (id.ssaId);
			for (int i = 1; i < expr->subexprcount; i++) {
				ssaExpr->subExpressions.add (ids[i]);
			}
			break;
		}

		case HIR_EXPR_EXTEND:
		case HIR_EXPR_SEXTEND:
		case HIR_EXPR_FEXTEND:
			return parseIRExtendtoSSA (expr, state);

		case HIR_EXPR_TMP:
			return state->getTempDef (expr->mod.var_index, expr->mod.index, expr->mod.size);
		case HIR_EXPR_ARG: 
			return parseIRArgValtoSSA (expr, &state->args[expr->mod.var_index - 1], state);
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
					arg.def = parseIRtoSSAExpr (expr->subexpressions[i], state);
					argList.push_back (arg);
					break;
				}
			}

			HList<HSSAGenArgument> cacheList = state->args;
			HList<HSSAGenDef> cacheTmp = state->tmpdefs;
			state->tmpdefs.clear();
			state->args = argList;
			HInstrDefinition* def = state->arch->getInstrDef (expr->mod.name_index);
			assert (def);
			parseIRtoSSA (def->il_string[expr->subexprcount].rootExpr, state);
			state->tmpdefs = cacheTmp;
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
			return state->addSSAExpression ({0, HSSA_EXPR_JMP, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_PC, 0, 0, {parseIRtoSSAExpr (expr->subexpressions[0], state) }});

		case HIR_EXPR_RJMP: 
			return state->addSSAExpression ({0, HSSA_EXPR_JMP, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_PC, 0, 0, {parseIRtoSSAExpr (expr->subexpressions[0], state) }});
		case HIR_EXPR_CALL:
			//todo define all return values
			return state->addSSAExpression ({0, HSSA_EXPR_CALL, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UNKNOWN, 0, 0, {parseIRtoSSAExpr (expr->subexpressions[0], state) }});
		case HIR_EXPR_RET:
			return state->addSSAExpression ({0, HSSA_EXPR_RETURN, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UNKNOWN, 0, 0, {state->getDefForUse (state->arch->getRegister ("rax")->id) }});
		case HIR_EXPR_SYSCALL:
			return state->addSSAExpression ({0, HSSA_EXPR_SYSCALL, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UNKNOWN, 0, 0, {parseIRtoSSAExpr (expr->subexpressions[0], state) }});
		case HIR_EXPR_TRAP:
			return state->addSSAExpression ({0, HSSA_EXPR_TRAP, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UNKNOWN, 0, 0, {parseIRtoSSAExpr (expr->subexpressions[0], state) }});

		case HIR_EXPR_VAL:
			return parseIRtoSSAVal (expr->subexpressions[0], state);

		case HIR_EXPR_CAST2F:
			return state->addSSAExpression ({0, HSSA_EXPR_CAST, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_FLOAT, expr->mod.size, 0, {parseIRtoSSAExpr (expr->subexpressions[0], state) }});
			break;
		case HIR_EXPR_CAST2I:
			return state->addSSAExpression ({0, HSSA_EXPR_CAST, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, expr->mod.size, 0, {parseIRtoSSAExpr (expr->subexpressions[0], state) }});
			break;

		case HIR_EXPR_PUSH: {
			HSSAArg id = parseIRtoSSAExpr (expr->subexpressions[1], state);
			HIRExpression* target = state->arch->getIrExpr (expr->subexpressions[0]);
			assert (target->type == HIR_EXPR_STCK);
			state->createPush (target->stck, id, HSSAArg::createArg ( (uint64_t) 1, state->arch->bitbase));
		}
		break;
		case HIR_EXPR_POP: {
			HSSAArg id = parseIRtoSSAExpr (expr->subexpressions[1], state);
			HIRExpression* target = state->arch->getIrExpr (expr->subexpressions[0]);
			assert (target->type == HIR_EXPR_STCK);
			return state->createPop (target->stck, id);
		}

		case HIR_EXPR_STORE: {
			HSSAArg target = parseIRtoSSAExpr (expr->subexpressions[0], state);
			HSSAArg value = parseIRtoSSAExpr (expr->subexpressions[1], state);
			return state->addSSAExpression ({0, HSSA_EXPR_STORE, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_MEM, 0, 0, {target, value }});
		}
		break;
		case HIR_EXPR_LOAD: {
			HSSAArg temp = parseIRtoSSAExpr (expr->subexpressions[0], state);
			HSSAArg target = parseIRtoSSAExpr (expr->subexpressions[1], state);
			assert (target.type == HSSA_TYPE_UINT);
			return state->addSSAExpression ({0, HSSA_EXPR_LOAD, HSSA_OP_INVALID, HSSA_COND_NONE, HSSA_TYPE_UINT, target.uval, 0, {temp}});
		}
		break;
		}
		return HSSAArg::createArg();
	}

	bool HSSAGenerator::parseFunction (HFunction * function) {
		HSSAGenState state;
		state.arch = arch;

		for (HStack& stack : arch->stacks) {
			state.stackDefs.push_back ({stack.name, {}});
		}
		for (HBasicBlock& bb : function->basicblocks) {
			state.genNewBasicBlock();

			for (HInstruction& instr : bb.instructions) {
				HIRRepresentation ir = instr.instrdef->il_string[instr.opcount];
				if (ir) {
					//instr.print (arch);
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
