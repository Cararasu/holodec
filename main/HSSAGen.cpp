#include "HSSAGen.h"
#include "HArchitecture.h"
#include <assert.h>

namespace holodec {

	template HIRArgument HSSAGen::parseConstExpression (HIRArgument argExpr, HList<HIRArgument>* arglist);
	template HIRArgument HSSAGen::parseConstExpression (HIRArgument argExpr, HLocalBackedList<HIRArgument, 4>* arglist);



	HSSAGen::HSSAGen (HArchitecture* arch) : arch (arch) {}

	HSSAGen::~HSSAGen() {}

	HIRRepresentation* HSSAGen::matchIr (HInstruction* instr) {

		HInstrDefinition* instrdef = instr->instrdef;
		for (int i = 0; i < instrdef->irs.size(); i++) {
			if (instr->operands.size() == instrdef->irs[i].argcount) {
				HIRArgument constArg = parseConstExpression (instrdef->irs[i].condExpr, &instr->operands);
				if (constArg && constArg.type == HIR_ARGTYPE_UINT && constArg.uval) {
					if (instrdef->irs[i].condstring) {
						printf ("Successfully parsed Condition for Instruction\n");
						instrdef->irs[i].print (arch);
						instr->print (arch);
						printf ("\n");
					}
					return &instrdef->irs[i];
				}
			}
		}
		for (int i = 0; i < instr->operands.size(); i++) {
			instr->operands[i].print (arch);
			printf ("\n");
		}
		instr->print (arch);
		printf ("Found No Match %s\n", instr->instrdef->mnemonics.cstr());
		return nullptr;
	}

	HIRArgument HSSAGen::parseMemArgToExpr (HIRArgument mem) {
		HSSAExpression memexpr;
		memexpr.type = HSSA_EXPR_MEM;
		memexpr.exprtype = HSSA_TYPE_UINT;
		memexpr.size = arch->bitbase;
		//segment::[base + index*scale + disp]
		if (mem.mem.segment)
			memexpr.subExpressions.push_back (HSSAArgument::createReg (arch->getRegister (mem.mem.segment)));
		else
			memexpr.subExpressions.push_back (HSSAArgument::createVal ( (uint64_t) 0, arch->bitbase));

		if (mem.mem.base)
			memexpr.subExpressions.push_back (HSSAArgument::createReg (arch->getRegister (mem.mem.base)));
		else
			memexpr.subExpressions.push_back (HSSAArgument::createVal ( (uint64_t) 0, arch->bitbase));

		if (mem.mem.index)
			memexpr.subExpressions.push_back (HSSAArgument::createReg (arch->getRegister (mem.mem.index)));
		else
			memexpr.subExpressions.push_back (HSSAArgument::createVal ( (uint64_t) 0, arch->bitbase));

		memexpr.subExpressions.push_back (HSSAArgument::createVal (mem.mem.scale, arch->bitbase));

		memexpr.subExpressions.push_back (HSSAArgument::createVal (mem.mem.disp, arch->bitbase));

		return HIRArgument::createSSAId (addExpression (&memexpr), arch->bitbase);
	}

	template<typename ARGLIST>
	HIRArgument HSSAGen::parseConstExpression (HIRArgument argExpr, ARGLIST* arglist) {
		switch (argExpr.type) {
		default:
			return HIRArgument::createVal ( (uint64_t) 1, arch->bitbase);
		case HIR_ARGTYPE_ARG: {
			return (*arglist) [argExpr.refId];
		}
		case HIR_ARGTYPE_ID: {
			HIRExpression* expr = arch->getIrExpr (argExpr.refId);

			switch (expr->type) {
			case HIR_EXPR_OP: {
				switch (expr->mod.opType) {
				case H_OP_AND: {
					uint64_t val = 0;
					for (size_t i = 0; i < expr->subExpressions.size(); i++) {
						HIRArgument arg = parseConstExpression (expr->subExpressions[i], arglist);
						if (arg.type == HIR_ARGTYPE_UINT)
							val = val && arg.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_OR: {
					uint64_t val = 0;
					for (size_t i = 0; i < expr->subExpressions.size(); i++) {
						HIRArgument arg = parseConstExpression (expr->subExpressions[i], arglist);
						if (arg && arg.type == HIR_ARGTYPE_UINT)
							val = val || arg.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_XOR: {
					uint64_t val = 0;
					for (size_t i = 0; i < expr->subExpressions.size(); i++) {
						HIRArgument arg = parseConstExpression (expr->subExpressions[i], arglist);
						if (arg && arg.type == HIR_ARGTYPE_UINT)
							val = !!val ^ !!arg.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_NOT: {
					uint64_t val = 0;
					if (expr->subExpressions.size()) {
						HIRArgument arg = parseConstExpression (expr->subExpressions[0], arglist);
						if (arg && arg.type == HIR_ARGTYPE_UINT)
							val = !arg.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}

				case H_OP_E: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HIRArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval == arg2.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_NE: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HIRArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval != arg2.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_L: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HIRArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval < arg2.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_LE: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HIRArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval <= arg2.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_G: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HIRArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval > arg2.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_GE: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HIRArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval >= arg2.uval;
						else
							return HIRArgument::create();
					}
					return HIRArgument::createVal (val, arch->bitbase);
				}
				default:
					return HIRArgument::create();
				}
			}
			case HIR_EXPR_SIZE:
				assert (expr->subExpressions.size() == 1);
				return HIRArgument::createVal ( (uint64_t) parseConstExpression (expr->subExpressions[0], arglist).size / arch->wordbase, arch->wordbase);
			case HIR_EXPR_BSIZE:
				assert (expr->subExpressions.size() == 1);
				return HIRArgument::createVal ( (uint64_t) parseConstExpression (expr->subExpressions[0], arglist).size, arch->wordbase);
			}
		}

		break;
		case HIR_ARGTYPE_SINT:
		case HIR_ARGTYPE_UINT:
		case HIR_ARGTYPE_FLOAT:
			return argExpr;
		case HIR_ARGTYPE_REG:
		case HIR_ARGTYPE_STACK:
		case HIR_ARGTYPE_TMP:
			break;
		}
		return HIRArgument::create();
	}

	void HSSAGen::insertLabel (uint64_t address, HId instructionId) {
		HSSAExpression expression;
		expression.type = HSSA_EXPR_LABEL;
		expression.exprtype = HSSA_TYPE_PC;
		expression.size = arch->bitbase;
		expression.subExpressions.push_back (HSSAArgument::createVal (address, arch->bitbase));
		addExpression (&expression);
	}
	HSSABB* HSSAGen::getBlock (HId blockId) {
		for (HSSABB& bb : ssaRepresentation->bbs) {
			if (bb.id == blockId) {
				return &bb;
			}
		}
		return nullptr;
	}
	HSSABB* HSSAGen::getActiveBlock () {
		if (!activeblock)
			activeblock = getBlock (activeBlockId);
		return activeblock;
	}
	void HSSAGen::setActiveBlock () {
		if (!activeblock)
			activeblock = getBlock (activeBlockId);
	}
	HId HSSAGen::addExpression (HSSAExpression* expression) {
		setActiveBlock();
		if (instruction) {
			expression->instrAddr = instruction->addr;
		}

		ssaRepresentation->expressions.push_back (*expression);
		activeblock->exprIds.push_back (ssaRepresentation->expressions.back().id);

		HId newId = ssaRepresentation->expressions.back().id;
		if (expression->type == HSSA_EXPR_OP)
			lastOp = newId;
		return newId;
	}
	void HSSAGen::reset() {
		ssaRepresentation = nullptr;
	}
	void HSSAGen::setup (HSSARepresentation* ssaReg, uint64_t addr) {
		ssaRepresentation = ssaReg;
		activateBlock (createNewBlock());
		for (HRegister& reg : arch->registers) {
			HSSAExpression expression;
			expression.type = HSSA_EXPR_INPUT;
			expression.exprtype = HSSA_TYPE_UINT;
			expression.regId = reg.id;
			expression.size = reg.size;

			addExpression (&expression);
		}
		for (HMemory& mem : arch->memories) {
			HSSAExpression expression;
			expression.type = HSSA_EXPR_INPUT;
			expression.exprtype = HSSA_TYPE_MEM;
			expression.memId = mem.id;
			expression.size = 0;

			addExpression (&expression);
		}
		for (HStack& stack : arch->stacks) {
			HSSAExpression expression;
			expression.type = HSSA_EXPR_INPUT;
			expression.stackId = {stack.id, 0};
			expression.size = 0;

			addExpression (&expression);
		}
		activeblock->endaddr = addr;
	}
	void HSSAGen::setupForInstr() {

		endOfBlock = false;
		fallthrough = true;
		instruction = nullptr;
		arguments.clear();
		tmpdefs.clear();
	}

	HId HSSAGen::splitBasicBlock (uint64_t addr) {
		for (HSSABB& bb : ssaRepresentation->bbs) {
			if (bb.startaddr == addr)
				return bb.id;

			if (bb.startaddr < addr && addr <= bb.endaddr) {
				for (auto it = bb.exprIds.begin(); it != bb.exprIds.end(); ++it) {
					HSSAExpression* expr = ssaRepresentation->expressions.get (*it);
					assert (expr);
					if (expr->type == HSSA_EXPR_LABEL && expr->subExpressions.size() > 0 && expr->subExpressions[0].type == HIR_ARGTYPE_UINT && expr->subExpressions[0].uval == addr) {
						printf ("Split SSA 0x%x\n", addr);
						HId oldId = bb.id;
						HId newEndAddr = bb.endaddr;
						bb.endaddr = addr;
						HList<HId> exprsOfNewBlock (it, bb.exprIds.end());
						bb.exprIds.erase (it, bb.exprIds.end());

						HSSABB createdbb (bb.fallthroughId, addr, newEndAddr, exprsOfNewBlock);
						ssaRepresentation->bbs.push_back (createdbb);

						HSSABB* newbb = &ssaRepresentation->bbs.back();
						ssaRepresentation->bbs.get (oldId)->fallthroughId = newbb->id;

						return newbb->id;
					}
				}
			}
		}
		return 0;
	}
	HId HSSAGen::createNewBlock () {
		activeblock = nullptr;
		HSSABB block;
		ssaRepresentation->bbs.push_back (block);
		return ssaRepresentation->bbs.list.back().id;
	}
	void HSSAGen::activateBlock (HId block) {
		activeblock = nullptr;
		activeBlockId = block;
	}

	HSSAArgument HSSAGen::parseIRArg2SSAArg (HIRArgument arg) {
		switch(arg.type){
		case HIR_ARGTYPE_UNKN:
			return HSSAArgument::create();
		case HIR_ARGTYPE_SSAID:
			return HSSAArgument::createId(arg.refId, arg.size);
		case HIR_ARGTYPE_FLOAT:
			return HSSAArgument::createVal(arg.fval, arg.size);
		case HIR_ARGTYPE_UINT:
			return HSSAArgument::createVal(arg.uval, arg.size);
		case HIR_ARGTYPE_SINT:
			return HSSAArgument::createVal(arg.sval, arg.size);
		case HIR_ARGTYPE_MEM:
			return HSSAArgument::createMem(arg.refId);
		case HIR_ARGTYPE_STACK:
			return HSSAArgument::createStck(arch->getStack(arg.refId), arg.index);
		case HIR_ARGTYPE_REG:
			return HSSAArgument::createReg(arch->getRegister(arg.refId));
			
		default:
			assert(false);
		}
		return HSSAArgument::create();
	}
	HIRArgument HSSAGen::replaceArg (HIRArgument arg) {
		while (arg.type == HIR_ARGTYPE_ARG) {
			assert (arg.refId && arg.refId <= arguments.size());
			arg = arguments[arg.refId - 1];
		}
		return arg;
	}
	void HSSAGen::addUpdateRegExpressions (HId regId, HId exprId) {

		HRegister* baseReg = arch->getRegister (regId);
		HRegister* reg = baseReg;
		while (reg->directParentId) {
			reg = arch->getRegister (reg->directParentId);
			HSSAExpression updateExpression;
			updateExpression.type = baseReg->clearParentOnWrite ? HSSA_EXPR_EXTEND :  HSSA_EXPR_UPDATEPART;
			updateExpression.exprtype = HSSA_TYPE_UINT;
			updateExpression.regId = reg->id;
			updateExpression.size = reg->size;
			if (baseReg->clearParentOnWrite) {
				assert (baseReg->offset == 0);
				updateExpression.subExpressions.push_back (HSSAArgument::createId (exprId, baseReg->size));
			} else {
				updateExpression.subExpressions.push_back (HSSAArgument::createReg (reg));
				updateExpression.subExpressions.push_back (HSSAArgument::createId (exprId, baseReg->size));
				updateExpression.subExpressions.push_back (HSSAArgument::createVal (baseReg->offset - reg->offset, arch->bitbase));
			}
			addExpression (&updateExpression);
		}
	}

	bool HSSAGen::parseInstruction (HInstruction* instruction) {
		if (getActiveBlock()->startaddr > instruction->addr)
			getActiveBlock()->startaddr = instruction->addr;

		HIRRepresentation* rep = matchIr (instruction);

		if (rep) {
			setupForInstr();
			this->instruction = instruction;
			for (int i = 0; i < instruction->operands.size(); i++) {
				arguments.push_back (instruction->operands[i]);
			}
			insertLabel (instruction->addr);
			parseExpression (rep->rootExpr);
		} else {
			printf ("Could not find IR-Match for Instruction\n");//maybe at some point we will hit this ;)
			instruction->print (arch);
			assert (false);
			return false;
		}
		if (getActiveBlock()->endaddr < instruction->addr + instruction->size)
			getActiveBlock()->endaddr = instruction->addr + instruction->size;
		return true;
	}
	HIRArgument HSSAGen::parseExpression (HIRArgument exprId) {

		exprId = replaceArg (exprId);

		switch (exprId.type) {
		default:
			return exprId;
		case HIR_ARGTYPE_ARG: {
			assert (false);
		}
		case HIR_ARGTYPE_MEMOP: {

			HSSAExpression expression;
			expression.type = HSSA_EXPR_LOAD;
			expression.exprtype = HSSA_TYPE_UINT;
			expression.size = exprId.size;
			expression.subExpressions = {
				HSSAArgument::createMem (arch->getDefaultMemory()->id),
				parseIRArg2SSAArg (parseMemArgToExpr (exprId)),
				HSSAArgument::createVal ( (uint64_t) exprId.size, arch->bitbase)
			};
			return HIRArgument::createSSAId (addExpression (&expression), expression.size);
		}
		case HIR_ARGTYPE_TMP: {
			assert (exprId.refId);
			for (HSSATmpDef& def : tmpdefs) {
				if (def.id == exprId.refId) {
					return def.arg;
				}
			}
			printf ("0x%x\n", instruction->addr);
			printf ("%d\n", exprId.refId);
			assert (false);
		}
		case HIR_ARGTYPE_ID: {
			HIRExpression* expr = arch->getIrExpr (exprId.refId);

			size_t subexpressioncount = expr->subExpressions.size();

			switch (expr->type) {
			case HIR_EXPR_UNDEF: {
				for (int i = 0; i < subexpressioncount; i++) {
					assert (expr->subExpressions[i].type == HIR_ARGTYPE_ARG ||
					        expr->subExpressions[i].type == HIR_ARGTYPE_REG ||
					        expr->subExpressions[i].type == HIR_ARGTYPE_STACK ||
					        expr->subExpressions[i].type == HIR_ARGTYPE_TMP);
					HIRArgument arg = replaceArg (expr->subExpressions[i]);

					HSSAExpression expression;
					expression.type = HSSA_EXPR_UNDEF;
					expression.exprtype = HSSA_TYPE_UINT;
					switch (arg.type) {
					case HIR_ARGTYPE_REG:
						expression.regId = arg.refId;
						expression.size = arg.size;
						addUpdateRegExpressions (arg.refId, addExpression (&expression));
						break;
					case HIR_ARGTYPE_STACK:
						expression.stackId = {arg.refId, arg.index};
						expression.size = arg.size;
						addExpression (&expression);
						break;
					case HIR_ARGTYPE_TMP:
						for (auto it = tmpdefs.begin(); it != tmpdefs.end(); ++it) {
							if ( (*it).id == arg.refId) {
								tmpdefs.erase (it);
								break;
							}
						}
						continue;
					default:
						assert (false);
					}
				}
				return HIRArgument::create ();
			}
			case HIR_EXPR_ASSIGN: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_ASSIGN;
				assert (subexpressioncount == 2);
				HIRArgument dstArg = replaceArg (expr->subExpressions[0]);

				HIRArgument srcArg = parseExpression (expr->subExpressions[1]);

				if (srcArg.type == HSSA_ARGTYPE_ID) {
					HSSAExpression* ssaExpr = ssaRepresentation->expressions.get (srcArg.refId);
					assert (ssaExpr);
					if (dstArg.type == HIR_ARGTYPE_REG || dstArg.type == HIR_ARGTYPE_STACK) {
						if (!ssaExpr->regId && !ssaExpr->stackId.id && ssaExpr->size == dstArg.size) {
							if (dstArg.type == HIR_ARGTYPE_REG) {
								ssaExpr->regId = dstArg.refId;
								ssaExpr->size = arch->getRegister (dstArg.refId)->size;
								HIRArgument arg = HIRArgument::createSSAId (ssaExpr->id, ssaExpr->size);
								addUpdateRegExpressions (dstArg.refId, ssaExpr->id);//can relocate ssaExpr
								return arg;
							} else if (dstArg.type == HIR_ARGTYPE_STACK) {
								ssaExpr->stackId = {dstArg.refId, dstArg.index};
								ssaExpr->size = arch->getStack (dstArg.refId)->wordbitsize;
								return HIRArgument::createSSAId (ssaExpr->id, ssaExpr->size);
							}
						}
					} else if (dstArg.type == HIR_ARGTYPE_TMP) {
						HIRArgument arg = HIRArgument::createSSAId (ssaExpr->id, ssaExpr->size);
						for (HSSATmpDef& def : tmpdefs) {
							if (def.id == dstArg.refId) {
								def.arg = arg;
								return HIRArgument::create();
							}
						}
						tmpdefs.push_back ({dstArg.refId, arg});
						return HIRArgument::create();
					}
					expression.exprtype = ssaExpr->exprtype;
				} else {
					expression.exprtype = HSSA_TYPE_UINT;
				}
				expression.size = srcArg.size;
				HSSAArgument srcSSAArg = parseIRArg2SSAArg (srcArg);
				switch (dstArg.type) {
				case HIR_ARGTYPE_TMP: {
					expression.exprtype = HSSA_TYPE_UINT;
					expression.subExpressions.push_back (srcSSAArg);
					HIRArgument arg = HIRArgument::createSSAId (addExpression (&expression), expression.size);
					for (HSSATmpDef& def : tmpdefs) {
						if (def.id == dstArg.refId) {
							def.arg = arg;
							return HIRArgument::create();
						}
					}
					tmpdefs.push_back ({dstArg.refId, arg});
					return HIRArgument::create();
				}
				case HIR_ARGTYPE_MEMOP: {
					expression.type = HSSA_EXPR_STORE;
					expression.exprtype = HSSA_TYPE_MEM;
					expression.size = 0;
					HMemory* memory = arch->getDefaultMemory();
					expression.memId = memory->id;
					expression.subExpressions.push_back (HSSAArgument::createMem (memory->id));
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseMemArgToExpr (dstArg)));
				}
				break;
				case HIR_ARGTYPE_REG:
					expression.regId = dstArg.refId;
					expression.size = arch->getRegister (dstArg.refId)->size;

					expression.subExpressions.push_back (srcSSAArg);
					{
						HId exprId = addExpression (&expression);
						addUpdateRegExpressions (dstArg.refId, exprId);
						return HIRArgument::createSSAId (exprId, expression.size);
					}
					break;
				case HIR_ARGTYPE_STACK:
					expression.stackId = {dstArg.refId, dstArg.index};
					expression.size = arch->getStack (dstArg.refId)->wordbitsize;
					break;
				case HIR_ARGTYPE_SSAID://assign to no particular thing, needed for recursive with write-parameter as tmp
					break;
				default:
					dstArg.print (arch);
					printf ("Invalid Type for Assignment 0x%x\n", dstArg.type);
					assert (false);
					break;
				}
				expression.subExpressions.push_back (srcSSAArg);
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}

			case HIR_EXPR_NOP:
				return HIRArgument::create();

			case HIR_EXPR_IF: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_CJMP;
				expression.exprtype = HSSA_TYPE_PC;
				expression.size = arch->bitbase;

				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[0])));

				assert (subexpressioncount >= 2 && subexpressioncount <= 3);

				HId oldBlock = activeBlockId;
				HId trueblockId = createNewBlock();
				HId falseblockId = (subexpressioncount == 3) ? createNewBlock() : 0;//generate early so the blocks are in order
				HId endBlockId = createNewBlock();

				expression.subExpressions.push_back (HSSAArgument::createBlock(trueblockId));
				addExpression (&expression);

				activateBlock (trueblockId);
				parseExpression (expr->subExpressions[1]);
				getActiveBlock()->fallthroughId = endBlockId;

				if (subexpressioncount == 3) {
					getBlock (oldBlock)->fallthroughId = falseblockId;
					activateBlock (falseblockId);
					parseExpression (expr->subExpressions[2]);
					getActiveBlock()->fallthroughId = endBlockId;
				} else {
					getBlock (oldBlock)->fallthroughId = endBlockId;
				}
				activateBlock (endBlockId);
				return HIRArgument::create ();
			}
			case HIR_EXPR_JMP: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_JMP;
				expression.exprtype = HSSA_TYPE_PC;
				expression.size = arch->bitbase;

				assert (subexpressioncount == 1);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[0])));

				endOfBlock = true;
				fallthrough = false;
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_CJMP: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_CJMP;
				expression.exprtype = HSSA_TYPE_PC;
				expression.size = arch->bitbase;

				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[0])));
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[1])));

				endOfBlock = true;
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_OP: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_OP;
				expression.opType = expr->mod.opType;
				expression.exprtype = expr->exprtype;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[i])));
				}
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			// Call - Return
			case HIR_EXPR_CALL:  {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_CALL;
				expression.exprtype = expr->exprtype;
				assert (subexpressioncount == 1);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[0])));

				for (HRegister& reg : arch->registers) {
					expression.subExpressions.push_back (HSSAArgument::createReg (&reg));
				}
				for (HStack& stack : arch->stacks) {
					expression.subExpressions.push_back (HSSAArgument::createStck (&stack, 0));
				}
				for (HMemory& memory : arch->memories) {
					expression.subExpressions.push_back (HSSAArgument::createMem (memory.id));
				}

				HIRArgument arg = HIRArgument::createSSAId (addExpression (&expression), expression.size);

				HSSAArgument ssaArg = parseIRArg2SSAArg (arg);

				for (HRegister& reg : arch->registers) {
					HSSAExpression retExpr;
					retExpr.type = HSSA_EXPR_OUTPUT;
					retExpr.exprtype = HSSA_TYPE_UINT;
					retExpr.regId = reg.id;
					retExpr.size = reg.size;
					retExpr.subExpressions.push_back (ssaArg);
					addExpression (&retExpr);
				}
				for (HStack& stack : arch->stacks) {
					HSSAExpression retExpr;
					retExpr.type = HSSA_EXPR_OUTPUT;
					retExpr.exprtype = HSSA_TYPE_MEM;
					retExpr.stackId = {stack.id, 0};
					retExpr.subExpressions.push_back (ssaArg);
					addExpression (&retExpr);
				}
				for (HMemory& memory : arch->memories) {
					HSSAExpression retExpr;
					retExpr.type = HSSA_EXPR_OUTPUT;
					retExpr.exprtype = HSSA_TYPE_MEM;
					retExpr.memId = memory.id;
					retExpr.size = 0;
					retExpr.subExpressions.push_back (ssaArg);
					addExpression (&retExpr);
				}

				return arg;
			}
			case HIR_EXPR_RETURN: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_RETURN;
				expression.exprtype = HSSA_TYPE_PC;
				expression.size = arch->bitbase;
				assert (!subexpressioncount);
				for (HRegister& reg : arch->registers) {
					expression.subExpressions.push_back (HSSAArgument::createReg (&reg));
				}
				for (HStack& stack : arch->stacks) {
					expression.subExpressions.push_back (HSSAArgument::createStck (&stack, 0));
				}
				for (HMemory& memory : arch->memories) {
					expression.subExpressions.push_back (HSSAArgument::createMem (memory.id));
				}
				endOfBlock = true;
				fallthrough = false;
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_SYSCALL: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_SYSCALL;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[i])));
				}
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_TRAP: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_TRAP;
				endOfBlock = true;
				fallthrough = false;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[i])));
				}
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_BUILTIN:
				printf ("Builtin\n");
				break;
			case HIR_EXPR_EXTEND: {
				assert (subexpressioncount == 2);
				HSSAExpression expression;
				expression.type = HSSA_EXPR_EXTEND;
				expression.exprtype = expr->exprtype;
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[0])));

				HIRArgument arg = parseConstExpression (expr->subExpressions[1], &arguments);
				assert (arg && arg.type == HIR_ARGTYPE_UINT);
				expression.size = arg.uval;
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_SPLIT: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_SPLIT;
				expression.exprtype = HSSA_TYPE_UINT;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[i])));
				}
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_APPEND: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_APPEND;
				expression.exprtype = HSSA_TYPE_UINT;
				expression.size = 0;
				for (int i = 0; i < subexpressioncount; i++) {
					HSSAArgument arg = parseIRArg2SSAArg (parseExpression (expr->subExpressions[i]));
					expression.size += arg.size;
					expression.subExpressions.push_back (arg);
				}
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_CAST: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_CAST;
				expression.exprtype = expr->exprtype;
				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[0])));
				HIRArgument sizeArg = replaceArg (expr->subExpressions[1]);
				assert (sizeArg.type = HIR_ARGTYPE_UINT);
				expression.size = sizeArg;
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}

			// Memory
			case HIR_EXPR_STORE: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_STORE;
				expression.exprtype = HSSA_TYPE_MEM;
				expression.size = 0;
				assert (subexpressioncount == 3);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[0])));
				expression.memId = expression.subExpressions[0].refId;
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[1])));
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[2])));
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_LOAD: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_LOAD;
				expression.exprtype = HSSA_TYPE_UINT;
				expression.size = expr->subExpressions[2].size;
				assert (subexpressioncount == 3);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[0])));
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[1])));
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[2])));
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}

			case HIR_EXPR_PUSH: {
				HIRArgument stackArg = parseExpression (expr->subExpressions[0]);
				assert (stackArg.type == HIR_ARGTYPE_STACK);
				HStack* stack = arch->getStack (stackArg.refId);
				assert (stack);
				switch (stack->type) {
				case H_STACK_BUILTIN: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_PUSH;
					assert (subexpressioncount == 1);
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (expr->subExpressions[0])));
					return HIRArgument::createSSAId (addExpression (&expression), expression.size);
				}
				case H_STACK_MEMORY: {
					assert (subexpressioncount == 2);
					assert (stack->backingMem);
					HSSAArgument value = parseIRArg2SSAArg(parseExpression (expr->subExpressions[1]));
					HRegister* reg = arch->getRegister (stack->trackingReg);
					HMemory* mem = arch->getMemory (stack->backingMem);
					assert (reg);
					assert (mem);

					HSSAExpression expression;
					expression.type = HSSA_EXPR_STORE;
					expression.exprtype = HSSA_TYPE_MEM;
					expression.size = 0;
					expression.memId = mem->id;
					expression.subExpressions.push_back (HSSAArgument::createMem (mem->id));
					expression.subExpressions.push_back (HSSAArgument::createReg (reg));
					expression.subExpressions.push_back (value);

					HSSAExpression adjustExpr;
					adjustExpr.type = HSSA_EXPR_OP;
					adjustExpr.exprtype = HSSA_TYPE_UINT;
					adjustExpr.opType = stack->policy == H_STACKPOLICY_TOP ?  H_OP_ADD : H_OP_SUB;
					adjustExpr.subExpressions.push_back (HSSAArgument::createReg (reg));
					adjustExpr.subExpressions.push_back (HSSAArgument::createVal ( (value.size + stack->wordbitsize - 1) / stack->wordbitsize, arch->bitbase));
					adjustExpr.regId = reg->id;

					addUpdateRegExpressions (reg->id, addExpression (&adjustExpr));
					return HIRArgument::createSSAId (addExpression (&expression), expression.size);
				}
				}
				return HIRArgument::create ();
			}
			case HIR_EXPR_POP: {
				HIRArgument stackArg = parseExpression (expr->subExpressions[0]);
				assert (stackArg.type == HIR_ARGTYPE_STACK);
				HStack* stack = arch->getStack (stackArg.refId);
				assert (stack);
				switch (stack->type) {
				case H_STACK_BUILTIN: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_POP;
					assert (subexpressioncount == 1);
					expression.subExpressions.push_back (parseIRArg2SSAArg(stackArg));
					expression.size = stack->wordbitsize;
					return HIRArgument::createSSAId (addExpression (&expression), expression.size);
				}
				case H_STACK_MEMORY: {
					assert (subexpressioncount == 2);
					HSSAArgument sizeadjust = parseIRArg2SSAArg(parseExpression (expr->subExpressions[1]));
					assert (sizeadjust.type == HSSA_ARGTYPE_UINT);
					HRegister* reg = arch->getRegister (stack->trackingReg);
					HMemory* mem = arch->getMemory (stack->backingMem);
					assert (reg);
					assert (mem);

					HSSAExpression expression;
					expression.type = HSSA_EXPR_LOAD;
					expression.exprtype = HSSA_TYPE_UINT;
					expression.size = stack->wordbitsize * sizeadjust.uval;
					expression.subExpressions.push_back (HSSAArgument::createMem (mem->id));
					expression.subExpressions.push_back (HSSAArgument::createReg (reg));
					expression.subExpressions.push_back (sizeadjust);

					HSSAExpression adjustExpr;
					adjustExpr.type = HSSA_EXPR_OP;
					adjustExpr.exprtype = HSSA_TYPE_UINT;
					adjustExpr.opType = stack->policy == H_STACKPOLICY_TOP ? H_OP_SUB : H_OP_ADD;
					adjustExpr.subExpressions.push_back (HSSAArgument::createReg (reg));
					adjustExpr.subExpressions.push_back (sizeadjust);
					adjustExpr.regId = reg->id;
					adjustExpr.size = reg->size;

					HIRArgument retArg = HIRArgument::createSSAId (addExpression (&expression), expression.size);
					addUpdateRegExpressions (reg->id, addExpression (&adjustExpr));
					return retArg;
				}
				}
				return HIRArgument::create ();
			}
			case HIR_EXPR_VALUE: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_ASSIGN;
				assert (subexpressioncount == 1);
				HIRArgument arg = replaceArg (expr->subExpressions[0]);
				assert (arg.type == HIR_ARGTYPE_MEMOP);
				expression.exprtype = HSSA_TYPE_UINT;
				expression.size = arch->bitbase;
				expression.subExpressions.push_back (parseIRArg2SSAArg(parseMemArgToExpr (arg)));
				return HIRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case HIR_EXPR_REC: {
				HList<HIRArgument> args;
				for (int i = 0; i < subexpressioncount; i++) {
					args.push_back (parseExpression (expr->subExpressions[i]));
				}
				HList<HSSATmpDef> cachedTemps = this->tmpdefs;
				HList<HIRArgument> cachedArgs = this->arguments;

				tmpdefs.clear();
				this->arguments = args;

				HInstrDefinition* instrdef = arch->getInstrDef (expr->mod.instrId);

				int i;
				for (i = 0; i < instrdef->irs.size(); i++) {
					if (arguments.size() == instrdef->irs[i].argcount) {
						HIRArgument constArg = parseConstExpression (instrdef->irs[i].condExpr, &arguments);
						if (constArg && constArg.type == HIR_ARGTYPE_UINT && constArg.uval) {
							parseExpression (instrdef->irs[i].rootExpr);
							break;
						}
					}
				}
				if (i ==  instrdef->irs.size()) {
					printf ("Found No Recursive Match %s in parsing instruction: ", instrdef->mnemonics.cstr());
					instruction->print (arch);
				}
				this->arguments = cachedArgs;
				this->tmpdefs = cachedTemps;
			}
			return HIRArgument::create ();
			case HIR_EXPR_REP: {
				HId startBlock = activeBlockId;
				HId condId = createNewBlock();
				HId bodyId = createNewBlock();
				getActiveBlock()->fallthroughId = condId;


				activateBlock (condId);
				HSSAExpression expression;
				expression.type = HSSA_EXPR_CJMP;
				expression.exprtype = HSSA_TYPE_PC;
				expression.size = arch->bitbase;
				expression.subExpressions.push_back (parseIRArg2SSAArg(parseExpression (expr->subExpressions[0])));
				expression.subExpressions.push_back (HSSAArgument::createBlock(bodyId));
				addExpression (&expression);
				condId = activeBlockId;

				activateBlock (bodyId);
				parseExpression (expr->subExpressions[1]);
				getActiveBlock()->fallthroughId = condId;
				bodyId = activeBlockId;

				HId endId = createNewBlock();
				getBlock (condId)->fallthroughId = endId;
				activateBlock (endId);
				return HIRArgument::create ();
			}
			case HIR_EXPR_SIZE:
				assert (subexpressioncount == 1);
				return HIRArgument::createVal (parseExpression (expr->subExpressions[0]).size / arch->wordbase, arch->bitbase);
			case HIR_EXPR_BSIZE:
				assert (subexpressioncount == 1);
				return HIRArgument::createVal ( (uint64_t) parseExpression (expr->subExpressions[0]).size, arch->bitbase);
			case HIR_EXPR_SEQUENCE://only for ir gets resolved in ir generation
				for (int i = 0; i < subexpressioncount; i++) {
					parseExpression (expr->subExpressions[i]);
				}
				return HIRArgument::create();
			case HIR_EXPR_FLAG: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_FLAG;
				expression.flagType = expr->mod.flagType;
				expression.exprtype = HSSA_TYPE_UINT;
				expression.size = 1;


				expression.subExpressions.push_back (HSSAArgument::createId (lastOp, ssaRepresentation->expressions[lastOp].size));
				HId www = addExpression (&expression);

				return HIRArgument::createSSAId (www, expression.size);
			}
			default:
				assert (false);
				break;
			}
			return HIRArgument::create();
		}
		}
		return exprId;
	}

	void HSSAGen::print (int indent) {
		ssaRepresentation->print (arch, indent);
	}
}
