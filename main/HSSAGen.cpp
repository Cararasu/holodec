#include "HSSAGen.h"
#include "HArchitecture.h"
#include <assert.h>

namespace holodec {

	template HArgument HSSAGen::parseConstExpression (HArgument argExpr, HList<HArgument>* arglist);
	template HArgument HSSAGen::parseConstExpression (HArgument argExpr, HIdList<HArgument>* arglist);
	template HArgument HSSAGen::parseConstExpression (HArgument argExpr, HLocalBackedList<HArgument, 4>* arglist);

	HSSAGen::HSSAGen (HArchitecture* arch) : arch (arch) {}

	HSSAGen::~HSSAGen() {}

	HIRRepresentation* HSSAGen::matchIr (HInstruction* instr) {

		HInstrDefinition* instrdef = instr->instrdef;
		for (int i = 0; i < instrdef->irs.size(); i++) {
			if (instr->operands.size() == instrdef->irs[i].argcount) {
				HArgument constArg = parseConstExpression (instrdef->irs[i].condExpr, &instr->operands);
				if (constArg && constArg.type == H_ARGTYPE_UINT && constArg.uval) {
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

	HArgument HSSAGen::parseMemArgToExpr (HArgument mem) {
		HSSAExpression memexpr;
		memexpr.type = HSSA_EXPR_MEM;
		memexpr.exprtype = HSSA_TYPE_UINT;
		memexpr.size = arch->bitbase;
		//segment::[base + index*scale + disp]
		if (mem.mem.segment)
			memexpr.subExpressions.push_back (HArgument::createReg (arch->getRegister (mem.mem.segment)));
		else
			memexpr.subExpressions.push_back (HArgument::createVal ( (uint64_t) 0, arch->bitbase));

		if (mem.mem.base)
			memexpr.subExpressions.push_back (HArgument::createReg (arch->getRegister (mem.mem.base)));
		else
			memexpr.subExpressions.push_back (HArgument::createVal ( (uint64_t) 0, arch->bitbase));

		if (mem.mem.index)
			memexpr.subExpressions.push_back (HArgument::createReg (arch->getRegister (mem.mem.index)));
		else
			memexpr.subExpressions.push_back (HArgument::createVal ( (uint64_t) 0, arch->bitbase));

		memexpr.subExpressions.push_back (HArgument::createVal (mem.mem.scale, arch->bitbase));

		memexpr.subExpressions.push_back (HArgument::createVal (mem.mem.disp, arch->bitbase));

		return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&memexpr), arch->bitbase);
	}

	template<typename ARGLIST>
	HArgument HSSAGen::parseConstExpression (HArgument argExpr, ARGLIST* arglist) {
		switch (argExpr.type) {
		default:
			return HArgument::createVal ( (uint64_t) 1, arch->bitbase);
		case HIR_ARGTYPE_ARG: {
			return (*arglist) [argExpr.index];
		}
		case HIR_ARGTYPE_ID: {
			HIRExpression* expr = arch->getIrExpr (argExpr.id);

			switch (expr->type) {
			case HIR_EXPR_OP: {
				switch (expr->mod.opType) {
				case HSSA_OP_AND: {
					uint64_t val = 0;
					for (size_t i = 0; i < expr->subExpressions.size(); i++) {
						HArgument arg = parseConstExpression (expr->subExpressions[i], arglist);
						if (arg.type == H_ARGTYPE_UINT)
							val = val && arg.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				case HSSA_OP_OR: {
					uint64_t val = 0;
					for (size_t i = 0; i < expr->subExpressions.size(); i++) {
						HArgument arg = parseConstExpression (expr->subExpressions[i], arglist);
						if (arg && arg.type == H_ARGTYPE_UINT)
							val = val || arg.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				case HSSA_OP_XOR: {
					uint64_t val = 0;
					for (size_t i = 0; i < expr->subExpressions.size(); i++) {
						HArgument arg = parseConstExpression (expr->subExpressions[i], arglist);
						if (arg && arg.type == H_ARGTYPE_UINT)
							val = !!val ^ !!arg.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				case HSSA_OP_NOT: {
					uint64_t val = 0;
					if (expr->subExpressions.size()) {
						HArgument arg = parseConstExpression (expr->subExpressions[0], arglist);
						if (arg && arg.type == H_ARGTYPE_UINT)
							val = !arg.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}

				case HSSA_OP_E: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
							val = arg1.uval == arg2.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				case HSSA_OP_NE: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
							val = arg1.uval != arg2.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				case HSSA_OP_L: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
							val = arg1.uval < arg2.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				case HSSA_OP_LE: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
							val = arg1.uval <= arg2.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				case HSSA_OP_G: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
							val = arg1.uval > arg2.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				case HSSA_OP_GE: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], arglist);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
							val = arg1.uval >= arg2.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				default:
					return HArgument::create();
				}
			}
			case HIR_EXPR_SIZE:
				assert (expr->subExpressions.size() == 1);
				return HArgument::createVal ( (uint64_t) parseConstExpression (expr->subExpressions[0], arglist).size / arch->wordbase, arch->wordbase);
			case HIR_EXPR_BSIZE:
				assert (expr->subExpressions.size() == 1);
				return HArgument::createVal ( (uint64_t) parseConstExpression (expr->subExpressions[0], arglist).size, arch->wordbase);
			}
		}

		break;
		case H_ARGTYPE_SINT:
		case H_ARGTYPE_UINT:
		case H_ARGTYPE_FLOAT:
			return argExpr;
		case H_ARGTYPE_REG:
		case H_ARGTYPE_STACK:
		case HIR_ARGTYPE_TMP:
			break;
		}
		return HArgument::create();
	}

	void HSSAGen::insertLabel (uint64_t address, HId instructionId) {
		HSSAExpression expression;
		expression.type = HSSA_EXPR_LABEL;
		expression.exprtype = HSSA_TYPE_PC;
		expression.size = arch->bitbase;
		expression.subExpressions.push_back (HArgument::createVal (address, arch->bitbase));
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
					if (expr->type == HSSA_EXPR_LABEL && expr->subExpressions.size() > 0 && expr->subExpressions[0].type == H_ARGTYPE_UINT && expr->subExpressions[0].uval == addr) {
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
	HArgument HSSAGen::replaceArg (HArgument arg) {
		while (arg.type == HIR_ARGTYPE_ARG) {
			assert (arg.index && arg.index <= this->arguments.size());
			arg = arguments[arg.index - 1];
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
				updateExpression.subExpressions.push_back (HArgument::createId (HSSA_ARGTYPE_ID, exprId, baseReg->size));
			} else {
				updateExpression.subExpressions.push_back (HArgument::createReg (reg));
				updateExpression.subExpressions.push_back (HArgument::createId (HSSA_ARGTYPE_ID, exprId, baseReg->size));
				updateExpression.subExpressions.push_back (HArgument::createVal (baseReg->offset - reg->offset, arch->bitbase));
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
	HArgument HSSAGen::parseExpression (HArgument exprId) {

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
			expression.subExpressions.push_back (HArgument::createMem (0));
			expression.subExpressions.push_back (parseMemArgToExpr (exprId));
			expression.subExpressions.push_back (HArgument::createVal (exprId.size, arch->bitbase));
			return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
		}
		case HIR_ARGTYPE_TMP: {
			assert (exprId.index);
			for (HSSATmpDef& def : tmpdefs) {
				if (def.id == exprId.index) {
					return def.arg;
				}
			}
			printf ("0x%x\n", instruction->addr);
			printf ("%d\n", exprId.index);
			assert (false);
		}
		case HIR_ARGTYPE_ID: {
			HIRExpression* expr = arch->getIrExpr (exprId.id);

			size_t subexpressioncount = expr->subExpressions.size();
			
			switch (expr->type) {
			case HIR_EXPR_UNDEF: {
				for (int i = 0; i < subexpressioncount; i++) {
					assert (expr->subExpressions[i].type == HIR_ARGTYPE_ARG ||
					        expr->subExpressions[i].type == H_ARGTYPE_REG ||
					        expr->subExpressions[i].type == H_ARGTYPE_STACK ||
					        expr->subExpressions[i].type == HIR_ARGTYPE_TMP);
					HArgument arg = replaceArg (expr->subExpressions[i]);

					HSSAExpression expression;
					expression.type = HSSA_EXPR_UNDEF;
					expression.exprtype = HSSA_TYPE_UINT;
					switch (arg.type) {
					case H_ARGTYPE_REG:
						expression.regId = arg.reg;
						expression.size = arg.size;
						addUpdateRegExpressions (arg.reg, addExpression (&expression));
						break;
					case H_ARGTYPE_STACK:
						expression.stackId = {arg.stack.id, arg.stack.index};
						expression.size = arg.size;
						addExpression (&expression);
						break;
					case HIR_ARGTYPE_TMP:
						for (auto it = tmpdefs.begin(); it != tmpdefs.end(); ++it) {
							if ( (*it).id == arg.index) {
								tmpdefs.erase (it);
								break;
							}
						}
						continue;
					default:
						assert (false);
					}
				}
				return HArgument::create ();
			}
			case HIR_EXPR_ASSIGN: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_ASSIGN;
				assert (subexpressioncount == 2);
				HArgument dstArg = replaceArg (expr->subExpressions[0]);

				HArgument srcArg = parseExpression (expr->subExpressions[1]);

				if (srcArg.type == HSSA_ARGTYPE_ID) {
					HSSAExpression* ssaExpr = ssaRepresentation->expressions.get (srcArg.id);
					assert (ssaExpr);
					if (dstArg.type == H_ARGTYPE_REG || dstArg.type == H_ARGTYPE_STACK) {
						if (!ssaExpr->regId && !ssaExpr->stackId.id && ssaExpr->size == dstArg.size) {
							if (dstArg.type == H_ARGTYPE_REG) {
								ssaExpr->regId = dstArg.reg;
								ssaExpr->size = arch->getRegister (dstArg.reg)->size;
								HArgument arg = HArgument::createId (HSSA_ARGTYPE_ID, ssaExpr->id, ssaExpr->size);
								addUpdateRegExpressions (dstArg.reg, ssaExpr->id);//can relocate ssaExpr
								return arg;
							} else if (dstArg.type == H_ARGTYPE_STACK) {
								ssaExpr->stackId = dstArg.stack;
								ssaExpr->size = arch->getStack (dstArg.stack.id)->wordbitsize;
								return HArgument::createId (HSSA_ARGTYPE_ID, ssaExpr->id, ssaExpr->size);
							}
						}
					} else if (dstArg.type == HIR_ARGTYPE_TMP) {
						HArgument arg = HArgument::createId (HSSA_ARGTYPE_ID, ssaExpr->id, ssaExpr->size);
						for (HSSATmpDef& def : tmpdefs) {
							if (def.id == dstArg.index) {
								def.arg = arg;
								return HArgument::create();
							}
						}
						tmpdefs.push_back ({dstArg.index, arg});
						return HArgument::create();
					}
					expression.exprtype = ssaExpr->exprtype;
				} else {
					expression.exprtype = HSSA_TYPE_UINT;
				}
				expression.size = srcArg.size;
				switch (dstArg.type) {
				case HIR_ARGTYPE_TMP: {
					expression.exprtype = HSSA_TYPE_UINT;
					expression.subExpressions.push_back (srcArg);
					HArgument arg = HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
					for (HSSATmpDef& def : tmpdefs) {
						if (def.id == dstArg.index) {
							def.arg = arg;
							return HArgument::create();
						}
					}
					tmpdefs.push_back ({dstArg.index, arg});
					return HArgument::create();
				}
				case HIR_ARGTYPE_MEMOP: {
					expression.type = HSSA_EXPR_STORE;
					expression.exprtype = HSSA_TYPE_MEM;
					expression.size = 0;
					expression.subExpressions.push_back (HArgument::createMem (0));
					expression.subExpressions.push_back (parseMemArgToExpr (dstArg));
				}
				break;
				case H_ARGTYPE_REG:
					expression.regId = dstArg.reg;
					expression.size = arch->getRegister (dstArg.reg)->size;

					expression.subExpressions.push_back (srcArg);
					{
						HId exprId = addExpression (&expression);
						addUpdateRegExpressions (dstArg.reg, exprId);
						return HArgument::createId (HSSA_ARGTYPE_ID, exprId, expression.size);
					}
					break;
				case H_ARGTYPE_STACK:
					expression.stackId = dstArg.stack;
					expression.size = arch->getStack (dstArg.reg)->wordbitsize;
					break;
				case HSSA_ARGTYPE_ID://assign to no particular thing, needed for recursive with write-parameter as tmp
					break;
				default:
					dstArg.print (arch);
					printf ("Invalid Type for Assignment 0x%x\n", dstArg.type);
					assert (false);
					break;
				}
				expression.subExpressions.push_back (srcArg);
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}

			case HIR_EXPR_NOP:
				return HArgument::create();

			case HIR_EXPR_IF: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_CJMP;
				expression.exprtype = HSSA_TYPE_PC;
				expression.size = arch->bitbase;

				expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));

				assert (subexpressioncount >= 2 && subexpressioncount <= 3);

				HId oldBlock = activeBlockId;
				HId trueblockId = createNewBlock();
				HId falseblockId = (subexpressioncount == 3) ? createNewBlock() : 0;//generate early so the blocks are in order
				HId endBlockId = createNewBlock();

				expression.subExpressions.push_back (HArgument::createIndex (HSSA_ARGTYPE_BLOCK, trueblockId));
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
				return HArgument::create ();
			}
			case HIR_EXPR_JMP: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_JMP;
				expression.exprtype = HSSA_TYPE_PC;
				expression.size = arch->bitbase;

				assert (subexpressioncount == 1);
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));

				endOfBlock = true;
				fallthrough = false;
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			case HIR_EXPR_CJMP: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_CJMP;
				expression.exprtype = HSSA_TYPE_PC;
				expression.size = arch->bitbase;

				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[1]));

				endOfBlock = true;
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			case HIR_EXPR_OP: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_OP;
				expression.opType = expr->mod.opType;
				expression.exprtype = expr->exprtype;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseExpression (expr->subExpressions[i]));
				}
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			// Call - Return
			case HIR_EXPR_CALL:  {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_CALL;
				expression.exprtype = expr->exprtype;
				assert (subexpressioncount == 1);
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));

				for (HRegister& reg : arch->registers) {
					expression.subExpressions.push_back (HArgument::createReg (&reg));
				}

				HArgument arg = HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);

				for (HRegister& reg : arch->registers) {
					HSSAExpression retExpr;
					retExpr.type = HSSA_EXPR_OUTPUT;
					retExpr.exprtype = HSSA_TYPE_UINT;
					retExpr.regId = reg.id;
					retExpr.size = reg.size;
					retExpr.subExpressions.push_back (arg);
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
				endOfBlock = true;
				fallthrough = false;
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			case HIR_EXPR_SYSCALL: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_SYSCALL;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseExpression (expr->subExpressions[i]));
				}
				HArgument arg = HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);

				return arg;
			}
			case HIR_EXPR_TRAP: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_TRAP;
				endOfBlock = true;
				fallthrough = false;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseExpression (expr->subExpressions[i]));
				}
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			case HIR_EXPR_BUILTIN:
				printf ("Builtin\n");
				break;
			case HIR_EXPR_EXTEND: {
				assert (subexpressioncount == 2);
				HSSAExpression expression;
				expression.type = HSSA_EXPR_EXTEND;
				expression.exprtype = expr->exprtype;
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));

				HArgument arg = this->parseConstExpression (expr->subExpressions[1], &arguments);
				assert (arg && arg.type == H_ARGTYPE_UINT);
				expression.size = arg.uval;
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			case HIR_EXPR_SPLIT: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_SPLIT;
				expression.exprtype = HSSA_TYPE_UINT;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseExpression (expr->subExpressions[i]));
				}
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			case HIR_EXPR_APPEND: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_APPEND;
				expression.exprtype = HSSA_TYPE_UINT;
				expression.size = 0;
				for (int i = 0; i < subexpressioncount; i++) {
					HArgument arg = parseExpression (expr->subExpressions[i]);
					expression.size += arg.size;
					expression.subExpressions.push_back (arg);
				}
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			case HIR_EXPR_CAST: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_CAST;
				expression.exprtype = expr->exprtype;
				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));
				HArgument sizeArg = replaceArg (expr->subExpressions[1]);
				assert (sizeArg.type = H_ARGTYPE_UINT);
				expression.size = sizeArg;
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}

			// Memory
			case HIR_EXPR_STORE: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_STORE;
				expression.exprtype = HSSA_TYPE_MEM;
				expression.size = 0;
				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[1]));
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			case HIR_EXPR_LOAD: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_LOAD;
				expression.exprtype = HSSA_TYPE_UINT;
				expression.size = expr->subExpressions[1].size;
				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (HArgument::createMem (0));
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[1]));
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}

			case HIR_EXPR_PUSH: {
				HArgument stackArg = parseExpression (expr->subExpressions[0]);
				assert (stackArg.type == H_ARGTYPE_STACK);
				HStack* stack = arch->getStack (stackArg.stack.id);
				assert (stack);
				switch (stack->type) {
				case H_STACK_BUILTIN: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_PUSH;
					assert (subexpressioncount == 1);
					expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
				}
				case H_STACK_MEMORY: {
					assert (subexpressioncount == 2);
					HArgument value = parseExpression (expr->subExpressions[1]);
					HRegister* reg = arch->getRegister (stack->trackingReg);
					assert (reg);

					HSSAExpression expression;
					expression.type = HSSA_EXPR_STORE;
					expression.exprtype = HSSA_TYPE_MEM;
					expression.size = 0;
					expression.subExpressions.push_back (HArgument::createMem (0));
					expression.subExpressions.push_back (HArgument::createReg (reg));
					expression.subExpressions.push_back (value);

					HSSAExpression adjustExpr;
					adjustExpr.type = HSSA_EXPR_OP;
					adjustExpr.exprtype = HSSA_TYPE_UINT;
					adjustExpr.opType = stack->policy == H_STACKPOLICY_TOP ?  HSSA_OP_ADD : HSSA_OP_SUB;
					adjustExpr.subExpressions.push_back (HArgument::createReg (reg));
					adjustExpr.subExpressions.push_back (HArgument::createVal ( (value.size + stack->wordbitsize - 1) / stack->wordbitsize, arch->bitbase));
					adjustExpr.regId = reg->id;

					addUpdateRegExpressions (reg->id, addExpression (&adjustExpr));
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
				}
				}
				return HArgument::create ();
			}
			case HIR_EXPR_POP: {
				HArgument stackArg = parseExpression (expr->subExpressions[0]);
				assert (stackArg.type == H_ARGTYPE_STACK);
				HStack* stack = arch->getStack (stackArg.stack.id);
				assert (stack);
				switch (stack->type) {
				case H_STACK_BUILTIN: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_POP;
					assert (subexpressioncount == 1);
					expression.subExpressions.push_back (stackArg);
					expression.size = stack->wordbitsize;
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
				}
				case H_STACK_MEMORY: {
					assert (subexpressioncount == 2);
					HArgument sizeadjust = parseExpression (expr->subExpressions[1]);
					assert (sizeadjust.type == H_ARGTYPE_UINT);
					HRegister* reg = arch->getRegister (stack->trackingReg);
					assert (reg);

					HSSAExpression expression;
					expression.type = HSSA_EXPR_LOAD;
					expression.exprtype = HSSA_TYPE_UINT;
					expression.size = stack->wordbitsize * sizeadjust.uval;
					expression.subExpressions.push_back (HArgument::createMem (0));
					expression.subExpressions.push_back (HArgument::createReg (reg));
					expression.subExpressions.push_back (sizeadjust);

					HSSAExpression adjustExpr;
					adjustExpr.type = HSSA_EXPR_OP;
					adjustExpr.exprtype = HSSA_TYPE_UINT;
					adjustExpr.opType = stack->policy == H_STACKPOLICY_TOP ? HSSA_OP_SUB : HSSA_OP_ADD;
					adjustExpr.subExpressions.push_back (HArgument::createReg (reg));
					adjustExpr.subExpressions.push_back (sizeadjust);
					adjustExpr.regId = reg->id;
					adjustExpr.size = reg->size;

					HArgument retArg = HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
					addUpdateRegExpressions (reg->id, addExpression (&adjustExpr));
					return retArg;
				}
				}
				return HArgument::create ();
			}
			case HIR_EXPR_VALUE: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_ASSIGN;
				assert (subexpressioncount == 1);
				HArgument arg = replaceArg (expr->subExpressions[0]);
				assert (arg.type == HIR_ARGTYPE_MEMOP);
				expression.exprtype = HSSA_TYPE_UINT;
				expression.size = arch->bitbase;
				expression.subExpressions.push_back (parseMemArgToExpr (arg));
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression), expression.size);
			}
			case HIR_EXPR_REC: {
				HList<HArgument> args;
				for (int i = 0; i < subexpressioncount; i++) {
					args.push_back (parseExpression (expr->subExpressions[i]));
				}
				HList<HSSATmpDef> cachedTemps = this->tmpdefs;
				HList<HArgument> cachedArgs = this->arguments;

				tmpdefs.clear();
				this->arguments = args;

				HInstrDefinition* instrdef = arch->getInstrDef (expr->mod.instrId);

				int i;
				for (i = 0; i < instrdef->irs.size(); i++) {
					if (arguments.size() == instrdef->irs[i].argcount) {
						HArgument constArg = parseConstExpression (instrdef->irs[i].condExpr, &arguments);
						if (constArg && constArg.type == H_ARGTYPE_UINT && constArg.uval) {
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
			return HArgument::create ();
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
				expression.subExpressions.push_back (parseExpression (expr->subExpressions[0]));
				expression.subExpressions.push_back (HArgument::createIndex (HSSA_ARGTYPE_BLOCK, bodyId));
				addExpression (&expression);
				condId = activeBlockId;

				activateBlock (bodyId);
				parseExpression (expr->subExpressions[1]);
				getActiveBlock()->fallthroughId = condId;
				bodyId = activeBlockId;

				HId endId = createNewBlock();
				getBlock (condId)->fallthroughId = endId;
				activateBlock (endId);
				return HArgument::create ();
			}
			case HIR_EXPR_SIZE:
				assert (subexpressioncount == 1);
				return HArgument::createVal (parseExpression (expr->subExpressions[0]).size / arch->wordbase, arch->bitbase);
			case HIR_EXPR_BSIZE:
				assert (subexpressioncount == 1);
				return HArgument::createVal (parseExpression (expr->subExpressions[0]).size, arch->bitbase);
			case HIR_EXPR_SEQUENCE://only for ir gets resolved in ir generation
				for (int i = 0; i < subexpressioncount; i++) {
					parseExpression (expr->subExpressions[i]);
				}
				return HArgument::create();
			case HIR_EXPR_FLAG: {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_FLAG;
				expression.flagType = expr->mod.flagType;
				expression.exprtype = HSSA_TYPE_UINT;
				expression.size = 1;


				expression.subExpressions.push_back (HArgument::createId (HSSA_ARGTYPE_ID, lastOp, ssaRepresentation->expressions[lastOp].size));
				HId www = addExpression (&expression);
				
				return HArgument::createId (HSSA_ARGTYPE_ID, www, expression.size);
			}
			default:
				assert (false);
				break;
			}
			return HArgument::create();
		}
		}
		return exprId;
	}

	void HSSAGen::print (int indent) {
		ssaRepresentation->print (arch, indent);
	}
}
