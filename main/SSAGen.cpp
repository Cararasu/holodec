#include "SSAGen.h"
#include "Architecture.h"
#include <assert.h>

namespace holodec {

	template IRArgument SSAGen::parseConstExpression (IRArgument argExpr, HList<IRArgument>* arglist);
	template IRArgument SSAGen::parseConstExpression (IRArgument argExpr, HLocalBackedList<IRArgument, 4>* arglist);



	SSAGen::SSAGen (Architecture* arch) : arch (arch) {}

	SSAGen::~SSAGen() {}

	IRRepresentation* SSAGen::matchIr (Instruction* instr) {

		InstrDefinition* instrdef = instr->instrdef;
		for (int i = 0; i < instrdef->irs.size(); i++) {
			if (instr->operands.size() == instrdef->irs[i].argcount) {
				IRArgument constArg = parseConstExpression (instrdef->irs[i].condExpr, &instr->operands);
				if (constArg && constArg.type == IR_ARGTYPE_UINT && constArg.uval) {
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

	IRArgument SSAGen::parseMemArgToExpr (IRArgument mem) {
		SSAExpression memexpr;
		memexpr.type = SSA_EXPR_LOADADDR;
		memexpr.returntype = SSA_TYPE_UINT;
		memexpr.size = arch->bitbase;
		//segment::[base + index*scale + disp]
		SSAArgument args[5];
		if (mem.mem.segment)
			args[0] = SSAArgument::createReg (arch->getRegister (mem.mem.segment));
		else
			args[0] = SSAArgument::createVal ( (uint64_t) 0, arch->bitbase);

		if (mem.mem.base)
			args[1] = SSAArgument::createReg (arch->getRegister (mem.mem.base));
		else
			args[1] = SSAArgument::createVal ( (uint64_t) 0, arch->bitbase);

		if (mem.mem.index)
			args[2] = SSAArgument::createReg (arch->getRegister (mem.mem.index));
		else
			args[2] = SSAArgument::createVal ( (uint64_t) 0, arch->bitbase);

		args[3] = SSAArgument::createVal (mem.mem.scale, arch->bitbase);

		args[4] = SSAArgument::createVal (mem.mem.disp, arch->bitbase);
		
		memexpr.subExpressions.assign(args, args + 5);
		return IRArgument::createSSAId (addExpression (&memexpr), arch->bitbase);
	}

	template<typename ARGLIST>
	IRArgument SSAGen::parseConstExpression (IRArgument argExpr, ARGLIST* arglist) {
		switch (argExpr.type) {
		default:
			return IRArgument::createVal ( (uint64_t) 1, arch->bitbase);
		case IR_ARGTYPE_ARG: {
			return (*arglist) [argExpr.ref.refId];
		}
		case IR_ARGTYPE_ID: {
			IRExpression* irExpr = arch->getIrExpr (argExpr.ref.refId);

			switch (irExpr->type) {
			case IR_EXPR_OP: {
				switch (irExpr->mod.opType) {
				case H_OP_AND: {
					uint64_t val = 0;
					for (size_t i = 0; i < irExpr->subExpressions.size(); i++) {
						IRArgument arg = parseConstExpression (irExpr->subExpressions[i], arglist);
						if (arg.type == IR_ARGTYPE_UINT)
							val = val && arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_OR: {
					uint64_t val = 0;
					for (size_t i = 0; i < irExpr->subExpressions.size(); i++) {
						IRArgument arg = parseConstExpression (irExpr->subExpressions[i], arglist);
						if (arg && arg.type == IR_ARGTYPE_UINT)
							val = val || arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_XOR: {
					uint64_t val = 0;
					for (size_t i = 0; i < irExpr->subExpressions.size(); i++) {
						IRArgument arg = parseConstExpression (irExpr->subExpressions[i], arglist);
						if (arg && arg.type == IR_ARGTYPE_UINT)
							val = !!val ^ !!arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_NOT: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size()) {
						IRArgument arg = parseConstExpression (irExpr->subExpressions[0], arglist);
						if (arg && arg.type == IR_ARGTYPE_UINT)
							val = !arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}

				case H_OP_EQ: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval == arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_NE: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval != arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_L: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval < arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_LE: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval <= arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_G: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval > arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}
				case H_OP_GE: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval >= arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createVal (val, arch->bitbase);
				}
				default:
					return IRArgument::create();
				}
			}
			case IR_EXPR_SIZE:
				assert (irExpr->subExpressions.size() == 1);
				return IRArgument::createVal ( (uint64_t) parseConstExpression (irExpr->subExpressions[0], arglist).size / arch->wordbase, arch->wordbase);
			case IR_EXPR_BSIZE:
				assert (irExpr->subExpressions.size() == 1);
				return IRArgument::createVal ( (uint64_t) parseConstExpression (irExpr->subExpressions[0], arglist).size, arch->wordbase);
			}
		}

		break;
		case IR_ARGTYPE_SINT:
		case IR_ARGTYPE_UINT:
		case IR_ARGTYPE_FLOAT:
			return argExpr;
		case IR_ARGTYPE_REG:
		case IR_ARGTYPE_STACK:
		case IR_ARGTYPE_TMP:
			break;
		}
		return IRArgument::create();
	}

	void SSAGen::insertLabel (uint64_t address, HId instructionId) {
		SSAExpression expression;
		expression.type = SSA_EXPR_LABEL;
		expression.returntype = SSA_TYPE_PC;
		expression.size = arch->bitbase;
		expression.subExpressions.push_back (SSAArgument::createVal (address, arch->bitbase));
		addExpression (&expression);
	}
	SSABB* SSAGen::getBlock (HId blockId) {
		for (SSABB& bb : ssaRepresentation->bbs) {
			if (bb.id == blockId) {
				return &bb;
			}
		}
		return nullptr;
	}
	SSABB* SSAGen::getActiveBlock () {
		if (!activeblock)
			activeblock = getBlock (activeBlockId);
		return activeblock;
	}
	void SSAGen::setActiveBlock () {
		if (!activeblock)
			activeblock = getBlock (activeBlockId);
	}
	HId SSAGen::addExpression (SSAExpression* expression) {
		setActiveBlock();
		if (instruction) {
			expression->instrAddr = instruction->addr;
		}

		ssaRepresentation->expressions.push_back (*expression);
		activeblock->exprIds.push_back (ssaRepresentation->expressions.back().id);
		
		
		HId ssaId = ssaRepresentation->expressions.back().id;
		if (expression->type == SSA_EXPR_OP)
			lastOp = ssaId;
		return ssaId;
	}
	void SSAGen::reset() {
		ssaRepresentation = nullptr;
	}
	void SSAGen::setup (SSARepresentation* ssaReg, uint64_t addr) {
		ssaRepresentation = ssaReg;
		activateBlock (createNewBlock());
		for (Register& reg : arch->registers) {
			if(!reg.id || reg.directParentRef)
				continue;
			SSAExpression expression;
			expression.type = SSA_EXPR_INPUT;
			expression.returntype = SSA_TYPE_UINT;
			expression.location = SSA_LOCATION_REG;
			expression.locref = {reg.id, 0};
			expression.size = reg.size;

			addExpression (&expression);
		}
		for (Memory& mem : arch->memories) {
			SSAExpression expression;
			expression.type = SSA_EXPR_INPUT;
			expression.returntype = SSA_TYPE_MEMACCESS;
			expression.location = SSA_LOCATION_MEM;
			expression.locref = {mem.id, 0};
			expression.size = 0;

			addExpression (&expression);
		}
		for (Stack& stack : arch->stacks) {
			SSAExpression expression;
			expression.type = SSA_EXPR_INPUT;
			expression.location = SSA_LOCATION_STACK;
			expression.locref = {stack.id, 0};
			expression.size = 0;

			addExpression (&expression);
		}
		activeblock->endaddr = addr;
	}
	void SSAGen::setupForInstr() {

		endOfBlock = false;
		fallthrough = true;
		instruction = nullptr;
		arguments.clear();
		tmpdefs.clear();
	}

	HId SSAGen::splitBasicBlock (uint64_t addr) {
		for (SSABB& bb : ssaRepresentation->bbs) {
			if (bb.startaddr == addr)
				return bb.id;

			if (bb.startaddr < addr && addr <= bb.endaddr) {
				for (auto it = bb.exprIds.begin(); it != bb.exprIds.end(); ++it) {
					SSAExpression* expr = ssaRepresentation->expressions.get (*it);
					assert (expr);
					if (expr->type == SSA_EXPR_LABEL && expr->subExpressions.size() > 0 && expr->subExpressions[0].type == SSA_ARGTYPE_UINT && expr->subExpressions[0].uval == addr) {
						printf ("Split SSA 0x%x\n", addr);
						HId oldId = bb.id;
						HId newEndAddr = bb.endaddr;
						bb.endaddr = addr;
						HList<HId> exprsOfNewBlock (it, bb.exprIds.end());
						bb.exprIds.erase (it, bb.exprIds.end());

						SSABB createdbb (bb.fallthroughId, addr, newEndAddr, exprsOfNewBlock, {oldId}, bb.outBlocks);
						ssaRepresentation->bbs.push_back (createdbb);

						SSABB* newbb = &ssaRepresentation->bbs.back();
						SSABB* oldbb = ssaRepresentation->bbs.get (oldId);
						oldbb->fallthroughId = newbb->id;
						oldbb->outBlocks = {newbb->id};

						return newbb->id;
					}
				}
			}
		}
		return 0;
	}
	HId SSAGen::createNewBlock () {
		activeblock = nullptr;
		SSABB block;
		ssaRepresentation->bbs.push_back (block);
		return ssaRepresentation->bbs.list.back().id;
	}
	void SSAGen::activateBlock (HId block) {
		activeblock = nullptr;
		activeBlockId = block;
	}

	SSAArgument SSAGen::parseIRArg2SSAArg (IRArgument arg) {
		switch(arg.type){
		case IR_ARGTYPE_UNKN:
			return SSAArgument::create();
		case IR_ARGTYPE_SSAID:
			return SSAArgument::createId(arg.ref.refId, arg.size);
		case IR_ARGTYPE_FLOAT:
			return SSAArgument::createVal(arg.fval, arg.size);
		case IR_ARGTYPE_UINT:
			return SSAArgument::createVal(arg.uval, arg.size);
		case IR_ARGTYPE_SINT:
			return SSAArgument::createVal(arg.sval, arg.size);
		case IR_ARGTYPE_MEM:
			return SSAArgument::createMem(arg.ref.refId);
		case IR_ARGTYPE_STACK:
			return SSAArgument::createStck(arg.ref, arg.size);
		case IR_ARGTYPE_REG:
			return SSAArgument::createReg(arg.ref, arg.size);
			
		default:
			assert(false);
		}
		return SSAArgument::create();
	}
	IRArgument SSAGen::replaceArg (IRArgument arg) {
		while (arg.type == IR_ARGTYPE_ARG) {
			assert (arg.ref.refId && arg.ref.refId <= arguments.size());
			arg = arguments[arg.ref.refId - 1];
		}
		return arg;
	}
	void SSAGen::addUpdateRegExpressions (HId regId, HId ssaId) {

		Register* baseReg = arch->getRegister (regId);
		Register* reg = baseReg;
		while (reg->directParentRef) {
			reg = arch->getRegister (reg->directParentRef);
			SSAExpression updateExpression;
			updateExpression.type = baseReg->clearParentOnWrite ? SSA_EXPR_EXTEND :  SSA_EXPR_UPDATEPART;
			updateExpression.returntype = SSA_TYPE_UINT;
			updateExpression.location = SSA_LOCATION_REG;
			updateExpression.locref = {reg->id, 0};
			updateExpression.size = reg->size;
			if (baseReg->clearParentOnWrite) {
				assert (baseReg->offset == 0);
				updateExpression.subExpressions.push_back (SSAArgument::createId (ssaId, baseReg->size));
			} else {
				updateExpression.subExpressions.push_back (SSAArgument::createReg (reg));
				updateExpression.subExpressions.push_back (SSAArgument::createId (ssaId, baseReg->size));
				updateExpression.subExpressions.push_back (SSAArgument::createVal (baseReg->offset - reg->offset, arch->bitbase));
			}
			addExpression (&updateExpression);
		}
	}

	bool SSAGen::parseInstruction (Instruction* instruction) {
		if (getActiveBlock()->startaddr > instruction->addr)
			getActiveBlock()->startaddr = instruction->addr;

		IRRepresentation* rep = matchIr (instruction);

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
	IRArgument SSAGen::parseExpression (IRArgument exprId) {

		exprId = replaceArg (exprId);

		switch (exprId.type) {
		default:
			return exprId;
		case IR_ARGTYPE_ARG: {
			assert (false);
		}
		case IR_ARGTYPE_MEMOP: {
			SSAExpression expression;
			expression.type = SSA_EXPR_LOAD;
			expression.returntype = SSA_TYPE_UINT;
			expression.location = SSA_LOCATION_MEM;
			expression.locref = {arch->getDefaultMemory()->id, 0};
			expression.size = exprId.size;
			expression.subExpressions = {
				parseIRArg2SSAArg (parseMemArgToExpr (exprId)),
				SSAArgument::createVal ( (uint64_t) exprId.size, arch->bitbase)
			};
			return IRArgument::createSSAId (addExpression (&expression), expression.size);
		}
		case IR_ARGTYPE_TMP: {
			assert (exprId.ref.refId);
			for (SSATmpDef& def : tmpdefs) {
				if (def.id == exprId.ref.refId) {
					return def.arg;
				}
			}
			printf ("0x%x\n", instruction->addr);
			printf ("%d\n", exprId.ref.refId);
			assert (false);
		}
		case IR_ARGTYPE_ID: {
			IRExpression* irExpr = arch->getIrExpr (exprId.ref.refId);

			size_t subexpressioncount = irExpr->subExpressions.size();

			switch (irExpr->type) {
			case IR_EXPR_UNDEF: {
				for (int i = 0; i < subexpressioncount; i++) {
					assert (irExpr->subExpressions[i].type == IR_ARGTYPE_ARG ||
							irExpr->subExpressions[i].type == IR_ARGTYPE_REG ||
							irExpr->subExpressions[i].type == IR_ARGTYPE_STACK ||
							irExpr->subExpressions[i].type == IR_ARGTYPE_TMP);
					IRArgument arg = replaceArg (irExpr->subExpressions[i]);

					SSAExpression expression;
					expression.type = SSA_EXPR_UNDEF;
					expression.returntype = SSA_TYPE_UINT;
					switch (arg.type) {
					case IR_ARGTYPE_REG:
						expression.location = SSA_LOCATION_REG;
						expression.locref = arg.ref;
						expression.size = arg.size;
						addUpdateRegExpressions (arg.ref.refId, addExpression (&expression));
						break;
					case IR_ARGTYPE_STACK:
						expression.location = SSA_LOCATION_STACK;
						expression.locref = arg.ref;
						expression.size = arg.size;
						addExpression (&expression);
						break;
					case IR_ARGTYPE_TMP:
						for (auto it = tmpdefs.begin(); it != tmpdefs.end(); ++it) {
							if ( (*it).id == arg.ref.refId) {
								tmpdefs.erase (it);
								break;
							}
						}
						continue;
					default:
						assert (false);
					}
				}
				return IRArgument::create ();
			}
			case IR_EXPR_ASSIGN: {
				SSAExpression expression;
				expression.type = SSA_EXPR_ASSIGN;
				assert (subexpressioncount == 2);
				IRArgument dstArg = replaceArg (irExpr->subExpressions[0]);

				IRArgument srcArg = parseExpression (irExpr->subExpressions[1]);

				if (srcArg.type == SSA_ARGTYPE_ID) {
					SSAExpression* ssaExpr = ssaRepresentation->expressions.get (srcArg.ref.refId);
					assert (ssaExpr);
					if (dstArg.type == IR_ARGTYPE_REG || dstArg.type == IR_ARGTYPE_STACK) {
						if (ssaExpr->location == SSA_LOCATION_NONE && ssaExpr->size == dstArg.size) {
							if (dstArg.type == IR_ARGTYPE_REG) {
								ssaExpr->location = SSA_LOCATION_REG;
								ssaExpr->locref = dstArg.ref;
								ssaExpr->size = dstArg.size;
								IRArgument arg = IRArgument::createSSAId (srcArg.ref.refId, ssaExpr->size);
								addUpdateRegExpressions (dstArg.ref.refId, srcArg.ref.refId);//can relocate ssaExpr
								return arg;
							} else if (dstArg.type == IR_ARGTYPE_STACK) {
								ssaExpr->location = SSA_LOCATION_STACK;
								ssaExpr->locref = dstArg.ref;
								ssaExpr->size = dstArg.size;
								return IRArgument::createSSAId (srcArg.ref.refId, ssaExpr->size);
							}
						}
					} else if (dstArg.type == IR_ARGTYPE_TMP) {
						IRArgument arg = IRArgument::createSSAId (srcArg.ref.refId, ssaExpr->size);
						for (SSATmpDef& def : tmpdefs) {
							if (def.id == dstArg.ref.refId) {
								def.arg = arg;
								return IRArgument::create();
							}
						}
						tmpdefs.push_back ({dstArg.ref.refId, arg});
						return IRArgument::create();
					}
					expression.returntype = ssaExpr->returntype;
				} else {
					expression.returntype = SSA_TYPE_UINT;
				}
				expression.size = srcArg.size;
				SSAArgument srcSSAArg = parseIRArg2SSAArg (srcArg);
				switch (dstArg.type) {
				case IR_ARGTYPE_TMP: {
					expression.returntype = SSA_TYPE_UINT;
					expression.subExpressions.push_back (srcSSAArg);
					IRArgument arg = IRArgument::createSSAId (addExpression (&expression), expression.size);
					for (SSATmpDef& def : tmpdefs) {
						if (def.id == dstArg.ref.refId) {
							def.arg = arg;
							return IRArgument::create();
						}
					}
					tmpdefs.push_back ({dstArg.ref.refId, arg});
					return IRArgument::create();
				}
				case IR_ARGTYPE_MEMOP: {
					expression.type = SSA_EXPR_STORE;
					expression.returntype = SSA_TYPE_MEMACCESS;
					expression.size = 0;
					Memory* memory = arch->getDefaultMemory();
					expression.location = SSA_LOCATION_MEM;
					expression.locref = {memory->id, 0};
					expression.subExpressions = {parseIRArg2SSAArg (parseMemArgToExpr (dstArg))};
				}
				break;
				case IR_ARGTYPE_REG:
					expression.location = SSA_LOCATION_REG;
					expression.locref = dstArg.ref;
					expression.size = dstArg.size;

					expression.subExpressions = {srcSSAArg};
					{
						HId ssaId = addExpression (&expression);
						addUpdateRegExpressions (dstArg.ref.refId, ssaId);
						return IRArgument::createSSAId (ssaId, expression.size);
					}
					break;
				case IR_ARGTYPE_STACK:
					expression.location = SSA_LOCATION_STACK;
					expression.locref = dstArg.ref;
					expression.size = dstArg.size;
					break;
				case IR_ARGTYPE_SSAID://assign to no particular thing, needed for recursive with write-parameter as tmp
					break;
				default:
					dstArg.print (arch);
					printf ("Invalid Type for Assignment 0x%x\n", dstArg.type);
					assert (false);
					break;
				}
				expression.subExpressions = {srcSSAArg};
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}

			case IR_EXPR_NOP:
				return IRArgument::create();

			case IR_EXPR_IF: {
				SSAExpression expression;
				expression.type = SSA_EXPR_CJMP;
				expression.returntype = SSA_TYPE_PC;
				expression.size = arch->bitbase;
				
				SSAArgument exprArgs[2];
				exprArgs[0] = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0]));

				assert (subexpressioncount >= 2 && subexpressioncount <= 3);

				HId oldBlock = activeBlockId;
				HId trueblockId = createNewBlock();
				HId falseblockId = (subexpressioncount == 3) ? createNewBlock() : 0;//generate early so the blocks are in order
				HId endBlockId = createNewBlock();

				exprArgs[1] = SSAArgument::createBlock(trueblockId);
				expression.subExpressions.assign(exprArgs, exprArgs + 2);
				addExpression (&expression);

				activateBlock (trueblockId);
				parseExpression (irExpr->subExpressions[1]);
				getActiveBlock()->fallthroughId = endBlockId;

				if (falseblockId) {
					getBlock (oldBlock)->fallthroughId = falseblockId;
					activateBlock (falseblockId);
					parseExpression (irExpr->subExpressions[2]);
					SSABB* activeblock = getActiveBlock();
					activeblock->fallthroughId = endBlockId;
					activeblock->outBlocks.insert(endBlockId);
					getBlock(endBlockId)->inBlocks.insert(activeblock->id);
				} else {
					SSABB* oldBB = getBlock(oldBlock);
					oldBB->fallthroughId = endBlockId;
					oldBB->outBlocks.insert(endBlockId);
					getBlock(endBlockId)->inBlocks.insert(oldBB->id);
				}
				activateBlock (endBlockId);
				return IRArgument::create ();
			}
			case IR_EXPR_JMP: {
				SSAExpression expression;
				expression.type = SSA_EXPR_JMP;
				expression.returntype = SSA_TYPE_PC;
				expression.size = arch->bitbase;

				assert (subexpressioncount == 1);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));

				endOfBlock = true;
				fallthrough = false;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_CJMP: {
				SSAExpression expression;
				expression.type = SSA_EXPR_CJMP;
				expression.returntype = SSA_TYPE_PC;
				expression.size = arch->bitbase;

				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1])));

				endOfBlock = true;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_OP: {
				SSAExpression expression;
				expression.type = SSA_EXPR_OP;
				expression.opType = irExpr->mod.opType;
				expression.returntype = irExpr->returntype;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i])));
				}
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			// Call - Return
			case IR_EXPR_CALL:  {
				SSAExpression expression;
				expression.type = SSA_EXPR_CALL;
				expression.returntype = irExpr->returntype;
				assert (subexpressioncount == 1);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));

				for (Register& reg : arch->registers) {
					if(!reg.id || reg.directParentRef)
						continue;
					expression.subExpressions.push_back (SSAArgument::createReg (&reg));
				}
				for (Stack& stack : arch->stacks) {
					expression.subExpressions.push_back (SSAArgument::createStck (&stack, 0));
				}
				for (Memory& memory : arch->memories) {
					expression.subExpressions.push_back (SSAArgument::createMem (memory.id));
				}

				IRArgument arg = IRArgument::createSSAId (addExpression (&expression), expression.size);

				SSAArgument ssaArg = parseIRArg2SSAArg (arg);

				for (Register& reg : arch->registers) {
					if(!reg.id || reg.directParentRef)
						continue;
					SSAExpression retExpr;
					retExpr.type = SSA_EXPR_OUTPUT;
					retExpr.returntype = SSA_TYPE_UINT;
					retExpr.location = SSA_LOCATION_REG;
					retExpr.locref = {reg.id, 0};
					retExpr.size = reg.size;
					retExpr.subExpressions.push_back (ssaArg);
					addExpression (&retExpr);
				}
				for (Stack& stack : arch->stacks) {
					SSAExpression retExpr;
					retExpr.type = SSA_EXPR_OUTPUT;
					retExpr.returntype = SSA_TYPE_MEMACCESS;
					retExpr.location = SSA_LOCATION_STACK;
					retExpr.locref = {stack.id, 0};
					retExpr.subExpressions.push_back (ssaArg);
					addExpression (&retExpr);
				}
				for (Memory& memory : arch->memories) {
					SSAExpression retExpr;
					retExpr.type = SSA_EXPR_OUTPUT;
					retExpr.returntype = SSA_TYPE_MEMACCESS;
					retExpr.location = SSA_LOCATION_MEM;
					retExpr.locref = {memory.id, 0};
					retExpr.size = 0;
					retExpr.subExpressions.push_back (ssaArg);
					addExpression (&retExpr);
				}

				return arg;
			}
			case IR_EXPR_RETURN: {
				SSAExpression expression;
				expression.type = SSA_EXPR_RETURN;
				expression.returntype = SSA_TYPE_PC;
				expression.size = arch->bitbase;
				assert (!subexpressioncount);
				for (Register& reg : arch->registers) {
					if(!reg.id || reg.directParentRef)
						continue;
					expression.subExpressions.push_back (SSAArgument::createReg (&reg));
				}
				for (Stack& stack : arch->stacks) {
					expression.subExpressions.push_back (SSAArgument::createStck (&stack, 0));
				}
				for (Memory& memory : arch->memories) {
					expression.subExpressions.push_back (SSAArgument::createMem (memory.id));
				}
				endOfBlock = true;
				fallthrough = false;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_SYSCALL: {
				SSAExpression expression;
				expression.type = SSA_EXPR_SYSCALL;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i])));
				}
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_TRAP: {
				SSAExpression expression;
				expression.type = SSA_EXPR_TRAP;
				endOfBlock = true;
				fallthrough = false;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i])));
				}
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_BUILTIN:
				printf ("Builtin\n");
				break;
			case IR_EXPR_EXTEND: {
				assert (subexpressioncount == 2);
				SSAExpression expression;
				expression.type = SSA_EXPR_EXTEND;
				expression.returntype = irExpr->returntype;
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));

				IRArgument arg = parseConstExpression (irExpr->subExpressions[1], &arguments);
				assert (arg && arg.type == IR_ARGTYPE_UINT);
				expression.size = arg.uval;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_SPLIT: {
				SSAExpression expression;
				expression.type = SSA_EXPR_SPLIT;
				expression.returntype = SSA_TYPE_UINT;
				for (int i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i])));
				}
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_APPEND: {
				SSAExpression expression;
				expression.type = SSA_EXPR_APPEND;
				expression.returntype = SSA_TYPE_UINT;
				expression.size = 0;
				for (int i = 0; i < subexpressioncount; i++) {
					SSAArgument arg = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i]));
					expression.size += arg.size;
					expression.subExpressions.push_back (arg);
				}
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_CAST: {
				SSAExpression expression;
				expression.type = SSA_EXPR_CAST;
				expression.returntype = irExpr->returntype;
				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));
				IRArgument sizeArg = replaceArg (irExpr->subExpressions[1]);
				assert (sizeArg.type = IR_ARGTYPE_UINT);
				expression.size = sizeArg;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}

			// Memory
			case IR_EXPR_STORE: {
				SSAExpression expression;
				expression.type = SSA_EXPR_STORE;
				expression.returntype = SSA_TYPE_MEMACCESS;
				expression.size = 0;
				assert (subexpressioncount == 3);
				SSAArgument memarg = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0]));
				assert(memarg.type == SSA_ARGTYPE_MEM);
				expression.location = SSA_LOCATION_MEM;
				expression.locref = memarg.ref;
				expression.subExpressions = {
					parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1])),
					parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[2]))
				};
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_LOAD: {
				SSAExpression expression;
				expression.type = SSA_EXPR_LOAD;
				expression.returntype = SSA_TYPE_UINT;
				assert (subexpressioncount == 3);
				SSAArgument memarg = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0]));
				assert(memarg.type == SSA_ARGTYPE_MEM);
				expression.location = SSA_LOCATION_MEM;
				expression.locref = memarg.ref;
				expression.size = irExpr->subExpressions[2].size;
				expression.subExpressions = {
					parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1])),
					parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[2]))
				};
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}

			case IR_EXPR_PUSH: {
				IRArgument stackArg = parseExpression (irExpr->subExpressions[0]);
				assert (stackArg.type == IR_ARGTYPE_STACK);
				Stack* stack = arch->getStack (stackArg.ref.refId);
				assert (stack);
				switch (stack->type) {
				case H_STACK_REGBACKED: {
					assert(false);
					return IRArgument::createSSAId (0, 0);
				}
				case H_STACK_MEMORY: {
					assert (subexpressioncount == 2);
					assert (stack->backingMem);
					SSAArgument value = parseIRArg2SSAArg(parseExpression (irExpr->subExpressions[1]));
					Register* reg = arch->getRegister (stack->trackingReg);
					Memory* mem = arch->getMemory (stack->backingMem);
					assert (reg);
					assert (mem);
					
					SSAExpression expression;
					expression.type = SSA_EXPR_STORE;
					expression.returntype = SSA_TYPE_MEMACCESS;
					expression.size = 0;
					expression.location = SSA_LOCATION_MEM;
					expression.locref = {mem->id, 0};
					expression.subExpressions = {
						SSAArgument::createReg (reg),
						value
					};

					SSAExpression adjustExpr;
					adjustExpr.type = SSA_EXPR_OP;
					adjustExpr.returntype = SSA_TYPE_UINT;
					adjustExpr.opType = stack->policy == H_STACKPOLICY_TOP ?  H_OP_ADD : H_OP_SUB;
					adjustExpr.subExpressions = {
						SSAArgument::createReg (reg),
						SSAArgument::createVal ( (value.size + stack->wordbitsize - 1) / stack->wordbitsize, arch->bitbase)
					};
					adjustExpr.location = SSA_LOCATION_REG;
					adjustExpr.locref = {reg->id, 0};

					addUpdateRegExpressions (reg->id, addExpression (&adjustExpr));
					return IRArgument::createSSAId (addExpression (&expression), expression.size);
				}
				}
				return IRArgument::create ();
			}
			case IR_EXPR_POP: {
				IRArgument stackArg = parseExpression (irExpr->subExpressions[0]);
				assert (stackArg.type == IR_ARGTYPE_STACK);
				Stack* stack = arch->getStack (stackArg.ref.refId);
				assert (stack);
				switch (stack->type) {
				case H_STACK_REGBACKED: {
					assert(false);
					return IRArgument::createSSAId (0,0);
				}
				case H_STACK_MEMORY: {
					assert (subexpressioncount == 2);
					SSAArgument sizeadjust = parseIRArg2SSAArg(parseExpression (irExpr->subExpressions[1]));
					assert (sizeadjust.type == SSA_ARGTYPE_UINT);
					Register* reg = arch->getRegister (stack->trackingReg);
					Memory* mem = arch->getMemory (stack->backingMem);
					assert (reg);
					assert (mem);

					SSAExpression expression;
					expression.type = SSA_EXPR_LOAD;
					expression.returntype = SSA_TYPE_UINT;
					expression.size = stack->wordbitsize * sizeadjust.uval;
					expression.location = SSA_LOCATION_MEM;
					expression.locref = {mem->id, 0};
					expression.subExpressions.push_back (SSAArgument::createMem (mem->id));
					expression.subExpressions.push_back (SSAArgument::createReg (reg));
					expression.subExpressions.push_back (sizeadjust);

					SSAExpression adjustExpr;
					adjustExpr.type = SSA_EXPR_OP;
					adjustExpr.returntype = SSA_TYPE_UINT;
					adjustExpr.opType = stack->policy == H_STACKPOLICY_TOP ? H_OP_SUB : H_OP_ADD;
					adjustExpr.subExpressions.push_back (SSAArgument::createReg (reg));
					adjustExpr.subExpressions.push_back (sizeadjust);
					adjustExpr.location = SSA_LOCATION_REG;
					adjustExpr.locref = {reg->id, 0};
					adjustExpr.size = reg->size;

					IRArgument retArg = IRArgument::createSSAId (addExpression (&expression), expression.size);
					addUpdateRegExpressions (reg->id, addExpression (&adjustExpr));
					return retArg;
				}
				}
				return IRArgument::create ();
			}
			case IR_EXPR_VALUE: {
				SSAExpression expression;
				expression.type = SSA_EXPR_ASSIGN;
				assert (subexpressioncount == 1);
				IRArgument arg = replaceArg (irExpr->subExpressions[0]);
				assert (arg.type == IR_ARGTYPE_MEMOP);
				expression.returntype = SSA_TYPE_UINT;
				expression.size = arch->bitbase;
				expression.subExpressions.push_back (parseIRArg2SSAArg(parseMemArgToExpr (arg)));
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_REC: {
				HList<IRArgument> args;
				for (int i = 0; i < subexpressioncount; i++) {
					args.push_back (parseExpression (irExpr->subExpressions[i]));
				}
				HList<SSATmpDef> cachedTemps = this->tmpdefs;
				HList<IRArgument> cachedArgs = this->arguments;

				tmpdefs.clear();
				this->arguments = args;

				InstrDefinition* instrdef = arch->getInstrDef (irExpr->mod.instrId);

				int i;
				for (i = 0; i < instrdef->irs.size(); i++) {
					if (arguments.size() == instrdef->irs[i].argcount) {
						IRArgument constArg = parseConstExpression (instrdef->irs[i].condExpr, &arguments);
						if (constArg && constArg.type == IR_ARGTYPE_UINT && constArg.uval) {
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
			return IRArgument::create ();
			case IR_EXPR_REP: {
				HId startBlock = activeBlockId;
				HId startCondId = createNewBlock();
				HId endCondId = 0;
				HId startBodyId = createNewBlock();
				HId endBodyId = 0;

				activateBlock (startCondId);
				SSAExpression expression;
				expression.type = SSA_EXPR_CJMP;
				expression.returntype = SSA_TYPE_PC;
				expression.size = arch->bitbase;
				expression.subExpressions.push_back (parseIRArg2SSAArg(parseExpression (irExpr->subExpressions[0])));
				expression.subExpressions.push_back (SSAArgument::createBlock(startBodyId));
				addExpression (&expression);
				endCondId = activeBlockId;

				activateBlock (startBodyId);
				parseExpression (irExpr->subExpressions[1]);
				endBodyId = activeBlockId;

				HId endId = createNewBlock();
				
				SSABB* startBlockBB = getBlock(startBlock);
				SSABB* startCondBB = getBlock(startCondId);
				SSABB* endCondBB = getBlock(endCondId);
				SSABB* startBodyBB = getBlock(startBodyId);
				SSABB* endBodyBB = getBlock(endBodyId);
				SSABB* endBB = getBlock(endId);
				
				//start -> startCond
				startBlockBB->fallthroughId = startCondId;
				startBlockBB->outBlocks.insert(startCondId);
				startCondBB->inBlocks.insert(startBlock);
				
				//endCond -> true: startBody; false: end
				endCondBB->fallthroughId = endId;
				endCondBB->outBlocks.insert(endId);
				endBB->inBlocks.insert(endCondId);
				
				endCondBB->outBlocks.insert(startBodyId);
				startBodyBB->inBlocks.insert(endCondId);
				
				//endBody -> startCond
				endBodyBB->fallthroughId = startCondId;
				endBodyBB->outBlocks.insert(startCondId);
				startCondBB->inBlocks.insert(endBodyId);
				
				activateBlock (endId);
				return IRArgument::create ();
			}
			case IR_EXPR_SIZE:
				assert (subexpressioncount == 1);
				return IRArgument::createVal (parseExpression (irExpr->subExpressions[0]).size / arch->wordbase, arch->bitbase);
			case IR_EXPR_BSIZE:
				assert (subexpressioncount == 1);
				return IRArgument::createVal ( (uint64_t) parseExpression (irExpr->subExpressions[0]).size, arch->bitbase);
			case IR_EXPR_SEQUENCE://only for ir gets resolved in ir generation
				for (int i = 0; i < subexpressioncount; i++) {
					parseExpression (irExpr->subExpressions[i]);
				}
				return IRArgument::create();
			case IR_EXPR_FLAG: {
				SSAExpression expression;
				expression.type = SSA_EXPR_FLAG;
				expression.flagType = irExpr->mod.flagType;
				expression.returntype = SSA_TYPE_UINT;
				expression.size = 1;


				expression.subExpressions.push_back (SSAArgument::createId (lastOp, ssaRepresentation->expressions[lastOp].size));

				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			default:
				assert (false);
				break;
			}
			return IRArgument::create();
		}
		}
		return exprId;
	}

	void SSAGen::print (int indent) {
		ssaRepresentation->print (arch, indent);
	}
}
