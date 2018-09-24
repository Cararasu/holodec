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
		for (size_t i = 0; i < instrdef->irs.size(); i++) {
			if (instrdef->irs[i].argcount == -1 || instr->operands.size() == instrdef->irs[i].argcount) {
				if (instrdef->irs[i].condstring) {
					IRArgument constArg = parseConstExpression(instrdef->irs[i].condExpr, &instr->operands);
					if (constArg && constArg.isConst(SSAType::eUInt) && constArg.uval) {
						/*printf("Successfully parsed Condition for Instruction\n");
						instrdef->irs[i].print(arch);
						instr->print(arch);
						printf("\n");*/
						return &instrdef->irs[i];
					}
					else {
						/*printf("Failed to parse Condition for Instruction\n");
						instrdef->irs[i].print(arch);
						instr->print(arch);
						printf("\n");*/
						continue;
					}
				}
				else {
					return &instrdef->irs[i];
				}
			}
		}
		for (size_t i = 0; i < instr->operands.size(); i++) {
			instr->operands[i].print (arch);
			printf ("\n");
		}
		instr->print (arch);
		printf ("Found No Match %s\n", instr->instrdef->mnemonics.cstr());
		return nullptr;
	}


	SSAArgument SSAGen::readReg(HId regid) {
		Register* reg = arch->getRegister(regid);
		return readReg(reg);
	}
	SSAArgument SSAGen::readReg(Register* reg) {
		Register* parentreg = arch->getRegister(reg->parentRef);
		SSAArgument arg = createSplit(createAssign(SSAArgument::createReg(parentreg), parentreg->size, { SSALocation::eReg, reg->parentRef.refId }), reg->size, reg->offset, { SSALocation::eReg, reg->id });
		arg.ref.location = SSALocation::eReg;
		arg.ref.id = reg->id;
		return arg;
	}
	SSAArgument SSAGen::createSplit(SSAArgument arg, uint32_t size, uint32_t offset, Reference locref) {
		if (arg.type == SSAArgType::eId) {
			SSAExpression& expr = ssaRep->expressions[arg.ssaId];
			if (offset == 0 && expr.size == size)
				return arg;
		}
		SSAExpression expr;
		expr.type = SSAExprType::eSplit;
		expr.size = size;
		expr.offset = offset;
		expr.subExpressions = { arg };
		expr.ref = locref;
		return SSAArgument::createId(addExpression(&expr));
	}
	SSAArgument SSAGen::createAssign(SSAArgument arg, uint32_t size, Reference locref) {
		SSAExpression expr;
		expr.type = SSAExprType::eAssign;
		expr.size = size;
		expr.subExpressions = { arg };
		expr.ref = locref;
		return SSAArgument::createId(addExpression(&expr));
	}
	SSAArgument SSAGen::createUVal(uint64_t val, uint32_t size, Reference locref) {
		SSAExpression expr;
		expr.type = SSAExprType::eValue;
		expr.size = size;
		expr.exprtype = SSAType::eUInt;
		expr.uval = val;
		expr.ref = locref;
		return SSAArgument::createId(addExpression(&expr));
	}
	SSAArgument SSAGen::createSVal(int64_t val, uint32_t size, Reference locref) {
		SSAExpression expr;
		expr.type = SSAExprType::eValue;
		expr.size = size;
		expr.exprtype = SSAType::eInt;
		expr.sval = val;
		expr.ref = locref;
		return SSAArgument::createId(addExpression(&expr));
	}
	SSAArgument SSAGen::createFVal(double val, uint32_t size, Reference locref) {
		SSAExpression expr;
		expr.type = SSAExprType::eValue;
		expr.size = size;
		expr.exprtype = SSAType::eFloat;
		expr.fval = val;
		expr.ref = locref;
		return SSAArgument::createId(addExpression(&expr));
	}

	IRArgument SSAGen::parseMemArgToExpr (IRArgument mem) {
		SSAExpression memexpr;
		memexpr.type = SSAExprType::eLoadAddr;
		memexpr.exprtype = SSAType::eUInt;
		memexpr.size = arch->bytebase * arch->bitbase;
		//segment::[base + index*scale + disp]
		SSAArgument args[5];
		if (mem.mem.segment)
			args[0].set(readReg(mem.mem.segment));
		else
			args[0].set(createUVal(0, arch->bytebase * arch->bitbase));

		if (mem.mem.base)
			args[1].set(readReg(mem.mem.base));
		else
			args[1].set(createUVal(0, arch->bytebase * arch->bitbase));

		if (mem.mem.index)
			args[2].set(readReg(mem.mem.index));
		else
			args[2].set(createUVal(0, arch->bytebase * arch->bitbase));

		args[3].set(createUVal(mem.mem.scale, arch->bytebase * arch->bitbase));

		args[4].set(createUVal(mem.mem.disp, arch->bytebase * arch->bitbase));

		memexpr.subExpressions.assign (args, args + 5);
		return IRArgument::createSSAId (addExpression (&memexpr), arch->bytebase * arch->bitbase);
	}

	template<typename ARGLIST>
	IRArgument SSAGen::parseConstExpression (IRArgument argExpr, ARGLIST* arglist) {
		switch (argExpr.type) {
		default:
			return IRArgument::createUVal( (uint64_t) 1, arch->bytebase * arch->bitbase);
		case IR_ARGTYPE_ARG: {
			return (*arglist) [argExpr.ref.id - 1];
		}
		case IR_ARGTYPE_ID: {
			IRExpression* irExpr = arch->getIrExpr (argExpr.ref.id);

			switch (irExpr->type) {
			case IR_EXPR_OP: {
				switch (irExpr->mod.opType) {
				case SSAOpType::eAdd: {
					uint64_t val = 0;
					for (size_t i = 0; i < irExpr->subExpressions.size(); i++) {
						IRArgument arg = parseConstExpression(irExpr->subExpressions[i], arglist);
						if (arg && arg.isConst() && arg.argtype == SSAType::eUInt)
							val += arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}
				case SSAOpType::eAnd: {
					uint64_t val = 1;
					for (size_t i = 0; i < irExpr->subExpressions.size(); i++) {
						IRArgument arg = parseConstExpression(irExpr->subExpressions[i], arglist);
						if (arg && arg.isConst() && arg.argtype == SSAType::eUInt)
							val = val && arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}
				case SSAOpType::eOr: {
					uint64_t val = 0;
					for (size_t i = 0; i < irExpr->subExpressions.size(); i++) {
						IRArgument arg = parseConstExpression (irExpr->subExpressions[i], arglist);
						if (arg && arg.isConst() && arg.argtype == SSAType::eUInt)
							val = val || arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}
				case SSAOpType::eNot: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size()) {
						IRArgument arg = parseConstExpression (irExpr->subExpressions[0], arglist);
						if (arg && arg.isConst() && arg.argtype == SSAType::eUInt)
							val = !arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}

				case SSAOpType::eEq: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg1.isConst() && arg1.argtype == SSAType::eUInt && arg2 && arg2.isConst() && arg2.argtype == SSAType::eUInt)
							val = arg1.uval == arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}
				case SSAOpType::eNe: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg1.isConst() && arg1.argtype == SSAType::eUInt && arg2 && arg2.isConst() && arg2.argtype == SSAType::eUInt)
							val = arg1.uval != arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}
				case SSAOpType::eLower: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg1.isConst() && arg1.argtype == SSAType::eUInt && arg2 && arg2.isConst() && arg2.argtype == SSAType::eUInt)
							val = arg1.uval < arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}
				case SSAOpType::eLe: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg1.isConst() && arg1.argtype == SSAType::eUInt && arg2 && arg2.isConst() && arg2.argtype == SSAType::eUInt)
							val = arg1.uval <= arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}
				case SSAOpType::eGreater: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg1.isConst() && arg1.argtype == SSAType::eUInt && arg2 && arg2.isConst() && arg2.argtype == SSAType::eUInt)
							val = arg1.uval > arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}
				case SSAOpType::eGe: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg1.isConst() && arg1.argtype == SSAType::eUInt && arg2 && arg2.isConst() && arg2.argtype == SSAType::eUInt)
							val = arg1.uval >= arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bytebase * arch->bitbase);
				}
				default:
					return IRArgument::create();
				}
			}
			case IR_EXPR_SIZE: {
				assert(irExpr->subExpressions.size() == 1);
				return IRArgument::createUVal(parseConstExpression(irExpr->subExpressions[0], arglist).size / arch->bitbase, arch->bytebase * arch->bitbase);
			}
			case IR_EXPR_BSIZE: {
				assert(irExpr->subExpressions.size() == 1);
				IRArgument arg = parseConstExpression(irExpr->subExpressions[0], arglist);
				return IRArgument::createUVal((uint64_t)arg.size, arch->bytebase * arch->bitbase);
			}
			default:
				return IRArgument::create();
			}
		}

		break;
		case IR_ARGTYPE_VALUE:
			return argExpr;
		case IR_ARGTYPE_IP:
			return IRArgument::createUVal(instruction->addr + instruction->size, arch->instrptrsize * arch->bitbase);
		case IR_ARGTYPE_REG:
		case IR_ARGTYPE_STACK:
		case IR_ARGTYPE_TMP:
			break;
		}
		return IRArgument::create();
	}

	void SSAGen::insertLabel (uint64_t address, HId instructionId) {
		SSAExpression expression;
		expression.type = SSAExprType::eLabel;
		expression.exprtype = SSAType::ePc;
		expression.size = arch->bytebase * arch->bitbase;
		addExpression (&expression);
	}
	SSABB* SSAGen::getBlock (HId blockId) {
		for (SSABB& bb : ssaRep->bbs) {
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
		HId ssaId = ssaRep->addAtEnd (expression, activeblock);
		if (expression->type == SSAExprType::eOp)
			lastOp = ssaId;
		return ssaId;
	}
	void SSAGen::reset() {
		ssaRep = nullptr;
	}
	void SSAGen::setup (Function* function, uint64_t addr) {
		this->instruction = nullptr;
		this->function = function;
		ssaRep = &function->ssaRep;
		activateBlock (createNewBlock());
		for (Register& reg : arch->registers) {
			if (!reg.id || reg.directParentRef)
				continue;
			SSAExpression expression;
			expression.type = SSAExprType::eInput;
			expression.exprtype = SSAType::eUInt;
			expression.instrAddr = function->baseaddr;
			expression.ref = &reg;
			expression.size = reg.size;

			addExpression(&expression);
		}
		for (Memory& mem : arch->memories) {
			if (!mem.id)
				continue;
			SSAExpression expression;
			expression.type = SSAExprType::eInput;
			expression.exprtype = SSAType::eUInt;
			expression.instrAddr = function->baseaddr;
			expression.ref = &mem;
			expression.size = 0;

			addExpression(&expression);
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
		for (SSABB& bb : ssaRep->bbs) {
			if (bb.startaddr == addr)
				return bb.id;

			if (bb.startaddr < addr && addr <= bb.endaddr) {
				for (auto it = bb.exprIds.begin(); it != bb.exprIds.end(); ++it) {
					SSAExpression* expr = ssaRep->expressions.get (*it);
					assert (expr);
					if (expr->type == SSAExprType::eLabel && expr->instrAddr == addr) {
						printf ("Split SSA 0x%" PRIx64 "\n", addr);
						HId oldId = bb.id;
						uint64_t newEndAddr = bb.endaddr;
						bb.endaddr = addr;
						HList<HId> exprsOfNewBlock (it, bb.exprIds.end());
						bb.exprIds.erase (it, bb.exprIds.end());

						SSABB createdbb (addr, newEndAddr, exprsOfNewBlock, {oldId}, bb.outBlocks);
						HId newBlockId = ssaRep->bbs.push_back (createdbb);
						for (HId id : exprsOfNewBlock) {//set the blockid for the split block
							ssaRep->expressions[id].blockId = newBlockId;
						}

						SSABB* newbb = &ssaRep->bbs.back();
						SSABB* oldbb = ssaRep->bbs.get (oldId);

						SSAExpression branchExpr(SSAExprType::eBranch, arch->bitbase * arch->bytebase, SSAType::ePc);
						branchExpr.subExpressions = { SSAArgument::createBlock(newbb->id) };
						function->ssaRep.addAtEnd(&branchExpr, oldbb);

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
		ssaRep->bbs.push_back (block);
		return ssaRep->bbs.list.back().id;
	}
	void SSAGen::activateBlock (HId block) {
		activeblock = nullptr;
		activeBlockId = block;
	}

	SSAArgument SSAGen::parseIRArg2SSAArg (IRArgument arg) {
		SSAArgument ssaarg;
		switch (arg.type) {
		case IR_ARGTYPE_UNKN:
			return SSAArgument::create();
		case IR_ARGTYPE_SSAID:
			return createSplit(SSAArgument::createId (arg.ref.id), arg.size, arg.offset);
		case IR_ARGTYPE_VALUE:
			switch (arg.argtype) {
			case SSAType::eFloat:
				return createFVal(arg.fval, arg.size);
			case SSAType::eInt:
				return createSVal(arg.sval, arg.size);
			case SSAType::eUInt:
				return createUVal(arg.uval, arg.size);
			}
			assert(false);
			return SSAArgument::create();
		case IR_ARGTYPE_MEM:
			return SSAArgument::createMem (arg.ref.id);
		case IR_ARGTYPE_REG:
			return createSplit(readReg(arg.ref.id), arg.size, arg.offset);
		default:
			assert (false);
		}
		return SSAArgument::create();
	}
	void SSAGen::replaceArg (IRArgument& arg) {
		while (arg.type == IR_ARGTYPE_ARG) {
			assert (arg.ref.refId && arg.ref.refId <= arguments.size());
			IRArgument& aarg = arguments[arg.ref.id - 1];
			arg = aarg;
		}
	}
	void SSAGen::addUpdateRegExpressions (HId regId, HId ssaId) {

		Register* baseReg = arch->getRegister (regId);
		Register* parentReg = baseReg;
		while (parentReg->directParentRef) {
			parentReg = arch->getRegister (parentReg->directParentRef);
			SSAExpression updateExpression;
			updateExpression.exprtype = SSAType::eUInt;
			updateExpression.ref = parentReg;
			updateExpression.size = parentReg->size;

			if (parentReg->offset == baseReg->offset && parentReg->size == baseReg->size) {
				updateExpression.type = SSAExprType::eAssign;
				updateExpression.subExpressions.push_back(SSAArgument::createId(ssaId));
			}
			else if (baseReg->clearParentOnWrite) {
				assert(baseReg->offset == 0);
				if (!baseReg->offset) {
					updateExpression.type = SSAExprType::eCast;
					updateExpression.subExpressions.push_back(SSAArgument::createId(ssaId));
				}
				else {
					updateExpression.type = SSAExprType::eAppend;
					updateExpression.subExpressions.push_back(createUVal(0, baseReg->offset));
					updateExpression.subExpressions.push_back(createSplit(SSAArgument::createId(ssaId), baseReg->size, baseReg->offset));
					if(parentReg->size != (baseReg->offset + baseReg->offset))
						updateExpression.subExpressions.push_back(createUVal(0, (parentReg->size + parentReg->offset) - (baseReg->offset + baseReg->size)));
				}
			} else {
				updateExpression.type = SSAExprType::eAppend;
				SSAArgument regarg = readReg(parentReg);
				if (baseReg->offset) {
					updateExpression.subExpressions.push_back(createSplit(regarg, baseReg->offset, 0));
				}
				updateExpression.subExpressions.push_back (SSAArgument::createId(ssaId));
				if ((parentReg->offset + parentReg->size) != (baseReg->offset + baseReg->size)) {
					updateExpression.subExpressions.push_back(createSplit(regarg, (parentReg->size + parentReg->offset) - (baseReg->offset + baseReg->size), baseReg->offset + baseReg->size));
				}
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
			for (size_t i = 0; i < instruction->operands.size(); i++) {
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

		replaceArg (exprId);
		switch (exprId.type) {
		default:
			return exprId;
		case IR_ARGTYPE_ARG: {
			assert (false);
		}
		case IR_ARGTYPE_MEMOP: {
			SSAExpression expression;
			expression.type = SSAExprType::eLoad;
			expression.exprtype = exprId.argtype;
			expression.size = exprId.size;
			expression.subExpressions = {
				SSAArgument::createMem(arch->getDefaultMemory()),
				parseIRArg2SSAArg (parseMemArgToExpr (exprId))
			};
			return IRArgument::createSSAId (addExpression (&expression), expression.size);
		}
		case IR_ARGTYPE_TMP: {
			assert (exprId.ref.refId);
			for (SSATmpDef& def : tmpdefs) {
				if (def.id == exprId.ref.id) {
					return def.arg;
				}
			}
			printf ("0x%" PRIx64 "\n", instruction->addr);
			printf ("%d\n", exprId.ref.id);
			assert (false);
		}
		case IR_ARGTYPE_IP:
			return IRArgument::createUVal (instruction->addr + instruction->size, arch->instrptrsize * arch->bitbase);
		case IR_ARGTYPE_ID: {
			IRExpression* irExpr = arch->getIrExpr (exprId.ref.id);

			size_t subexpressioncount = irExpr->subExpressions.size();

			switch (irExpr->type) {
			case IR_EXPR_UNDEF: {
				for (size_t i = 0; i < subexpressioncount; i++) {
					assert (irExpr->subExpressions[i].type == IR_ARGTYPE_ARG ||
					        irExpr->subExpressions[i].type == IR_ARGTYPE_REG ||
					        irExpr->subExpressions[i].type == IR_ARGTYPE_STACK ||
					        irExpr->subExpressions[i].type == IR_ARGTYPE_TMP);
					IRArgument arg = irExpr->subExpressions[i];
					replaceArg (arg);

					SSAExpression expression;
					expression.type = SSAExprType::eUndef;
					expression.exprtype = irExpr->exprtype;
					assert(arg.size);
					switch (arg.type) {
					case IR_ARGTYPE_REG:
						expression.ref = { SSALocation::eReg, arg.ref.id };
						expression.size = arg.size;
						addUpdateRegExpressions (arg.ref.id, addExpression (&expression));
						break;
					case IR_ARGTYPE_STACK:
						assert(false);
						//expression.location = SSALocation::eStack;
						//expression.ref = arg.ref;
						//expression.size = arg.size;
						//addExpression (&expression);
						break;
					case IR_ARGTYPE_TMP:
						for (auto it = tmpdefs.begin(); it != tmpdefs.end(); ++it) {
							if ( (*it).id == arg.ref.id) {
								it = tmpdefs.erase (it);
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
				expression.type = SSAExprType::eAssign;
				assert (subexpressioncount == 2);
				IRArgument dstArg = irExpr->subExpressions[0];
				replaceArg (dstArg);

				IRArgument srcArg = parseExpression (irExpr->subExpressions[1]);

				if (srcArg.type == IR_ARGTYPE_ID) {
					SSAExpression* ssaExpr = ssaRep->expressions.get (srcArg.ref.id);
					assert (ssaExpr);
					assert(ssaExpr->size);
					switch (dstArg.type) {
					case IR_ARGTYPE_REG:
					case IR_ARGTYPE_STACK: {
						if (!ssaExpr->ref.isLocation(SSALocation::eNone) && ssaExpr->size == dstArg.size) {
							if (dstArg.type == IR_ARGTYPE_REG) {
								ssaExpr->ref = { SSALocation::eReg, dstArg.ref.id };
								ssaExpr->size = dstArg.size;
								IRArgument arg = IRArgument::createSSAId (srcArg.ref.id, ssaExpr->size * arch->bitbase);
								addUpdateRegExpressions (dstArg.ref.id, srcArg.ref.id);//can relocate ssaExpr
								return arg;
							} else if (dstArg.type == IR_ARGTYPE_STACK) {
								assert(false);
								/*
								ssaExpr->location = SSALocation::eStack;
								ssaExpr->ref = dstArg.ref;
								ssaExpr->size = dstArg.size;
								return IRArgument::createSSAId (srcArg.ref.refId, ssaExpr->size * arch->bitbase);*/
								return IRArgument::create();
							}
						}
					}
					break;
					case IR_ARGTYPE_TMP: {
						IRArgument arg = IRArgument::createSSAId (srcArg.ref.id, ssaExpr->size * arch->bitbase);
						for (SSATmpDef& def : tmpdefs) {
							if (def.id == dstArg.ref.id) {
								def.arg = arg;
								return IRArgument::create();
							}
						}
						tmpdefs.push_back ({dstArg.ref.id, arg});
						return IRArgument::create();
					}
					break;
					default:
						break;
					}
					expression.exprtype = ssaExpr->exprtype;
				}
				else {
					expression.exprtype = SSAType::eUInt;
				}
				SSAArgument srcSSAArg = parseIRArg2SSAArg (srcArg);
				expression.size = ssaRep->expressions[srcSSAArg.ssaId].size;
				//assert(expression.size);
				switch (dstArg.type) {
				case IR_ARGTYPE_TMP: {
					expression.exprtype = SSAType::eUInt;
					expression.subExpressions.push_back (srcSSAArg);
					IRArgument arg = IRArgument::createSSAId (addExpression (&expression), expression.size);
					for (SSATmpDef& def : tmpdefs) {
						if (def.id == dstArg.ref.id) {
							def.arg = arg;
							return IRArgument::create();
						}
					}
					tmpdefs.push_back ({dstArg.ref.id, arg});
					return IRArgument::create();
				}
				case IR_ARGTYPE_MEMOP: {
					expression.type = SSAExprType::eStore;
					expression.exprtype = SSAType::eMemaccess;
					expression.size = 0;
					Memory* memory = arch->getDefaultMemory();
					expression.ref = memory;
					expression.subExpressions = {
						SSAArgument::createMem(memory),
						parseIRArg2SSAArg (parseMemArgToExpr (dstArg)) 
					};
				}
				break;
				case IR_ARGTYPE_REG:{
					expression.ref = { SSALocation::eReg, dstArg.ref.id };
					expression.size = dstArg.size;

					expression.subExpressions = {srcSSAArg};

					HId ssaId = addExpression (&expression);
					addUpdateRegExpressions (dstArg.ref.id, ssaId);
					return IRArgument::createSSAId (ssaId, expression.size);
				}
				case IR_ARGTYPE_STACK: {
					/*
					expression.location = SSALocation::eStack;
					expression.ref = dstArg.ref;
					expression.size = dstArg.size;
					*/
					assert(false);
					return IRArgument::create();
				}break;
				case IR_ARGTYPE_SSAID: {//assign to no particular thing, needed for recursive with write-parameter as tmp
					IRArgument* arg = &irExpr->subExpressions[0];
					assert(arg->type == IR_ARGTYPE_ARG);

					while (true) {//get argument index
						assert(arg->ref.refId && arg->ref.refId <= arguments.size());
						if (arguments[arg->ref.id - 1].type != IR_ARGTYPE_ARG)
							break;
						arg = &arguments[arg->ref.id - 1];
					}
					//write the new ssaId
					expression.subExpressions.push_back(srcSSAArg);
					IRArgument retarg = IRArgument::createSSAId(addExpression(&expression), expression.size);
					arguments[arg->ref.id - 1] = retarg;
					return retarg;
				}break;
				default:
					dstArg.print (arch);
					printf ("Invalid Type for Assignment 0x%x\n", dstArg.type);
					assert (false);
					break;
				}
				expression.subExpressions.push_back (srcSSAArg);
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}

			case IR_EXPR_NOP:
				return IRArgument::create();

			case IR_EXPR_IF: {//TODO there seems to be an error where a block input/output is not set correctly
				SSAExpression expression;
				expression.type = SSAExprType::eBranch;
				expression.exprtype = SSAType::ePc;
				expression.size = arch->bytebase * arch->bitbase;


				assert (subexpressioncount >= 2 && subexpressioncount <= 3);

				HId oldBlock = activeBlockId;
				HId trueblockId = createNewBlock();
				HId endBlockId = createNewBlock();
				HId falseblockId = (subexpressioncount == 3) ? createNewBlock() : endBlockId;//generate early so the blocks are in order

				SSAArgument exprArgs[3] = {
					SSAArgument::createBlock(trueblockId),
					parseIRArg2SSAArg(parseExpression(irExpr->subExpressions[0])),
					SSAArgument::createBlock(falseblockId)
				};
				expression.subExpressions.assign (exprArgs, exprArgs + 3);
				addExpression (&expression);

				activateBlock (trueblockId);
				parseExpression (irExpr->subExpressions[1]);//trueblock

				SSAExpression branchExpr(SSAExprType::eBranch, arch->bitbase * arch->bytebase, SSAType::ePc);
				branchExpr.subExpressions = { SSAArgument::createBlock(endBlockId) };
				function->ssaRep.addAtEnd(&branchExpr, getActiveBlock());

				if (subexpressioncount == 3) {

					activateBlock (falseblockId);
					parseExpression (irExpr->subExpressions[2]);//falseblock
					SSABB* activeblock = getActiveBlock();

					SSAExpression branchExpr(SSAExprType::eBranch, arch->bitbase * arch->bytebase, SSAType::ePc);
					branchExpr.subExpressions = { SSAArgument::createBlock(endBlockId) };
					function->ssaRep.addAtEnd(&branchExpr, activeblock);

					activeblock->outBlocks.insert (endBlockId);
					getBlock (endBlockId)->inBlocks.insert (activeblock->id);
				} else {
					SSABB* oldBB = getBlock (oldBlock);

					oldBB->outBlocks.insert (endBlockId);
					getBlock (endBlockId)->inBlocks.insert (oldBB->id);
				}
				activateBlock (endBlockId);
				return IRArgument::create ();
			}
			case IR_EXPR_JMP: {
				SSAExpression expression;
				expression.type = SSAExprType::eBranch;
				expression.exprtype = SSAType::ePc;
				expression.size = arch->bytebase * arch->bitbase;
				assert(subexpressioncount % 2 == 1);
				for (size_t i = 1; i < irExpr->subExpressions.size(); i += 2) {
					expression.subExpressions.push_back(parseIRArg2SSAArg(parseExpression(irExpr->subExpressions[i - 1])));
					expression.subExpressions.push_back(parseIRArg2SSAArg(parseExpression(irExpr->subExpressions[i])));
				}
				expression.subExpressions.push_back(parseIRArg2SSAArg(parseExpression(irExpr->subExpressions.back())));
				{
					SSAExpression* dstexpr = find_baseexpr(ssaRep, expression.subExpressions[0]);
					if (dstexpr->type == SSAExprType::eValue && dstexpr->exprtype == SSAType::eUInt)
						function->addrToAnalyze.insert(dstexpr->uval);
				}

				endOfBlock = true;
				return IRArgument::createSSAId(addExpression(&expression), expression.size);
			}
			case IR_EXPR_OP: {
				SSAExpression expression;
				expression.type = SSAExprType::eOp;
				expression.opType = irExpr->mod.opType;
				expression.exprtype = irExpr->exprtype;
				uint32_t size = 0;
				for (size_t i = 0; i < subexpressioncount; i++) {
					SSAArgument arg = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i]));
					if (expression.opType == SSAOpType::eMul)
						size += getSize(arg);
					else if (!size)
						size = getSize(arg);
					else
						assert(!arg.ssaId || size >= ssaRep->expressions[arg.ssaId].size);
					assert(!(!ssaRep->expressions[arg.ssaId].isConst() && getSize(arg) == 0));
					expression.subExpressions.push_back (arg);
				}
				switch (expression.opType) {
				case SSAOpType::eEq:
				case SSAOpType::eNe:
				case SSAOpType::eLower:
				case SSAOpType::eLe:
				case SSAOpType::eGreater:
				case SSAOpType::eGe:
					size = 1;
					break;
				default:
					break;
				}
				expression.size = size;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			// Call - Return
			case IR_EXPR_CALL:  {
				if (instruction->addr + instruction->size == instruction->jumpdest)
					return IRArgument::create();
				SSAExpression expression;
				expression.type = SSAExprType::eCall;
				expression.exprtype = irExpr->exprtype;
				assert (subexpressioncount == 1);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));

				{
					SSAExpression* dstexpr = find_baseexpr(ssaRep, expression.subExpressions[0]);
					if (dstexpr->type == SSAExprType::eValue && dstexpr->exprtype == SSAType::eUInt)
						function->funcsCaller.insert(dstexpr->uval);
				}

				for (Register& reg : arch->registers) {
					if (!reg.directParentRef)
						expression.subExpressions.push_back(readReg(&reg));
				}
				for (Memory& mem : arch->memories) {
					expression.subExpressions.push_back(SSAArgument::createMem(&mem));
				}
				expression.size = arch->bytebase * arch->bitbase;
				IRArgument arg = IRArgument::createSSAId (addExpression (&expression), expression.size);

				SSAArgument ssaArg = parseIRArg2SSAArg (arg);

				for (Register& reg : arch->registers) {
					if (!reg.id || reg.directParentRef)
						continue;
					SSAExpression retExpr;
					retExpr.type = SSAExprType::eOutput;
					retExpr.exprtype = SSAType::eUInt;
					retExpr.ref = &reg;
					retExpr.size = reg.size;
					retExpr.subExpressions = { ssaArg, readReg(&reg) };
					addExpression(&retExpr);
				}
				for (Memory& mem : arch->memories) {
					if (!mem.id)
						continue;
					SSAExpression retExpr;
					retExpr.type = SSAExprType::eMemOutput;
					retExpr.exprtype = SSAType::eUInt;
					retExpr.ref = &mem;
					retExpr.size = 0;
					retExpr.subExpressions = { ssaArg, SSAArgument::createMem(&mem) };
					addExpression(&retExpr);
				}

				return arg;
			}
			case IR_EXPR_RETURN: {
				SSAExpression expression;
				expression.type = SSAExprType::eReturn;
				expression.exprtype = SSAType::ePc;
				expression.size = arch->bytebase * arch->bitbase;
				assert (subexpressioncount == 1);
				
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));

				for (Register& reg : arch->registers) {
					if (!reg.id || reg.directParentRef)
						continue;
					expression.subExpressions.push_back(readReg(&reg));
				}
				for (Memory& mem : arch->memories) {
					if (!mem.id)
						continue;
					expression.subExpressions.push_back(SSAArgument::createMem(&mem));
				}
				endOfBlock = true;
				fallthrough = false;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_SYSCALL: {
				SSAExpression expression;
				expression.type = SSAExprType::eSyscall;
				for (size_t i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i])));
				}
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_TRAP: {
				SSAExpression expression;
				expression.type = SSAExprType::eTrap;
				endOfBlock = true;
				fallthrough = false;
				for (size_t i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i])));
				}
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_BUILTIN: {
				SSAExpression expression;
				expression.type = SSAExprType::eBuiltin;
				for (size_t i = 0; i < subexpressioncount; i++) {
					expression.subExpressions.push_back(parseIRArg2SSAArg(parseExpression(irExpr->subExpressions[i])));
				}
				//TODO if sideeffects are set add all arguments and outputs...
				expression.builtinId = irExpr->mod.builtinId;
				expression.size = arch->bytebase * arch->bitbase;
				return IRArgument::createSSAId(addExpression(&expression), expression.size);
			}
			case IR_EXPR_EXTEND: {
				assert (subexpressioncount == 2);
				SSAExpression expression;
				expression.type = SSAExprType::eCast;
				expression.exprtype = irExpr->exprtype;
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));
				IRArgument arg = parseConstExpression (irExpr->subExpressions[1], &arguments);
				assert (arg && arg.isConst() && arg.argtype == SSAType::eUInt);
				expression.size = static_cast<uint32_t>(arg.uval);
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_SPLIT: {
				assert(irExpr->subExpressions.size() == 3);
				SSAArgument arg = parseIRArg2SSAArg(parseExpression(irExpr->subExpressions[0]));
				IRArgument offset = parseExpression(irExpr->subExpressions[1]);
				IRArgument size = parseExpression(irExpr->subExpressions[2]);
				assert(offset && offset.isConst() && offset.argtype == SSAType::eUInt);
				assert(size && size.isConst() && size.argtype == SSAType::eUInt);
				return IRArgument::createSSAId(createSplit(arg, static_cast<uint32_t>(size.uval), static_cast<uint32_t>(offset.uval)).ssaId, static_cast<uint32_t>(size.uval));
			}
			case IR_EXPR_APPEND: {
				SSAExpression expression;
				expression.type = SSAExprType::eAppend;
				expression.exprtype = SSAType::eUInt;
				expression.size = 0;
				for (size_t i = 0; i < subexpressioncount; i++) {
					SSAArgument arg = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i]));
					expression.size += getSize(arg);
					expression.subExpressions.push_back (arg);
				}
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_CAST: {
				SSAExpression expression;
				expression.type = SSAExprType::eCast;
				expression.exprtype = irExpr->exprtype;
				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));
				IRArgument sizeArg = irExpr->subExpressions[1];
				replaceArg (sizeArg);
				assert (sizeArg && sizeArg.isConst() && sizeArg.argtype == SSAType::eUInt);
				expression.size = sizeArg;
				expression.sourcetype = irExpr->subExpressions[0].argtype;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			// Memory
			case IR_EXPR_STORE: {
				SSAExpression expression;
				expression.type = SSAExprType::eStore;
				expression.exprtype = SSAType::eMemaccess;
				expression.size = 0;
				assert (subexpressioncount == 3);
				SSAArgument memarg = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0]));
				assert (memarg.ref.isLocation(SSALocation::eMem));
				expression.ref = { SSALocation::eMem, memarg.ref.id };
				expression.subExpressions = {
					memarg,
					parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1])),
					parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[2]))
				};
				expression.size = arch->bytebase * arch->bitbase;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_LOAD: {
				SSAExpression expression;
				expression.type = SSAExprType::eLoad;
				expression.exprtype = SSAType::eUInt;
				assert (subexpressioncount == 3);
				SSAArgument memarg = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0]));
				assert (memarg.ref.isLocation(SSALocation::eMem));
				IRArgument arg = parseConstExpression(irExpr->subExpressions[2], &arguments);
				assert (arg && arg.isConst() && arg.argtype == SSAType::eUInt);
				expression.size = static_cast<uint32_t>(arg.uval * arch->bitbase);
				expression.subExpressions = {
					memarg,
					parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1]))
				};
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}

			case IR_EXPR_PUSH: {
				IRArgument stackArg = parseExpression (irExpr->subExpressions[0]);
				assert (stackArg.type == IR_ARGTYPE_STACK);
				Stack* stack = arch->getStack (stackArg.ref.id);
				assert (stack);
				switch (stack->type) {
				case StackType::eRegBacked: {
					assert (false);
					return IRArgument::createSSAId (0, 0);
				}
				case StackType::eMemory: {
					assert (subexpressioncount == 2);
					assert (stack->backingMem);
					SSAArgument value = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1]));
					Register* reg = arch->getRegister (stack->trackingReg);
					Memory* mem = arch->getMemory (stack->backingMem);
					assert (reg->id);
					assert (mem);

					SSAExpression expression;
					expression.type = SSAExprType::eStore;
					expression.exprtype = SSAType::eMemaccess;
					expression.size = 0;
					expression.ref = mem;
					expression.subExpressions = {
						SSAArgument::createMem(mem),
						readReg(reg),
						value
					};

					SSAExpression adjustExpr;
					adjustExpr.type = SSAExprType::eOp;
					adjustExpr.exprtype = SSAType::eUInt;
					adjustExpr.opType = stack->policy == StackPolicy::eTop ?  SSAOpType::eAdd : SSAOpType::eSub;
					adjustExpr.subExpressions = {
						readReg(reg),
						createUVal((getSize(value) + stack->wordbitsize - 1) / stack->wordbitsize, arch->bytebase * arch->bitbase)
					};
					adjustExpr.size = reg->size;
					adjustExpr.ref = reg;

					IRArgument arg = IRArgument::createSSAId(addExpression(&expression), expression.size);

					addUpdateRegExpressions (reg->id, addExpression (&adjustExpr));
					return arg;
				}
				}
				return IRArgument::create ();
			}
			case IR_EXPR_POP: {
				IRArgument stackArg = parseExpression (irExpr->subExpressions[0]);
				assert (stackArg.type == IR_ARGTYPE_STACK);
				Stack* stack = arch->getStack (stackArg.ref.id);
				assert (stack);
				switch (stack->type) {
				case StackType::eRegBacked: {
					assert (false);
					return IRArgument::createSSAId (0, 0);
				}
				case StackType::eMemory: {
					assert (subexpressioncount == 2);
					IRArgument sizeadjust = parseExpression (irExpr->subExpressions[1]);
					assert (sizeadjust.isConst(SSAType::eUInt));
					Register* reg = arch->getRegister (stack->trackingReg);
					Memory* mem = arch->getMemory(stack->backingMem);
					assert(reg->id);
					assert(mem);

					SSAExpression expression;
					expression.type = SSAExprType::eLoad;
					expression.exprtype = SSAType::eUInt;
					expression.size = static_cast<uint32_t>(sizeadjust.uval * stack->wordbitsize);
					expression.subExpressions = {
						SSAArgument::createMem(mem),
						readReg(reg)
					};

					SSAExpression adjustExpr;
					adjustExpr.type = SSAExprType::eOp;
					adjustExpr.exprtype = SSAType::eUInt;
					adjustExpr.opType = stack->policy == StackPolicy::eTop ? SSAOpType::eSub : SSAOpType::eAdd;
					adjustExpr.subExpressions = {
						readReg(reg),
						parseIRArg2SSAArg(sizeadjust)
					};

					adjustExpr.ref = reg;
					adjustExpr.size = reg->size;

					addUpdateRegExpressions (reg->id, addExpression (&adjustExpr));
					return IRArgument::createSSAId(addExpression(&expression), expression.size);
				}
				}
				return IRArgument::create ();
			}
			case IR_EXPR_VALUE: {
				assert (subexpressioncount == 1);
				IRArgument arg = irExpr->subExpressions[0];
				replaceArg(arg);
				assert (arg.type == IR_ARGTYPE_MEMOP);
				return parseMemArgToExpr(arg);
			}
			case IR_EXPR_REC: {
				HList<IRArgument> args;
				for (size_t i = 0; i < subexpressioncount; i++) {
					args.push_back (parseExpression (irExpr->subExpressions[i]));
				}
				HList<SSATmpDef> cachedTemps = this->tmpdefs;
				HList<IRArgument> cachedArgs = this->arguments;

				tmpdefs.clear();
				this->arguments = args;

				InstrDefinition* instrdef = arch->getInstrDef (irExpr->mod.instrId);

				size_t i;
				for (i = 0; i < instrdef->irs.size(); i++) {
					if (arguments.size() == instrdef->irs[i].argcount) {
						if (instrdef->irs[i].condExpr) {
							IRArgument constArg = parseConstExpression(instrdef->irs[i].condExpr, &arguments);
							if (!(constArg && constArg.isConst() && constArg.argtype == SSAType::eUInt && constArg.uval)) {
								continue;
							}
						}
						parseExpression (instrdef->irs[i].rootExpr);
						break;
					}
				}
				if (i == instrdef->irs.size()) {
					printf ("Found No Recursive Match %s in parsing instruction: ", instrdef->mnemonics.cstr());
					instruction->print (arch);
				}
				for (size_t i = 0; i < subexpressioncount; i++) {
					IRArgument& arg = irExpr->subExpressions[i];
					if (arguments[i].type == IRArgTypes::IR_ARGTYPE_SSAID && arg.type == IRArgTypes::IR_ARGTYPE_TMP) {
						bool found = false;
						for (SSATmpDef& tmpDef : cachedTemps) {
							if (tmpDef.id == arg.ref.id) {
								tmpDef.arg = arguments[i];
								found = true;
							}
						}
						if (!found)
							cachedTemps.push_back({arg.ref.id, arguments[i]});
					}
				}
				this->tmpdefs = cachedTemps;
				this->arguments = cachedArgs;
			}
			return IRArgument::create ();
			case IR_EXPR_REP: {
				HId startBlock = activeBlockId;
				HId startCondId = createNewBlock();
				HId endCondId = 0;
				HId startBodyId = createNewBlock();
				HId endBodyId = 0;
				HId endId = createNewBlock();

				activateBlock (startCondId);
				SSAExpression branchExpr(SSAExprType::eBranch, arch->bitbase * arch->bytebase, SSAType::ePc);
				branchExpr.subExpressions = { SSAArgument::createBlock(startBodyId), parseIRArg2SSAArg(parseExpression(irExpr->subExpressions[1])), SSAArgument::createBlock(endId) };
				addExpression (&branchExpr);
				endCondId = activeBlockId;
				this->endOfBlock = false;
				this->fallthrough = false;

				activateBlock (startBodyId);
				parseExpression (irExpr->subExpressions[1]);
				endBodyId = activeBlockId;


				SSABB* startBlockBB = getBlock (startBlock);
				SSABB* startCondBB = getBlock (startCondId);
				SSABB* endCondBB = getBlock (endCondId);
				SSABB* startBodyBB = getBlock (startBodyId);
				SSABB* endBodyBB = getBlock (endBodyId);
				SSABB* endBB = getBlock (endId);

				//start -> startCond
				branchExpr.subExpressions = { SSAArgument::createBlock(startCondId) };
				function->ssaRep.addAtEnd(&branchExpr, startBlockBB);
				startBlockBB->outBlocks.insert (startCondId);
				startCondBB->inBlocks.insert (startBlock);

				//endCond -> true: startBody; false: end
				endCondBB->outBlocks.insert (endId);
				endBB->inBlocks.insert (endCondId);

				endCondBB->outBlocks.insert (startBodyId);
				startBodyBB->inBlocks.insert (endCondId);

				//endBody -> startCond
				branchExpr.subExpressions = { SSAArgument::createBlock(startCondId) };
				function->ssaRep.addAtEnd(&branchExpr, endBodyBB);
				endBodyBB->outBlocks.insert (startCondId);
				startCondBB->inBlocks.insert (endBodyId);

				activateBlock (endId);
				return IRArgument::create ();
			}
			case IR_EXPR_SIZE:
				assert (subexpressioncount == 1);
				return IRArgument::createUVal(parseExpression (irExpr->subExpressions[0]).size / arch->bitbase, arch->bytebase * arch->bitbase);
			case IR_EXPR_BSIZE: {
				assert(subexpressioncount == 1);
				IRArgument arg = parseExpression(irExpr->subExpressions[0]);
				return IRArgument::createUVal((uint64_t)arg.size, arch->bytebase * arch->bitbase);
			}
			case IR_EXPR_SEQUENCE://only for ir gets resolved in ir generation
				for (size_t i = 0; i < subexpressioncount; i++) {
					parseExpression (irExpr->subExpressions[i]);
				}
				return IRArgument::create();
			case IR_EXPR_FLAG: {
				SSAExpression expression;
				expression.type = SSAExprType::eFlag;
				expression.flagType = irExpr->mod.flagType;
				expression.exprtype = SSAType::eUInt;
				expression.size = 1;

				uint32_t size;
				if (irExpr->subExpressions.size() == 1 && irExpr->subExpressions[0].isConst() && irExpr->subExpressions[0].argtype == SSAType::eUInt)
					size = static_cast<uint32_t>(irExpr->subExpressions[0].uval);
				else
					size = ssaRep->expressions[lastOp].size;
				expression.flagbit = size;
				expression.subExpressions.push_back (SSAArgument::createId (lastOp));

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
		ssaRep->print (arch, indent);
	}
}
