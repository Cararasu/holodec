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
					if (constArg && constArg.type == IR_ARGTYPE_UINT && constArg.uval) {
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

	IRArgument SSAGen::parseMemArgToExpr (IRArgument mem) {
		SSAExpression memexpr;
		memexpr.type = SSAExprType::eLoadAddr;
		memexpr.exprtype = SSAType::eUInt;
		memexpr.size = arch->bitbase;
		//segment::[base + index*scale + disp]
		SSAArgument args[5];
		if (mem.mem.segment)
			args[0].set(SSAArgument::createReg (arch->getRegister (mem.mem.segment)));
		else
			args[0].set(SSAArgument::createUVal ( (uint64_t) 0, arch->bitbase));

		if (mem.mem.base)
			args[1].set(SSAArgument::createReg (arch->getRegister (mem.mem.base)));
		else
			args[1].set(SSAArgument::createUVal ( (uint64_t) 0, arch->bitbase));

		if (mem.mem.index)
			args[2].set(SSAArgument::createReg (arch->getRegister (mem.mem.index)));
		else
			args[2].set(SSAArgument::createUVal ( (uint64_t) 0, arch->bitbase));

		args[3].set(SSAArgument::createUVal (mem.mem.scale, arch->bitbase));

		args[4].set(SSAArgument::createUVal (mem.mem.disp, arch->bitbase));

		memexpr.subExpressions.assign (args, args + 5);
		return IRArgument::createSSAId (addExpression (&memexpr), arch->bitbase);
	}

	template<typename ARGLIST>
	IRArgument SSAGen::parseConstExpression (IRArgument argExpr, ARGLIST* arglist) {
		switch (argExpr.type) {
		default:
			return IRArgument::createUVal( (uint64_t) 1, arch->bitbase);
		case IR_ARGTYPE_ARG: {
			return (*arglist) [argExpr.ref.refId - 1];
		}
		case IR_ARGTYPE_ID: {
			IRExpression* irExpr = arch->getIrExpr (argExpr.ref.refId);

			switch (irExpr->type) {
			case IR_EXPR_OP: {
				switch (irExpr->mod.opType) {
				case SSAOpType::eAdd: {
					uint64_t val = 0;
					for (size_t i = 0; i < irExpr->subExpressions.size(); i++) {
						IRArgument arg = parseConstExpression(irExpr->subExpressions[i], arglist);
						if (arg.type == IR_ARGTYPE_UINT)
							val += arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}
				case SSAOpType::eAnd: {
					uint64_t val = 1;
					for (size_t i = 0; i < irExpr->subExpressions.size(); i++) {
						IRArgument arg = parseConstExpression(irExpr->subExpressions[i], arglist);
						if (arg.type == IR_ARGTYPE_UINT)
							val = val && arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}
				case SSAOpType::eOr: {
					uint64_t val = 0;
					for (size_t i = 0; i < irExpr->subExpressions.size(); i++) {
						IRArgument arg = parseConstExpression (irExpr->subExpressions[i], arglist);
						if (arg && arg.type == IR_ARGTYPE_UINT)
							val = val || arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}
				case SSAOpType::eNot: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size()) {
						IRArgument arg = parseConstExpression (irExpr->subExpressions[0], arglist);
						if (arg && arg.type == IR_ARGTYPE_UINT)
							val = !arg.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}

				case SSAOpType::eEq: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval == arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}
				case SSAOpType::eNe: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval != arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}
				case SSAOpType::eLower: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval < arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}
				case SSAOpType::eLe: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval <= arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}
				case SSAOpType::eGreater: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval > arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}
				case SSAOpType::eGe: {
					uint64_t val = 0;
					if (irExpr->subExpressions.size() == 2) {
						IRArgument arg1 = parseConstExpression (irExpr->subExpressions[0], arglist);
						IRArgument arg2 = parseConstExpression (irExpr->subExpressions[1], arglist);
						if (arg1 && arg2 && arg1.type == IR_ARGTYPE_UINT && arg2.type == IR_ARGTYPE_UINT)
							val = arg1.uval >= arg2.uval;
						else
							return IRArgument::create();
					}
					return IRArgument::createUVal(val, arch->bitbase);
				}
				default:
					return IRArgument::create();
				}
			}
			case IR_EXPR_SIZE: {
				assert(irExpr->subExpressions.size() == 1);
				uint64_t size = parseConstExpression(irExpr->subExpressions[0], arglist).size;
				return IRArgument::createUVal((size + arch->wordbase - 1) / arch->wordbase, arch->wordbase);
			}
			case IR_EXPR_BSIZE:
				assert (irExpr->subExpressions.size() == 1);
				return IRArgument::createUVal( (uint64_t) parseConstExpression (irExpr->subExpressions[0], arglist).size, arch->wordbase);
			default:
				return IRArgument::create();
			}
		}

		break;
		case IR_ARGTYPE_SINT:
		case IR_ARGTYPE_UINT:
		case IR_ARGTYPE_FLOAT:
			return argExpr;
		case IR_ARGTYPE_IP:
			return IRArgument::createUVal(instruction->addr + instruction->size, arch->wordbase * arch->instrptrsize);
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
		expression.size = arch->bitbase;
		expression.subExpressions.push_back (SSAArgument::createUVal (address, arch->bitbase));
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
		HId ssaId = ssaRepresentation->addAtEnd (expression, activeblock);
		if (expression->type == SSAExprType::eOp)
			lastOp = ssaId;
		return ssaId;
	}
	void SSAGen::reset() {
		ssaRepresentation = nullptr;
	}
	void SSAGen::setup (Function* function, uint64_t addr) {
		this->instruction = nullptr;
		this->function = function;
		ssaRepresentation = &function->ssaRep;
		activateBlock (createNewBlock());
		for (Register& reg : arch->registers) {
			if (!reg.id || reg.directParentRef)
				continue;
			SSAExpression expression;
			expression.type = SSAExprType::eInput;
			expression.exprtype = SSAType::eUInt;
			expression.instrAddr = function->baseaddr;
			expression.location = SSALocation::eReg;
			expression.locref = {reg.id, 0};
			expression.size = reg.size;

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
					if (expr->type == SSAExprType::eLabel && expr->subExpressions.size() > 0 && expr->subExpressions[0].type == SSAArgType::eUInt && expr->subExpressions[0].uval == addr) {
						printf ("Split SSA 0x%" PRIx64 "\n", addr);
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
		switch (arg.type) {
		case IR_ARGTYPE_UNKN:
			return SSAArgument::create();
		case IR_ARGTYPE_SSAID:
			return SSAArgument::createId (arg.ref.refId, arg.size, arg.offset);
		case IR_ARGTYPE_FLOAT:
			return SSAArgument::createDVal (arg.fval, arg.size, arg.offset);
		case IR_ARGTYPE_UINT:
			return SSAArgument::createUVal (arg.uval, arg.size, arg.offset);
		case IR_ARGTYPE_SINT:
			return SSAArgument::createSVal (arg.sval, arg.size, arg.offset);
		case IR_ARGTYPE_MEM:
			return SSAArgument::createMem (arg.ref.refId);
		case IR_ARGTYPE_STACK:
			return SSAArgument::createStck (arg.ref);
		case IR_ARGTYPE_REG:
			return SSAArgument::createReg (arg.ref, arg.size, arg.offset);

		default:
			assert (false);
		}
		return SSAArgument::create();
	}
	void SSAGen::replaceArg (IRArgument& arg) {
		while (arg.type == IR_ARGTYPE_ARG) {
			assert (arg.ref.refId && arg.ref.refId <= arguments.size());
			IRArgument& aarg = arguments[arg.ref.refId - 1];
			arg = aarg;
		}
	}
	void SSAGen::addUpdateRegExpressions (HId regId, HId ssaId) {

		Register* baseReg = arch->getRegister (regId);
		Register* reg = baseReg;
		while (reg->directParentRef) {
			reg = arch->getRegister (reg->directParentRef);
			SSAExpression updateExpression;
			updateExpression.type = baseReg->clearParentOnWrite ? SSAExprType::eExtend :  SSAExprType::eUpdatePart;
			updateExpression.exprtype = SSAType::eUInt;
			updateExpression.location = SSALocation::eReg;
			updateExpression.locref = {reg->id, 0};
			updateExpression.size = reg->size;
			if (baseReg->clearParentOnWrite) {
				assert (baseReg->offset == 0);
				updateExpression.subExpressions.push_back (SSAArgument::createId (ssaId, baseReg->size));
			} else {
				updateExpression.subExpressions.push_back (SSAArgument::createReg (reg));
				updateExpression.subExpressions.push_back (SSAArgument::createId (ssaId, baseReg->size));
				updateExpression.subExpressions.push_back (SSAArgument::createUVal (baseReg->offset - reg->offset, arch->bitbase));
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
			expression.exprtype = SSAType::eUInt;
			expression.location = SSALocation::eMem;
			expression.locref = {arch->getDefaultMemory()->id, 0};
			expression.size = exprId.size;
			expression.subExpressions = {
				parseIRArg2SSAArg (parseMemArgToExpr (exprId)),
				SSAArgument::createUVal ( (uint64_t) exprId.size, arch->bitbase)
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
			printf ("0x%" PRIx64 "\n", instruction->addr);
			printf ("%d\n", exprId.ref.refId);
			assert (false);
		}
		case IR_ARGTYPE_IP:
			return IRArgument::createUVal (instruction->addr + instruction->size, arch->wordbase * arch->instrptrsize);
		case IR_ARGTYPE_ID: {
			IRExpression* irExpr = arch->getIrExpr (exprId.ref.refId);

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
					expression.exprtype = SSAType::eUInt;
					assert(arg.size);
					switch (arg.type) {
					case IR_ARGTYPE_REG:
						expression.location = SSALocation::eReg;
						expression.locref = arg.ref;
						expression.size = arg.size;
						addUpdateRegExpressions (arg.ref.refId, addExpression (&expression));
						break;
					case IR_ARGTYPE_STACK:
						expression.location = SSALocation::eStack;
						expression.locref = arg.ref;
						expression.size = arg.size;
						addExpression (&expression);
						break;
					case IR_ARGTYPE_TMP:
						for (auto it = tmpdefs.begin(); it != tmpdefs.end(); ++it) {
							if ( (*it).id == arg.ref.refId) {
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
					SSAExpression* ssaExpr = ssaRepresentation->expressions.get (srcArg.ref.refId);
					assert (ssaExpr);
					assert(ssaExpr->size);
					switch (dstArg.type) {
					case IR_ARGTYPE_REG:
					case IR_ARGTYPE_STACK: {
						if (ssaExpr->location == SSALocation::eNone && ssaExpr->size == dstArg.size) {
							if (dstArg.type == IR_ARGTYPE_REG) {
								ssaExpr->location = SSALocation::eReg;
								ssaExpr->locref = dstArg.ref;
								ssaExpr->size = dstArg.size;
								IRArgument arg = IRArgument::createSSAId (srcArg.ref.refId, ssaExpr->size);
								addUpdateRegExpressions (dstArg.ref.refId, srcArg.ref.refId);//can relocate ssaExpr
								return arg;
							} else if (dstArg.type == IR_ARGTYPE_STACK) {
								ssaExpr->location = SSALocation::eStack;
								ssaExpr->locref = dstArg.ref;
								ssaExpr->size = dstArg.size;
								return IRArgument::createSSAId (srcArg.ref.refId, ssaExpr->size);
							}
						}
					}
					break;
					case IR_ARGTYPE_TMP: {
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
				expression.size = srcSSAArg.size;
				//assert(expression.size);
				switch (dstArg.type) {
				case IR_ARGTYPE_TMP: {
					expression.exprtype = SSAType::eUInt;
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
					expression.type = SSAExprType::eStore;
					expression.exprtype = SSAType::eMemaccess;
					expression.size = 0;
					Memory* memory = arch->getDefaultMemory();
					expression.location = SSALocation::eMem;
					expression.locref = {memory->id, 0};
					expression.subExpressions = {parseIRArg2SSAArg (parseMemArgToExpr (dstArg)) };
				}
				break;
				case IR_ARGTYPE_REG:{
					expression.location = SSALocation::eReg;
					expression.locref = dstArg.ref;
					expression.size = dstArg.size;

					expression.subExpressions = {srcSSAArg};

					HId ssaId = addExpression (&expression);
					addUpdateRegExpressions (dstArg.ref.refId, ssaId);
					return IRArgument::createSSAId (ssaId, expression.size);
				}
				case IR_ARGTYPE_STACK: {
					expression.location = SSALocation::eStack;
					expression.locref = dstArg.ref;
					expression.size = dstArg.size;
				}break;
				case IR_ARGTYPE_SSAID: {//assign to no particular thing, needed for recursive with write-parameter as tmp
					IRArgument* arg = &irExpr->subExpressions[0];
					assert(arg->type == IR_ARGTYPE_ARG);

					while (true) {//get argument index
						assert(arg->ref.refId && arg->ref.refId <= arguments.size());
						if (arguments[arg->ref.refId - 1].type != IR_ARGTYPE_ARG)
							break;
						arg = &arguments[arg->ref.refId - 1];
					}
					//write the new ssaId
					expression.subExpressions.push_back(srcSSAArg);
					IRArgument retarg = IRArgument::createSSAId(addExpression(&expression), expression.size);
					arguments[arg->ref.refId - 1] = retarg;
					return retarg;
				}break;
				default:
					dstArg.print (arch);
					printf ("Invalid Type for Assignment 0x%" PRIx64 "\n", dstArg.type);
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
				expression.type = SSAExprType::eCJmp;
				expression.exprtype = SSAType::ePc;
				expression.size = arch->bitbase;


				assert (subexpressioncount >= 2 && subexpressioncount <= 3);

				HId oldBlock = activeBlockId;
				HId trueblockId = createNewBlock();
				HId falseblockId = (subexpressioncount == 3) ? createNewBlock() : 0;//generate early so the blocks are in order
				HId endBlockId = createNewBlock();

				SSAArgument exprArgs[2] = {
					SSAArgument::createBlock(trueblockId),
					parseIRArg2SSAArg(parseExpression(irExpr->subExpressions[0]))
				};
				expression.subExpressions.assign (exprArgs, exprArgs + 2);
				addExpression (&expression);

				activateBlock (trueblockId);
				parseExpression (irExpr->subExpressions[1]);//trueblock
				getActiveBlock()->fallthroughId = endBlockId;

				if (falseblockId) {
					getBlock (oldBlock)->fallthroughId = falseblockId;
					activateBlock (falseblockId);
					parseExpression (irExpr->subExpressions[2]);//falseblock
					SSABB* activeblock = getActiveBlock();
					activeblock->fallthroughId = endBlockId;
					activeblock->outBlocks.insert (endBlockId);
					getBlock (endBlockId)->inBlocks.insert (activeblock->id);
				} else {
					SSABB* oldBB = getBlock (oldBlock);
					oldBB->fallthroughId = endBlockId;
					oldBB->outBlocks.insert (endBlockId);
					getBlock (endBlockId)->inBlocks.insert (oldBB->id);
				}
				activateBlock (endBlockId);
				return IRArgument::create ();
			}
			case IR_EXPR_JMP: {
				SSAExpression expression;
				expression.type = SSAExprType::eJmp;
				expression.exprtype = SSAType::ePc;
				expression.size = arch->bitbase;

				assert (subexpressioncount == 1);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));

				endOfBlock = true;
				fallthrough = false;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_CJMP: {
				SSAExpression expression;
				expression.type = SSAExprType::eCJmp;
				expression.exprtype = SSAType::ePc;
				expression.size = arch->bitbase;

				assert (subexpressioncount == 2);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));//
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1])));//

				endOfBlock = true;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
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
						size += arg.size;
					else if (!size)
						size = arg.size;
					if (arg.size) {
						assert(size >= arg.size);
					}
					assert(!(!arg.isConst() && arg.type != SSAArgType::eOther && arg.size == 0));
					expression.subExpressions.push_back (arg);
				}
				if (expression.opType != SSAOpType::eMul) {
					for (SSAArgument& arg : expression.subExpressions) {
						if (!arg.size)
							arg.size = size;
					}
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
				SSAExpression expression;
				expression.type = SSAExprType::eCall;
				expression.exprtype = irExpr->exprtype;
				assert (subexpressioncount == 1);
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));

				if (expression.subExpressions[0].type == SSAArgType::eUInt) {
					function->funcsCalled.insert (expression.subExpressions[0].uval);
				}

				for (Register& reg : arch->registers) {
					if (!reg.directParentRef)
						expression.subExpressions.push_back(SSAArgument::createReg(&reg));
				}
				expression.size = arch->bitbase;
				IRArgument arg = IRArgument::createSSAId (addExpression (&expression), expression.size);

				SSAArgument ssaArg = parseIRArg2SSAArg (arg);

				for (Register& reg : arch->registers) {
					if (!reg.id || reg.directParentRef)
						continue;
					SSAExpression retExpr;
					retExpr.type = SSAExprType::eOutput;
					retExpr.exprtype = SSAType::eUInt;
					retExpr.location = SSALocation::eReg;
					retExpr.locref = {reg.id, 0};
					retExpr.size = reg.size;
					retExpr.subExpressions = {ssaArg, SSAArgument::createReg(&reg) };
					addExpression (&retExpr);
				}

				return arg;
			}
			case IR_EXPR_RETURN: {
				SSAExpression expression;
				expression.type = SSAExprType::eReturn;
				expression.exprtype = SSAType::ePc;
				expression.size = arch->bitbase;
				assert (subexpressioncount == 1);
				
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));
				
				for (Register& reg : arch->registers) {
					if (!reg.id || reg.directParentRef)
						continue;
					expression.subExpressions.push_back (SSAArgument::createReg (&reg));
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
				expression.builtinId = irExpr->mod.builtinId;
				expression.size = arch->bitbase;
				return IRArgument::createSSAId(addExpression(&expression), expression.size);
			}
			case IR_EXPR_EXTEND: {
				assert (subexpressioncount == 2);
				SSAExpression expression;
				expression.type = SSAExprType::eExtend;
				expression.exprtype = irExpr->exprtype;
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0])));

				IRArgument arg = parseConstExpression (irExpr->subExpressions[1], &arguments);
				assert (arg && arg.type == IR_ARGTYPE_UINT);
				expression.size = arg.uval;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_SPLIT: {
				assert(irExpr->subExpressions.size() == 3);
				SSAArgument arg = parseIRArg2SSAArg(parseExpression(irExpr->subExpressions[0]));
				IRArgument offset = parseExpression(irExpr->subExpressions[1]);
				IRArgument size = parseExpression(irExpr->subExpressions[2]);
				assert(offset.type == IR_ARGTYPE_UINT && size.type == IR_ARGTYPE_UINT);
				arg.offset = offset.uval;
				arg.size = size.uval;
				
				SSAExpression expression;
				expression.type = SSAExprType::eAssign;
				expression.exprtype = SSAType::eUInt;
				expression.subExpressions = { arg };
				expression.size = arg.size;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_APPEND: {
				SSAExpression expression;
				expression.type = SSAExprType::eAppend;
				expression.exprtype = SSAType::eUInt;
				expression.size = 0;
				for (size_t i = 0; i < subexpressioncount; i++) {
					SSAArgument arg = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[i]));
					expression.size += arg.size;
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
				assert (sizeArg.type = IR_ARGTYPE_UINT);
				expression.size = sizeArg;
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
				assert (memarg.location == SSALocation::eMem);
				expression.location = SSALocation::eMem;
				expression.locref = memarg.locref;
				expression.subExpressions = {
					parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1])),
					parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[2]))
				};
				expression.size = arch->bitbase;
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
			}
			case IR_EXPR_LOAD: {
				SSAExpression expression;
				expression.type = SSAExprType::eLoad;
				expression.exprtype = SSAType::eUInt;
				assert (subexpressioncount == 3);
				SSAArgument memarg = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[0]));
				assert (memarg.location == SSALocation::eMem);
				expression.location = SSALocation::eMem;
				expression.locref = memarg.locref;
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
				case StackType::eRegBacked: {
					assert (false);
					return IRArgument::createSSAId (0, 0);
				}
				case StackType::eMemory: {
					assert (subexpressioncount == 2);
					assert (stack->backingMem);
					SSAArgument sizeadjust = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1]));
					Register* reg = arch->getRegister (stack->trackingReg);
					Memory* mem = arch->getMemory (stack->backingMem);
					assert (reg->id);
					assert (mem);

					SSAExpression expression;
					expression.type = SSAExprType::ePush;
					expression.exprtype = SSAType::eMemaccess;
					expression.size = 0;
					expression.location = SSALocation::eMem;
					expression.locref = {mem->id, 0};
					expression.subExpressions = {
						SSAArgument::createMem(mem->id),
						SSAArgument::createReg (reg)
					};

					SSAExpression adjustExpr;
					adjustExpr.type = SSAExprType::eOp;
					adjustExpr.exprtype = SSAType::eUInt;
					adjustExpr.opType = stack->policy == StackPolicy::eTop ?  SSAOpType::eAdd : SSAOpType::eSub;
					adjustExpr.subExpressions = {
						SSAArgument::createReg (reg),
						sizeadjust
					};
					adjustExpr.size = reg->size;
					adjustExpr.location = SSALocation::eReg;
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
				case StackType::eRegBacked: {
					assert (false);
					return IRArgument::createSSAId (0, 0);
				}
				case StackType::eMemory: {
					assert (subexpressioncount == 2);
					SSAArgument sizeadjust = parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1]));
					assert (sizeadjust.type == SSAArgType::eUInt);
					Register* reg = arch->getRegister (stack->trackingReg);
					Memory* mem = arch->getMemory (stack->backingMem);
					assert (reg);
					assert (mem);

					SSAExpression expression;
					expression.type = SSAExprType::ePop;
					expression.exprtype = SSAType::eUInt;
					expression.size = sizeadjust.uval * stack->wordbitsize;
					expression.subExpressions = {
						SSAArgument::createMem(mem->id),
						SSAArgument::createReg(reg)
					};

					SSAExpression adjustExpr;
					adjustExpr.type = SSAExprType::eOp;
					adjustExpr.exprtype = SSAType::eUInt;
					adjustExpr.opType = stack->policy == StackPolicy::eTop ? SSAOpType::eSub : SSAOpType::eAdd;
					adjustExpr.subExpressions = {
						SSAArgument::createReg (reg),
						sizeadjust
					};

					adjustExpr.location = SSALocation::eReg;
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
				expression.type = SSAExprType::eAssign;
				assert (subexpressioncount == 1);
				IRArgument arg = irExpr->subExpressions[0];
				replaceArg(arg);
				assert (arg.type == IR_ARGTYPE_MEMOP);
				expression.exprtype = SSAType::eUInt;
				expression.size = arch->bitbase;
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseMemArgToExpr (arg)));
				return IRArgument::createSSAId (addExpression (&expression), expression.size);
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
							if (!(constArg && constArg.type == IR_ARGTYPE_UINT && constArg.uval)) {
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
							if (tmpDef.id == arg.ref.refId) {
								tmpDef.arg = arguments[i];
								found = true;
							}
						}
						if (!found)
							cachedTemps.push_back({arg.ref.refId, arguments[i]});
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

				activateBlock (startCondId);
				SSAExpression expression;
				expression.type = SSAExprType::eCJmp;
				expression.exprtype = SSAType::ePc;
				expression.size = arch->bitbase;
				expression.subExpressions.push_back(SSAArgument::createBlock(startBodyId));
				expression.subExpressions.push_back (parseIRArg2SSAArg (parseExpression (irExpr->subExpressions[1])));
				addExpression (&expression);
				endCondId = activeBlockId;
				this->endOfBlock = false;
				this->fallthrough = false;

				activateBlock (startBodyId);
				parseExpression (irExpr->subExpressions[1]);
				endBodyId = activeBlockId;

				HId endId = createNewBlock();

				SSABB* startBlockBB = getBlock (startBlock);
				SSABB* startCondBB = getBlock (startCondId);
				SSABB* endCondBB = getBlock (endCondId);
				SSABB* startBodyBB = getBlock (startBodyId);
				SSABB* endBodyBB = getBlock (endBodyId);
				SSABB* endBB = getBlock (endId);

				//start -> startCond
				startBlockBB->fallthroughId = startCondId;
				startBlockBB->outBlocks.insert (startCondId);
				startCondBB->inBlocks.insert (startBlock);

				//endCond -> true: startBody; false: end
				endCondBB->fallthroughId = endId;
				endCondBB->outBlocks.insert (endId);
				endBB->inBlocks.insert (endCondId);

				endCondBB->outBlocks.insert (startBodyId);
				startBodyBB->inBlocks.insert (endCondId);

				//endBody -> startCond
				endBodyBB->fallthroughId = startCondId;
				endBodyBB->outBlocks.insert (startCondId);
				startCondBB->inBlocks.insert (endBodyId);

				activateBlock (endId);
				return IRArgument::create ();
			}
			case IR_EXPR_SIZE:
				assert (subexpressioncount == 1);
				return IRArgument::createUVal(parseExpression (irExpr->subExpressions[0]).size / arch->wordbase, arch->bitbase);
			case IR_EXPR_BSIZE:
				assert (subexpressioncount == 1);
				return IRArgument::createUVal( (uint64_t) parseExpression (irExpr->subExpressions[0]).size, arch->bitbase);
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
				if (irExpr->subExpressions.size() == 1 && irExpr->subExpressions[0].type == IR_ARGTYPE_UINT)
					size = irExpr->subExpressions[0].uval;
				else
					size = ssaRepresentation->expressions[lastOp].size;

				expression.subExpressions.push_back (SSAArgument::createId (lastOp, size));



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
