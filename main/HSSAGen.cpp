#include "HSSAGen.h"
#include "HArchitecture.h"
#include <assert.h>

namespace holodec {

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

	template<typename ARGLIST>
	HArgument HSSAGen::parseConstExpression (HArgument argExpr, ARGLIST* arglist) {
		switch (argExpr.type) {
		default:
			return HArgument::createVal ( (uint64_t) 1, arch->bitbase);
		case HIR_ARGTYPE_ARG: {
			return (*arglist)[argExpr.index];
		}
		case HIR_ARGTYPE_ID: {
			HIRExpression* expr = arch->getIrExpr (argExpr.id);

			switch (expr->type) {
			case HIR_EXPR_OP: {
				switch (expr->mod.opType) {
				case HSSA_OP_AND: {
					uint64_t val = 0;
					for (int i = 0; i < expr->subExpressions.size(); i++) {
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
					for (int i = 0; i < expr->subExpressions.size(); i++) {
						HArgument arg = parseConstExpression (expr->subExpressions[i], arglist);
						if (arg.type == H_ARGTYPE_UINT)
							val = val || arg.uval;
						else
							return HArgument::create();
					}
					return HArgument::createVal (val, arch->bitbase);
				}
				case HSSA_OP_XOR: {
					uint64_t val = 0;
					for (int i = 0; i < expr->subExpressions.size(); i++) {
						HArgument arg = parseConstExpression (expr->subExpressions[i], arglist);
						if (arg.type == H_ARGTYPE_UINT)
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
						if (arg.type == H_ARGTYPE_UINT)
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
						if (arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
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
						if (arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
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
						if (arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
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
						if (arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
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
						if (arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
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
						if (arg1.type == H_ARGTYPE_UINT && arg2.type == H_ARGTYPE_UINT)
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
		expression.subExpressions.add (HArgument::createVal (address, arch->bitbase));
		addExpression (&expression);
	}
	HSSAGenBB* HSSAGen::getBlock (HId blockId) {
		for (HSSAGenBB& bbs : genBBs) {
			if (bbs.id == blockId) {
				return &bbs;
			}
		}
		return nullptr;
	}
	HSSAGenBB* HSSAGen::getActiveBlock () {
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
		if (!activeblock->startaddr) {
			activeblock->startaddr = instruction->addr;
		}
		activeblock->endaddr = instruction->addr + instruction->size;
		expression->instrAddr = instruction->addr;
		expressions.add (*expression);
		activeblock->exprIds.push_back (expressions.back().id);
		return expressions.back().id;
	}
	HId HSSAGen::splitBasicBlock (uint64_t addr) {
		for (HSSAGenBB& bb : genBBs) {
			if (bb.startaddr == addr)
				return bb.id;
			if (bb.startaddr < addr && addr < bb.endaddr) {
				for (auto it = bb.exprIds.begin(); it != bb.exprIds.end(); ++it) {
					HSSAExpression* expr = expressions.get (*it);
					if (expr->type == HSSA_EXPR_LABEL && expr->subExpressions[0].type == H_ARGTYPE_UINT && expr->subExpressions[0].uval == addr) {
						HSSAGenBB newbb (bb.fallthroughId, addr, bb.endaddr, HList<HId> (it, bb.exprIds.end()));
						HId retId = bb.id;
						genBBs.add (newbb);
						bb.endaddr = addr;
						bb.fallthroughId = genBBs.back().id;
						bb.exprIds.erase (it, bb.exprIds.end());
						return retId;
					}
				}
			}
		}
		return 0;
	}
	HId HSSAGen::createNewBlock () {
		activeblock = nullptr;
		HSSAGenBB block;
		genBBs.add (block);
		return genBBs.list.back().id;
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
	HArgument HSSAGen::parseExpression (HArgument exprId) {

		exprId = replaceArg (exprId);

		switch (exprId.type) {
		default:
			return exprId;
		case HIR_ARGTYPE_ARG: {
			assert (false);
		}
		case H_ARGTYPE_MEM: {
			HSSAExpression expression;
			expression.type = HSSA_EXPR_LOAD;
			expression.subExpressions.add (exprId);
			expression.subExpressions.add (HArgument::createVal (exprId.size, arch->bitbase));
			expression.size = exprId.size;
			return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
		}
		case HIR_ARGTYPE_TMP: {
			assert (exprId.index);
			for (HSSAGenDef& def : tmpdefs) {
				if (def.id == exprId.index) {
					return def.arg;
				}
			}
			printf("0x%x\n", instruction->addr);
			printf("%d\n", exprId.index);
			assert (false);
		}
		case HIR_ARGTYPE_ID: {
			HIRExpression* expr = arch->getIrExpr (exprId.id);
			/*printf ("----\n");
			expr->print (arch, 0, false);*/

			size_t subexpressioncount = expr->subExpressions.size();

			if (expr->type == HIR_EXPR_UNDEF) { //undef
				/*for (int i = 0; i < subexpressioncount; i++) {
					assert (args[i].type == HIR_ARGTYPE_ARG || args[i].type == HIR_ARGTYPE_REG || args[i].type == HIR_ARGTYPE_STACK || args[i].type == HIR_ARGTYPE_TMP);
					HSSAId ssa = {idGen.next(), id};
					printf ("%d:%d = Undef(");
					switch (args[i].type) {
					case HIR_ARGTYPE_ARG:
						createSSARegDef (arch->getRegister (args[i].));
						break;
					case HIR_ARGTYPE_REG:
						break;
					case HIR_ARGTYPE_STACK:
						break;
					case HIR_ARGTYPE_TMP:
						break;
					default:
						assert (false);
					}
					printf (")\n");
				}*/
			} else if (expr->type == HIR_EXPR_ASSIGN) {
				HSSAExpression expression;
				expression.type = HSSA_EXPR_IDENT;
				assert (subexpressioncount == 2);
				HArgument dstArg = replaceArg (expr->subExpressions[0]);

				HArgument srcArg = parseExpression (expr->subExpressions[1]);

				if ( (dstArg.type == H_ARGTYPE_REG || dstArg.type == H_ARGTYPE_STACK) && expression.subExpressions[0].type == HIR_ARGTYPE_ID) {
					HSSAExpression* ssaExpr = expressions.get (expression.subExpressions[0].id);
					assert (ssaExpr);
					if (!ssaExpr->regId && !ssaExpr->stackId.id) {
						if (dstArg.type == H_ARGTYPE_REG) {
							ssaExpr->regId = dstArg.reg;
							return HArgument::createId (HSSA_ARGTYPE_ID, ssaExpr->id);
						} else if (dstArg.type == H_ARGTYPE_STACK) {
							ssaExpr->stackId = dstArg.stack;
							return HArgument::createId (HSSA_ARGTYPE_ID, ssaExpr->id);
						}
					}
				}
				switch (dstArg.type) {
				case HIR_ARGTYPE_TMP: {
					HArgument arg = HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
					for (HSSAGenDef& def : tmpdefs) {
						if (def.id == dstArg.index) {
							def.arg = arg;
							return HArgument::create();
						}
					}
					tmpdefs.push_back ({dstArg.index, 0, arg.size, arg});
					return HArgument::create();
				}
				case H_ARGTYPE_MEM:
				case HIR_ARGTYPE_ID:
					expression.type = HSSA_EXPR_STORE;
					expression.subExpressions.add (dstArg);
					break;
				case H_ARGTYPE_REG:
					expression.regId = dstArg.reg;
					break;
				case H_ARGTYPE_STACK:
					expression.stackId = dstArg.stack;
					break;
				default:
					dstArg.print (arch);
					printf ("Invalid Type for Assignment 0x%x\n", dstArg.type);
					assert (false);
					break;
				}
				expression.subExpressions.add (srcArg);
				return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
			} else {

				switch (expr->type) {
				case HIR_EXPR_UNDEF:
				case HIR_EXPR_ASSIGN:
				default:
					assert (false);
					break;

				case HIR_EXPR_NOP:
					return HArgument::create();

				case HIR_EXPR_IF: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_CJMP;

					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));

					assert (subexpressioncount >= 2 && subexpressioncount <= 3);

					HId oldBlock = activeBlockId;
					HId endBlockId = createNewBlock();
					HId trueblockId = createNewBlock();

					expression.subExpressions.add (HArgument::createIndex (HSSA_ARGTYPE_BLOCK, trueblockId));
					addExpression (&expression);

					activateBlock (trueblockId);
					parseExpression (expr->subExpressions[1]);
					getActiveBlock()->fallthroughId = endBlockId;

					if (subexpressioncount == 3) {
						HId falseblockId = createNewBlock();
						getBlock (oldBlock)->fallthroughId = falseblockId;
						activateBlock (falseblockId);
						parseExpression (expr->subExpressions[2]);
						getActiveBlock()->fallthroughId = endBlockId;
					}
					activateBlock (endBlockId);
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				break;
				case HIR_EXPR_JMP: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_JMP;

					assert (subexpressioncount == 1);
					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
					if (expression.subExpressions[0].type == H_ARGTYPE_UINT)
						addressesToAnalyze.push_back (expression.subExpressions[0].uval);

					endOfBlock = true;
					fallthrough = false;
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_CJMP: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_CJMP;

					assert (subexpressioncount == 2);
					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
					expression.subExpressions.add (parseExpression (expr->subExpressions[1]));
					if (expression.subExpressions[1].type == H_ARGTYPE_UINT)
						addressesToAnalyze.push_back (expression.subExpressions[1].uval);

					HId cjmpExpr = addExpression (&expression);

					endOfBlock = true;
					fallthrough = true;
					return HArgument::createId (HSSA_ARGTYPE_ID, cjmpExpr);
				}
				case HIR_EXPR_OP: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_OP;
					expression.opType = expr->mod.opType;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					HId id = addExpression (&expression);
#
					lastOp = id;
					return HArgument::createId (HSSA_ARGTYPE_ID, id);
				}
				// Call - Return
				case HIR_EXPR_CALL:  {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_CALL;
					assert (subexpressioncount == 1);
					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_RETURN: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_RETURN;
					assert (!subexpressioncount);
					endOfBlock = true;
					fallthrough = false;
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_SYSCALL: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_SYSCALL;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_TRAP: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_TRAP;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_BUILTIN:
					printf ("Builtin\n");
					break;
				case HIR_EXPR_EXTEND: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_EXTEND;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_SPLIT: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_SPLIT;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_APPEND: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_APPEND;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_CAST: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_CAST;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}

				// Memory
				case HIR_EXPR_STORE: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_STORE;
					assert (subexpressioncount == 2);
					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
					expression.subExpressions.add (parseExpression (expr->subExpressions[1]));
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_LOAD: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_STORE;
					assert (subexpressioncount == 2);
					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
					expression.subExpressions.add (parseExpression (expr->subExpressions[1]));
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}

				case HIR_EXPR_PUSH: {
					HArgument stackArg = parseExpression (expr->subExpressions[0]);
					assert (stackArg.type == H_ARGTYPE_STACK);
					HStack* stack = arch->getStack (stackArg.stack.id);
					assert (stack);
					switch (stack->type) {
					case H_STACK_BUILTIN: {
						HSSAExpression expression;
						expression.type = HSSA_EXPR_POP;
						assert (subexpressioncount == 1);
						expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
						return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
					}
					case H_STACK_MEMORY: {
						assert (subexpressioncount == 2);
						HArgument value = parseExpression (expr->subExpressions[1]);
						HRegister* reg = arch->getRegister (stack->trackingReg);
						assert (reg);

						HSSAExpression expression;
						expression.type = HSSA_EXPR_STORE;
						expression.subExpressions.add (HArgument::createReg (reg));
						expression.subExpressions.add (value);

						HSSAExpression adjustExpr;
						adjustExpr.type = HSSA_EXPR_OP;
						adjustExpr.opType = stack->policy == H_STACKPOLICY_TOP ?  HSSA_OP_ADD : HSSA_OP_SUB;
						adjustExpr.subExpressions.add (HArgument::createReg (reg));
						adjustExpr.subExpressions.add (HArgument::createVal ( (value.size + stack->wordbitsize - 1) / stack->wordbitsize, arch->bitbase));
						adjustExpr.regId = reg->id;

						addExpression (&adjustExpr);
						return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
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
						expression.subExpressions.add (stackArg);
						expression.size = stack->wordbitsize;
						return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
					}
					case H_STACK_MEMORY: {
						assert (subexpressioncount == 2);
						HArgument sizeadjust = parseExpression (expr->subExpressions[1]);
						assert (sizeadjust.type == H_ARGTYPE_UINT);
						HRegister* reg = arch->getRegister (stack->trackingReg);
						assert (reg);

						HSSAExpression expression;
						expression.type = HSSA_EXPR_LOAD;
						expression.subExpressions.add (HArgument::createReg (reg));
						expression.subExpressions.add (sizeadjust);
						expression.size = stack->wordbitsize * sizeadjust.uval;

						HSSAExpression adjustExpr;
						adjustExpr.type = HSSA_EXPR_OP;
						adjustExpr.opType = stack->policy == H_STACKPOLICY_TOP ? HSSA_OP_SUB : HSSA_OP_ADD;
						adjustExpr.subExpressions.add (HArgument::createReg (reg));
						adjustExpr.subExpressions.add (sizeadjust);
						adjustExpr.regId = reg->id;

						HArgument retArg = HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
						addExpression (&adjustExpr);
						return retArg;
					}
					}
					return HArgument::create ();
				}
				case HIR_EXPR_VALUE: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_IDENT;
					assert (subexpressioncount == 1);
					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				case HIR_EXPR_REC: {
					HList<HArgument> args;
					for (int i = 0; i < subexpressioncount; i++) {
						args.push_back (parseExpression (expr->subExpressions[i]));
					}
					HList<HSSAGenDef> cachedTempds = this->tmpdefs;
					HList<HArgument> cachedArgs = this->arguments;
					
					tmpdefs.clear();
					this->arguments = args;

					HInstrDefinition* instrdef = arch->getInstrDef (expr->mod.instrId);
					printf("Recursive %s\n",instrdef->mnemonics.cstr());

					int i;
					for (i = 0; i < instrdef->irs.size(); i++) {
						if (arguments.size() == instrdef->irs[i].argcount) {
							HArgument constArg = parseConstExpression (instrdef->irs[i].condExpr, &arguments);
							if (constArg && constArg.type == H_ARGTYPE_UINT && constArg.uval) {
								printf("Recursive Start %s\n",instrdef->mnemonics.cstr());
								parseExpression (instrdef->irs[i].rootExpr);
								break;
							}
						}
					}
					printf("Recursive End %s\n",instrdef->mnemonics.cstr());
					if (i <  instrdef->irs.size()) {
						printf ("Found No Match %s\n", instrdef->mnemonics.cstr());
						printf ("Could not find IR-Match for Instruction\n");
						instruction->print (arch);
					}
					this->arguments = cachedArgs;
					this->tmpdefs = cachedTempds;
				}
				printf ("HIR_EXPR_REC\n");
				return HArgument::create ();
				case HIR_EXPR_REP: {
					HId startBlock = activeBlockId;
					HId condId = createNewBlock();
					HId bodyId = createNewBlock();
					HId endId = createNewBlock();
					getActiveBlock()->fallthroughId = condId;


					activateBlock (condId);
					HSSAExpression expression;
					expression.type = HSSA_EXPR_CJMP;
					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
					expression.subExpressions.add (HArgument::createIndex (HSSA_ARGTYPE_BLOCK, bodyId));
					addExpression (&expression);
					getActiveBlock()->fallthroughId = endId;
					condId = activeBlockId;

					activateBlock (bodyId);
					parseExpression (expr->subExpressions[1]);
					getActiveBlock()->fallthroughId = endId;
					bodyId = activeBlockId;

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
					expression.subExpressions.add (HArgument::createId (HSSA_ARGTYPE_ID, lastOp));
					return HArgument::createId (HSSA_ARGTYPE_ID, addExpression (&expression));
				}
				}
			}
			return HArgument::create();
		}
		}
		return exprId;
	}

	void HSSAGen::print (int indent) {
		printIndent (indent);
		printf ("------------------\n");
		printIndent (indent);
		printf ("Printing SSA-Gen Data\n");
		for (HSSAGenBB& bb : genBBs) {
			printIndent (indent + 1);
			printf ("Block bb Id: %d 0x%x - 0x%x\n", bb.id, bb.startaddr, bb.endaddr);
			printIndent (indent + 1);
			printf ("Fallthrough: %d\n", bb.fallthroughId);
			for (HId id : bb.exprIds) {
				expressions.get (id)->print (arch, indent + 2);
			}
		}

	}
}
