#include "HSSAGen.h"
#include "HArchitecture.h"
#include <assert.h>

namespace holodec {

	/*
		HSSAArg HSSAGenBB::createSSARegDef (HRegister* reg) {
			HSSAGenRegDefs* theRegDefs;
			for (HSSAGenRegDefs& regdefs : regdefslist) {
				if (regdefs.id == reg->parentId) {
					theRegDefs = &regdefs;
				}
			}
			if (!theRegDefs) {
				HSSAGenRegDefs newregdefs;
				newregdefs.cleared = reg->clearParentOnWrite;
				newregdefs.id = reg->parentId;
				regdefslist.push_back (newregdefs);
				theRegDefs = &regdefslist.back();
			} else {
				if (reg->clearParentOnWrite) {
					theRegDefs->defs.clear();
				} else {
					uint64_t newlb = reg->offset, newub = reg->offset + reg->size;
					for (auto it = theRegDefs->defs.begin(); it != theRegDefs->defs.end();) {
						uint64_t itlb = (*it).offset, itub = (*it).offset + (*it).size;

						uint64_t newdefcount = 0;
						HSSAGenDef newdefs[2];
						if (itlb < newub && itub > newlb) {//if partially overlap and we need to split
							if (itlb < newlb) {
								newdefs[newdefcount] = { (*it).id, (*it).offset, itlb - newlb, {idGen.next(), id}};
								printf ("%d:%d = Split(%d:%d,%d,%d)\n", newdefs[newdefcount].ssaId.id, newdefs[newdefcount].ssaId.label, 0, itlb - newlb);
								newdefcount++;
							}
							if (newub < itub) {
								newdefs[newdefcount] = { (*it).id, newub, itub - newub, {idGen.next(), id}};
								printf ("%d:%d = Split(%d:%d,%d,%d)\n", newdefs[newdefcount].ssaId.id, newdefs[newdefcount].ssaId.label, newub - itlb, itub - newub);
								newdefcount++;
							}
							if (!newdefcount) {
								theRegDefs->defs.erase (it);
								continue;
							} else {
								(*it) = newdefs[0];
								if (newdefcount == 2)
									theRegDefs->defs.push_back (newdefs[1]);
							}
						}
						it++;
					}
				}
			}
			HSSAGenDef def = {reg->id, reg->offset, reg->size, {idGen.next(), id}};
			theRegDefs->defs.push_back (def);
			return HArgument::createId (theRegDefs->defs.back().ssaId);
		}
		HSSAId HSSAGenBB::getInputSSA (HRegister* reg) {
			for (HSSAGenRegDefs& regdefs : regInputs) {
				if (regdefs.id == reg->parentId) {
					for (HSSAGenDef& def : regdefs.defs) {
						if (def.id == reg->id)
							return def.ssaId;
					}
					HSSAGenDef def = {reg->id, reg->offset, reg->offset, {idGen.next(), id}};
					regdefs.defs.push_back (def);
					return def.ssaId;
				}
			}
			HSSAGenRegDefs newregdefs;
			newregdefs.cleared = reg->clearParentOnWrite;
			newregdefs.id = reg->parentId;
			HSSAGenDef def = {reg->id, reg->offset, reg->offset, {idGen.next(), id}};
			newregdefs.defs.push_back (def);
			regInputs.push_back (newregdefs);
			return (&regInputs.back())->defs.back().ssaId;
		}
		HSSAArg HSSAGenBB::getSSARegUse (HRegister* reg) {
			HSSAGenRegDefs* theRegDefs;
			for (HSSAGenRegDefs& regdefs : regdefslist) {
				if (regdefs.id == reg->parentId) {
					theRegDefs = &regdefs;
				}
			}
			if (!theRegDefs) {
				HSSAGenRegDefs newregdefs;
				newregdefs.cleared = reg->clearParentOnWrite;
				newregdefs.id = reg->parentId;
				regdefslist.push_back (newregdefs);
				theRegDefs = &regdefslist.back();

			} else {
				HList<HSSAGenDef> overlappingdefs;
				for (HSSAGenDef& def : theRegDefs->defs) {
					uint64_t itlb = def.offset, itub = def.offset + def.size;
					uint64_t newlb = reg->offset, newub = reg->offset + reg->size;
					if (itlb == newlb && itub == newub) {
						return HArgument::createId (def.ssaId);
					} else if (itlb < newub && itub > newlb) {//if partially overlap and we need to split
						overlappingdefs.push_back (def);
					}
				}
				std::sort (overlappingdefs.begin(), overlappingdefs.end());

				uint64_t offsetit = reg->offset;
				HList<HSSAArg> args;
				uint64_t reglb = reg->offset, regub = reg->offset + reg->size;
				HSSAId inputssa = {0, 0};
				for (HSSAGenDef& def : overlappingdefs) {
					uint64_t itlb = def.offset, itub = def.offset + def.size;
					if (def.offset > offsetit) {
						if (theRegDefs->cleared) {
							args.push_back (HSSAArg::createVal ( (uint64_t) 0, def.offset - offsetit));
						} else {
							if (!inputssa)
								inputssa = getInputSSA (reg);
							HSSAId ssa = {idGen.next(), id};
							printf ("%d:%d = Split(%d:%d,%d,%d,)\n", ssa.id, ssa.label, inputssa.id, inputssa.label, offsetit, def.offset - offsetit);
							args.push_back (HArgument::createId (ssa));
						}
					}
					HSSAId ssaId = def.ssaId;
					uint64_t newlb = itlb < reglb ? itlb : reglb;
					uint64_t newub = itub > regub ? itub : regub;
					if (newlb < reglb && newub > regub) {
						ssaId = {idGen.next(), id};
						printf ("%d:%d = Split(%d:%d,%d,%d)\n", ssaId.id, ssaId.label, def.ssaId.id, def.ssaId.label, reglb - newlb, reg->size - (reglb - newlb) - (newub - regub));
						offsetit = (reglb - newlb) + (def.size - (reglb - newlb) - (newub - regub));
					} else {
						offsetit = def.offset + def.size;
					}
					args.push_back (HArgument::createId (ssaId));
				}
				if (offsetit < reg->offset + reg->size) {
					if (!inputssa)
						inputssa = getInputSSA (reg);
					HSSAId ssa = {idGen.next(), id};
					printf ("%d:%d = Split(%d:%d,%d,%d,)\n", ssa.id, ssa.label, inputssa.id, inputssa.label, offsetit, reg->offset + reg->size - offsetit);
					args.push_back (HArgument::createId (ssa));
				}
				assert (overlappingdefs.size());
				if (args.size() == 1)
					return args[0];
				HSSAId ssa = {idGen.next(), id};
				printf ("%d:%d = Append(", ssa.id, ssa.label);
				for (HSSAArg& arg : args) {
					arg.print (arch);
					printf (",");
				}
				printf (")\n");
				return HArgument::createId (ssa);
			}
			return HSSAArg::create();
		}
		HSSAArg HSSAGenBB::createSSATmpDef (HId index, uint64_t size) {
			for (HSSAGenDef& def : tmpdefs) {
				if (def.id == index) {
					def = {index, 0, size, {idGen.next(), id}};
					return HArgument::createId (def.ssaId);
				}
			}
			tmpdefs.push_back ({index, 0, size, {idGen.next(), id}});
			return HArgument::createId (tmpdefs.back().ssaId);
		}
		HSSAArg HSSAGenBB::getSSATmpDef (HId index) {
			for (HSSAGenDef& def : tmpdefs) {
				if (def.id == index) {
					return HArgument::createId (def.ssaId);
				}
			}
			assert (false);
			return HSSAArg::create();
		}
		void HSSAGenBB::clearSSATmpDefs () {
			tmpdefs.clear();
		}
		HSSAArg HSSAGenBB::createSSAStckDef (HId id, HId index) {
			assert (false);
		}
		HSSAArg HSSAGenBB::getSSAStckDef (HId id, HId index) {
			assert (false);
		}*/


	HSSAGen::HSSAGen (HArchitecture* arch) : arch (arch) {}

	HSSAGen::~HSSAGen() {}

	HIRRepresentation* HSSAGen::matchIr (HInstruction* instr) {

		HInstrDefinition* instrdef = instr->instrdef;
		int i;
		for (i = 0; i < instrdef->irs.size(); i++) {
			if (instr->operands.size() == instrdef->irs[i].argcount) {
				HArgument constArg = parseConstExpression (instrdef->irs[i].condExpr, instr);
				if (constArg && constArg.type == H_ARGTYPE_UINT && constArg.uval) {
					if (instrdef->irs[i].condstring) {
						printf ("Successfully parsed Condition for Instruction\n");
						instrdef->irs[i].print (arch);
						instr->print (arch);
						printf ("\n");
					}
					break;
				}
			}
		}
		if (i < instrdef->irs.size()) {
			return &instrdef->irs[i];
		} else {
			printf ("i %d\n", instr->operands.size());
			for (int i = 0; i < instr->operands.size(); i++) {
				instr->operands[i].print (arch);
				printf ("\n");
			}
			instr->print (arch);
			printf ("Found No Match %s\n", instr->instrdef->mnemonics.cstr());
		}
		return nullptr;
	}

	HArgument HSSAGen::parseConstExpression (HArgument argExpr, HInstruction* instr) {
		switch (argExpr.type) {
		default:
			return HArgument::createVal ( (uint64_t) 1, arch->bitbase);
		case H_ARGTYPE_ID: {
			HIRExpression* expr = arch->getIrExpr (argExpr.id);

			switch (expr->type) {
			case HIR_EXPR_OP: {
				switch (expr->mod.opType) {
				case HSSA_OP_AND: {
					uint64_t val = 0;
					for (int i = 0; i < expr->subExpressions.size(); i++) {
						HArgument arg = parseConstExpression (expr->subExpressions[i], instr);
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
						HArgument arg = parseConstExpression (expr->subExpressions[i], instr);
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
						HArgument arg = parseConstExpression (expr->subExpressions[i], instr);
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
						HArgument arg = parseConstExpression (expr->subExpressions[0], instr);
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
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], instr);
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
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], instr);
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
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], instr);
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
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], instr);
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
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], instr);
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
						HArgument arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HArgument arg2 = parseConstExpression (expr->subExpressions[1], instr);
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
				return HArgument::createVal ( (uint64_t) parseConstExpression (expr->subExpressions[0], instr).size / arch->wordbase, arch->wordbase);
			case HIR_EXPR_BSIZE:
				assert (expr->subExpressions.size() == 1);
				return HArgument::createVal ( (uint64_t) parseConstExpression (expr->subExpressions[0], instr).size, arch->wordbase);
			}
		}

		break;
		case H_ARGTYPE_SINT:
		case H_ARGTYPE_UINT:
		case H_ARGTYPE_FLOAT:
		case HIR_ARGTYPE_ARG:
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
		expression.instrId = instructionId;
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
		expressions.add (*expression);
		activeblock->expressionIds.push_back (expressions.back().id);
		expressions.back().print (arch);
		return expressions.back().id;
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
			return HArgument::createId (addExpression (&expression));
		}
		case HIR_ARGTYPE_TMP: {
			assert (exprId.index);
			for (HSSAGenDef& def : tmpdefs) {
				if (def.id == exprId.index) {
					return def.arg;
				}
			}
			assert (false);
		}
		case H_ARGTYPE_ID: {
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

				if ( (dstArg.type == H_ARGTYPE_REG || dstArg.type == H_ARGTYPE_STACK) && expression.subExpressions[0].type == H_ARGTYPE_ID) {
					HSSAExpression* ssaExpr = expressions.get (expression.subExpressions[0].id);
					assert (ssaExpr);
					if (!ssaExpr->regId && !ssaExpr->stackId.id) {
						if (dstArg.type == H_ARGTYPE_REG) {
							ssaExpr->regId = dstArg.reg;
							return HArgument::createId (ssaExpr->id);
						} else if (dstArg.type == H_ARGTYPE_STACK) {
							ssaExpr->stackId = dstArg.stack;
							return HArgument::createId (ssaExpr->id);
						}
					}
				}
				switch (dstArg.type) {
				case HIR_ARGTYPE_TMP: {
					HArgument arg = HArgument::createId (addExpression (&expression));
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
				case H_ARGTYPE_ID:
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
				return HArgument::createId (addExpression (&expression));
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
					return HArgument::createId (addExpression (&expression));
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
					return HArgument::createId (addExpression (&expression));
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
					return HArgument::createId (cjmpExpr);
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
					return HArgument::createId (id);
				}
				// Call - Return
				case HIR_EXPR_CALL:  {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_CALL;
					assert (subexpressioncount == 1);
					expression.subExpressions.add (parseExpression (expr->subExpressions[1]));
					return HArgument::createId (addExpression (&expression));
				}
				case HIR_EXPR_RETURN: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_RETURN;
					assert (!subexpressioncount);
					endOfBlock = true;
					fallthrough = false;
					return HArgument::createId (addExpression (&expression));
				}
				case HIR_EXPR_SYSCALL: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_SYSCALL;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (addExpression (&expression));
				}
				case HIR_EXPR_TRAP: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_TRAP;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (addExpression (&expression));
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
					return HArgument::createId (addExpression (&expression));
				}
				case HIR_EXPR_SPLIT: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_SPLIT;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (addExpression (&expression));
				}
				case HIR_EXPR_APPEND: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_APPEND;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (addExpression (&expression));
				}
				case HIR_EXPR_CAST: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_CAST;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					return HArgument::createId (addExpression (&expression));
				}

				// Memory
				case HIR_EXPR_STORE: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_STORE;
					assert (subexpressioncount == 2);
					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
					expression.subExpressions.add (parseExpression (expr->subExpressions[1]));
					return HArgument::createId (addExpression (&expression));
				}
				case HIR_EXPR_LOAD: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_STORE;
					assert (subexpressioncount == 2);
					expression.subExpressions.add (parseExpression (expr->subExpressions[0]));
					expression.subExpressions.add (parseExpression (expr->subExpressions[1]));
					return HArgument::createId (addExpression (&expression));
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
						return HArgument::createId (addExpression (&expression));
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
						return HArgument::createId (addExpression (&expression));
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
						return HArgument::createId (addExpression (&expression));
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

						HArgument retArg = HArgument::createId (addExpression (&expression));
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
					return HArgument::createId (addExpression (&expression));
				}
				case HIR_EXPR_REC:
					printf ("HIR_EXPR_REC\n");
					break;
				case HIR_EXPR_REP:
					printf ("HIR_EXPR_REP\n");
					break;
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
					expression.subExpressions.add (HArgument::createId (lastOp));
					return HArgument::createId (addExpression (&expression));
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
			printf ("Block bb 0x%x\n", 0);
			for (HId id : bb.expressionIds) {
				expressions.get (id)->print (arch, indent + 2);
			}
		}

	}
}
