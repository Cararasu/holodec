#include "HSSAGen.h"
#include "HArchitecture.h"
#include <assert.h>

namespace holodec {


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
		return HSSAArg::createSSA (theRegDefs->defs.back().ssaId);
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
					return HSSAArg::createSSA (def.ssaId);
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
						args.push_back (HSSAArg::createSSA (ssa));
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
				args.push_back (HSSAArg::createSSA (ssaId));
			}
			if (offsetit < reg->offset + reg->size) {
				if (!inputssa)
					inputssa = getInputSSA (reg);
				HSSAId ssa = {idGen.next(), id};
				printf ("%d:%d = Split(%d:%d,%d,%d,)\n", ssa.id, ssa.label, inputssa.id, inputssa.label, offsetit, reg->offset + reg->size - offsetit);
				args.push_back (HSSAArg::createSSA (ssa));
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
			return HSSAArg::createSSA (ssa);
		}
		return HSSAArg::create();
	}
	HSSAArg HSSAGenBB::createSSATmpDef (HId index, uint64_t size) {
		for (HSSAGenDef& def : tmpdefs) {
			if (def.id == index) {
				def = {index, 0, size, {idGen.next(), id}};
				return HSSAArg::createSSA (def.ssaId);
			}
		}
		tmpdefs.push_back ({index, 0, size, {idGen.next(), id}});
		return HSSAArg::createSSA (tmpdefs.back().ssaId);
	}
	HSSAArg HSSAGenBB::getSSATmpDef (HId index) {
		for (HSSAGenDef& def : tmpdefs) {
			if (def.id == index) {
				return HSSAArg::createSSA (def.ssaId);
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
	}


	HSSAGen::HSSAGen (HArchitecture* arch) : arch (arch) {}

	HSSAGen::~HSSAGen() {}

	HIRRepresentation* HSSAGen::matchIr (HInstruction* instr) {

		HInstrDefinition* instrdef = instr->instrdef;
		int i;
		for (i = 0; i < instrdef->irs.size(); i++) {
			if (instr->operands.size() == instrdef->irs[i].argcount) {
				HIRArg constArg = parseConstExpression (instrdef->irs[i].condExpr, instr);
				if (constArg && constArg.type == HIR_ARGTYPE_UINT && constArg.uval) {
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

	HIRArg HSSAGen::parseConstExpression (HIRArg argExpr, HInstruction* instr) {
		switch (argExpr.type) {
		case HIR_ARGTYPE_INVALID:
			return HIRArg::createVal ( (uint64_t) 1, arch->bitbase);
		case HIR_ARGTYPE_IR: {
			HIRExpression* expr = arch->getIrExpr (argExpr.irId);

			switch (expr->type) {
			case HIR_EXPR_OP: {
				switch (expr->mod.opType) {
				case HSSA_OP_AND: {
					uint64_t val = 0;
					for (int i = 0; i < expr->subExpressions.size(); i++) {
						HIRArg arg = parseConstExpression (expr->subExpressions[i], instr);
						if (arg.type == HIR_ARGTYPE_UINT)
							val = val && arg.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}
				case HSSA_OP_OR: {
					uint64_t val = 0;
					for (int i = 0; i < expr->subExpressions.size(); i++) {
						HIRArg arg = parseConstExpression (expr->subExpressions[i], instr);
						if (arg.type == HIR_ARGTYPE_UINT)
							val = val || arg.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}
				case HSSA_OP_XOR: {
					uint64_t val = 0;
					for (int i = 0; i < expr->subExpressions.size(); i++) {
						HIRArg arg = parseConstExpression (expr->subExpressions[i], instr);
						if (arg.type == HIR_ARGTYPE_UINT)
							val = !!val ^ !!arg.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}
				case HSSA_OP_NOT: {
					uint64_t val = 0;
					if (expr->subExpressions.size()) {
						HIRArg arg = parseConstExpression (expr->subExpressions[0], instr);
						if (arg.type == HIR_ARGTYPE_UINT)
							val = !arg.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}

				case HSSA_OP_E: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArg arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HIRArg arg2 = parseConstExpression (expr->subExpressions[1], instr);
						if (arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval == arg2.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}
				case HSSA_OP_NE: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArg arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HIRArg arg2 = parseConstExpression (expr->subExpressions[1], instr);
						if (arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval != arg2.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}
				case HSSA_OP_L: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArg arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HIRArg arg2 = parseConstExpression (expr->subExpressions[1], instr);
						if (arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval < arg2.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}
				case HSSA_OP_LE: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArg arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HIRArg arg2 = parseConstExpression (expr->subExpressions[1], instr);
						if (arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval <= arg2.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}
				case HSSA_OP_G: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArg arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HIRArg arg2 = parseConstExpression (expr->subExpressions[1], instr);
						if (arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval > arg2.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}
				case HSSA_OP_GE: {
					uint64_t val = 0;
					if (expr->subExpressions.size() == 2) {
						HIRArg arg1 = parseConstExpression (expr->subExpressions[0], instr);
						HIRArg arg2 = parseConstExpression (expr->subExpressions[1], instr);
						if (arg1.type == HIR_ARGTYPE_UINT && arg2.type == HIR_ARGTYPE_UINT)
							val = arg1.uval >= arg2.uval;
						else
							return HIRArg::create();
					}
					return HIRArg::createVal (val, arch->bitbase);
				}
				default:
					return HIRArg::create();
				}
			}
			case HIR_EXPR_SIZE:
				assert (expr->subExpressions.size() == 1);
				return HIRArg::createVal ( (uint64_t) parseConstExpression (expr->subExpressions[0], instr).size / arch->wordbase, arch->wordbase);
			case HIR_EXPR_BSIZE:
				assert (expr->subExpressions.size() == 1);
				return HIRArg::createVal ( (uint64_t) parseConstExpression (expr->subExpressions[0], instr).size, arch->wordbase);
			}
		}

		break;
		case HIR_ARGTYPE_INT:
		case HIR_ARGTYPE_UINT:
		case HIR_ARGTYPE_FLOAT:
		case HIR_ARGTYPE_ARG:
			return argExpr;
		case HIR_ARGTYPE_REG:
		case HIR_ARGTYPE_STACK:
		case HIR_ARGTYPE_TMP:
			break;
		}
		return HIRArg::create();
	}

	void HSSAGen::insertLabel (uint64_t address) {
		HSSAExpression expression;
		expression.type = HSSA_EXPR_LABEL;
		expression.subExpressions.add (HSSAArg::createVal (address, arch->bitbase));
		addExpression (&expression);
	}
	void addExpression (HSSAExpression* expression) {

	}
	HSSAArg HSSAGen::parseExpression (HIRArg exprId) {
		if (exprId.type == HIR_ARGTYPE_IR) {
			HIRExpression* expr = arch->getIrExpr (exprId.irId);

			size_t subexpressioncount = expr->subExpressions.size();

			if (expr->type != HIR_EXPR_UNDEF) {
				
				switch (expr->type) {
				case HIR_EXPR_UNDEF:
				case HIR_EXPR_ASSIGN:
				default:
					assert (false);
					break;

				case HIR_EXPR_NOP:
					return HSSAArg::create();

				case HIR_EXPR_IF:
				//create condition
				//create 2 new blocks
				//create conditional jump to 1st new block in old block
				//create fallthrough to 2nd new block from old block
				//add code to 1st new block
				//create fallthrough from 1st block to 2nd block
				//activate 2nd new block
				case HIR_EXPR_JMP://jump depending on value
				//create the jump
				//add new address to analyze if it is static
				//end the block
				case HIR_EXPR_CJMP:
				//create condition
				//Create 1 new blocks
				//create fallthrough from old block to new block
				//create jump
				//add new address to analyze if it is static
				//activate 1st new block
				case HIR_EXPR_OP: {
					HSSAExpression expression;
					expression.type = HSSA_EXPR_OP;
					expression.opType =expr->mod.opType;
					for (int i = 0; i < subexpressioncount; i++) {
						expression.subExpressions.add (parseExpression (expr->subExpressions[i]));
					}
					addExpression (&expression);
				}
				// Call - Return
				case HIR_EXPR_CALL:  // a call to a function
				case HIR_EXPR_RETURN:  // a return
				case HIR_EXPR_SYSCALL:  // a syscall
				case HIR_EXPR_TRAP:  // a trap

				case HIR_EXPR_BUILTIN:  // call a builtin(invalidates all previous variables and creates a new def)
				case HIR_EXPR_EXTEND:  // zero extend a value
				case HIR_EXPR_SPLIT:  // access to part of a variable
				case HIR_EXPR_APPEND:  // combine variables
				case HIR_EXPR_CAST:  // cast to other type

				case HIR_EXPR_MEM:  // addr = base: index: scale: disp: ?segment?
				// Memory
				case HIR_EXPR_STORE: //mem = mem: addr: value
				case HIR_EXPR_LOAD: //value = mem: addr

				//IR only
				case HIR_EXPR_PUSH:
				case HIR_EXPR_POP:

				case HIR_EXPR_VALUE:
				case HIR_EXPR_REC:
				case HIR_EXPR_REP:
				case HIR_EXPR_SIZE:
				case HIR_EXPR_BSIZE:
				case HIR_EXPR_SEQUENCE://only for ir gets resolved in ir generation

				case HIR_EXPR_FLAG:
					return HSSAArg::create();
				}
			} else if (expr->type == HIR_EXPR_UNDEF) { //undef
				for (int i = 0; i < subexpressioncount; i++) {
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
				}
			} else if (expr->type == HIR_EXPR_ASSIGN) {

			}
		}
	}

	/*
	 * Generate Basic Blocks with inputs and outputs
	 *
	 *
	 *
	 *
	 */
}
