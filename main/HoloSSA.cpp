
#include "HoloSSA.h"
#include <assert.h>
#include <algorithm>

namespace holodec {
	namespace holossa {

		struct HSSARegDef {
			HId parentRegId;
			HId regId;//can be 0
			uint64_t offset;
			uint64_t size;
			HId ssaId;
		};

		bool operator< (HSSARegDef& lhs, HSSARegDef& rhs) {
			return lhs.offset < rhs.offset;
		}


		struct HSSAGenState {
			HArchitecture* arch;
			HId flag_gen = 0;
			HMap<HId, HId> map; //TODO remove and change into something faster
			HIdGenerator gen;
			HList<HSSARegDef> defs;

			void addLastRegDef (HSSARegDef def) {
				printf ("Add Reg Def\n");
				printf ("Id: %d P:%s - R:%s Offset: %d Size: %d\n", def.ssaId, arch->getRegister (def.parentRegId)->name.cstr(), arch->getRegister (def.regId)->name.cstr(), def.offset, def.size);
				print();
				HRegister* reg = arch->getRegister (def.regId);
				for (auto it = defs.begin(); it != defs.end();) {
					HSSARegDef& defit = *it;
					if (reg->clearParentOnWrite) {//if parent is reset on write
						if (def.parentRegId && def.parentRegId == defit.parentRegId) {//TODO don't clear everything but only things outside of register we are writing to
							defs.erase (it);
							continue;
						}
					} else {
						if (def.parentRegId && def.parentRegId == defit.parentRegId) {//if same parent reg
							if (def.offset == defit.offset && def.size == defit.size) {//if it is the same
								defit = def;
								return;
							} else if (def.offset < defit.offset && defit.offset < (def.offset + def.size)) {//if found starts earlier
								if (defit.offset + defit.size < def.offset + def.size) {//and ends after
									//TODO insert split
									defs.push_back ({def.parentRegId, def.regId, defit.offset + defit.size, (def.offset + def.size) - (defit.offset + defit.size) });
								}
								//TODO insert split
								defit.size = defit.offset - def.offset;
								defs.erase (it);
								continue;
							} else if (def.offset <= defit.offset && defit.offset < (def.offset + def.size) && (def.offset + def.size) < (defit.offset + defit.size)) {// if starts in and ends after
								//TODO insert split
								defit.regId = 0;
								defit.offset = def.offset + def.size;
								defit.size = (defit.offset + defit.size) - (def.offset + def.size);
							} else if (def.offset < defit.offset && (defit.offset + defit.size) < (def.offset + def.size)) {//if completely in the one we want to insert
								defs.erase (it);
								continue;
							}
						}
					}
					it++;
				}
				defs.push_back (def);
				print();
			}

			HSSARegDef getLastRegDef (HRegister* reg, uint64_t offset, uint64_t size) {
				HRegister* parentreg = reg->getParentRegister (reg->id);
				if (!parentreg) {
					return {0, 0, 0, 0, 0};
				}
				int localdefcount = 0;
				HSSARegDef localdefs[20];
				for (auto it = defs.begin(); it != defs.end();) {
					HSSARegDef& def = *it;
					if (def.parentRegId == parentreg->id) {
						if (def.offset == offset && def.size == size) //perfect match
							return def;
						if (def.offset >= offset) { //start after
							if (def.offset < offset + size) { //but before end
								//merge target
								localdefs[localdefcount++] = def;
								defs.erase (it);
								continue;
							}
						} else if (def.offset + def.size > offset) { //start before but intersect
							//merge target
							localdefs[localdefcount++] = def;
							defs.erase (it);
							continue;
						}
					}
					it++;
				}
				//first split if needed
				for (int i = 0; i < localdefcount; i++) {
					HSSARegDef& def = localdefs[i];
					if (def.offset < offset) {//split of lower nibble
						HId lowerId = gen.next(), higherId = gen.next();
						uint64_t lowersize = offset - def.offset;
						printf ("%d = Split(%d,%d,&d)\n", lowerId, def.ssaId, 0, lowersize);
						printf ("%d = Split(%d,%d,&d)\n", lowerId, def.ssaId, lowersize, def.size - lowersize);
						defs.push_back ({def.parentRegId, 0, def.offset, lowersize, lowerId});
						def.offset += lowersize;
						def.size -= lowersize;
						def.regId = 0;
					}
					if (def.offset + def.size > offset + size) {//split of upper nibble
						HId lowerId = gen.next(), higherId = gen.next();
						uint64_t highersize = (def.offset + def.size) - (offset + size);
						printf ("%d = Split(%d,%d,&d)\n", lowerId, def.ssaId, 0, def.size - highersize);
						printf ("%d = Split(%d,%d,&d)\n", lowerId, def.ssaId, def.size - highersize, highersize);
						defs.push_back ({def.parentRegId, 0, def.offset + def.size - highersize, highersize, higherId});
						def.size -= highersize;
						def.regId = 0;
					}
				}
				//sort defs by offset
				std::sort (localdefs, localdefs + localdefcount);
				//then merge if needed
				if (localdefcount == 1) { //this case is the most likely
					if (localdefs[0].offset == offset && localdefs[0].size == size)
						return localdefs[0];
					else
						printf ("Error\n");
				}
				uint64_t resultsize = 0;
				HId id = gen.next();
				printf ("%d = Extend(", id);
				for (int i = 0; i < localdefcount; i++) {
					printf ("%d,", localdefs[i]);
					resultsize += localdefs[i].size;
				}
				printf (")\n");
				return {parentreg->id, 0, offset, resultsize, id};
			};
			HSSARegDef getLastRegDef (HRegister* reg) {
				for (HSSARegDef& def : defs) {
					if (def.regId == reg->id)
						return def;
				}
				return getLastRegDef (reg, reg->offset, reg->size);
			};
			HSSARegDef getLastRegDef (HId reg, uint64_t offset, uint64_t size) {
				return getLastRegDef (arch->getRegister (reg), offset, size);
			};
			HSSARegDef getLastRegDef (HId reg) {
				return getLastRegDef (arch->getRegister (reg));
			};

			void print (int indent = 0) {
				printf ("Reg Defs -------------\n");
				for (HSSARegDef& def : defs) {
					printIndent (indent);
					printf ("Id: %d P:%s - R:%s Offset: %d Size: %d\n", def.ssaId, arch->getRegister (def.parentRegId)->name.cstr(), arch->getRegister (def.regId)->name.cstr(), def.offset, def.size);
				}
			}
		};
		//struct H
		//HMap<HId,>

		HId parseForSSA (HIRRepresentation* ir, HId nodeid, HSSAGenState* state/*, flag dom, stack dom, reg dom */) {
			if (!nodeid)
				return 0;
			HIRExpression* expr = ir->getExpr (nodeid);
			if (!expr)
				return 0;
			auto it = state->map.find (expr->id);
			if (it != state->map.end())
				return (*it).second;
			HId id;
			switch (expr->token) {

			case HIR_TOKEN_FLAG_C:
				id = state->gen.next();
				printf ("%d = Flag_Carry(%d)", id, parseForSSA (ir, expr->subexpressions[0], state));
				state->map.insert (std::pair<HId, HId> (expr->id, id));
				break;
			case HIR_TOKEN_FLAG_A:
				id = state->gen.next();
				printf ("%d = Flag_HalfCarry(%d)", id, parseForSSA (ir, expr->subexpressions[0], state));
				state->map.insert (std::pair<HId, HId> (expr->id, id));
				break;
			case HIR_TOKEN_FLAG_P:
				id = state->gen.next();
				printf ("%d = Flag_Parity(%d)", id, parseForSSA (ir, expr->subexpressions[0], state));
				state->map.insert (std::pair<HId, HId> (expr->id, id));
				break;
			case HIR_TOKEN_FLAG_O:
				id = state->gen.next();
				printf ("%d = Flag_Overflow(%d)", id, parseForSSA (ir, expr->subexpressions[0], state));
				state->map.insert (std::pair<HId, HId> (expr->id, id));
				break;
			case HIR_TOKEN_FLAG_Z:
				id = state->gen.next();
				printf ("%d = Flag_Zero(%d)", id, parseForSSA (ir, expr->subexpressions[0], state));
				state->map.insert (std::pair<HId, HId> (expr->id, id));
				break;
			case HIR_TOKEN_FLAG_S:
				id = state->gen.next();
				printf ("%d = Flag_Signed(%d)", id, parseForSSA (ir, expr->subexpressions[0], state));
				state->map.insert (std::pair<HId, HId> (expr->id, id));
				break;
			case HIR_TOKEN_OP_ARG:
				printf ("Arg not replaced\n");
				break;
			case HIR_TOKEN_OP_STCK:
				printf ("Stck not replaced\n");
				break;
			case HIR_TOKEN_OP_TMP:
				printf ("Tmp not replaced\n");
				break;

			case HIR_TOKEN_REGISTER: {
				HSSARegDef def = state->getLastRegDef (expr->regacces);
				id = def.ssaId;
				printf ("Reg not implemented\n");
			}
			break;
			case HIR_TOKEN_NUMBER:
				id = state->gen.next();
				printf ("%d = 0x%x\n", id, expr->value);
				state->map.insert (std::pair<HId, HId> (expr->id, id));
				break;
			case HIR_TOKEN_FLOAT:
				id = state->gen.next();
				printf ("%d = %d\n", id, expr->fvalue);
				state->map.insert (std::pair<HId, HId> (expr->id, id));
				break;
			case HIR_TOKEN_VALUE:
				expr = ir->getExpr (expr->subexpressions[0]);
				if (!expr)
					return 0;
				if (expr->token != HIR_TOKEN_MEM) {
					id = parseForSSA (ir, expr->id, state);
					break;
				}
			//fallthrough
			case HIR_TOKEN_MEM:
				id = state->gen.next();
				printf ("%d = [%s + %s*%d + %d]\n", id, state->arch->getRegister (expr->mem.base)->name.cstr(), state->arch->getRegister (expr->mem.index)->name.cstr(), expr->mem.scale, expr->mem.disp);
				state->map.insert (std::pair<HId, HId> (expr->id, id));
				break;

			case HIR_TOKEN_OP_ASSIGN:
				HIRExpression* source = ir->getExpr (expr->subexpressions[1]);
				if (!source)
					return 0;
				HIRToken sourcetoken = source->token;
				HId sourceId = parseForSSA (ir, expr->subexpressions[1], state);
				if (sourcetoken == HIR_TOKEN_MEM) {
					HId temp = state->gen.next();
					printf ("%d = load(%d)\n", temp, sourceId);
					sourceId = temp;
				}
				HIRExpression* target = ir->getExpr (expr->subexpressions[0]);
				if (!target)
					return 0;
				HIRToken targettoken = target->token;
				id = state->gen.next();
				if (targettoken == HIR_TOKEN_MEM) {
					HId targetId = parseForSSA (ir, expr->subexpressions[0], state);
					printf ("%d = store(%d,%d)\n", id, targetId, sourceId);
				} else if (targettoken == HIR_TOKEN_REGISTER) {
					HRegister* reg = state->arch->getRegister (target->regacces);
					HRegister* parent = state->arch->getParentRegister (target->regacces);
					state->addLastRegDef ({parent->id, reg->id, reg->offset + target->mod.index, target->mod.size, id});
					printf ("%d = %d\n", id, sourceId);
				} else {

				}
				break;
				/*
				//Call - Return
				HIR_TOKEN_OP_JMP,
				HIR_TOKEN_OP_CALL,
				HIR_TOKEN_OP_RET,
				HIR_TOKEN_OP_SYSCALL,
				HIR_TOKEN_OP_TRAP,
				//Misc
				HIR_TOKEN_OP_SIZE,
				HIR_TOKEN_OP_POPCNT,
				HIR_TOKEN_OP_LOOP,
				HIR_TOKEN_OP_IF,
				HIR_TOKEN_OP_REC,
				HIR_TOKEN_OP_EXTEND,
				HIR_TOKEN_OP_SEXTEND,
				//Arithmetic
				HIR_TOKEN_OP_ADD,
				HIR_TOKEN_OP_SADD,
				HIR_TOKEN_OP_FADD,
				HIR_TOKEN_OP_SUB,
				HIR_TOKEN_OP_SSUB,
				HIR_TOKEN_OP_FSUB,
				HIR_TOKEN_OP_MUL,
				HIR_TOKEN_OP_SMUL,
				HIR_TOKEN_OP_FMUL,
				HIR_TOKEN_OP_DIV,
				HIR_TOKEN_OP_SDIV,
				HIR_TOKEN_OP_FDIV,
				//Memory
				HIR_TOKEN_OP_STORE,
				HIR_TOKEN_OP_LOAD,
				//Comparison
				HIR_TOKEN_CMP_E,
				HIR_TOKEN_CMP_NE,
				HIR_TOKEN_CMP_L,
				HIR_TOKEN_CMP_LE,
				HIR_TOKEN_CMP_G,
				HIR_TOKEN_CMP_GE,
				HIR_TOKEN_CMP_NOT,
				//
				HIR_TOKEN_OP_AND,
				HIR_TOKEN_OP_OR,
				HIR_TOKEN_OP_XOR,
				//Bit Operators
				HIR_TOKEN_BINOP_AND,
				HIR_TOKEN_BINOP_OR,
				HIR_TOKEN_BINOP_XOR,
				HIR_TOKEN_BINOP_NOT,
				//Shifts - Rotates
				HIR_TOKEN_BINOP_SHR,
				HIR_TOKEN_BINOP_SHL,
				HIR_TOKEN_BINOP_SAR,
				HIR_TOKEN_BINOP_SAL,
				HIR_TOKEN_BINOP_ROR,
				HIR_TOKEN_BINOP_ROL,
				//Casts
				HIR_TOKEN_CAST_I2F,
				HIR_TOKEN_CAST_F2I,*/
			}
			printf ("Size: %d\n", expr->mod.size);
			parseForSSA (ir, expr->append, state);
			parseForSSA (ir, expr->sequence, state);
			return id;
		}


		void labelSize (HIRRepresentation* ir, HId nodeid) {
			if (!nodeid)
				return ;
			HIRExpression* expr = ir->getExpr (nodeid);
			if (!expr)
				return ;
			for (int i = 0; i < HIR_LOCAL_SUBEXPRESSION_COUNT; i++) {
				labelSize (ir, expr->subexpressions[i]);
			}
			switch (expr->token) {

			case HIR_TOKEN_FLAG_C:
			case HIR_TOKEN_FLAG_A:
			case HIR_TOKEN_FLAG_P:
			case HIR_TOKEN_FLAG_O:
			case HIR_TOKEN_FLAG_Z:
			case HIR_TOKEN_FLAG_S:
			case HIR_TOKEN_CMP_E:
			case HIR_TOKEN_CMP_NE:
			case HIR_TOKEN_CMP_L:
			case HIR_TOKEN_CMP_LE:
			case HIR_TOKEN_CMP_G:
			case HIR_TOKEN_CMP_GE:
			case HIR_TOKEN_CMP_NOT:
			case HIR_TOKEN_OP_AND:
			case HIR_TOKEN_OP_OR:
			case HIR_TOKEN_OP_XOR:
				expr->mod.size = 1;
				break;
			case HIR_TOKEN_OP_STCK:
				break;
			case HIR_TOKEN_OP_TMP:
				break;

			case HIR_TOKEN_REGISTER:
				break;
			case HIR_TOKEN_NUMBER:
			case HIR_TOKEN_FLOAT:
				break;
			case HIR_TOKEN_VALUE:
				break;
			//fallthrough
			case HIR_TOKEN_MEM:
				break;
			//Arithmetic
			case HIR_TOKEN_OP_ASSIGN:
				expr->mod.size = 0;
				break;
			case HIR_TOKEN_OP_ADD:
			case HIR_TOKEN_OP_SADD:
			case HIR_TOKEN_OP_FADD:
			case HIR_TOKEN_OP_SUB:
			case HIR_TOKEN_OP_SSUB:
			case HIR_TOKEN_OP_FSUB:
			case HIR_TOKEN_OP_MUL:
			case HIR_TOKEN_OP_SMUL:
			case HIR_TOKEN_OP_FMUL:
			case HIR_TOKEN_OP_DIV:
			case HIR_TOKEN_OP_SDIV:
			case HIR_TOKEN_OP_FDIV:
			case HIR_TOKEN_BINOP_AND:
			case HIR_TOKEN_BINOP_OR:
			case HIR_TOKEN_BINOP_XOR:
			case HIR_TOKEN_BINOP_NOT: {
				uint64_t size = 0;
				for (int i = 0; i < HIR_LOCAL_SUBEXPRESSION_COUNT; i++) {
					if (!expr->subexpressions[i]) break;
					HIRExpression* sexpr = ir->getExpr (expr->subexpressions[i]);
					if (!sexpr) continue;
					if (!sexpr->mod.size) continue;
					if (!size) size = sexpr->mod.size;
					printf ("%d\n", size);
					printf ("%d\n", sexpr->mod.size);
					assert (size == sexpr->mod.size);
				}
				expr->mod.size = size;
			}
			break;
			case HIR_TOKEN_BINOP_SHR:
			case HIR_TOKEN_BINOP_SHL:
			case HIR_TOKEN_BINOP_SAR:
			case HIR_TOKEN_BINOP_SAL:
			case HIR_TOKEN_BINOP_ROR:
			case HIR_TOKEN_BINOP_ROL: {
				if (!expr->subexpressions[0]) break;
				HIRExpression* sexpr = ir->getExpr (expr->subexpressions[0]);
				if (!sexpr) break;
				expr->mod.size = sexpr->mod.size;
			}
			break;
				/*
				//Call - Return
				HIR_TOKEN_OP_JMP,
				HIR_TOKEN_OP_CALL,
				HIR_TOKEN_OP_RET,
				HIR_TOKEN_OP_SYSCALL,
				HIR_TOKEN_OP_TRAP,
				//Misc
				HIR_TOKEN_OP_SIZE,
				HIR_TOKEN_OP_POPCNT,
				HIR_TOKEN_OP_LOOP,
				HIR_TOKEN_OP_IF,
				HIR_TOKEN_OP_REC,
				HIR_TOKEN_OP_EXTEND,
				HIR_TOKEN_OP_SEXTEND,
				//Memory
				HIR_TOKEN_OP_STORE,
				HIR_TOKEN_OP_LOAD,
				//Casts
				HIR_TOKEN_CAST_I2F,
				HIR_TOKEN_CAST_F2I,*/
			}
			labelSize (ir, expr->append);
			labelSize (ir, expr->sequence);
		}
	}
}


bool holodec::holossa::HSSAGenerator::parseFunction (HFunction* function) {
	for (HBasicBlock& bb : function->basicblocks) {
		printf ("Basic Block ------------------------------\n");

		HSSAGenState state;
		state.arch = arch;
		for (HInstruction& instr : bb.instructions) {
			HIRRepresentation ir = instr.instrdef->il_string[instr.opcount];
			if (ir) {
				instr.print (arch);
				printf ("Root: %d\n", ir.rootExpr);
				for (HIRExpression& expr : ir.expressions) {
					if (expr.token == HIR_TOKEN_OP_ARG) {
						HInstArgument& arg = instr.operands[expr.mod.var_index - 1];
						switch (arg.type.type) {
						case H_LOCAL_TYPE_REGISTER:
							expr.token = HIR_TOKEN_REGISTER;
							expr.regacces = arg.reg;
							expr.mod.var_index = 0;
							{
								HRegister* reg = arch->getRegister (arg.reg);
								expr.mod.index = reg->offset;
								assert (reg->size == arg.type.size);
							}
							break;
						case H_LOCAL_TYPE_STACK:
							expr.token = HIR_TOKEN_OP_STCK;
							expr.mod.var_index = arg.stackindex;
							break;
						case H_LOCAL_TYPE_MEM:
							//TODO
							expr.token = HIR_TOKEN_MEM;
							expr.mem.base = arg.mem.base;
							expr.mem.index = arg.mem.index;
							expr.mem.disp = arg.mem.disp;
							expr.mem.scale = arg.mem.scale;
							expr.mod.var_index = 0;
							break;
						case H_LOCAL_TYPE_IMM_SIGNED:
						case H_LOCAL_TYPE_IMM_UNSIGNED:
							expr.token = HIR_TOKEN_NUMBER;
							expr.value = arg.ival;
							expr.mod.var_index = 0;
							break;
						case H_LOCAL_TYPE_IMM_FLOAT:
							expr.token = HIR_TOKEN_FLOAT;
							expr.value = arg.fval;
							expr.mod.var_index = 0;
							break;
						}
						expr.mod.size = arg.type.size;
					} else if (expr.token == HIR_TOKEN_OP_SIZE) {
						HIRExpression* subexpr = ir.getExpr (expr.subexpressions[0]);
						if (subexpr && subexpr->mod.size) {
							expr.token = HIR_TOKEN_NUMBER;
							expr.value = subexpr->mod.size;
							expr.subexpressions[0] = 0;
						}
					}
				}
				labelSize (&ir, ir.rootExpr);
				for (HIRExpression& expr : ir.expressions) {
					expr.print (arch);
				}
				printf ("SSA------------------\n");
				HId end = parseForSSA (&ir, ir.rootExpr, &state);
				printf ("EndId: %d\n", end);
			}
			//parseInstruction (&instr);
		}
		state.print (1);
	}
}
