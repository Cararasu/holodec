
#include "SSA.h"
#include "Architecture.h"

namespace holodec {

	void SSAExpression::print (Architecture* arch, int indent) {
		printIndent (indent);
		printf ("0x%x:", instrAddr);

		switch (this->returntype) {
		case SSA_TYPE_UNKNOWN:
			printf ("Unknown Type");
			break;
		case SSA_TYPE_INT:
			printf ("int");
			break;
		case SSA_TYPE_UINT:
			printf ("uint");
			break;
		case SSA_TYPE_FLOAT:
			printf ("float");
			break;
		case SSA_TYPE_PC:
			printf ("pc");
			break;
		case SSA_TYPE_MEMACCESS:
			printf ("memaccess");
			break;
		}
		printf ("%d ", this->size);

		switch (type) {
		case SSA_EXPR_INVALID:
			printf ("---------------------------------------");
			printf ("Invalid%d ", type);
			break;
		case SSA_EXPR_LABEL:
			printf ("Label ");
			break;
		case SSA_EXPR_INPUT:
			printf ("Input ");
			break;
		case SSA_EXPR_UNDEF:
			printf ("Undef ");
			break;
		case SSA_EXPR_NOP:
			printf ("Nop ");
			break;
		case SSA_EXPR_PHI:
			printf ("Phi ");
			break;
		case SSA_EXPR_ASSIGN:
			printf ("Assign ");
			break;
		case SSA_EXPR_JMP:
			printf ("Jmp ");
			break;
		case SSA_EXPR_CJMP:
			printf ("Cjmp ");
			break;
		case SSA_EXPR_MULTIBR:
			printf ("Multi-Branch ");
			break;
		case SSA_EXPR_OP:
			printf ("Op ");
			switch (opType) {
			case H_OP_INVALID:
				printf ("Invalid ");
				break;
			case H_OP_ADD:
				printf ("+ ");
				break;
			case H_OP_SUB:
				printf ("- ");
				break;
			case H_OP_MUL:
				printf ("* ");
				break;
			case H_OP_DIV:
				printf ("/ ");
				break;
			case H_OP_MOD:
				printf ("% ");
				break;
			case H_OP_AND:
				printf ("&& ");
				break;
			case H_OP_OR:
				printf ("|| ");
				break;
			case H_OP_XOR:
				printf ("xor ");
				break;
			case H_OP_NOT:
				printf ("! ");
				break;
			case H_OP_EQ:
				printf ("== ");
				break;
			case H_OP_NE:
				printf ("!= ");
				break;
			case H_OP_L:
				printf ("< ");
				break;
			case H_OP_LE:
				printf ("<= ");
				break;
			case H_OP_G:
				printf ("> ");
				break;
			case H_OP_GE:
				printf (">= ");
				break;
			case H_OP_BAND:
				printf ("& ");
				break;
			case H_OP_BOR:
				printf ("| ");
				break;
			case H_OP_BXOR:
				printf ("^ ");
				break;
			case H_OP_BNOT:
				printf ("~ ");
				break;
			case H_OP_SHR:
				printf (">> ");
				break;
			case H_OP_SHL:
				printf ("<< ");
				break;
			case H_OP_SAR:
				printf ("pow ");
				break;
			case H_OP_SAL:
				printf ("sqrt2 ");
				break;
			case H_OP_ROR:
				printf (">>> ");
				break;
			case H_OP_ROL:
				printf ("<<< ");
				break;
			}
			break;
		case SSA_EXPR_LOADADDR:
			printf ("Load Effective Addr ");
			break;
		case SSA_EXPR_CALL:
			printf ("Call ");
			break;
		case SSA_EXPR_OUTPUT:
			printf ("Output ");
			break;
		case SSA_EXPR_RETURN:
			printf ("Return ");
			break;
		case SSA_EXPR_SYSCALL:
			printf ("Syscall ");
			break;
		case SSA_EXPR_TRAP:
			printf ("Trap ");
			break;
		case SSA_EXPR_BUILTIN:
			printf ("Builtin ");
			break;
		case SSA_EXPR_UPDATEPART:
			printf ("Update Part ");
			break;
		case SSA_EXPR_EXTEND:
			printf ("Extend ");
			break;
		case SSA_EXPR_SPLIT:
			printf ("Split ");
			break;
		case SSA_EXPR_APPEND:
			printf ("Append ");
			break;
		case SSA_EXPR_CAST:
			printf ("Cast ");
			break;
		case SSA_EXPR_MEMACCESS:
			printf ("MemAccess ");
			break;
		case SSA_EXPR_STORE:
			printf ("Store ");
			break;
		case SSA_EXPR_LOAD:
			printf ("Load ");
			break;
		case SSA_EXPR_FLAG:
			printf ("Flag ");
			break;
		}
		switch (location) {
		case SSA_LOCATION_REG:
			printf ("Reg: %s, ", arch->getRegister (locref.refId)->name.cstr());
			break;
		case SSA_LOCATION_STACK:
			printf ("Stack: %s[%d], ", arch->getStack (locref.refId)->name.cstr(), locref.index);
			break;
		case SSA_LOCATION_MEM:
			printf ("Mem: %d, ", locref.refId);
			break;
		case SSA_LOCATION_NONE:
			break;
		}
		printf ("Ref: %d | %d = ", refcount, id);
		for (SSAArgument& arg : subExpressions) {
			arg.print (arch);
			printf (", ");
		}
		printf ("\n");
	}

	void SSARepresentation::replaceNodes (HMap<HId, SSAArgument>* replacements) {

		bool replaced = false;
		do {
			replaced = false;
			for (auto it = replacements->begin(); it != replacements->end(); ++it) {
				if ( (*it).first == (*it).second.ssaId) //to prevent unlimited loops in circualr dependencies
					continue;
				auto innerIt = it;
				for (++innerIt; innerIt != replacements->end(); ++innerIt) {
					if ( (*it).first == (*innerIt).second.ssaId) {
						(*innerIt).second = (*it).second;
						replaced = true;
					} else if ( (*innerIt).first == (*it).second.ssaId) {
						(*it).second = (*innerIt).second;
						replaced = true;
					}
				}
			}
		} while (replaced);

		for (SSABB& bb : bbs) {
			for (auto it = bb.exprIds.begin(); it != bb.exprIds.end();) {
				if (replacements->find (*it) != replacements->end()) {
					it = removeExpr (bb.exprIds, it);
					continue;
				}
				it++;
			}
		}
		for (SSAExpression& expr : expressions) {
			for (SSAArgument& arg : expr.subExpressions) {
				auto it = replacements->find (arg.ssaId);
				if (it != replacements->end()) {
					if(EXPR_IS_TRANSIENT(expr.type))
						arg = (*it).second;
					else{
						changeRefCount (it->first, -1);
						arg = (*it).second;
						changeRefCount (it->second.ssaId, 1);
					}
				}
			}
		}
	}
	void SSARepresentation::removeNodes (HSet<HId>* ids) {
		for (SSABB& bb : bbs) {
			for (auto it = bb.exprIds.begin(); it != bb.exprIds.end();) {
				if (ids->find (*it) != ids->end()) {
					it = removeExpr (bb.exprIds, it);
					continue;
				}
				++it;
			}
		}
	}

	void SSARepresentation::compress() {

		std::map<HId, HId> replacements;

		expressions.shrink ([&replacements] (HId oldId, HId newId) {
			replacements[oldId] = newId;
		});

		if (!replacements.empty()) {
			for (SSAExpression& expr : expressions) {
				for (SSAArgument& arg : expr.subExpressions) {
					auto it = replacements.find (arg.ssaId);
					if (it != replacements.end()) {
						arg.ssaId = it->second;
					}
				}
			}
			for (SSABB& bb : bbs) {
				for (HId& id : bb.exprIds) {
					auto it = replacements.find (id);
					if (it != replacements.end()) {
						id = it->second;
					}
				}
			}
		}
	}

	void SSARepresentation::propagateRefCount (HId id, int64_t count) {
		if (!id) return;
		
		for (SSAArgument& arg : expressions[id].subExpressions) {
			changeRefCount (arg.ssaId, count);
		}
	}
	void SSARepresentation::changeRefCount (HId id, int64_t count) {
		if (!id) return;
		if (EXPR_IS_TRANSIENT(expressions[id].type)) {
			std::vector<bool> visited;
			visited.resize (expressions.size(), false);
			changeRefCount (id, visited, count);
		} else {
			expressions[id].refcount += count;
		}
	}
	void SSARepresentation::changeRefCount (HId id, std::vector<bool>& visited, int64_t count) {
		if (!id || visited[id - 1])
			return;
		visited[id - 1] = true;
		expressions[id].refcount += count;
		if (EXPR_IS_TRANSIENT(expressions[id].type)) {
			for (SSAArgument& arg : expressions[id].subExpressions) {
				if (arg.ssaId)
					changeRefCount (arg.ssaId, visited, count);
			}
		}
	}
	HId SSARepresentation::addExpr (SSAExpression* expr) {
		expressions.push_back (*expr);
		HId newId = expressions.back().id;
		if(!EXPR_IS_TRANSIENT(expr->type))
			propagateRefCount (newId, 1);
		return newId;
	}

	HId SSARepresentation::addAtEnd (SSAExpression* expr, HId blockId) {
		return addAtEnd (expr, &bbs[blockId]);
	}
	HId SSARepresentation::addAtEnd (SSAExpression* expr, SSABB* bb) {
		HId newId = addExpr (expr);
		bb->exprIds.push_back (newId);
		return newId;
	}
	HId SSARepresentation::addAtStart (SSAExpression* expr, HId blockId) {
		return addAtStart (expr, &bbs[blockId]);
	}
	HId SSARepresentation::addAtStart (SSAExpression* expr, SSABB* bb) {
		HId newId = addExpr (expr);
		bb->exprIds.insert (bb->exprIds.begin(), newId);
		return newId;
	}

	HId SSARepresentation::addBefore (SSAExpression* expr, HId ssaId, HId blockId) {
		if (blockId)
			return addBefore (expr, ssaId, &bbs[blockId]);
		else
			return addBefore (expr, ssaId);
	}
	HId SSARepresentation::addBefore (SSAExpression* expr, HId ssaId, SSABB* bb) {
		if (! (ssaId && ssaId <= expressions.size() && expressions[ssaId].id))
			return 0;

		if (bb) {
			for (auto it = bb->exprIds.begin(); it != bb->exprIds.end(); ++it) {
				if (*it == ssaId) {
					return *addBefore (expr, bb->exprIds, it);
				}
			}
		}
		for (SSABB& basicblock : bbs) {
			for (auto it = basicblock.exprIds.begin(); it != basicblock.exprIds.end(); ++it) {
				if (*it == ssaId) {
					return *addBefore (expr, bb->exprIds, it);
				}
			}
		}
		return 0;
	}
	HList<HId>::iterator SSARepresentation::addBefore (SSAExpression* expr, HList<HId>& ids, HList<HId>::iterator it) {
		return ids.insert (it, addExpr (expr));
	}
	HId SSARepresentation::addAfter (SSAExpression* expr, HId ssaId, HId blockId) {
		if (blockId)
			return addAfter (expr, ssaId, &bbs[blockId]);
		else
			return addAfter (expr, ssaId);
	}
	HId SSARepresentation::addAfter (SSAExpression* expr, HId ssaId, SSABB* bb) {
		if (! (ssaId && ssaId <= expressions.size() && expressions[ssaId].id))
			return 0;
		if (bb) {
			for (auto it = bb->exprIds.begin(); it != bb->exprIds.end(); ++it) {
				if (*it == ssaId) {
					return *addAfter (expr, bb->exprIds, it);
				}
			}
		}
		for (SSABB& basicblock : bbs) {
			for (auto it = basicblock.exprIds.begin(); it != basicblock.exprIds.end(); ++it) {
				if (*it == ssaId) {
					return *addAfter (expr, bb->exprIds, it);
				}
			}
		}
		return 0;
	}
	HList<HId>::iterator SSARepresentation::addAfter (SSAExpression* expr, HList<HId>& ids, HList<HId>::iterator it) {
		return ids.insert (++it, addExpr (expr));
	}

	HList<HId>::iterator SSARepresentation::removeExpr (HList<HId>& ids, HList<HId>::iterator it) {
		auto expr_it = expressions.it_at (*it);
		if(EXPR_IS_TRANSIENT(expr_it->type)){
			propagateRefCount(expr_it->id, -1*expr_it->refcount);
		}else{
			propagateRefCount(expr_it->id, -1);
		}
		expressions.erase (expr_it);
		return ids.erase (it);
	}
	void SSARepresentation::removeExpr (HId ssaId, HId blockId) {
		if (blockId)
			removeExpr (ssaId, &bbs[blockId]);
		else
			removeExpr (ssaId);
	}
	void SSARepresentation::removeExpr (HId ssaId, SSABB* bb) {
		if (! (ssaId && ssaId <= expressions.size() && expressions[ssaId].id))
			return;
		if (bb) {
			for (auto it = bb->exprIds.begin(); it != bb->exprIds.end(); ++it) {
				if (*it == ssaId) {
					bb->exprIds.erase (it);
					return;
				}
			}
		}
		for (SSABB& basicblock : bbs) {
			for (auto it = basicblock.exprIds.begin(); it != basicblock.exprIds.end(); ++it) {
				if (*it == ssaId) {
					bb->exprIds.erase (it);
					return;
				}
			}
		}
	}


	void SSARepresentation::print (Architecture* arch, int indent) {
		printIndent (indent);
		printf ("------------------\n");
		printIndent (indent);
		printf ("Printing SSA-Gen Data\n");
		printIndent (indent);
		printf ("Number Of Expressions: %d\n", expressions.size());

		for (SSABB& bb : bbs) {
			printIndent (indent + 1);
			printf ("Block bb Id: %d 0x%x - 0x%x\n", bb.id, bb.startaddr, bb.endaddr);

			printIndent (indent + 1);
			printf ("InBlocks ");
			for (HId id : bb.inBlocks) printf ("%d, ", id);
			printf ("\n");

			printIndent (indent + 1);
			printf ("OutBlocks ");
			for (HId id : bb.outBlocks) printf ("%d, ", id);
			printf ("\n");

			printIndent (indent + 1);
			printf ("Fallthrough: %d\n", bb.fallthroughId);
			for (HId id : bb.exprIds) {
				expressions[id].print (arch, indent + 2);
			}
		}


	}
}
