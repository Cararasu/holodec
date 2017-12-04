
#include "SSA.h"
#include "Architecture.h"

namespace holodec {

	void SSAExpression::print (Architecture* arch, int indent) {
		printIndent (indent);
		printf ("0x%x:", instrAddr);

		switch (this->returntype) {
		case SSAType::eUnknown:
			printf ("Unknown Type");
			break;
		case SSAType::eInt:
			printf ("int");
			break;
		case SSAType::eUInt:
			printf ("uint");
			break;
		case SSAType::eFloat:
			printf ("float");
			break;
		case SSAType::ePc:
			printf ("pc");
			break;
		case SSAType::eMemaccess:
			printf ("memaccess");
			break;
		}
		printf ("%d ", this->size);

		switch (type) {
		case SSAExprType::eInvalid:
			printf ("---------------------------------------");
			printf ("Invalid%d ", type);
			break;
		case SSAExprType::eLabel:
			printf ("Label ");
			break;
		case SSAExprType::eInput:
			printf ("Input ");
			break;
		case SSAExprType::eUndef:
			printf ("Undef ");
			break;
		case SSAExprType::eNop:
			printf ("Nop ");
			break;
		case SSAExprType::ePhi:
			printf ("Phi ");
			break;
		case SSAExprType::eAssign:
			printf ("Assign ");
			break;
		case SSAExprType::eJmp:
			printf ("Jmp ");
			break;
		case SSAExprType::eCJmp:
			printf ("Cjmp ");
			break;
		case SSAExprType::eMultiBranch:
			printf ("Multi-Branch ");
			break;
		case SSAExprType::eOp:
			printf ("Op ");
			switch (opType) {
			case SSAOpType::eInvalid:
				printf ("Invalid ");
				break;
			case SSAOpType::eAdd:
				printf ("+ ");
				break;
			case SSAOpType::eSub:
				printf ("- ");
				break;
			case SSAOpType::eMul:
				printf ("* ");
				break;
			case SSAOpType::eDiv:
				printf ("/ ");
				break;
			case SSAOpType::eMod:
				printf ("% ");
				break;
			case SSAOpType::eAnd:
				printf ("&& ");
				break;
			case SSAOpType::eOr:
				printf ("|| ");
				break;
			case SSAOpType::eXor:
				printf ("xor ");
				break;
			case SSAOpType::eNot:
				printf ("! ");
				break;
			case SSAOpType::eEq:
				printf ("== ");
				break;
			case SSAOpType::eNe:
				printf ("!= ");
				break;
			case SSAOpType::eLower:
				printf ("< ");
				break;
			case SSAOpType::eLe:
				printf ("<= ");
				break;
			case SSAOpType::eGreater:
				printf ("> ");
				break;
			case SSAOpType::eGe:
				printf (">= ");
				break;
			case SSAOpType::eBAnd:
				printf ("& ");
				break;
			case SSAOpType::eBOr:
				printf ("| ");
				break;
			case SSAOpType::eBXor:
				printf ("^ ");
				break;
			case SSAOpType::eBNot:
				printf ("~ ");
				break;
			case SSAOpType::eShr:
				printf (">> ");
				break;
			case SSAOpType::eShl:
				printf ("<< ");
				break;
			case SSAOpType::eSar:
				printf ("pow ");
				break;
			case SSAOpType::eSal:
				printf ("sqrt2 ");
				break;
			case SSAOpType::eRor:
				printf (">>> ");
				break;
			case SSAOpType::eRol:
				printf ("<<< ");
				break;
			}
			break;
		case SSAExprType::eLoadAddr:
			printf ("Load Effective Addr ");
			break;
		case SSAExprType::eCall:
			printf ("Call ");
			break;
		case SSAExprType::eOutput:
			printf ("Output ");
			break;
		case SSAExprType::eReturn:
			printf ("Return ");
			break;
		case SSAExprType::eSyscall:
			printf ("Syscall ");
			break;
		case SSAExprType::eTrap:
			printf ("Trap ");
			break;
		case SSAExprType::eBuiltin:
			printf ("Builtin ");
			break;
		case SSAExprType::eUpdatePart:
			printf ("Update Part ");
			break;
		case SSAExprType::eExtend:
			printf ("Extend ");
			break;
		case SSAExprType::eSplit:
			printf ("Split ");
			break;
		case SSAExprType::eAppend:
			printf ("Append ");
			break;
		case SSAExprType::eCast:
			printf ("Cast ");
			break;
		case SSAExprType::eMemAccess:
			printf ("MemAccess ");
			break;
		case SSAExprType::eStore:
			printf ("Store ");
			break;
		case SSAExprType::eLoad:
			printf ("Load ");
			break;
		case SSAExprType::eFlag:
			printf ("Flag ");
			break;
		}
		switch (location) {
		case SSAExprLocation::eReg:
			printf ("Reg: %s, ", arch->getRegister (locref.refId)->name.cstr());
			break;
		case SSAExprLocation::eStack:
			printf ("Stack: %s[%d], ", arch->getStack (locref.refId)->name.cstr(), locref.index);
			break;
		case SSAExprLocation::eMem:
			printf ("Mem: %d, ", locref.refId);
			break;
		case SSAExprLocation::eNone:
			break;
		}
		printf ("Ref: %d | %d = ", refcount, id);
		for (SSAArgument& arg : subExpressions) {
			arg.print (arch);
			printf (", ");
		}
		printf ("\n");
	}

	void SSAArgument::print (Architecture* arch) {
		switch (type) {
		case SSAArgType::eUndef:
			printf ("Undef");
			break;
		case SSAArgType::eSInt:
			if (sval < 0)
				printf ("-0x%x", -sval);
			else
				printf ("0x%x", sval);
			break;
		case SSAArgType::eUInt:
			printf ("0x%X", uval);
			break;
		case SSAArgType::eFloat:
			printf ("%f", fval);
			break;
		case SSAArgType::eId:
			printf ("SSA: %d", ssaId);
			break;
		default:
			printf ("Unknown Argtype %x ", type);
		}
		switch (location) {
		case SSAExprLocation::eReg:
			if (locref.refId)
				printf (" Reg: %s", arch->getRegister (locref.refId)->name.cstr());
			else
				printf ("No Reg Def");
			break;
		case SSAExprLocation::eStack:
			printf ("Stack-%s[%d]", arch->getStack (locref.refId)->name.cstr(), locref.index);
			break;
		case SSAExprLocation::eMem:
			printf ("Memory %d", locref.refId);
			break;
		case SSAExprLocation::eBlock:
			printf ("Block %d", locref.refId);
			break;
		}
		if (size) printf (" S%d", size);
	}


	void SSARepresentation::replaceNodes (HMap<HId, SSAArgument>* replacements) {

		bool replaced = false;
		do {
			replaced = false;
			for (auto it = replacements->begin(); it != replacements->end(); ++it) {
				if (it->second.type != SSAArgType::eId || it->first == it->second.ssaId)  //
					continue;
				auto innerIt = it;
				for (++innerIt; innerIt != replacements->end(); ++innerIt) {
					if (innerIt->second.type == SSAArgType::eId)  //
						continue;
					if (it->first == innerIt->second.ssaId) {
						innerIt->second = it->second;
						replaced = true;
					} else if (innerIt->first == it->second.ssaId) {
						it->second = innerIt->second;
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
				if(arg.type == SSAArgType::eId){
					auto it = replacements->find (arg.ssaId);
					if(it != replacements->end()){
						if (EXPR_IS_TRANSIENT (expr.type))
							arg = it->second;
						else {
							changeRefCount (it->first, -1);
							arg = it->second;
							if(it->second.type == SSAArgType::eId)
								changeRefCount (it->second.ssaId, 1);
						}
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
					if(arg.type == SSAArgType::eId){
						auto it = replacements.find (arg.ssaId);
						if (it != replacements.end()) {
							arg.ssaId = it->second;
						}
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
			if(arg.type == SSAArgType::eId)
				changeRefCount (arg.ssaId, count);
		}
	}
	void SSARepresentation::changeRefCount (HId id, int64_t count) {
		if (!id) return;
		if (EXPR_IS_TRANSIENT (expressions[id].type)) {
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
		if (EXPR_IS_TRANSIENT (expressions[id].type)) {
			for (SSAArgument& arg : expressions[id].subExpressions) {
				if (arg.type == SSAArgType::eId)
					changeRefCount (arg.ssaId, visited, count);
			}
		}
	}
	HId SSARepresentation::addExpr (SSAExpression* expr) {
		expressions.push_back (*expr);
		HId newId = expressions.back().id;
		if (!EXPR_IS_TRANSIENT (expr->type))
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
					return *addBefore (expr, basicblock.exprIds, it);
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
		if (EXPR_IS_TRANSIENT (expr_it->type)) {
			propagateRefCount (expr_it->id, -1 * expr_it->refcount);
		} else {
			propagateRefCount (expr_it->id, -1);
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
