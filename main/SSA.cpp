
#include "SSA.h"
#include "Architecture.h"

#include <cassert>

namespace holodec {

	void SSAExpression::print (Architecture* arch, int indent) {
		printIndent (indent);
		printf ("0x%" PRIx64 ":", instrAddr);

		switch (this->exprtype) {
		case SSAType::eUnknown:
			printf (" unkn");
			break;
		case SSAType::eInt:
			printf ("  int");
			break;
		case SSAType::eUInt:
			printf (" uint");
			break;
		case SSAType::eFloat:
			printf ("float");
			break;
		case SSAType::ePc:
			printf ("   pc");
			break;
		case SSAType::eMemaccess:
			printf ("  mem");
			break;
		}
		printf ("%03d ", size);

		switch (type) {
		case SSAExprType::eInvalid:
			printf ("---------------------------------------");
			printf ("Invalid%d ", type);
			break;
		case SSAExprType::eLabel:
			printf ("Label  ");
			break;
		case SSAExprType::eInput:
			printf ("Input  ");
			break;
		case SSAExprType::eUndef:
			printf ("Undef  ");
			break;
		case SSAExprType::eNop:
			printf ("Nop    ");
			break;
		case SSAExprType::ePhi:
			printf ("Phi    ");
			break;
		case SSAExprType::eAssign:
			printf ("Assign ");
			break;
		case SSAExprType::eJmp:
			printf ("Jmp    ");
			break;
		case SSAExprType::eCJmp:
			printf ("Cjmp   ");
			break;
		case SSAExprType::eMultiBranch:
			printf ("Mlt-Br ");
			break;
		case SSAExprType::eOp:
			printf ("Op");
			switch (opType) {
			case SSAOpType::eInvalid:
				printf (" Inv ");
				break;
			case SSAOpType::eAdd:
				printf (" +   ");
				break;
			case SSAOpType::eSub:
				printf (" -   ");
				break;
			case SSAOpType::eMul:
				printf (" *   ");
				break;
			case SSAOpType::eDiv:
				printf (" /   ");
				break;
			case SSAOpType::eMod:
				printf (" %   ");
				break;
			case SSAOpType::eAnd:
				printf (" &&  ");
				break;
			case SSAOpType::eOr:
				printf (" ||  ");
				break;
			case SSAOpType::eNot:
				printf (" !   ");
				break;
			case SSAOpType::eEq:
				printf (" ==  ");
				break;
			case SSAOpType::eNe:
				printf (" !=  ");
				break;
			case SSAOpType::eLower:
				printf (" <   ");
				break;
			case SSAOpType::eLe:
				printf (" <=  ");
				break;
			case SSAOpType::eGreater:
				printf (" >   ");
				break;
			case SSAOpType::eGe:
				printf (" >=  ");
				break;
			case SSAOpType::eBAnd:
				printf (" &   ");
				break;
			case SSAOpType::eBOr:
				printf (" |   ");
				break;
			case SSAOpType::eBXor:
				printf (" ^   ");
				break;
			case SSAOpType::eBNot:
				printf (" ~   ");
				break;
			case SSAOpType::eShr:
				printf (" >>  ");
				break;
			case SSAOpType::eShl:
				printf (" <<  ");
				break;
			case SSAOpType::eSar:
				printf (" pow ");
				break;
			case SSAOpType::eSal:
				printf (" sqt2");
				break;
			case SSAOpType::eRor:
				printf (" >>> ");
				break;
			case SSAOpType::eRol:
				printf (" <<< ");
				break;
			}
			break;
		case SSAExprType::eLoadAddr:
			printf ("Lea    ");
			break;
		case SSAExprType::eCall:
			printf ("Call   ");
			break;
		case SSAExprType::eOutput:
			printf ("Output ");
			break;
		case SSAExprType::eReturn:
			printf ("Return ");
			break;
		case SSAExprType::eSyscall:
			printf ("Syscall");
			break;
		case SSAExprType::eTrap:
			printf ("Trap   ");
			break;
		case SSAExprType::eBuiltin:
			printf ("Builtin");
			break;
		case SSAExprType::eUpdatePart:
			printf ("UpdPart");
			break;
		case SSAExprType::eExtend:
			printf ("Extend ");
			break;
		case SSAExprType::eAppend:
			printf ("Append ");
			break;
		case SSAExprType::eCast:
			printf ("Cast   ");
			break;
		case SSAExprType::eMemAccess:
			printf ("MemAcc ");
			break;
		case SSAExprType::eStore:
			printf ("Store  ");
			break;
		case SSAExprType::eLoad:
			printf ("Load   ");
			break;
		case SSAExprType::ePop:
			printf ("Pop    ");
			break;
		case SSAExprType::ePush:
			printf ("Push   ");
			break;
		case SSAExprType::eFlag:
			printf ("Flag");
			switch (flagType) {
			case SSAFlagType::eUnknown:
				printf ("Unk");
				break;
			case SSAFlagType::eC:
				printf ("Cry");
				break;
			case SSAFlagType::eO:
				printf ("Ovf");
				break;
			case SSAFlagType::eU:
				printf ("Udf");
				break;
			}
			break;
		}
		switch (location) {
		case SSALocation::eReg:
			printf ("Reg: %s, ", arch->getRegister (locref.refId)->name.cstr());
			break;
		case SSALocation::eStack:
			printf ("Stack: %s[%" PRId32 "], ", arch->getStack (locref.refId)->name.cstr(), locref.index);
			break;
		case SSALocation::eMem:
			printf ("Mem: %" PRId32 ", ", locref.refId);
			break;
		case SSALocation::eBlock:
			printf ("Block %" PRId32, locref.refId);
			break;
		case SSALocation::eNone:
			break;
		}
		printf ("Ref: %02" PRId64 " UId: %04" PRIx64 " | %04" PRId32 " = ", refs.size(), uniqueId, id);
		for (SSAArgument& arg : subExpressions) {
			arg.print(arch);
			printf(", ");
		}

		printf(" | Refs: ");
		for (HId refId : refs) {
			printf("%d, ", refId);
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
				printf ("-0x%" PRIx64 "", -sval);
			else
				printf ("0x%" PRIx64 "", sval);
			break;
		case SSAArgType::eUInt:
			printf ("0x%" PRIx64, uval);
			break;
		case SSAArgType::eFloat:
			printf ("%f", fval);
			break;
		case SSAArgType::eId:
			printf("SSA: %d", ssaId);
			break;
		case SSAArgType::eOther:
			printf("Other ");
			break;
		default:
			printf ("Unknown Argtype %x ", type);
		}
		switch (location) {
		case SSALocation::eReg:
			if (locref.refId)
				printf (" Reg: %s", arch->getRegister (locref.refId)->name.cstr());
			else
				printf ("No Reg Def");
			break;
		case SSALocation::eStack:
			printf ("Stack-%s[%d]", arch->getStack (locref.refId)->name.cstr(), locref.index);
			break;
		case SSALocation::eMem:
			printf ("Memory %d", locref.refId);
			break;
		case SSALocation::eBlock:
			printf ("Block %d", locref.refId);
			break;
		case SSALocation::eNone:
			break;
		}
		if (offset || size) printf (" S[%d,%d]", offset, size);
	}


	void SSARepresentation::replaceNodes (HMap<HId, SSAArgument>* replacements) {

		bool replaced = false;
		do {
			replaced = false;
			for (auto it = replacements->begin(); it != replacements->end(); ++it) {
				if (it->second.type != SSAArgType::eId || it->first == it->second.ssaId)
					continue;
				auto innerIt = replacements->find(it->second.ssaId);
				while (innerIt != replacements->end()) {//TODO infinite loop alarm!!!!!!
					if (it->first == innerIt->second.ssaId)
						break;
					it->second.replace(innerIt->second);// = arg;
					innerIt = replacements->find(it->second.ssaId);
					replaced = true;
				}
			}
		} while (replaced);

		printf ("Remove\n");
		for (SSABB& bb : bbs) {
			for (auto it = bb.exprIds.begin(); it != bb.exprIds.end();) {
				if (replacements->find (*it) != replacements->end()) {
					it = removeExpr (bb.exprIds, it);
					continue;
				}
				it++;
			}
		}
		printf ("Change Args\n");
		for (SSAExpression& expr : expressions) {
			for (SSAArgument& arg : expr.subExpressions) {
				if (arg.type == SSAArgType::eId) {
					auto it = replacements->find(arg.ssaId);
					if (it != replacements->end()) {
						arg.replace(it->second);
					}
				}
			}
			for (auto it = expr.refs.begin(); it != expr.refs.end(); ) {
				HId refId = *it;
				auto repIt = replacements->find(refId);
				if (repIt != replacements->end()) {
					if (repIt->second.type == SSAArgType::eId){
						refId = repIt->second.ssaId;
					}
					else {
						expr.refs.erase(it);
						continue;
					}
				}
				++it;
			}
		}
		recalcRefCounts();
	}
	uint64_t SSARepresentation::replaceAllArgs(SSAExpression& origExpr, SSAArgument replaceArg) {

		uint64_t count = 0;
		if (replaceArg.ssaId == origExpr.id) {//don't replace refs and args if replace is the same
			for (HId id : origExpr.directRefs) {//iterate refs
				SSAExpression& expr = expressions[id];
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id) {
						arg.replace(replaceArg);
						count++;
					}
				}
			}
		}
		else {
			for (HId id : origExpr.directRefs) {//iterate refs
				SSAExpression& expr = expressions[id];
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id) {
						arg.replace(replaceArg);
						count++;
						if (replaceArg.type == SSAArgType::eId)
							expressions[replaceArg.ssaId].directRefs.push_back(id);
					}
				}
			}
		}
		if (!(replaceArg.type == SSAArgType::eId && replaceArg.ssaId == origExpr.id)) {
			origExpr.directRefs.clear();
			origExpr.refs.clear();
		}
		return count;
	}
	uint64_t SSARepresentation::replaceArg(SSAExpression& origExpr, SSAArgument replaceArg) {
		uint64_t count = 0;
		for (auto it = origExpr.directRefs.begin(); it != origExpr.directRefs.end();++it) {//iterate refs
			SSAExpression& expr = expressions[*it];
			if (expr.type == SSAExprType::eFlag) {//ignore flags because they are operation specific
				continue;
			}
			if (replaceArg.type == SSAArgType::eId && replaceArg.ssaId == origExpr.id) {//don't replace refs and args if replace is the same
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id) {
						arg.replace(replaceArg);
						count++;
					}
				}
			}
			else {
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id) {
						arg.replace(replaceArg);
						count++;
						if (replaceArg.type == SSAArgType::eId)
							expressions[replaceArg.ssaId].refs.push_back(*it);
					}
				}
			}
		}
		if (!(replaceArg.type == SSAArgType::eId && replaceArg.ssaId == origExpr.id)) {
			origExpr.directRefs.clear();
			for (auto it = origExpr.refs.begin(); it != origExpr.refs.end();) {
				if (expressions[*it].type == SSAExprType::eFlag) {
					it++;
					continue;
				}
				it = origExpr.refs.erase(it);
			}
		}
		return count;
	}
	void SSARepresentation::removeNodes (HSet<HId>* ids) {
		for (SSABB& bb : bbs) {
			for (auto it = bb.exprIds.begin(); it != bb.exprIds.end();) {
				if (ids->find (*it) != ids->end())
					it = removeExpr (bb.exprIds, it);
				else
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
					if (arg.type == SSAArgType::eId) {
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

	void SSARepresentation::propagateRefCount (SSAExpression* expr, HId refId) {
		for (SSAArgument& arg : expr->subExpressions) {
			if (arg.type == SSAArgType::eId && arg.ssaId) {
				expressions[arg.ssaId].directRefs.push_back(refId);
				changeRefCount(arg.ssaId, refId);
			}
		}
	}
	void SSARepresentation::propagateRefCount (HId id, HId refId) {
		if (!id)
			return;
		propagateRefCount (&expressions[id], refId);
	}
	void SSARepresentation::changeRefCount (HId id, HId refId) {
		if (!id)
			return;
		if (EXPR_IS_TRANSPARENT (expressions[id].type)) {
			std::vector<bool> visited;
			visited.resize (expressions.size(), false);
			changeRefCount (id, visited, refId);
		}
		else {
			expressions[id].refs.push_back(refId);
		}
	}
	void SSARepresentation::changeRefCount (HId id, std::vector<bool>& visited, HId refId) {
		if (!id || visited[id - 1])
			return;
		visited[id - 1] = true;
		expressions[id].refs.push_back(refId);
		if (EXPR_IS_TRANSPARENT (expressions[id].type)) {
			for (SSAArgument& arg : expressions[id].subExpressions) {
				if (arg.type == SSAArgType::eId)
					changeRefCount (arg.ssaId, visited, refId);
			}
		}
	}
	void SSARepresentation::recalcRefCounts() {
		for (SSAExpression& expr : expressions) {
			expr.refs.clear();
			expr.directRefs.clear();
		}
		for (SSAExpression& expr : expressions) {
			if (expr.id) {
				propagateRefCount(&expr, expr.id);
			}
		}
	}
	bool SSARepresentation::calcConstValue(SSAArgument argument, uint64_t* result) {
		if (argument.isConst()) {
			switch (argument.type) {
			case SSAArgType::eSInt:
				*result = static_cast<uint64_t>(argument.sval);
				return true;
			case SSAArgType::eUInt:
				*result = argument.uval;
				return true;
			case SSAArgType::eFloat:
				*result = static_cast<uint64_t>(argument.fval);
				return true;
			default:
				return false;
			}
		}
		else if (argument.type == SSAArgType::eId) {
			SSAExpression& expr = expressions[argument.ssaId];
			switch (expr.type) {
			case SSAExprType::eLoadAddr:
				uint64_t base, index, disp, offset;
				if (calcConstValue(expr.subExpressions[1], &base) &&
					calcConstValue(expr.subExpressions[2], &index) &&
					calcConstValue(expr.subExpressions[3], &disp) &&
					calcConstValue(expr.subExpressions[4], &offset)) {
					*result = base + (index * disp) + offset;
					return true;
				}
			}
		}
		return false;
	}
	HId SSARepresentation::addExpr (SSAExpression* expr) {
		expr->uniqueId = exprIdGen.next();
		expressions.push_back (*expr);
		HId newId = expressions.back().id;
		if (!EXPR_IS_TRANSPARENT (expr->type))
			propagateRefCount (newId, newId);
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
		else {
			for (SSABB& basicblock : bbs) {
				for (auto it = basicblock.exprIds.begin(); it != basicblock.exprIds.end(); ++it) {
					if (*it == ssaId) {
						return *addAfter(expr, basicblock.exprIds, it);
					}
				}
			}
		}
		assert(false);
		return 0;
	}
	HList<HId>::iterator SSARepresentation::addAfter (SSAExpression* expr, HList<HId>& ids, HList<HId>::iterator it) {
		return ids.insert (++it, addExpr (expr));
	}

	HList<HId>::iterator SSARepresentation::removeExpr (HList<HId>& ids, HList<HId>::iterator it) {
		SSAExpression& expr = expressions[*it];
		expr.id = 0;
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
					removeExpr (bb->exprIds, it);
					return;
				}
			}
		}
		for (SSABB& basicblock : bbs) {
			for (auto it = basicblock.exprIds.begin(); it != basicblock.exprIds.end(); ++it) {
				if (*it == ssaId) {
					removeExpr (basicblock.exprIds, it);
					return;
				}
			}
		}
	}


	void SSARepresentation::print (Architecture* arch, int indent) {
		printIndent (indent);
		printf ("Printing SSA-Gen DataSegment\n");
		printIndent (indent);
		printf ("Number Of Expressions: %" PRId64 "\n", expressions.size());

		for (SSABB& bb : bbs) {
			printIndent (indent + 1);
			printf ("Block bb Id: %d 0x%" PRIx64 " - 0x%" PRIx64 "\n", bb.id, bb.startaddr, bb.endaddr);

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
			printIndent (indent + 1);
			printf ("Number Of Ids: %" PRId64 "\n", bb.exprIds.size());
			for (HId id : bb.exprIds) {
				expressions[id].print (arch, indent + 2);
			}
		}


	}
}
