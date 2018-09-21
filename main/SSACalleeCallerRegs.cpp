

#include "SSACalleeCallerRegs.h"

namespace holodec{

	bool SSACalleeCallerRegs::isInputMem(Function* function, HId memId, CalleeArgument arg, uint32_t outoffset, std::set<HId>& exprvisited, Register* reg, CalleeArgument* retArg, CalleeArgument ptrArg) {
		SSAExpression* expr = &function->ssaRep.expressions[memId];
		exprvisited.insert(expr->id);
		if (expr->type == SSAExprType::ePhi) {
			for (SSAArgument& exprArg : expr->subExpressions) {
				if (exprArg.type == SSAArgType::eBlock)
					continue;
				if (exprArg.type != SSAArgType::eId || exprArg.location != SSALocation::eMem)
					return false;
				if (exprvisited.find(exprArg.ssaId) == exprvisited.end()) {
					if (!isInputMem(function, exprArg.ssaId, arg, outoffset, exprvisited, reg, retArg, ptrArg)) {
						return false;
					}
				}
			}
			return true;
		}
		else if (expr->type == SSAExprType::eStore) {
			if (expr->subExpressions[1].type == SSAArgType::eId && expr->subExpressions[1].ssaId == ptrArg.ssaId) {
				//TODO check if the ptrArg is a stack???
				return isInput(function, arg.replace(expr->subExpressions[2]), outoffset, exprvisited, reg, retArg);
			}
			return isInputMem(function, expr->subExpressions[0].ssaId, arg, outoffset, exprvisited, reg, retArg, ptrArg);
		}
		else if (expr->type == SSAExprType::eLoad) {
			return isInputMem(function, expr->subExpressions[0].ssaId, arg, outoffset, exprvisited, reg, retArg, ptrArg);
		}
		else if (expr->type == SSAExprType::eMemOutput) {
			SSAExpression* callExpr = &function->ssaRep.expressions[expr->subExpressions[0].ssaId];
			for (SSAArgument& arg : callExpr->subExpressions) {
				if (ptrArg.equals(arg)) {
					return false;
				}
			}
			return isInputMem(function, expr->subExpressions[1].ssaId, arg, outoffset, exprvisited, reg, retArg, ptrArg);

		}
		return false;
	}
	bool SSACalleeCallerRegs::isInput(Function* function, CalleeArgument arg, uint32_t outoffset, std::set<HId>& exprvisited, Register* reg,  CalleeArgument* retArg) {
		SSAExpression* expr = &function->ssaRep.expressions[arg.ssaId];
		exprvisited.insert(expr->id);
		if (expr->size < arg.size)
			return false;
		if (expr->type == SSAExprType::eAppend) {
			uint32_t poffset = outoffset;
			for (SSAArgument& argIt : expr->subExpressions) {
				if (argIt.type != SSAArgType::eId || !isInput(function, arg.replace(argIt), poffset, exprvisited, reg, retArg)) {
					return false;
				}
				poffset += function->ssaRep.expressions[argIt.ssaId].size;
			}
			return true;
		}
		else if (expr->type == SSAExprType::ePhi) {
			for (SSAArgument subarg : expr->subExpressions) {
				if (subarg.type == SSAArgType::eId) {
					if (!isInput(function, arg.replace(subarg), outoffset, exprvisited, reg, retArg))
						return false;
				}
			}
			return true;
		}
		else if (expr->type == SSAExprType::eSplit) {
			SSAExpression* valexpr = &function->ssaRep.expressions[expr->subExpressions[1].ssaId];
			if(valexpr->isConst(SSAType::eUInt)){
				return isInput(function, arg.replace(expr->subExpressions[0]), outoffset - valexpr->uval, exprvisited, reg, retArg);
			}
		}
		else if (expr->type == SSAExprType::eLoad) {
			return isInputMem(function, expr->subExpressions[0].ssaId, arg, outoffset, exprvisited, reg, retArg, expr->subExpressions[1]);
		}
		else if (expr->type == SSAExprType::eOutput) {
			if (expr->location == SSALocation::eReg && expr->locref.refId == reg->id) {
				SSAExpression* callexpr = &function->ssaRep.expressions[expr->subExpressions[0].ssaId];
				if (callexpr->type == SSAExprType::eCall) {
					SSAExpression* valueexpr = &function->ssaRep.expressions[callexpr->subExpressions[0].ssaId];
					if (valueexpr->isValue(function->baseaddr)) {//recursion...
						for (auto it = callexpr->subExpressions.begin() + 1/*skip the calltarget*/; it != callexpr->subExpressions.end(); it++) {
							if (it->location == SSALocation::eReg && it->locref.refId == expr->locref.refId) {//if it is read and returned we can assume correctness
								return isInput(function, arg.replace(*it), outoffset, exprvisited, reg, retArg);
							}
						}
						//if it is not read but only returned then we can still assume correctness
						return true;
					}
				}
			}
		}
		else if (expr->type == SSAExprType::eInput) {
			if (expr->location == SSALocation::eReg && expr->locref.refId == reg->id) {
				if (!retArg->ssaId)
					*retArg = arg;
				return *retArg == arg && arg.offset == outoffset;
			}
		} 
		return false;
	}
	bool SSACalleeCallerRegs::isOnlyRecursive(Function* function, HId currentId, HId lastId, std::set<HId>& exprvisited, SSALocation location, Reference locref) {
		if (exprvisited.find(currentId) != exprvisited.end()) return true;
		exprvisited.insert(currentId);
		SSAExpression* expr = &function->ssaRep.expressions[currentId];
		if (expr->type == SSAExprType::eCall) {
			SSAExpression* targetExpr = &function->ssaRep.expressions[expr->subExpressions[0].ssaId];
			if (!targetExpr->isValue(function->baseaddr))//recursive call
				return false;
			//check if the use refers to the same register or memory space
			for (int i = 0; i < expr->subExpressions.size(); i++) {
				SSAArgument& arg = expr->subExpressions[i];
				if (arg.ssaId == lastId) {
					if (arg.location != location || arg.locref != locref)
						return false;
				}
			}
			return true;
		}
		else if (expr->type == SSAExprType::eOutput) {
			if (expr->location != location || expr->locref != locref) {
				return true;
			}
			bool isrecursive = true;
			for (HId id : expr->directRefs) { //follow expressions
				isrecursive = isrecursive && isOnlyRecursive(function, id, currentId, exprvisited, expr->location, expr->locref);
			}
			return isrecursive;
		}
		else if (expr->type == SSAExprType::ePhi) {
			bool isrecursive = true;
			for (HId id : expr->directRefs) { //follow expressions
				isrecursive = isrecursive && isOnlyRecursive(function, id, currentId, exprvisited, expr->location, expr->locref);
			}
			return isrecursive;
		}
		return false;
	}
	bool SSACalleeCallerRegs::doTransformation(Binary* binary, Function* function) {// interprocedural liveness analysis for callee saved registers

		printf("Resolving Callee-saved-Registers in Function at Address 0x%" PRIx64 "\n", function->baseaddr);
		function->ssaRep.checkIntegrity();
		bool changed = false;
		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (expr.type == SSAExprType::eReturn) {
				std::set<HId> visited;
				for (int it = 0; it < expr.subExpressions.size(); it++) {
					SSAArgument& arg = expr.subExpressions[it];
					if (!(arg.type == SSAArgType::eId && arg.location == SSALocation::eReg))
						continue;
					Register* reg = arch->getRegister(arg.locref.refId);
					HId id = 0;
					CalleeArgument retArg;

					visitedFuncs.clear();
					visitedFuncs.insert(function);
					bool succ = isInput(function, arg, 0, visited, reg, &retArg);
					visited.clear();
					if (succ) {
						if (expr.subExpressions[it].ssaId == retArg.ssaId) {
							expr.removeArgument(&function->ssaRep, it);
							changed = true;
						}
						else {
							changed |= expr.replaceArgument(&function->ssaRep, it, SSAArgument::createId(retArg.ssaId, SSALocation::eReg, arg.locref)) != 0;
						}
					}
				}
			}
		}
		//check for recursive calls without return calls
		for (int i = 0; i < function->ssaRep.bbs[1].exprIds.size(); i++) {
			SSAExpression* expr = &function->ssaRep.expressions[function->ssaRep.bbs[1].exprIds[i]];
			if (expr->type == SSAExprType::eInput) {
				HSet<HId> visited;
				if (expr->location != SSALocation::eNone) {
					bool isrecursive = true;
					for (HId id : expr->directRefs) {
						//follow expressions
						isrecursive = isrecursive && isOnlyRecursive(function, id, expr->id, visited, expr->location, expr->locref);
					}
					if (isrecursive) {
						expr->type = SSAExprType::eUndef;
						changed = true;
					}
				}
			}
		}

		return changed;
	}

}