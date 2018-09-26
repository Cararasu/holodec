

#include "SSACalleeCallerRegs.h"

namespace holodec{

	bool SSACalleeCallerRegs::isInputMem(Function* function, HId memId, CalleeArgument arg, uint32_t outoffset, std::set<HId>& exprvisited, Register* reg, CalleeArgument* retArg, CalleeArgument ptrArg) {
		SSAExpression* expr = &function->ssaRep.expressions[memId];
		exprvisited.insert(expr->id);
		if (expr->type == SSAExprType::ePhi) {
			for (SSAArgument& exprArg : expr->subExpressions) {
				if (exprArg.type == SSAArgType::eBlock)
					continue;
				if (exprArg.type != SSAArgType::eId || !exprArg.ref.isLocation(SSALocation::eMem))
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
			return isInput(function, arg.replace(expr->subExpressions[0]), outoffset - expr->offset, exprvisited, reg, retArg);
		}
		else if (expr->type == SSAExprType::eLoad) {
			return isInputMem(function, expr->subExpressions[0].ssaId, arg, outoffset, exprvisited, reg, retArg, expr->subExpressions[1]);
		}
		else if (expr->type == SSAExprType::eOutput) {
			if (expr->ref.isReg(reg)) {
				SSAExpression* callexpr = &function->ssaRep.expressions[expr->subExpressions[0].ssaId];
				if (callexpr->type == SSAExprType::eCall) {
					SSAExpression* valueexpr = &function->ssaRep.expressions[callexpr->subExpressions[0].ssaId];
					if (valueexpr->isValue(function->baseaddr)) {//recursion...
						for (auto it = callexpr->subExpressions.begin() + 1/*skip the calltarget*/; it != callexpr->subExpressions.end(); it++) {
							if (it->ref.isReg(reg)) {//if it is read and returned we can assume correctness
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
			if (expr->ref.isReg(reg)) {
				if (!retArg->ssaId)
					*retArg = arg;
				return *retArg == arg && arg.offset == outoffset;
			}
		} 
		return false;
	}
	bool SSACalleeCallerRegs::isOnlyRecursive(Function* function, HId currentId, HId lastId, std::set<HId>& exprvisited, Reference locref) {
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
					if (arg.ref != locref)
						return false;
				}
			}
			return true;
		}
		else if (expr->type == SSAExprType::eOutput) {
			if (expr->ref != locref) {
				return true;
			}
			bool isrecursive = true;
			for (HId id : expr->directRefs) { //follow expressions
				isrecursive = isrecursive && isOnlyRecursive(function, id, currentId, exprvisited, expr->ref);
			}
			return isrecursive;
		}
		else if (expr->type == SSAExprType::ePhi) {
			bool isrecursive = true;
			for (HId id : expr->directRefs) { //follow expressions
				isrecursive = isrecursive && isOnlyRecursive(function, id, currentId, exprvisited, expr->ref);
			}
			return isrecursive;
		}
		return false;
	}
	bool SSACalleeCallerRegs::doTransformation(Binary* binary, Function* function) {// interprocedural liveness analysis for callee saved registers

		printf("Resolving Callee-saved-Registers in Function at Address 0x%" PRIx64 "\n", function->baseaddr);
		function->ssaRep.checkIntegrity();
		function->regStates.reset();
		bool changed = false;
		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (expr.type == SSAExprType::eReturn) {
				std::set<HId> visited;
				for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end(); ) {
					SSAArgument& arg = *it;
					if (!(arg.type == SSAArgType::eId && arg.ref.isLocation(SSALocation::eReg))) {
						it++;
						continue;
					}
					Register* reg = arch->getRegister(arg.ref.id);
					HId id = 0;
					CalleeArgument retArg;

					visitedFuncs.clear();
					visitedFuncs.insert(function);
					bool succ = isInput(function, arg, 0, visited, reg, &retArg);
					visited.clear();
					if (succ) {
						if (it->ssaId == retArg.ssaId) {
							it = expr.removeArgument(&function->ssaRep, it);
							changed = true;
							continue;
						}
						else {
							expr.replaceArgument(&function->ssaRep, it, SSAArgument::createId(retArg.ssaId, arg.ref));
							changed = true;
						}
						it++;
						continue;
					}
					if (it->ref.isLocation(SSALocation::eReg)) {
						Register* reg = arch->getRegister(it->ref.id);
						RegisterState* state = function->regStates.getNewRegisterState(reg->parentRef.refId);

						int64_t change = 0;
						HId baseExprId = 0;
						if (calculate_basearg_plus_offset(&function->ssaRep, it->ssaId, &change, &baseExprId) != 0) {
							SSAExpression& baseExpr = function->ssaRep.expressions[baseExprId];
							if (baseExpr.type == SSAExprType::eInput && baseExpr.ref.isLocation(SSALocation::eReg) && baseExpr.ref.id == it->ref.id) {
								state->arithmeticChange = change;
								it++;
								continue;
							}
						}
						else {
							state->flags |= UsageFlags::eWrite;
						}
					}
					else if (it->ref.isLocation(SSALocation::eMem)) {
						function->regStates.getNewMemoryState(it->ref.id)->flags |= UsageFlags::eWrite;
					}
					it++;
				}
			}
			else if (expr.type == SSAExprType::eInput) {
				if (expr.ref.isLocation(SSALocation::eReg)) {
					Register* reg = arch->getRegister(expr.ref.id);
					function->regStates.getNewRegisterState(reg->parentRef.refId)->flags |= UsageFlags::eRead;
				}
				else if (expr.ref.isLocation(SSALocation::eMem)) {
					function->regStates.getNewMemoryState(expr.ref.id)->flags |= UsageFlags::eRead;
				}
			}
		}
		function->regStates.parsed = true;
		//remove call-parameters and output-expressions if possible
		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (!expr.id) continue;
			if (expr.type == SSAExprType::eCall) {
				SSAExpression* dstExpr = find_baseexpr(&function->ssaRep, expr.subExpressions[0]);
				if (!dstExpr->isConst(SSAType::eUInt))
					continue;
				Function* callFunc = binary->getFunctionByAddr(dstExpr->uval);
				if (!callFunc || !callFunc->regStates.parsed)
					continue;
				//first argument is the call destination so skip it
				for (auto argIt = expr.subExpressions.begin() + 1; argIt != expr.subExpressions.end();) {
					if (argIt->ref.isLocation(SSALocation::eReg)) {
						Register* reg = arch->getRegister(argIt->ref.id);
						if (!reg) {
							++argIt;
							continue;
						}
						RegisterState* state = callFunc->regStates.getRegisterState(reg->parentRef.refId);
						if (!state || !state->flags.contains(UsageFlags::eRead)) {//if there is no state set then neither read nor write is set
							argIt = expr.subExpressions.erase(argIt);
							changed = true;
							continue;
						}
					}
					else if (argIt->ref.isLocation(SSALocation::eMem)) {
						Memory* mem = arch->getMemory(argIt->ref.id);
						if (!mem) {
							++argIt;
							continue;
						}
						MemoryState* state = callFunc->regStates.getMemoryState(mem->id);
						if (!state || !state->flags.contains(UsageFlags::eRead)) {//if there is no state set then neither read nor write is set
							argIt = expr.subExpressions.erase(argIt);
							changed = true;
							continue;
						}
					}
					++argIt;

				}
			}
			else if (expr.type == SSAExprType::eOutput) {
				if (expr.subExpressions[0].type != SSAArgType::eId || !expr.ref.isLocation(SSALocation::eReg)) continue;
				if (expr.subExpressions.size() == 1) continue;

				SSAExpression& callExpr = function->ssaRep.expressions[expr.subExpressions[0].ssaId];
				SSAExpression* dstexpr = find_baseexpr(&function->ssaRep, callExpr.subExpressions[0]);
				if (!dstexpr->isConst(SSAType::eUInt)) continue;

				Function* callFunc = binary->getFunctionByAddr(dstexpr->uval);
				if (!(callFunc && callFunc->regStates.parsed)) continue;

				Register* reg = arch->getRegister(expr.ref.id);
				if (!reg) continue;

				RegisterState* state = callFunc->regStates.getRegisterState(reg->parentRef.refId);
				if (!state) {//no state was generated so it was neither written not read
					expr.type = SSAExprType::eAssign;
					expr.removeArgument(&function->ssaRep, expr.subExpressions.begin());
					changed = true;
				}
				else if (!state->flags.contains(UsageFlags::eWrite)) {//if the register was not written there is no change or just an arithmetic one
					expr.type = SSAExprType::eAssign;
					expr.removeArgument(&function->ssaRep, expr.subExpressions.begin());
					if (state->arithmeticChange) {
						SSAExpression valexpr;
						valexpr.type = SSAExprType::eValue;
						valexpr.exprtype = SSAType::eUInt;
						valexpr.size = arch->bitbase * arch->bytebase;
						if (state->arithmeticChange > 0) {
							expr.type = SSAExprType::eOp;
							expr.opType = SSAOpType::eAdd;
							valexpr.uval = state->arithmeticChange;
						}
						else {
							expr.type = SSAExprType::eOp;
							expr.opType = SSAOpType::eSub;
							valexpr.uval = -state->arithmeticChange;
						}
						HId exprId = expr.id;
						HId newId = function->ssaRep.addBefore(&valexpr, expr.id);
						function->ssaRep.expressions.list[exprId].addArgument(&function->ssaRep, SSAArgument::createId(newId));
					}
					changed = true;
				}
				//if the register was written to but not read, we remove the input as a second argument
				else if (state->flags.contains(UsageFlags::eWrite) && !state->flags.contains(UsageFlags::eRead)) {
					expr.subExpressions.erase(expr.subExpressions.begin() + 1);
					changed = true;
				}
			}
			else if (expr.type == SSAExprType::eMemOutput) {
				if (expr.subExpressions[0].type != SSAArgType::eId || !expr.ref.isLocation(SSALocation::eMem)) continue;

				SSAExpression& callExpr = function->ssaRep.expressions[expr.subExpressions[0].ssaId];
				SSAExpression* dstExpr = find_baseexpr(&function->ssaRep, callExpr.subExpressions[0]);
				if (!dstExpr->isConst(SSAType::eUInt)) continue;

				Function* callFunc = binary->getFunctionByAddr(dstExpr->uval);
				if (!(callFunc && callFunc->regStates.parsed)) continue;

				Memory* mem = arch->getMemory(expr.ref.id);
				if (!mem) continue;

				MemoryState* state = callFunc->regStates.getMemoryState(mem->id);
				if (!state || !state->flags.contains(UsageFlags::eWrite)) {
					expr.type = SSAExprType::eAssign;
					expr.subExpressions.erase(expr.subExpressions.begin());
					changed = true;
				}
				else if (!state->flags.contains(UsageFlags::eRead)) {
					if (expr.subExpressions.size() > 1) {
						expr.subExpressions.erase(expr.subExpressions.begin() + 1);
						changed = true;
					}
				}
			}
		}
		//check for recursive calls without return calls
		for (int i = 0; i < function->ssaRep.bbs[1].exprIds.size(); i++) {
			SSAExpression* expr = &function->ssaRep.expressions[function->ssaRep.bbs[1].exprIds[i]];
			if (expr->type == SSAExprType::eInput) {
				HSet<HId> visited;
				if (!expr->ref.isLocation(SSALocation::eNone)) {
					bool isrecursive = true;
					for (HId id : expr->directRefs) {
						//follow expressions
						isrecursive = isrecursive && isOnlyRecursive(function, id, expr->id, visited, expr->ref);
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