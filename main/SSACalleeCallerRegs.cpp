

#include "SSACalleeCallerRegs.h"

namespace holodec{

	bool calc_basearg_plus_offset(Architecture* arch, Function* function, CalleeArgument arg, std::map<HId, CalleeArgument>& exprvisited, Register* reg, CalleeArgument* retArg);
	bool calc_basearg_plus_offset_mem(Architecture* arch, Function* function, HId memId, CalleeArgument arg, std::map<HId, CalleeArgument>& exprvisited, Register* reg, CalleeArgument* retArg, HId ptrBaseExprId, uint32_t bitsread, int64_t ptrBaseExprChange) {
		auto f = exprvisited.find(arg.ssaId);
		if (f != exprvisited.end()) {
			return f->second == arg;
		}
		SSAExpression* expr = &function->ssaRep.expressions[memId];
		if (expr->type == SSAExprType::ePhi) {
			exprvisited.insert(std::make_pair(expr->id, arg));
			for (size_t i = 1; i < expr->subExpressions.size(); i += 2) {
				SSAArgument& exprArg = expr->subExpressions[i];
				if (exprArg.type != SSAArgType::eId || !exprArg.ref.isLocation(SSALocation::eMem))
					return false;
				if (exprvisited.find(exprArg.ssaId) == exprvisited.end()) {
					if (!calc_basearg_plus_offset_mem(arch, function, exprArg.ssaId, arg, exprvisited, reg, retArg, ptrBaseExprId, bitsread, ptrBaseExprChange)) {
						return false;
					}
				}
			}
			return true;
		}
		else if (expr->type == SSAExprType::eStore) {
			HId baseExprId = 0;
			int64_t storeoffsetmin = 0, storeoffsetmax = 0;
			int64_t ptroffsetmin = ptrBaseExprChange, ptroffsetmax = 0;
			//an argument is passed to the function that has the same base + storechange as our pointer
			calculate_basearg_plus_offset(&function->ssaRep, expr->subExpressions[1].ssaId, &storeoffsetmin, &baseExprId);

			uint32_t valuesize = function->ssaRep.expressions[expr->subExpressions[2].ssaId].size;

			storeoffsetmax = storeoffsetmin + ((valuesize - 1) / arch->bitbase) + 1;
			ptroffsetmax = ptroffsetmin + ((bitsread - 1) / arch->bitbase) + 1;
			if (baseExprId == ptrBaseExprId) {
				//exact match
				if (storeoffsetmin == ptroffsetmin && storeoffsetmax == ptroffsetmax) {
					return calc_basearg_plus_offset(arch, function, arg.replace(expr->subExpressions[2]), exprvisited, reg, retArg);
				}
				//some kind of overlap
				else if (storeoffsetmin < ptroffsetmax && ptroffsetmin < storeoffsetmax) {
					return false;
				}
			}
			return calc_basearg_plus_offset_mem(arch, function, expr->subExpressions[0].ssaId, arg, exprvisited, reg, retArg, ptrBaseExprId, bitsread, ptrBaseExprChange);
		}
		else if (expr->type == SSAExprType::eOutput) {
			SSAExpression* callExpr = &function->ssaRep.expressions[expr->subExpressions[0].ssaId];
			for (auto it = callExpr->subExpressions.begin(); it != callExpr->subExpressions.end(); it++) {
				int64_t change = 0;
				HId baseExprId = 0;
				//an argument is passed to the function that has the same base + change as our pointer
				if (calculate_basearg_plus_offset(&function->ssaRep, it->ssaId, &change, &baseExprId) && baseExprId == ptrBaseExprId && change == ptrBaseExprChange) {
					return false;
				}
			}
			for (auto it = callExpr->subExpressions.begin(); it != callExpr->subExpressions.end(); it++) {
				if (it->ref == expr->ref) {
					return calc_basearg_plus_offset_mem(arch, function, it->ssaId, arg, exprvisited, reg, retArg, ptrBaseExprId, bitsread, ptrBaseExprChange);
				}
			}
		}
		return false;
	}
	bool calc_basearg_plus_offset(Architecture* arch, Function* function, CalleeArgument arg, std::map<HId, CalleeArgument>& exprvisited, Register* reg, CalleeArgument* retArg) {
		auto f = exprvisited.find(arg.ssaId);
		if (f != exprvisited.end()) {
			return f->second == arg;
		}
		
		SSAExpression* expr = &function->ssaRep.expressions[arg.ssaId];
		if (expr->type == SSAExprType::ePhi) {
			//create temporary map so we can reset if the first loop fails otherwise temporary phi-argument pairs may remain
			//which might cause a success where there is none
			std::map<HId, CalleeArgument> tempexprvisited = exprvisited;
			tempexprvisited.insert(std::make_pair(expr->id, arg));
			bool retry, success;
			retry = !(success = calc_basearg_plus_offset(arch, function, arg.replace(expr->subExpressions[1]), tempexprvisited, reg, retArg));
			for (size_t i = 3; i < expr->subExpressions.size(); i+=2) {
				success = calc_basearg_plus_offset(arch, function, arg.replace(expr->subExpressions[i]), tempexprvisited, reg, retArg) && success;
			}
			//otherwise it might be because of recursion so we try again
			if (retry) {
				exprvisited.insert(std::make_pair(expr->id, arg));
				for (size_t i = 1; i < expr->subExpressions.size(); i+=2) {
					if(!calc_basearg_plus_offset(arch, function, arg.replace(expr->subExpressions[i]), exprvisited, reg, retArg))
						return false;
				}
				success = true;
			}else{
				//lock the temporary map because we will not continue
				exprvisited = tempexprvisited;
			}
			return success;
		}
		else if (expr->type == SSAExprType::eLoad) {
			int64_t change = 0;
			HId baseExprId = 0;
			//the pointer has to be one of the arguments to make sure it is the stack or something working similar to the stack
			calculate_basearg_plus_offset(&function->ssaRep, expr->subExpressions[1].ssaId, &change, &baseExprId);
			SSAExpression& baseExpr = function->ssaRep.expressions[baseExprId];
			if (baseExpr.type == SSAExprType::eInput) {
				return calc_basearg_plus_offset_mem(arch, function, expr->subExpressions[0].ssaId, arg, exprvisited, reg, retArg, baseExprId, expr->size, change);
			}
			return false;
		}
		else if (expr->type == SSAExprType::eOutput) {
			if (!expr->ref.isReg(reg)) return false;

			SSAExpression* callexpr = &function->ssaRep.expressions[expr->subExpressions[0].ssaId];
			assert (callexpr->type == SSAExprType::eCall);

			SSAExpression* valueexpr = &function->ssaRep.expressions[callexpr->subExpressions[0].ssaId];
			if (!valueexpr->isValue(function->baseaddr))  return false;//not a recursion...

			for (auto it = callexpr->subExpressions.begin() + 1/*skip the calltarget*/; it != callexpr->subExpressions.end(); it++) {
				if (it->ref.isReg(reg) && retArg->ssaId) {//if it is read and the return-argument is set(another path already found a solution) then we assume that argument
					return calc_basearg_plus_offset(arch, function, arg.replace(*retArg).replace(*it), exprvisited, reg, retArg);
				}
			}
			//if it is not read but only returned then it is not a callee saved register
			return false;
		}
		else if (expr->isOp()) {
			if(expr->opType == SSAOpType::eAdd || expr->opType == SSAOpType::eSub) {
				SSAExpression* idExpr = nullptr;
				int64_t change = 0;
				for (size_t i = 0; i < expr->subExpressions.size(); ++i) {
					SSAExpression& subexpr = function->ssaRep.expressions[expr->subExpressions[i].ssaId];
					if (!subexpr.isConst()) {
						if (idExpr)
							return false;
						idExpr = &subexpr;
						continue;
					}
					if (expr->opType == SSAOpType::eAdd) {
						if (!subexpr.isConst())
							return false;
						if (subexpr.isConst(SSAType::eUInt))
							change += subexpr.uval;
						else if (subexpr.isConst(SSAType::eInt))
							change += subexpr.sval;
						else
							return false;
					}
					else if (expr->opType == SSAOpType::eSub) {
						if (!subexpr.isConst() || i == 0)
							return false;
						if (subexpr.isConst(SSAType::eUInt))
							change -= subexpr.uval;
						else if (subexpr.isConst(SSAType::eInt))
							change -= subexpr.sval;
						else
							return false;
					}
				}
				if (idExpr) {
					arg.ssaId = idExpr->id;
					arg.change += change;
					return calc_basearg_plus_offset(arch, function, arg, exprvisited, reg, retArg);
				}
			}
		}
		else if (expr->type == SSAExprType::eInput) {
			if (expr->ref.isReg(reg)) {
				if (!retArg->ssaId)
					*retArg = arg;
				return *retArg == arg;
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
		FuncRegState regStates;
		bool changed = false;
		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (expr.type == SSAExprType::eReturn) {
				for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end(); ) {
					SSAArgument& arg = *it;
					if (arg.type == SSAArgType::eId && arg.ref.isLocation(SSALocation::eReg)) {
						Register* reg = arch->getRegister(arg.ref.id);
#ifdef HOLODEC_REMOVE_OBVIOUS
						if (reg->size == 1) {
							it = expr.removeArgument(&function->ssaRep, it);
							regStates.getNewRegisterState(reg->parentRef.refId)->flags |= UsageFlags::eUndef;
							changed = true;
							continue;
						}
#endif
						HId id = 0;
						CalleeArgument retArg;
						RegisterState* state = regStates.getRegisterState(reg->parentRef.refId);
						if (state && state->flags.contains(UsageFlags::eWrite)) {//if we found no result for the same register from another return
							it++;
							continue;
						}

						std::map<HId, CalleeArgument> visited;
						bool succ = calc_basearg_plus_offset(arch, function, arg, visited, reg, &retArg);
						if (succ) {
							if (state && state->flags.contains(UsageFlags::eWrite) && state->fixedValueChange != retArg.change) {//if we found a different result for the same register from another return
								state->flags |= UsageFlags::eWrite;
								it++;
								continue;
							}
							if (retArg.change == 0) {
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
							else {
								state = regStates.getNewRegisterState(reg->parentRef.refId);
								SSAExpression& baseExpr = function->ssaRep.expressions[retArg.ssaId];
								if (baseExpr.type == SSAExprType::eInput && baseExpr.ref.isLocation(SSALocation::eReg) && baseExpr.ref.id == it->ref.id) {
									state->fixedValueChange = retArg.change;
									it++;
									continue;
								}
							}
						}
						else {
							regStates.getNewRegisterState(it->ref.id)->flags |= UsageFlags::eWrite;
						}
					}
					else if (arg.type == SSAArgType::eId && arg.ref.isLocation(SSALocation::eMem)) {
						regStates.getNewMemoryState(it->ref.id)->flags |= UsageFlags::eWrite;
					}
					it++;
				}
			}
			else if (expr.type == SSAExprType::eInput) {
				if (expr.ref.isLocation(SSALocation::eReg)) {
					Register* reg = arch->getRegister(expr.ref.id);
					regStates.getNewRegisterState(reg->parentRef.refId)->flags |= UsageFlags::eRead;
				}
				else if (expr.ref.isLocation(SSALocation::eMem)) {
					regStates.getNewMemoryState(expr.ref.id)->flags |= UsageFlags::eRead;
				}
			}
		}
		function->regStates = regStates;
		function->regStates.parsed = true;
		//remove call-parameters and output-expressions if possible
		for (size_t it = 0; it < function->ssaRep.expressions.list.size(); it++) {
			SSAExpression& expr = function->ssaRep.expressions.list[it];
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
				else if (!state->flags.contains(UsageFlags::eWrite)) {//if the register was not written there is no change or just an fixed one
					expr.type = SSAExprType::eAssign;
					expr.removeArgument(&function->ssaRep, expr.subExpressions.begin());
					if (state->fixedValueChange) {
						SSAExpression valexpr;
						valexpr.type = SSAExprType::eValue;
						valexpr.exprtype = SSAType::eUInt;
						valexpr.size = arch->bitbase * arch->bytebase;
						if (state->fixedValueChange > 0) {
							expr.type = SSAExprType::eOp;
							expr.opType = SSAOpType::eAdd;
							valexpr.uval = state->fixedValueChange;
						}
						else {
							expr.type = SSAExprType::eOp;
							expr.opType = SSAOpType::eSub;
							valexpr.uval = -state->fixedValueChange;
						}
						HId exprId = expr.id;
						HId newId = function->ssaRep.addBefore(&valexpr, expr.id);
						function->ssaRep.expressions[exprId].addArgument(&function->ssaRep, SSAArgument::createId(newId));
					}
					changed = true;
				}
				//if the register was written to but not read, we remove the input as a second argument
				else if (state->flags.contains(UsageFlags::eWrite) && !state->flags.contains(UsageFlags::eRead)) {
					expr.subExpressions.erase(expr.subExpressions.begin() + 1);
					changed = true;
				}
			}
			else if (expr.type == SSAExprType::eOutput) {
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
#ifdef HOLODEC_REMOVE_OBVIOUS
					/*else if(expr->ref.isLocation(SSALocation::eReg)) {
						Register* reg = arch->getRegister(expr->ref.id);
						if (reg->name == "r1") {
							expr->type = SSAExprType::eValue;
							expr->exprtype = SSAType::eUInt;
							expr->uval = 0x00;
							changed = true;
						}
					}*/
#endif
				}
			}
		}

		return changed;
	}

}