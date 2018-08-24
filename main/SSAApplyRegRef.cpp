#include "SSAApplyRegRef.h"



namespace holodec {


	bool SSAApplyRegRef::doTransformation(Binary* binary, Function* function) {// results of interprocedural liveness analysis
		bool applied = false;
		function->regStates.reset();

		for (size_t index = 0; index < function->ssaRep.expressions.list.size(); index++) {
			SSAExpression* expr = &function->ssaRep.expressions.list[index];
			if (expr->type == SSAExprType::eReturn) {
				for (auto argIt = expr->subExpressions.begin() + 1; argIt != expr->subExpressions.end(); ++argIt) {
					if (argIt->type == SSAArgType::eId) {
						int64_t change = 0;
						HId baseExprId;
						if (calculate_basearg_plus_offset(&function->ssaRep, argIt->ssaId, &change, &baseExprId) != 0) {
							SSAExpression& baseExpr = function->ssaRep.expressions[baseExprId];
							if (baseExpr.type == SSAExprType::eInput && baseExpr.location == SSALocation::eReg && baseExpr.locref.refId == argIt->locref.refId) {
								RegisterState* state = function->regStates.getNewRegisterState(argIt->locref.refId);
								state->arithChange = change;
								continue;
							}
						}
					}
					if (argIt->location == SSALocation::eReg) {
						RegisterState* state = function->usedRegStates.getRegisterState(argIt->locref.refId);//reverse check if the argument is used outside in another function
						if (!function->exported && !state || !state->flags.contains(UsageFlags::eRead)) {
							argIt = expr->subExpressions.erase(argIt) - 1;
							applied = true;
						}
						else {
							Register* reg = arch->getRegister(argIt->locref.refId);
							RegisterState* state = function->regStates.getNewRegisterState(reg->parentRef.refId);
							state->flags |= UsageFlags::eWrite;
						}
					}
					else if (argIt->location == SSALocation::eMem) {
						MemoryState* state = function->usedRegStates.getMemoryState(argIt->locref.refId);//reverse check if the argument is used outside in another function
						if (!function->exported && !state || !state->flags.contains(UsageFlags::eRead)) {
							argIt = expr->subExpressions.erase(argIt) - 1;
							applied = true;
						}
						else {
							Memory* mem = arch->getMemory(argIt->locref.refId);
							MemoryState* state = function->regStates.getNewMemoryState(mem->id);
							state->flags |= UsageFlags::eWrite;
						}
					}
				}
			}
			else if (expr->type == SSAExprType::eInput) {
				if (expr->location == SSALocation::eReg) {
					Register* reg = arch->getRegister(expr->locref.refId);
					RegisterState* state = function->regStates.getNewRegisterState(reg->parentRef.refId);
					state->flags |= UsageFlags::eRead;
				}
				else if (expr->location == SSALocation::eMem) {
					Memory* mem = arch->getMemory(expr->locref.refId);
					MemoryState* state = function->regStates.getNewMemoryState(mem->id);
					state->flags |= UsageFlags::eRead;
				}
			}
			else if (expr->type == SSAExprType::eCall) {
				SSAExpression* dstExpr = find_baseexpr(&function->ssaRep, expr->subExpressions[0]);
				if (!dstExpr->isConst(SSAType::eUInt))
					continue;
				Function* callFunc = binary->getFunctionByAddr(dstExpr->uval);
				if (!callFunc || !callFunc->regStates.parsed)
					continue;
				//first argument is the call destination so skip it
				for (auto argIt = expr->subExpressions.begin(); argIt != expr->subExpressions.end(); ++argIt) {
					if (argIt->location == SSALocation::eReg) {
						Register* reg = arch->getRegister(argIt->locref.refId);
						if (!reg)
							continue;
						RegisterState* state = callFunc->regStates.getRegisterState(reg->parentRef.refId);
						if (!state || !state->flags.contains(UsageFlags::eRead)) {
							argIt = expr->subExpressions.erase(argIt);
							if (argIt != expr->subExpressions.begin()) argIt--;
							applied = true;
							continue;
						}
					}
					else if (argIt->location == SSALocation::eMem) {
						Memory* mem = arch->getMemory(argIt->locref.refId);
						if (!mem)
							continue;
						MemoryState* state = callFunc->regStates.getMemoryState(mem->id);
						if (!state || !state->flags.contains(UsageFlags::eRead)) {
							argIt = expr->subExpressions.erase(argIt);
							if (argIt != expr->subExpressions.begin()) argIt--;
							applied = true;
							continue;
						}
					}
				}
			}
			else if (expr->type == SSAExprType::eOutput) {
				if (expr->subExpressions[0].type != SSAArgType::eId || expr->location != SSALocation::eReg)
					continue;
				SSAExpression& callExpr = function->ssaRep.expressions[expr->subExpressions[0].ssaId];
				SSAExpression* dstexpr = find_baseexpr(&function->ssaRep, callExpr.subExpressions[0]);
				if (!dstexpr->isConst(SSAType::eUInt))
					continue;
				Function* callFunc = binary->getFunctionByAddr(dstexpr->uval);
				if (!(callFunc && callFunc->regStates.parsed))
					continue;
				if (expr->location == SSALocation::eReg) {
					Register* reg = arch->getRegister(expr->locref.refId);
					if (!reg)
						continue;
					RegisterState* state = callFunc->regStates.getRegisterState(reg->parentRef.refId);
					if (state) {
						if (expr->subExpressions.size() > 1) {
							if (!state->flags.contains(UsageFlags::eWrite)) {//if the register was not written to ther is no change or just an arithmetic one
								expr->type = SSAExprType::eAssign;
								expr->removeArgument(&function->ssaRep, expr->subExpressions.begin());
								if (state->arithChange) {
									expr->type = SSAExprType::eOp;
									expr->opType = SSAOpType::eAdd;
									SSAExpression valexpr;
									valexpr.type = SSAExprType::eValue;
									valexpr.exprtype = SSAType::eInt;
									valexpr.size = arch->bitbase * arch->bytebase;
									valexpr.sval = state->arithChange;
									HId newId = function->ssaRep.addBefore(&valexpr, expr->id);
									expr = &function->ssaRep.expressions.list[index];
									expr->addArgument(&function->ssaRep, SSAArgument::createId(newId));
								}
								applied = true;
							}
							else if (!state->flags.contains(UsageFlags::eRead)) {//if the register was written to but not read, we remove the input as a second argument
								expr->subExpressions.erase(expr->subExpressions.begin() + 1);
								applied = true;
							}
						}
					}
				}
			}
			else if (expr->type == SSAExprType::eMemOutput) {
				if (expr->subExpressions[0].type != SSAArgType::eId || expr->location != SSALocation::eMem)
					continue;
				SSAExpression& callExpr = function->ssaRep.expressions[expr->subExpressions[0].ssaId];
				SSAExpression* dstExpr = find_baseexpr(&function->ssaRep, callExpr.subExpressions[0]);
				if (!dstExpr->isConst(SSAType::eUInt))
					continue;
				Function* callFunc = binary->getFunctionByAddr(dstExpr->uval);
				if (!(callFunc && callFunc->regStates.parsed))
					continue;
				if (expr->location == SSALocation::eMem) {
					Memory* mem = arch->getMemory(expr->locref.refId);
					if (!mem)
						continue;
					MemoryState* state = callFunc->regStates.getMemoryState(mem->id);
					if (!state || !state->flags.contains(UsageFlags::eWrite)) {
						expr->type = SSAExprType::eAssign;
						expr->subExpressions.erase(expr->subExpressions.begin());
						applied = true;
					}
					else if (!state || !state->flags.contains(UsageFlags::eRead)) {
						if (expr->subExpressions.size() > 1) {
							expr->subExpressions.erase(expr->subExpressions.begin() + 1);
							applied = true;
						}
					}
				}
			}
		}
		function->regStates.parsed = true;
		return applied;
	}


}

