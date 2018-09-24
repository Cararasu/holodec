#include "SSAApplyRegRef.h"



namespace holodec {


	bool SSAApplyRegRef::doTransformation(Binary* binary, Function* function) {// results of interprocedural liveness analysis

		printf("Applying Used Registers for Functions at Address: 0x%" PRIx64 "\n", function->baseaddr);
		bool applied = false;

		function->regStates.reset();
		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (!expr.id) continue;
			if (expr.type == SSAExprType::eReturn) {
				for (auto argIt = expr.subExpressions.begin() + 1; argIt != expr.subExpressions.end(); ++argIt) {
					if (argIt->ref.isLocation(SSALocation::eReg)) {
						Register* reg = arch->getRegister(argIt->ref.id);
						RegisterState* state = function->regStates.getNewRegisterState(reg->parentRef.refId);
						state->flags |= UsageFlags::eWrite;

						int64_t change = 0;
						HId baseExprId = 0;
						if (calculate_basearg_plus_offset(&function->ssaRep, argIt->ssaId, &change, &baseExprId) != 0) {
							SSAExpression& baseExpr = function->ssaRep.expressions[baseExprId];
							if (baseExpr.type == SSAExprType::eInput && baseExpr.ref.isLocation(SSALocation::eReg) && baseExpr.ref.id == argIt->ref.id) {
								state->arithChange = change;
								continue;
							}
						}
					}
					else if (argIt->ref.isLocation(SSALocation::eMem)) {
						function->regStates.getNewMemoryState(argIt->ref.id)->flags |= UsageFlags::eWrite;
					}
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
							applied = true;
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
							applied = true;
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
					applied = true;
				} else if (!state->flags.contains(UsageFlags::eWrite)) {//if the register was not written there is no change or just an arithmetic one
					expr.type = SSAExprType::eAssign;
					expr.removeArgument(&function->ssaRep, expr.subExpressions.begin());
					if (state->arithChange) {
						SSAExpression valexpr;
						valexpr.type = SSAExprType::eValue;
						valexpr.exprtype = SSAType::eUInt;
						valexpr.size = arch->bitbase * arch->bytebase;
						if (state->arithChange > 0) {
							expr.type = SSAExprType::eOp;
							expr.opType = SSAOpType::eAdd; 
							valexpr.uval = state->arithChange;
						}
						else {
							expr.type = SSAExprType::eOp;
							expr.opType = SSAOpType::eSub;
							valexpr.uval = -state->arithChange;
						}
						HId exprId = expr.id;
						HId newId = function->ssaRep.addBefore(&valexpr, expr.id);
						function->ssaRep.expressions.list[exprId].addArgument(&function->ssaRep, SSAArgument::createId(newId));
					}
					applied = true;
				}
				//if the register was written to but not read, we remove the input as a second argument
				else if (state->flags.contains(UsageFlags::eWrite) && !state->flags.contains(UsageFlags::eRead)) {
					expr.subExpressions.erase(expr.subExpressions.begin() + 1);
					applied = true;
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
					applied = true;
				}
				else if (!state->flags.contains(UsageFlags::eRead)) {
					if (expr.subExpressions.size() > 1) {
						expr.subExpressions.erase(expr.subExpressions.begin() + 1);
						applied = true;
					}
				}
			}
		}
		return applied;
	}

}

