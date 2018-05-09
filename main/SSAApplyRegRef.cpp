#include "SSAApplyRegRef.h"



namespace holodec {


	bool SSAApplyRegRef::doTransformation(Binary* binary, Function* function) {// results of interprocedural liveness analysis
		bool applied = false;
		function->regStates.reg_states.clear();
		function->regStates.mem_states.clear();
		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (expr.type == SSAExprType::eReturn) {
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId) {
						SSAExpression& reffedExpr = function->ssaRep.expressions[arg.ssaId];
						if (reffedExpr.type == SSAExprType::eInput && arg.location == SSALocation::eReg) {
							Register* reg = arch->getRegister(arg.locref.refId);
							RegisterState* state = function->regStates.getNewRegisterState(reg->parentRef.refId);
							state->arithChange = arg.valueoffset;
							continue;
						}
						if (reffedExpr.type == SSAExprType::eInput && arg.location == SSALocation::eMem) {
							continue;
						}
					}
					if (arg.location == SSALocation::eReg) {
						Register* reg = arch->getRegister(arg.locref.refId);
						RegisterState* state = function->regStates.getNewRegisterState(reg->parentRef.refId);
						state->flags |= UsageFlags::eWrite;
					}
					else if (arg.location == SSALocation::eMem) {
						Memory* mem = arch->getMemory(arg.locref.refId);
						MemoryState* state = function->regStates.getNewMemoryState(mem->id);
						state->flags |= UsageFlags::eWrite;
					}
				}
			}
			else if (expr.type == SSAExprType::eInput) {
				if (expr.location == SSALocation::eReg) {
					Register* reg = arch->getRegister(expr.locref.refId);
					RegisterState* state = function->regStates.getNewRegisterState(reg->parentRef.refId);
					state->flags |= UsageFlags::eRead;
				}
				else if (expr.location == SSALocation::eMem) {
					Memory* mem = arch->getMemory(expr.locref.refId);
					MemoryState* state = function->regStates.getNewMemoryState(mem->id);
					state->flags |= UsageFlags::eRead;
				}
			}
			else if (expr.type == SSAExprType::eCall) {
				if (expr.subExpressions[0].type != SSAArgType::eUInt)
					continue;
				Function* callFunc = binary->getFunctionByAddr(expr.subExpressions[0].uval);
				if (!(callFunc && callFunc->regStates.parsed))
					continue;
				for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end(); ++it) {
					if (it->location == SSALocation::eReg) {
						Register* reg = arch->getRegister(it->locref.refId);
						if (!reg)
							continue;
						RegisterState* state = callFunc->regStates.getRegisterState(reg->parentRef.refId);
						if (!state || !state->flags.contains(UsageFlags::eRead)) {
							it = expr.subExpressions.erase(it) - 1;
							applied = true;
							continue;
						}
					}
					else if (it->location == SSALocation::eMem) {
						Memory* mem = arch->getMemory(it->locref.refId);
						if (!mem)
							continue;
						MemoryState* state = callFunc->regStates.getMemoryState(mem->id);
						if (!state || !state->flags.contains(UsageFlags::eRead)) {
							it = expr.subExpressions.erase(it) - 1;
							applied = true;
							continue;
						}
					}
				}
			}
			else if (expr.type == SSAExprType::eOutput) {
				if (expr.subExpressions[0].type != SSAArgType::eId || expr.location != SSALocation::eReg)
					continue;
				SSAExpression& callExpr = function->ssaRep.expressions[expr.subExpressions[0].ssaId];
				if (callExpr.subExpressions[0].type != SSAArgType::eUInt)
					continue;
				Function* callFunc = binary->getFunctionByAddr(callExpr.subExpressions[0].uval);
				if (!(callFunc && callFunc->regStates.parsed))
					continue;
				if (expr.location == SSALocation::eReg) {
					Register* reg = arch->getRegister(expr.locref.refId);
					if (!reg)
						continue;
					RegisterState* state = callFunc->regStates.getRegisterState(reg->parentRef.refId);
					if (state) {
						if (expr.subExpressions.size() > 1) {
							if (!state->flags.contains(UsageFlags::eWrite)) {//if the register was not written to ther is no change or just an arithmetic one
								expr.type = SSAExprType::eAssign;
								expr.removeArgument(&function->ssaRep, expr.subExpressions.begin());
								expr.subExpressions[0].valueoffset += state->arithChange;
								applied = true;
							}
							else if (!state->flags.contains(UsageFlags::eRead)) {//if the register was written to but not read, we remove the input as a second argument
								expr.subExpressions.erase(expr.subExpressions.begin() + 1);
								applied = true;
							}
						}
					}
				}
			}
			else if (expr.type == SSAExprType::eMemOutput) {
				if (expr.subExpressions[0].type != SSAArgType::eId || expr.location != SSALocation::eMem)
					continue;
				SSAExpression& callExpr = function->ssaRep.expressions[expr.subExpressions[0].ssaId];
				if (callExpr.subExpressions[0].type != SSAArgType::eUInt)
					continue;
				Function* callFunc = binary->getFunctionByAddr(callExpr.subExpressions[0].uval);
				if (!(callFunc && callFunc->regStates.parsed))
					continue;
				if (expr.location == SSALocation::eMem) {
					Memory* mem = arch->getMemory(expr.locref.refId);
					if (!mem)
						continue;
					MemoryState* state = callFunc->regStates.getMemoryState(mem->id);
					if (!state || !state->flags.contains(UsageFlags::eWrite)) {
						expr.type = SSAExprType::eAssign;
						expr.subExpressions.erase(expr.subExpressions.begin());
						applied = true;
					}
					else if (!state || !state->flags.contains(UsageFlags::eRead)) {
						if (expr.subExpressions.size() > 1) {
							expr.subExpressions.erase(expr.subExpressions.begin() + 1);
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

