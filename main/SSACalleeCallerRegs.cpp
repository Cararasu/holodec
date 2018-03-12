#include "SSACalleeCallerRegs.h"

namespace holodec{

	bool SSACalleeCallerRegs::isInputMem(HId memId, CalleeArgument arg, uint32_t outoffset, std::set<HId>& visited, CalleeArgument* retArg, CalleeArgument ptrArg) {
		SSAExpression* expr = &ssaRep->expressions[memId];
		visited.insert(memId);
		if (expr->type == SSAExprType::ePhi) {
			for (SSAArgument& exprArg : expr->subExpressions) {
				if (exprArg.type == SSAArgType::eOther && exprArg.location == SSALocation::eBlock)
					continue;
				if (exprArg.type != SSAArgType::eId || exprArg.location != SSALocation::eMem)
					return false;
				if (visited.find(exprArg.ssaId) == visited.end()) {
					if (!isInputMem(exprArg.ssaId, arg, outoffset, visited, retArg, ptrArg)) {
						return false;
					}
				}
			}
			return true;
		}
		else if (expr->type == SSAExprType::eStore) {
			if (expr->subExpressions[1].type == SSAArgType::eId && expr->subExpressions[1].ssaId == ptrArg.ssaId && expr->subExpressions[1].valueoffset == ptrArg.valueoffset) {
				return isInput(arg.replace(expr->subExpressions[2]), outoffset, retArg);
			}
			return isInputMem(expr->subExpressions[0].ssaId, arg, outoffset, visited, retArg, ptrArg);
		}
		else if (expr->type == SSAExprType::eLoad) {
			return isInputMem(expr->subExpressions[0].ssaId, arg, outoffset, visited, retArg, ptrArg);
		}
		else if (expr->type == SSAExprType::eMemOutput) {
			SSAExpression* callExpr = &ssaRep->expressions[expr->subExpressions[0].ssaId];
			for (SSAArgument& arg : callExpr->subExpressions) {
				if (ptrArg.equals(arg)) {
					return false;
				}
			}
			return isInputMem(expr->subExpressions[1].ssaId, arg, outoffset, visited, retArg, ptrArg);

		}
		return false;
	}
	bool SSACalleeCallerRegs::isInput(CalleeArgument arg, uint32_t outoffset, CalleeArgument* retArg) {
		SSAExpression* expr = &ssaRep->expressions[arg.ssaId];
		if (expr->size < arg.size)
			return false;
		if (expr->type == SSAExprType::eAppend) {
			uint32_t poffset = outoffset;
			HId id = 0;
			for (SSAArgument& argIt : expr->subExpressions) {
				if (!isInput(arg.replace(argIt), poffset, retArg)) {
					return false;
				}
				poffset += argIt.size;
			}
			return true;
		}
		else if (expr->type == SSAExprType::eLoad) {
			std::set<HId> visited;
			return isInputMem(expr->subExpressions[0].ssaId, arg, outoffset, visited, retArg, expr->subExpressions[1]);
		}
		else if (expr->type == SSAExprType::eInput) {
			if (expr->location == SSALocation::eReg) {
				if (!retArg->ssaId)
					retArg[0] = arg;
				return *retArg == arg && arg.offset == outoffset;
			}
		}
		return false;
	}
	bool SSACalleeCallerRegs::doTransformation(Binary* binary, Function* function) {

		ssaRep = &function->ssaRep;

		for (SSAExpression& expr : ssaRep->expressions) {
			if (expr.type != SSAExprType::eReturn)
				continue;
			for (SSAArgument& arg : expr.subExpressions) {
				if (!(arg.type == SSAArgType::eId && arg.location == SSALocation::eReg))
					continue;
				
				HId id = 0;
				CalleeArgument retArg;
				bool succ = isInput(arg, 0, &retArg);
				if (succ) {
					arg.ssaId = retArg.ssaId;
					arg.valueoffset = retArg.valueoffset;
				}
			}
		}
		return false;
	}

}