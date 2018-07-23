#include "SSAReverseRegUsageAnalyzer.h"

namespace holodec {


	SSAReverseRegUsageAnalyzer::SSAReverseRegUsageAnalyzer()
	{
	}


	SSAReverseRegUsageAnalyzer::~SSAReverseRegUsageAnalyzer()
	{
	}

	bool SSAReverseRegUsageAnalyzer::doTransformation(Binary* binary, Function* function) {
		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (expr.type == SSAExprType::eCall) {
				if (expr.subExpressions[0].isConst(SSAType::eUInt)) {
					Function* callingFunc = binary->getFunctionByAddr(expr.subExpressions[0].uval);
					if (callingFunc) {
						for (SSAArgument& arg : expr.subExpressions) {
							//if reg or mem and it is not an undef definition then we add a write, because the input is defined
							if (arg.location == SSALocation::eReg && !(arg.type == SSAArgType::eId && function->ssaRep.expressions[arg.ssaId].type == SSAExprType::eUndef)) {
								callingFunc->usedRegStates.getNewRegisterState(arg.locref.refId)->flags |= UsageFlags::eWrite;
							} else if (arg.location == SSALocation::eMem && !(arg.type == SSAArgType::eId && function->ssaRep.expressions[arg.ssaId].type == SSAExprType::eUndef)) {
								callingFunc->usedRegStates.getNewMemoryState(arg.locref.refId)->flags |= UsageFlags::eWrite;
							}
						}
					}
				}
			} else if (expr.type == SSAExprType::eOutput && expr.location == SSALocation::eReg) {
				if (expr.subExpressions[0].type == SSAArgType::eId) {
					SSAExpression& callExpr = function->ssaRep.expressions[expr.subExpressions[0].ssaId];
					if (callExpr.subExpressions[0].isConst(SSAType::eUInt)) {
						Function* callingFunc = binary->getFunctionByAddr(callExpr.subExpressions[0].uval);
						if (callingFunc) {
							//if reg or mem then it is read after the function is completed
							if (expr.location == SSALocation::eReg) {
								callingFunc->usedRegStates.getNewRegisterState(expr.locref.refId)->flags |= UsageFlags::eRead;
							} else if (expr.location == SSALocation::eMem) {
								callingFunc->usedRegStates.getNewMemoryState(expr.locref.refId)->flags |= UsageFlags::eRead;
							}
						}
					}
				}
			}
		}
		return false;
	}
}