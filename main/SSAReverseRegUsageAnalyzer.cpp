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
				if (expr.subExpressions[0].type == SSAArgType::eUInt) {
					Function* callingFunc = binary->getFunctionByAddr(expr.subExpressions[0].uval);
					if (callingFunc) {
						for (SSAArgument& arg : expr.subExpressions) {
							if (arg.location == SSALocation::eReg && !(arg.type == SSAArgType::eId && function->ssaRep.expressions[arg.ssaId].type == SSAExprType::eUndef)) {
								callingFunc->usedRegStates.getNewRegisterState(arg.locref.refId)->flags |= UsageFlags::eWrite;
							}
							if (arg.location == SSALocation::eMem && !(arg.type == SSAArgType::eId && function->ssaRep.expressions[arg.ssaId].type == SSAExprType::eUndef)) {
								callingFunc->usedRegStates.getNewMemoryState(arg.locref.refId)->flags |= UsageFlags::eWrite;
							}
						}
					}
				}
			} else if (expr.type == SSAExprType::eOutput && expr.location == SSALocation::eReg) {
				if (expr.subExpressions[0].type == SSAArgType::eId) {
					Function* callingFunc = binary->getFunctionByAddr(expr.subExpressions[0].ssaId);
					if (callingFunc) {
						if (expr.location == SSALocation::eReg) {
							callingFunc->usedRegStates.getNewRegisterState(expr.locref.refId)->flags |= UsageFlags::eRead;
						}
						if (expr.location == SSALocation::eMem) {
							callingFunc->usedRegStates.getNewMemoryState(expr.locref.refId)->flags |= UsageFlags::eRead;
						}
					}
				}
			}
		}
		return false;
	}
}