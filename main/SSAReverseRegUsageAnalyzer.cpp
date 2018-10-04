#include "SSAReverseRegUsageAnalyzer.h"

namespace holodec {


	SSAReverseRegUsageAnalyzer::SSAReverseRegUsageAnalyzer(){
	}


	SSAReverseRegUsageAnalyzer::~SSAReverseRegUsageAnalyzer(){
	}

	bool SSAReverseRegUsageAnalyzer::doTransformation(Binary* binary, Function* function) {
		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (expr.type == SSAExprType::eCall) {
				SSAExpression* dstExpr = find_baseexpr(&function->ssaRep, expr.subExpressions[0]);
				if (dstExpr->isConst(SSAType::eUInt)) {
					Function* callingFunc = binary->getFunctionByAddr(dstExpr->uval);
					if (callingFunc) {
						for (SSAArgument& arg : expr.subExpressions) {
							//if reg or mem and it is not an undef definition then we add a write, because the input is defined
							if (arg.ref.isLocation(SSALocation::eReg) && !(arg.type == SSAArgType::eId && function->ssaRep.expressions[arg.ssaId].type == SSAExprType::eUndef)) {
								callingFunc->usedRegStates.getNewRegisterState(arg.ref.id)->flags |= UsageFlags::eWrite;
							} else if (arg.ref.isLocation(SSALocation::eMem) && !(arg.type == SSAArgType::eId && function->ssaRep.expressions[arg.ssaId].type == SSAExprType::eUndef)) {
								callingFunc->usedRegStates.getNewMemoryState(arg.ref.id)->flags |= UsageFlags::eWrite;
							}
						}
					}
				}
			} else if (expr.type == SSAExprType::eOutput && expr.ref.isLocation(SSALocation::eReg)) {
				if (expr.subExpressions[0].type == SSAArgType::eId) {
					SSAExpression& callExpr = function->ssaRep.expressions[expr.subExpressions[0].ssaId];
					SSAExpression* dstExpr = find_baseexpr(&function->ssaRep, callExpr.subExpressions[0]);
					if (dstExpr->isConst(SSAType::eUInt)) {
						Function* callingFunc = binary->getFunctionByAddr(dstExpr->uval);
						if (callingFunc) {
							//if reg or mem then it is read after the function is completed
							if (expr.ref.isLocation(SSALocation::eReg)) {
								callingFunc->usedRegStates.getNewRegisterState(expr.ref.id)->flags |= UsageFlags::eRead;
							} else if (expr.ref.isLocation(SSALocation::eMem)) {
								callingFunc->usedRegStates.getNewMemoryState(expr.ref.id)->flags |= UsageFlags::eRead;
							}
						}
					}
				}
			}
		}
		return false;
	}
}