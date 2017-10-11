#include "HSSAAssignmentSimplifier.h"
#include "HArgument.h"
#include "HId.h"
#include "HGeneral.h"
#include "HSSA.h"
#include "HFunction.h"


namespace holodec{
	
	void HSSAAssignmentSimplifier::doTransformation (HFunction* function){
		
		HList<std::pair<HId, HArgument>> replacements;
		
		
		while(true){
			replacements.clear();
			for(HSSAExpression& expr : function->ssaRep.expressions){
				if(expr.type == HSSA_EXPR_ASSIGN) {
					replacements.push_back(std::pair<HId, HArgument>(expr.id, expr.subExpressions[0]));
				}else if(expr.type == HSSA_EXPR_UNDEF){
					HArgument arg = HArgument::createUnknown();
					if(expr.regId)
						arg.reg = expr.regId;
					replacements.push_back(std::pair<HId, HArgument>(expr.id, arg));
				}
			}
			function->ssaRep.replaceNodes(&replacements);
			replacements.clear();
			for(HSSAExpression& expr : function->ssaRep.expressions){
				if(expr.type == HSSA_EXPR_PHI) {
					bool undef = true;
					HArgument& firstArg = expr.subExpressions[0];
					bool alwaysTheSame = true;
					
					for(HArgument& arg : expr.subExpressions){
						if(arg.type != H_ARGTYPE_UNKN_REG){
							undef = false;
						}
						if(arg != firstArg){
							alwaysTheSame = false;
						}
					}
					if(undef){
						HArgument arg = HArgument::createUnknown();
						if(expr.regId)
							arg.reg = expr.regId;
						replacements.push_back(std::pair<HId, HArgument>(expr.id, arg));
					}else if(alwaysTheSame){
						replacements.push_back(std::pair<HId, HArgument>(expr.id, firstArg));
					}
				}
			}
			if(replacements.empty())
				break;
			function->ssaRep.replaceNodes(&replacements);
		}
	}
}