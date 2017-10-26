#include "HSSAPeepholeOptimizer.h"
#include "HFunction.h"

namespace holodec {

	void HSSAPeepholeOptimizer::doTransformation (HFunction* function){
		//Lets see what we need to make this work
		
		HSSARepresentation& rep = function->ssaRep;
		for(HSSABB& bb : rep.bbs){
			
			for(HId exprId : bb.exprIds){
				HSSAExpression& ssaExpr = rep.expressions[exprId];
				
				if(ssaExpr.type == HSSA_EXPR_CJMP && ssaExpr.subExpressions[0].id){
					HSSAExpression& subExpr1 = rep.expressions[ssaExpr.subExpressions[0].id];
					
					if(subExpr1.type == HSSA_EXPR_FLAG && subExpr1.flagType == HSSA_FLAG_Z && subExpr1.subExpressions[0].id){
						HSSAExpression& subExpr2 = rep.expressions[subExpr1.subExpressions[0].id];
						
						if(subExpr2.type == HSSA_EXPR_OP && subExpr2.opType == H_OP_BAND){
							printf("Equality Jump Found\n");
							printf("------------------------------------------------\n");
						}
					}
				}
				
			}
		}
		
	}

}
