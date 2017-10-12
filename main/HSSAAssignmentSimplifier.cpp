#include "HSSAAssignmentSimplifier.h"
#include "HArgument.h"
#include "HId.h"
#include "HGeneral.h"
#include "HSSA.h"
#include "HFunction.h"


namespace holodec{
	
	void HSSAAssignmentSimplifier::doTransformation (HFunction* function){
		
		printf ("Simplifying Assignments for Function at Address 0x%x\n", function->baseaddr);
		
		HList<std::pair<HId, HArgument>> replacements;
		
		while(true){
			replacements.clear();
			for(HSSAExpression& expr : function->ssaRep.expressions){
				if(expr.type == HSSA_EXPR_ASSIGN) {
					replacements.push_back(std::pair<HId, HArgument>(expr.id, expr.subExpressions[0]));
				}else if(expr.type == HSSA_EXPR_UNDEF){
					HArgument arg = HArgument::createUnknown();
					if(expr.regId)
						arg.reg = HArgument::createUnknownReg(expr.regId);
					else if(expr.memId)
						arg.reg = HArgument::createUnknownMem(expr.memId);
					replacements.push_back(std::pair<HId, HArgument>(expr.id, arg));
				}else if(expr.type == HSSA_EXPR_LABEL){
					replacements.push_back(std::pair<HId, HArgument>(expr.id, HArgument::createUnknown()));
				}else if(expr.type == HSSA_EXPR_PHI) {
					bool undef = true;
					HArgument& firstArg = expr.subExpressions[0];
					bool alwaysTheSame = true;
					
					for(HArgument& arg : expr.subExpressions){
						if(arg.type != H_ARGTYPE_UNKN){
							undef = false;
						}
						if(arg != firstArg){
							alwaysTheSame = false;
						}
					}
					if(undef){
						HArgument arg = HArgument::createUnknown();
						if(expr.regId)
							arg.reg = HArgument::createUnknownReg(expr.regId);
						else if(expr.memId)
							arg.reg = HArgument::createUnknownMem(expr.memId);
						replacements.push_back(std::pair<HId, HArgument>(expr.id, arg));
					}else if(alwaysTheSame){
						replacements.push_back(std::pair<HId, HArgument>(expr.id, firstArg));
					}
				}else if(expr.type == HSSA_EXPR_SPLIT || expr.type == HSSA_EXPR_UPDATEPART){
					if(expr.subExpressions[0].type == H_ARGTYPE_UNKN){
						HArgument arg = HArgument::createUnknown();
						if(expr.regId)
							arg.reg = HArgument::createUnknownReg(expr.regId);
						else if(expr.memId)
							arg.reg = HArgument::createUnknownMem(expr.memId);
						replacements.push_back(std::pair<HId, HArgument>(expr.id, arg));
					}
				}
			}
			if(replacements.empty())
				break;
			function->ssaRep.replaceNodes(&replacements);
		}
	}
}