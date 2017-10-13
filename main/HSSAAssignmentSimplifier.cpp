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
				if(expr.type == HSSA_EXPR_ASSIGN && !expr.subExpressions[0].isConst()) {
					if(expr.subExpressions[0].type == HSSA_ARGTYPE_ID){
						HArgument arg = expr.subExpressions[0];
						if(expr.regId){
							arg.type = H_ARGTYPE_REG;
							arg.reg = expr.regId;
						}else if(expr.stackId.id){
							arg.type = H_ARGTYPE_STACK;
							arg.stack = expr.stackId;
						}else if(expr.memId){
							arg.type = H_ARGTYPE_MEM;
							arg.index = expr.memId;
						}
						replacements.push_back(std::pair<HId, HArgument>(expr.id, arg));
					}else{
						
					}
				}else if(expr.type == HSSA_EXPR_UNDEF){
					HArgument arg;
					if(expr.regId)
						arg = HArgument::createUnknownReg(expr.regId);
					else if(expr.memId)
						arg = HArgument::createUnknownMem(expr.memId);
					else if(expr.stackId.id)
						arg = HArgument::createUnknownStack(expr.stackId);
					replacements.push_back(std::pair<HId, HArgument>(expr.id, arg));
				}else if(expr.type == HSSA_EXPR_LABEL){
					replacements.push_back(std::pair<HId, HArgument>(expr.id, HArgument::create()));
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
						HArgument arg;
						if(expr.regId)
							arg = HArgument::createUnknownReg(expr.regId);
						else if(expr.memId)
							arg = HArgument::createUnknownMem(expr.memId);
						else if(expr.stackId.id)
							arg = HArgument::createUnknownStack(expr.stackId);
						replacements.push_back(std::pair<HId, HArgument>(expr.id, arg));
					}else if(alwaysTheSame){
						replacements.push_back(std::pair<HId, HArgument>(expr.id, firstArg));
					}
				}else if(expr.type == HSSA_EXPR_SPLIT || expr.type == HSSA_EXPR_UPDATEPART){
					if(expr.subExpressions[0].type == H_ARGTYPE_UNKN){
						HArgument arg;
						if(expr.regId)
							arg = HArgument::createUnknownReg(expr.regId);
						else if(expr.memId)
							arg = HArgument::createUnknownMem(expr.memId);
						else if(expr.stackId.id)
							arg = HArgument::createUnknownStack(expr.stackId);
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