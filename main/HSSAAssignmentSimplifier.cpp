#include "HSSAAssignmentSimplifier.h"
#include "HArgument.h"
#include "HId.h"
#include "HGeneral.h"
#include "HSSA.h"
#include "HFunction.h"


namespace holodec{
	
	void HSSAAssignmentSimplifier::doTransformation (HFunction* function){
		
		printf ("Simplifying Assignments for Function at Address 0x%x\n", function->baseaddr);
		
		HList<std::pair<HId, HSSAArgument>> replacements;
		
		while(true){
			replacements.clear();
			for(HSSAExpression& expr : function->ssaRep.expressions){
				if(expr.type == HSSA_EXPR_ASSIGN && !expr.subExpressions[0].isConst()) {
					if(expr.subExpressions[0].type == HSSA_ARGTYPE_ID){
						HSSAArgument arg = expr.subExpressions[0];
						if(expr.regId){
							arg.type = HSSA_ARGTYPE_REG;
							arg.refId = expr.regId;
						}else if(expr.stackId.id){
							arg.type = HSSA_ARGTYPE_STACK;
							arg.refId = expr.stackId.id;
							arg.wusl = expr.stackId.index;
						}else if(expr.memId){
							arg.type = HSSA_ARGTYPE_MEM;
							arg.refId = expr.memId;
						}
						replacements.push_back(std::pair<HId, HSSAArgument>(expr.id, arg));
					}else{
						
					}
				}else if(expr.type == HSSA_EXPR_UNDEF){
					HSSAArgument arg;
					if(expr.regId)
						arg = HSSAArgument::createReg(expr.regId, expr.size);
					else if(expr.memId)
						arg = HSSAArgument::createMem(expr.memId, expr.size);
					else if(expr.stackId.id)
						arg = HSSAArgument::createStck(expr.stackId.id, expr.size, expr.stackId.index);
					replacements.push_back(std::pair<HId, HSSAArgument>(expr.id, arg));
				}else if(expr.type == HSSA_EXPR_LABEL){
					replacements.push_back(std::pair<HId, HSSAArgument>(expr.id, HSSAArgument::create()));
				}else if(expr.type == HSSA_EXPR_PHI) {
					bool undef = true;
					HSSAArgument& firstArg = expr.subExpressions[0];
					bool alwaysTheSame = true;
					
					for(HSSAArgument& arg : expr.subExpressions){
						if(arg.type != HIR_ARGTYPE_UNKN){
							undef = false;
						}
						if(arg != firstArg){
							alwaysTheSame = false;
						}
					}
					if(undef){
						HSSAArgument arg;
						if(expr.regId)
							arg = HSSAArgument::createReg(expr.regId, expr.size);
						else if(expr.memId)
							arg = HSSAArgument::createMem(expr.memId);
						else if(expr.stackId.id)
							arg = HSSAArgument::createStck(expr.stackId.id, expr.stackId.index, expr.size);
						replacements.push_back(std::pair<HId, HSSAArgument>(expr.id, arg));
					}else if(alwaysTheSame){
						replacements.push_back(std::pair<HId, HSSAArgument>(expr.id, firstArg));
					}
				}else if(expr.type == HSSA_EXPR_SPLIT || expr.type == HSSA_EXPR_UPDATEPART){
					if(expr.subExpressions[0].type == HIR_ARGTYPE_UNKN){
						HSSAArgument arg;
						if(expr.regId)
							arg = HSSAArgument::createReg(expr.regId, expr.size);
						else if(expr.memId)
							arg = HSSAArgument::createMem(expr.memId);
						else if(expr.stackId.id)
							arg = HSSAArgument::createStck(expr.stackId.id, expr.stackId.index, expr.size);
						replacements.push_back(std::pair<HId, HSSAArgument>(expr.id, arg));
					}
				}
			}
			if(replacements.empty())
				break;
			function->ssaRep.replaceNodes(&replacements);
		}
	}
}