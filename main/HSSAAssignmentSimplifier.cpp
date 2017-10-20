#include "HSSAAssignmentSimplifier.h"
#include "HArgument.h"

#include "HGeneral.h"
#include "HSSA.h"
#include "HFunction.h"


namespace holodec{
	
	void HSSAAssignmentSimplifier::doTransformation (HFunction* function){
		
		printf ("Simplifying Assignments for Function at Address 0x%x\n", function->baseaddr);
		
		HMap<HId, HSSAArgument> replacements;
		
		while(true){
			replacements.clear();
			for(HSSAExpression& expr : function->ssaRep.expressions){
				if(!expr.id)
					continue;
				if(expr.type == HSSA_EXPR_ASSIGN && !expr.subExpressions[0].isConst()) {
					if(expr.subExpressions[0].type == HSSA_ARGTYPE_ID){
						HSSAArgument arg = expr.subExpressions[0];
						switch(expr.location){
						case HSSA_LOCATION_REG:
							arg.type = HSSA_ARGTYPE_REG;
							arg.ref = expr.locref;
							break;
						case HSSA_LOCATION_STACK:
							arg.type = HSSA_ARGTYPE_STACK;
							arg.ref = expr.locref;
							break;
						case HSSA_LOCATION_MEM:
							arg.type = HSSA_ARGTYPE_MEM;
							arg.ref = expr.locref;
							break;
						default:
							break;
						}
						replacements.insert(std::pair<HId, HSSAArgument>(expr.id, arg));
					}else{
						
					}
				}else if(expr.type == HSSA_EXPR_UNDEF){
					HSSAArgument arg;
					switch(expr.location){
					case HSSA_LOCATION_REG:
						arg = HSSAArgument::createReg(expr.locref, expr.size);
						break;
					case HSSA_LOCATION_STACK:
						arg = HSSAArgument::createStck(expr.locref, expr.size);
						break;
					case HSSA_LOCATION_MEM:
						arg = HSSAArgument::createMem(expr.locref.refId, expr.size);
						break;
					default:
						break;
					}
					replacements.insert(std::pair<HId, HSSAArgument>(expr.id, arg));
				}else if(expr.type == HSSA_EXPR_LABEL){
					replacements.insert(std::pair<HId, HSSAArgument>(expr.id, HSSAArgument::create()));
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
						switch(expr.location){
						case HSSA_LOCATION_REG:
							arg = HSSAArgument::createReg(expr.locref, expr.size);
							break;
						case HSSA_LOCATION_STACK:
							arg = HSSAArgument::createMem(expr.locref.refId);
							break;
						case HSSA_LOCATION_MEM:
							arg = HSSAArgument::createStck(expr.locref, expr.size);
							break;
						default:
							break;
						}
						replacements.insert(std::pair<HId, HSSAArgument>(expr.id, arg));
					}else if(alwaysTheSame){
						replacements.insert(std::pair<HId, HSSAArgument>(expr.id, firstArg));
					}
				}else if(expr.type == HSSA_EXPR_SPLIT || expr.type == HSSA_EXPR_UPDATEPART){
					if(expr.subExpressions[0].type == HIR_ARGTYPE_UNKN){
						HSSAArgument arg;
						switch(expr.location){
						case HSSA_LOCATION_REG:
							arg = HSSAArgument::createReg(expr.locref, expr.size);
							break;
						case HSSA_LOCATION_STACK:
							arg = HSSAArgument::createMem(expr.locref.refId);
							break;
						case HSSA_LOCATION_MEM:
							arg = HSSAArgument::createStck(expr.locref, expr.size);
							break;
						default:
							break;
						}
						replacements.insert(std::pair<HId, HSSAArgument>(expr.id, arg));
					}
				}
			}
			if(replacements.empty())
				break;
			function->ssaRep.replaceNodes(&replacements);
			function->ssaRep.compress();
		}
	}
}