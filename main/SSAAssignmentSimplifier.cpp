#include "SSAAssignmentSimplifier.h"
#include "Argument.h"

#include "General.h"
#include "SSA.h"
#include "Function.h"


namespace holodec{
	
	void SSAAssignmentSimplifier::doTransformation (Function* function){
		
		printf ("Simplifying Assignments for Function at Address 0x%x\n", function->baseaddr);
		
		HMap<HId, SSAArgument> replacements;
		
		while(true){
			replacements.clear();
			for(SSAExpression& expr : function->ssaRep.expressions){
				if(!expr.id)
					continue;
				if(expr.type == SSA_EXPR_ASSIGN/* && !expr.subExpressions[0].isConst()*/) {
					if(expr.subExpressions[0].type == SSA_ARGTYPE_ID){
						SSAArgument arg = expr.subExpressions[0];
						switch(expr.location){
						case SSA_LOCATION_REG:
							arg.type = SSA_ARGTYPE_REG;
							arg.ref = expr.locref;
							break;
						case SSA_LOCATION_STACK:
							arg.type = SSA_ARGTYPE_STACK;
							arg.ref = expr.locref;
							break;
						case SSA_LOCATION_MEM:
							arg.type = SSA_ARGTYPE_MEM;
							arg.ref = expr.locref;
							break;
						default:
							break;
						}
						replacements.insert(std::pair<HId, SSAArgument>(expr.id, arg));
					}else{
						
					}
				}else if(expr.type == SSA_EXPR_UNDEF){
					SSAArgument arg;
					switch(expr.location){
					case SSA_LOCATION_REG:
						arg = SSAArgument::createReg(expr.locref, expr.size);
						break;
					case SSA_LOCATION_STACK:
						arg = SSAArgument::createStck(expr.locref, expr.size);
						break;
					case SSA_LOCATION_MEM:
						arg = SSAArgument::createMem(expr.locref.refId, expr.id);//TODO what is the blockId
						break;
					default:
						break;
					}
					replacements.insert(std::pair<HId, SSAArgument>(expr.id, arg));
				}else if(expr.type == SSA_EXPR_LABEL){
					replacements.insert(std::pair<HId, SSAArgument>(expr.id, SSAArgument::create()));
				}else if(expr.type == SSA_EXPR_PHI) {
					bool undef = true;
					SSAArgument& firstArg = expr.subExpressions[0];
					bool alwaysTheSame = true;
					
					for(SSAArgument& arg : expr.subExpressions){
						if(arg.type != SSA_ARGTYPE_UNKN){
							undef = false;
						}
						if(arg != firstArg){
							alwaysTheSame = false;
						}
					}
					if(undef){
						SSAArgument arg;
						switch(expr.location){
						case SSA_LOCATION_REG:
							arg = SSAArgument::createReg(expr.locref, expr.size);
							break;
						case SSA_LOCATION_STACK:
							arg = SSAArgument::createMem(expr.locref.refId);
							break;
						case SSA_LOCATION_MEM:
							arg = SSAArgument::createStck(expr.locref, expr.size);
							break;
						default:
							break;
						}
						replacements.insert(std::pair<HId, SSAArgument>(expr.id, arg));
					}else if(alwaysTheSame){
						replacements.insert(std::pair<HId, SSAArgument>(expr.id, firstArg));
					}
				}else if(expr.type == SSA_EXPR_SPLIT || expr.type == SSA_EXPR_UPDATEPART){
					if(expr.subExpressions[0].type == SSA_ARGTYPE_UNKN){
						SSAArgument arg;
						switch(expr.location){
						case SSA_LOCATION_REG:
							arg = SSAArgument::createReg(expr.locref, expr.size);
							break;
						case SSA_LOCATION_STACK:
							arg = SSAArgument::createMem(expr.locref.refId);
							break;
						case SSA_LOCATION_MEM:
							arg = SSAArgument::createStck(expr.locref, expr.size);
							break;
						default:
							break;
						}
						replacements.insert(std::pair<HId, SSAArgument>(expr.id, arg));
					}
				}else if(expr.type == SSA_EXPR_LOADADDR){
					if(expr.subExpressions.size() == 5){
						SSAArgument &arg0 = expr.subExpressions[0], &arg1 = expr.subExpressions[1], &arg2 = expr.subExpressions[2], &arg3 = expr.subExpressions[3], &arg4 = expr.subExpressions[4];
						if(arg0.isValue(0)){
							if(arg1.isValue(0)){
								if(arg2.isValue(0)){
									replacements.insert(std::pair<HId, SSAArgument>(expr.id, arg4));
								}else if(arg3.isValue(0)){
									replacements.insert(std::pair<HId, SSAArgument>(expr.id, arg4));
								}
							}else if(arg4.isValue(0)){
								if(arg2.isValue(0)){
									replacements.insert(std::pair<HId, SSAArgument>(expr.id, arg1));
								}else if(arg3.isValue(0)){
									replacements.insert(std::pair<HId, SSAArgument>(expr.id, arg1));
								}
							}
						}
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