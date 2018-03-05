#include "SSAAssignmentSimplifier.h"
#include "Argument.h"

#include "General.h"
#include "SSA.h"
#include "Function.h"
#include "Binary.h"


namespace holodec{
	
	bool SSAAssignmentSimplifier::doTransformation (Binary* binary, Function* function){
		
		printf ("Simplifying Assignments for Function at Address 0x%" PRIx64 "\n", function->baseaddr);
		
		HMap<HId, SSAArgument> replacements;

		replacements.clear();
		for(SSAExpression& expr : function->ssaRep.expressions){
			if(!expr.id)
				continue;
			if(expr.type == SSAExprType::ePhi) {
				bool undef = true;
				SSAArgument cmpArg;
				cmpArg.type = SSAArgType::eId;
				cmpArg.ssaId = 0;
				bool alwaysTheSame = true;
					
				for (size_t i = 0; i < expr.subExpressions.size(); i += 2) {
					//SSAArgument& blockArg = expr.subExpressions[i];
					SSAArgument& arg = expr.subExpressions[i + 1];
					if (arg.type == SSAArgType::eId && arg.ssaId == expr.id)
						continue;
					if (cmpArg.type == SSAArgType::eId && cmpArg.ssaId == 0)
						cmpArg = arg;
					if(arg.type != SSAArgType::eUndef){
						undef = false;
					}
					if(!weak_equals(arg, cmpArg)){
						alwaysTheSame = false;
					}
				}
				if(undef){
					replacements.insert(std::pair<HId, SSAArgument>(expr.id, SSAArgument::createUndef (expr.location, expr.locref, expr.size)));
				}else if(alwaysTheSame){
					replacements.insert(std::pair<HId, SSAArgument>(expr.id, cmpArg));
				}
			}
		}
		if(replacements.empty())
			return false;
		function->ssaRep.replaceNodes(&replacements);
		function->ssaRep.compress();
		return true;
	}
}