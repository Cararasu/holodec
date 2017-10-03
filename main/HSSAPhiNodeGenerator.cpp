#include "HSSAPhiNodeGenerator.h"
#include "HFunction.h"
#include "HArchitecture.h"

namespace holodec {

	void HSSAPhiNodeGenerator::doTransformation (HFunction* function){
		
		printf("Generating Phi-Nodes for Function at Address 0x%x\n", function->baseaddr);
		
		for(HSSABB& bb : function->ssaRep.bbs){
			printf("BB %d\n", bb.id);
			printf("Address 0x%x - 0x%x\n", bb.startaddr, bb.endaddr);
			for(HId& id : bb.exprIds){
				HSSAExpression* expr = function->ssaRep.expressions.get(id);
				if(expr->regId)
					;//printf("Def: %s\n", arch->getRegister(expr->regId)->name.cstr());
				for(int i = 0; i < expr->subExpressions.size();i++){
					if(expr->subExpressions[i].type == H_ARGTYPE_REG)
						;//printf("Use: %s\n", arch->getRegister(expr->subExpressions[i].reg)->name.cstr());
				}
			}
		}
	}
}
