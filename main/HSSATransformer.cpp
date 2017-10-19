#include "HSSATransformer.h"
#include "HFunction.h"
#include "HArchitecture.h"
#include "HSSA.h"

namespace holodec {

	void HSSATransformParser::doTransformation (HFunction* function) {
		this->function = function;

		for (HSSABB& bb : function->ssaRep.bbs) {
			parseBlock (&bb);
		}
		
		for(HSSABB& bb : function->ssaRep.bbs){
			for(HId id : bb.exprIds){
				parseExpression (&bb, function->ssaRep.expressions.get(id));
			}
		}
		
		function->ssaRep.compress();
	}

}
