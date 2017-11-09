#include "SSATransformer.h"
#include "Function.h"
#include "Architecture.h"
#include "SSA.h"

namespace holodec {

	void SSATransformParser::doTransformation (Function* function) {
		this->function = function;

		for (SSABB& bb : function->ssaRep.bbs) {
			parseBlock (&bb);
		}
		
		for(SSABB& bb : function->ssaRep.bbs){
			for(HId id : bb.exprIds){
				parseExpression (&bb, function->ssaRep.expressions.get(id));
			}
		}
		
		function->ssaRep.compress();
	}

}
