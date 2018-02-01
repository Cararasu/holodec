#include "SSATransformer.h"
#include "Function.h"
#include "Architecture.h"
#include "SSA.h"

namespace holodec {

	void SSATransformParser::doTransformation (Binary* binary, Function* function) {
		this->binary = binary;
		this->function = function;

		for (SSABB& bb : function->ssaRep.bbs) {
			parseBlock (&bb);
		}
		
		for(SSABB& bb : function->ssaRep.bbs){
			for(auto it = bb.exprIds.begin(); it != bb.exprIds.end(); ++it){
				it = parseExpression (&bb, it);
			}
		}
		
		function->ssaRep.compress();
	}

}
