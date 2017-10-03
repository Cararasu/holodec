#include "HSSATransformer.h"
#include "HFunction.h"
#include "HArchitecture.h"
#include "HSSA.h"

namespace holodec {

	void HSSATransformParser::parseBlock (HSSABB* block) {
		printIndent (1);
		printf ("Parsing Block: %d\n", block->id);
	}
	void HSSATransformParser::parseExpression (HSSAExpression* expression) {
		printIndent (1);
		printf ("Parsing Expression: ");
		expression->print (arch);
	}
	void HSSATransformParser::doTransformation (HFunction* function) {
		this->function = function;

		for (HSSABB& bb : function->ssaRep.bbs) {
			parseBlock (&bb);
		}
		
		for (HSSAExpression& expr : function->ssaRep.expressions) {
			parseExpression (&expr);
		}
	}

}
