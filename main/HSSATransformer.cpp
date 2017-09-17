#include "HSSATransformer.h"
#include "HFunction.h"
#include "HArchitecture.h"
#include "HSSA.h"

namespace holodec {

	void HSSATransformParser::parseExpression (HSSAExpression* expression) {
		printIndent (1);
		printf ("Parsing Expression: ");
		expression->print (arch);
	}
	void HSSATransformParser::doTransformation (HFunction* function) {
		this->function = function;

		for (HSSAExpression& expr : function->ssaRep.expressions) {
			parseExpression (&expr);
		}
	}

}
