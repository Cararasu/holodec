#ifndef HSSATRANSFORMER_H
#define HSSATRANSFORMER_H


#include "HSSA.h"
namespace holodec {

	class HArchitecture;
	class HFunction;
	class HSSAExpression;

	struct HSSATransformer {
		HId id;
		HArchitecture* arch;

		virtual void doTransformation (HFunction* function) = 0;
	};

	struct HSSATransformParser : public HSSATransformer {
		HFunction* function;

		virtual void parseBlock (HSSABB* block){};
		
		virtual void parseExpression (HSSABB* basicBlock, HSSAExpression* expression){};

		virtual void doTransformation (HFunction* function);
	};

}

#endif // HSSATRANSFORMER_H
