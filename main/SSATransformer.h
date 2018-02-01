#ifndef SSATRANSFORMER_H
#define SSATRANSFORMER_H


#include "SSA.h"
#include "Binary.h"

namespace holodec {

	struct Architecture;
	struct Function;
	struct SSAExpression;

	struct SSATransformer {
		Architecture* arch;

		virtual void doTransformation (Binary* binary, Function* function) = 0;
	};

	struct SSATransformParser : public SSATransformer {
		Binary* binary;
		Function* function;

		virtual void parseBlock (SSABB* block){};
		
		virtual HList<HId>::iterator parseExpression (SSABB* basicBlock, HList<HId>::iterator it) = 0;

		virtual void doTransformation (Binary* binary, Function* function);
	};

}

#endif // SSATRANSFORMER_H
