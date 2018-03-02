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

		virtual bool doTransformation (Binary* binary, Function* function) = 0;
	};

}

#endif // SSATRANSFORMER_H
