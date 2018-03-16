#ifndef SSAADDRESSTOBLOCKTRANSFORMER_H
#define SSAADDRESSTOBLOCKTRANSFORMER_H

#include "SSATransformer.h"
namespace holodec {
	struct SSAAddressToBlockTransformer : public SSATransformer {
		Binary* binary;
		Function* function;
		bool resolveDstTarget(SSABB& block, SSAExpression& expr, SSAArgument& arg);

		virtual bool doTransformation(Binary* binary, Function* function);

	};
}

#endif // SSAADDRESSTOBLOCKTRANSFORMER_H
