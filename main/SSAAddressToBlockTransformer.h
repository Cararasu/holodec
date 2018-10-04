#pragma once

#include "SSATransformer.h"

namespace holodec {
	struct SSAAddressToBlockTransformer : public SSATransformer {
		Binary* binary;
		Function* function;
		bool resolveDstTarget(SSABB& block, SSAExpression& expr, SSAArgument& arg);

		virtual bool doTransformation(Binary* binary, Function* function);

	};
}

