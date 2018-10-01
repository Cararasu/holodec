#pragma once

#include "SSATransformer.h"

namespace holodec {

	struct SSARedundancyElimination : public SSATransformer {
		Binary* binary;
		Function* function;

		virtual bool doTransformation(Binary* binary, Function* function);

	};

}