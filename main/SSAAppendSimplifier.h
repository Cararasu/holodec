#pragma once

#include "SSATransformer.h"

namespace holodec {
	class SSAAppendSimplifier : public SSATransformer {

		virtual bool doTransformation(Binary* binary, Function* function);

	};


}