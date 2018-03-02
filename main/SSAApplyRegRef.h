#pragma once

#include "SSATransformer.h"

namespace holodec {

	class SSAApplyRegRef : public SSATransformer {

		virtual bool doTransformation(Binary* binary, Function* function);

	};

}

