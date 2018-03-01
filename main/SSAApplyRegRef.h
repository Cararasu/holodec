#pragma once

#include "SSATransformer.h"

namespace holodec {

	class SSAApplyRegRef : public SSATransformer {

		virtual void doTransformation(Binary* binary, Function* function);

	};

}

