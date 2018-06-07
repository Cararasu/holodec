#pragma once

#include "SSATransformer.h"

namespace holodec {

	class SSAApplyRegRef : public SSATransformer {
		Function* function;

		bool getRegisterState(Register* reg, int64_t* arithchange, SSAArgument* arg);

		virtual bool doTransformation(Binary* binary, Function* function);

	};

}

