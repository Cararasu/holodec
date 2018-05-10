#pragma once

#include "SSATransformer.h"

namespace holodec {

	class SSAReverseRegUsageAnalyzer : public SSATransformer {
	public:
		SSAReverseRegUsageAnalyzer();
		virtual ~SSAReverseRegUsageAnalyzer();


		virtual bool doTransformation(Binary* binary, Function* function);

	};


}
