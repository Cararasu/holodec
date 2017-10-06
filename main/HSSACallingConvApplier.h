#ifndef HSSACALLINGCONVAPPLIER_H
#define HSSACALLINGCONVAPPLIER_H

#include "HSSATransformer.h"
#include "HFunction.h"

namespace holodec {

	struct HSSACallingConvApplier : public HSSATransformer{

		virtual void doTransformation (HFunction* function);
	};
	
}

#endif // HSSACALLINGCONVAPPLIER_H
