#ifndef SSACALLINGCONVAPPLIER_H
#define SSACALLINGCONVAPPLIER_H

#include "SSATransformer.h"
#include "Function.h"

namespace holodec {

	struct SSACallingConvApplier : public SSATransformer{

		virtual bool doTransformation (Function* function);
	};
	
}

#endif // SSACALLINGCONVAPPLIER_H
