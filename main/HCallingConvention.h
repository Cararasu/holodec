#ifndef HCALLINGCONVENTION_H
#define HCALLINGCONVENTION_H

#include "HString.h"
#include "HGeneral.h"

namespace holodec {

	enum HCCStackPolicy{
		H_CC_STACK_R2L,
		H_CC_STACK_L2R,
	};
	enum HCCRegSavedPolicy{
		H_CC_STACK_CALLER_SAVED,
		H_CC_STACK_CALLEE_SAVED,
	};
	enum HCCParameterType{
		H_CC_PARA_INT,
		H_CC_PARA_PTR,
		H_CC_PARA_FLOAT,
		H_CC_PARA_VEC128,
		H_CC_PARA_VEC256,
		H_CC_PARA_MAX
	};
	
	struct HCCParameter{
		HString reg[H_CC_PARA_MAX];
	};
	struct HCallingConvention {
		HString name;
		HCCRegSavedPolicy regsaved;
		HList<HString> savedRegs;
		HList<HCCParameter> parameters;
		HString parameterCount;
		HList<HCCParameter> returns;
		HString stack;
		HCCStackPolicy stackPolicy;
	};
	
}

#endif // HCALLINGCONVENTION_H
