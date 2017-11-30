#ifndef HCALLINGCONVENTION_H
#define HCALLINGCONVENTION_H

#include "HString.h"
#include "General.h"

#include "HIdList.h"

namespace holodec {

	enum HCCStackPolicy{
		H_CC_STACK_R2L,
		H_CC_STACK_L2R,
	};
	enum CCStackPolicy{
		eR2L = H_CC_STACK_R2L,
		eL2R = H_CC_STACK_L2R,
	};
	enum HCCParameterTypeFlags{
		H_CC_PARA_INT = 0x1,
		H_CC_PARA_FLOAT = 0x2,
		H_CC_PARA_VEC128 = 0x4,
		H_CC_PARA_VEC256 = 0x8,
		H_CC_PARA_ALL = 0xF,
	};
	enum CCParameterTypeFlags{
		eInt = H_CC_PARA_INT,
		eFloat = H_CC_PARA_FLOAT,
		eVec128 = H_CC_PARA_VEC128,
		eVec256 = H_CC_PARA_VEC256,
		eAll = H_CC_PARA_ALL,
	};
	struct CCParameter{
		StringRef regref;
		uint32_t typeflags;
		uint32_t index;
	};
	enum HCCStackAdjust{
		H_CC_STACK_ADJUST_CALLER,
		H_CC_STACK_ADJUST_CALLEE,
	};
	enum CCStackAdjust{
		eCaller = H_CC_STACK_ADJUST_CALLER,
		eCallee = H_CC_STACK_ADJUST_CALLEE,
	};

	struct CallingConvention {
		HId id;
		HString name;
		HList<StringRef> nonVolatileReg;
		HList<CCParameter> parameters;
		HList<CCParameter> returns;
		StringRef parameterCount;
		
		StringRef stack;
		bool callerstackadjust;
		CCStackPolicy stackPolicy;
		
		void relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer) {
			HId newid = gen->next();
			if (replacer)
				replacer (id, newid);
			id = newid;
		}
	};
	
}

#endif // HCALLINGCONVENTION_H
