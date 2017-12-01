#ifndef HCALLINGCONVENTION_H
#define HCALLINGCONVENTION_H

#include "HString.h"
#include "General.h"

#include "HIdList.h"

namespace holodec {

	enum HCCStackPolicy{
		CC_STACK_R2L,
		CC_STACK_L2R,
	};
	enum HCCParameterTypeFlags{
		CC_PARA_NONE = 0x0,
		CC_PARA_INT = 0x1,
		CC_PARA_FLOAT = 0x2,
		CC_PARA_VEC128 = 0x4,
		CC_PARA_VEC256 = 0x8,
		CC_PARA_ALL = 0xF,
	};
	enum HCCStackAdjust{
		CC_STACK_ADJUST_CALLER,
		CC_STACK_ADJUST_CALLEE,
	};
	enum class CCStackPolicy{
		eR2L = CC_STACK_R2L,
		eL2R = CC_STACK_L2R,
	};
	enum class CCParameterTypeFlags{
		eNone = CC_PARA_NONE,
		eInt = CC_PARA_INT,
		eFloat = CC_PARA_FLOAT,
		eVec128 = CC_PARA_VEC128,
		eVec256 = CC_PARA_VEC256,
		eAll = CC_PARA_ALL,
	};
	enum class CCStackAdjust{
		eCaller = CC_STACK_ADJUST_CALLER,
		eCallee = CC_STACK_ADJUST_CALLEE,
	};
	struct CCParameter{
		StringRef regref;
		Flags<CCParameterTypeFlags> typeflags;
		uint32_t index;
	};

	struct CallingConvention {
		HId id;
		HString name;
		HList<StringRef> nonVolatileReg;
		HList<CCParameter> parameters;
		HList<CCParameter> returns;
		StringRef parameterCount;
		
		StringRef stack;
		CCStackAdjust callerstackadjust;
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
