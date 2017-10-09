#ifndef HCALLINGCONVENTION_H
#define HCALLINGCONVENTION_H

#include "HString.h"
#include "HGeneral.h"
#include "HId.h"

namespace holodec {

	enum HCCStackPolicy{
		H_CC_STACK_R2L,
		H_CC_STACK_L2R,
	};
	enum HCCParameterType{
		H_CC_PARA_INT,
		H_CC_PARA_FLOAT,
		H_CC_PARA_VEC128,
		H_CC_PARA_VEC256,
		H_CC_PARA_MAX
	};
#define H_CC_MAX_ARGS (16)

	struct HCallingConvention {
		HId id;
		HString name;
		HList<HString> callerSaved;
		HString parameters[H_CC_PARA_MAX][H_CC_MAX_ARGS];
		HString parameterCount;
		HString returns[H_CC_PARA_MAX][H_CC_MAX_ARGS];
		HString stack;
		HCCStackPolicy stackPolicy;
		
		void relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer) {
			HId newid = gen->next();
			if (replacer)
				replacer (id, newid);
			id = newid;
		}
	};
	
}

#endif // HCALLINGCONVENTION_H
