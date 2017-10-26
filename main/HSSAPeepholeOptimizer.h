#ifndef HSSAPEEPHOLEOPTIMIZER_H
#define HSSAPEEPHOLEOPTIMIZER_H

#include "HGeneral.h"
#include "HSSA.h"
#include "HSSATransformer.h"
namespace holodec {

		
	struct HArgumentRef{
		HId argIndex;
		bool newArgument;
	};
	
	struct HExpressionRef{
		HArgumentRef exprRef;
		
		HSSAExprType type = HSSA_EXPR_INVALID;
		uint64_t size = 0;
		HSSAType returntype = HSSA_TYPE_UNKNOWN;
		union { //64 bit
			HSSAFlagType flagType;
			HSSAOpType opType;
			HId builtinId;
			HId instrId;
		};
		
	};
	
	class HSSAPeepholeOptimizer : public HSSATransformer {

		virtual void doTransformation (HFunction* function);
	};

}

#endif // HSSAPEEPHOLEOPTIMIZER_H
