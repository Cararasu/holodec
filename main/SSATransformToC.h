#ifndef SSATRANSFORMTOC_H
#define SSATRANSFORMTOC_H

#include "SSATransformer.h"
namespace holodec {

	struct CArgument {
		HId id;
		HId ssaId;
		StringRef regRef;
	};
	struct UnifiedExprs {
		HId id;
		std::set<HId> occuringIds;
	};

	struct SSATransformToC : public SSATransformer {

		Binary* binary;
		Function* function;
		HSet<HId> resolveIds;
		HIdList<CArgument> arguments;
		HIdList<UnifiedExprs> unifiedExprs;

		virtual bool doTransformation (Binary* binary, Function* function);

		UnifiedExprs* getUnifiedExpr(HId uId);

		void printBasicBlock(SSABB& bb);
		void printExpression(SSAExpression& expression);
		void resolveArgs(SSAExpression& expression, const char* delimiter = ", ");
		void resolveArgWithoutOffset(SSAArgument& arg);
		void resolveArg(SSAArgument& arg);
		void resolveMemArg(SSAArgument& arg, uint32_t size);
		void resolveExpression(SSAExpression& expression);
		bool shouldResolve(SSAExpression& expr);

		bool shouldResolve(HId id);
	};

}

#endif // SSATRANSFORMTOC_H
