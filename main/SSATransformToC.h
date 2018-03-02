#ifndef SSATRANSFORMTOC_H
#define SSATRANSFORMTOC_H

#include "SSATransformer.h"
namespace holodec {

	struct CArgument {
		HId id;
		HId ssaId;
		StringRef regRef;
	};

	struct SSATransformToC : public SSATransformer {

		Binary* binary;
		Function* function;
		HSet<HId> resolveIds;
		HIdList<CArgument> arguments;

		virtual bool doTransformation (Binary* binary, Function* function);

		void printBasicBlock(SSABB& bb);
		void printExpression(SSAExpression& expression);
		void resolveArgs(SSAExpression& expression, const char* delimiter = ", ");
		void resolveArg(SSAArgument& arg);
		void resolveExpression(SSAExpression& expression);
		bool shouldResolve(SSAExpression& expr);

		bool shouldResolve(HId id);
	};

}

#endif // SSATRANSFORMTOC_H
