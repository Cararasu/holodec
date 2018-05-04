#include "SSAAppendSimplifier.h"



namespace holodec {

	bool SSAAppendSimplifier::doTransformation(Binary* binary, Function* function) {

		printf("Simplifying Appends for Function at Address 0x%" PRIx64 "\n", function->baseaddr);

		uint32_t replaced = 0;

		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (expr.type != SSAExprType::eAppend)
				continue;
			for (auto argIt = expr.subExpressions.begin(); argIt != expr.subExpressions.end(); ++argIt) {
				if (argIt->type == SSAArgType::eId && argIt->location != SSALocation::eMem) {
					SSAExpression& subExpr = function->ssaRep.expressions[argIt->ssaId];
					if (subExpr.type != SSAExprType::eAppend)
						continue;
					if (argIt->offset == 0 && subExpr.size == argIt->size)
						continue;

					uint32_t offset = 0;
					for (SSAArgument& subArg : subExpr.subExpressions) {
						if (argIt->offset == offset && argIt->size == subArg.size) {
							expr.setArgument(&function->ssaRep, argIt, subArg);
							replaced++;
							break;
						}
						offset += subArg.size;
					}
				}
			}
		}
		printf("Replaced %" PRId64 "\n", replaced);

		return replaced != 0;
	}
}