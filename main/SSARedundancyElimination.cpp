#include "SSARedundancyElimination.h"




namespace holodec {

	//reduced expressions that appear twice but do the same
	//complexity is n^2 per basic block. Is this improvable?
	bool SSARedundancyElimination::doTransformation(Binary* binary, Function* function) {

		this->binary = binary;
		this->function = function;
		uint32_t applied = 0;

		for (SSABB& block : function->ssaRep.bbs) {
			for (auto iit = block.exprIds.begin(); iit != block.exprIds.end(); iit++) {
				if (EXPR_IS_CONTROLFLOW(function->ssaRep.expressions[*iit].type)) continue;
				for (auto jit = iit + 1; jit != block.exprIds.end(); jit++) {
					if (weak_equals(function->ssaRep.expressions[*iit], function->ssaRep.expressions[*jit])) {
						if (function->ssaRep.expressions[*jit].directRefs.size()) {
							//always replace the second with the first otherwise ordering becomes an issue
							function->ssaRep.replaceAllExprs(function->ssaRep.expressions[*jit], SSAArgument::createId(*iit));
							applied++;
						}
					}
				}
			}
		}
		printf("Removes %" PRId32 " duplicate Expressions\n", applied);
		return applied != 0;
	}
}