#include "SSARedundancyElimination.h"




namespace holodec {

	//reduced expressions that appear twice but do the same
	//complexity is n^2 per basic block. Is this improvable?
	bool SSARedundancyElimination::doTransformation(Binary* binary, Function* function) {

		this->binary = binary;
		this->function = function;
		uint32_t applied = 0;

		for (SSABB& block : function->ssaRep.bbs) {
			for (HId iid : block.exprIds) {
				if (EXPR_IS_CONTROLFLOW(function->ssaRep.expressions[iid].type)) continue;
				for (HId jid : block.exprIds) {
					if (iid != jid) {
						if (weak_equals(function->ssaRep.expressions[iid], function->ssaRep.expressions[jid])) {
							if (function->ssaRep.expressions[jid].directRefs.size()) {
								function->ssaRep.replaceExpr(function->ssaRep.expressions[iid], SSAArgument::createId(jid));
								applied++;
								printf("");
							}
						}
					}
				}
			}
		}
		printf("Removes %" PRId32 " duplicate Expressions\n", applied);
		return applied != 0;
	}
}