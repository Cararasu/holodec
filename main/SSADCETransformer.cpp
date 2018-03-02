#include "SSADCETransformer.h"
#include <set>

#include "SSA.h"
#include "Function.h"
#include "Argument.h"
#include "General.h"

namespace holodec {

	bool SSADCETransformer::doTransformation (Binary* binary, Function* function) {

		printf ("DCE for Function at Address 0x%llx\n", function->baseaddr);
		function->ssaRep.recalcRefCounts();
		bool removed = false;
		ssaRep = &function->ssaRep;
		do {
			HSet<HId> toRemove;
			for (auto it = function->ssaRep.expressions.begin(); it != function->ssaRep.expressions.end();++it){
				if(!it->id || EXPR_HAS_SIDEEFFECT(it->type) || !it->refs.empty())
					continue;
				toRemove.insert(it->id);
			}
			if(toRemove.empty())
				break;
			removed |= !toRemove.empty();
			function->ssaRep.removeNodes(&toRemove);
			printf("Removed %d\n", toRemove.size());
		}while(true);
		function->ssaRep.compress();
		return removed;
	}
}
