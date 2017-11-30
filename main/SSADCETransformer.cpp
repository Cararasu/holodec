#include "SSADCETransformer.h"
#include <set>

#include "SSA.h"
#include "Function.h"
#include "Argument.h"
#include "General.h"

namespace holodec {

	void SSADCETransformer::doTransformation (Function* function) {

		printf ("DCE for Function at Address 0x%llx\n", function->baseaddr);
		
		ssaRep = &function->ssaRep;
		do {
			HSet<HId> toRemove;
			for (auto it = function->ssaRep.expressions.begin(); it != function->ssaRep.expressions.end();++it){
				if(!it->id | EXPR_HAS_SIDEEFFECT(it->type) | it->refcount)
					continue;
				toRemove.insert(it->id);
			}
			if(toRemove.empty())
				break;
			function->ssaRep.removeNodes(&toRemove);
		}while(true);
		function->ssaRep.compress();
	}
}
