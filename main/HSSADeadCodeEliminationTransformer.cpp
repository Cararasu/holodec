#include "HSSADeadCodeEliminationTransformer.h"
#include <set>
#include "HId.h"
#include "HSSA.h"
#include "HFunction.h"
#include "HArgument.h"
#include "HGeneral.h"

namespace holodec {

	void HSSADeadCodeEliminationTransformer::doTransformation (HFunction* function) {

		printf ("DCE for Function at Address 0x%x\n", function->baseaddr);
		
		do {
			std::set<HId> usedIds;

			for (HSSAExpression& expr : function->ssaRep.expressions) {
				for (HArgument& arg : expr.subExpressions) {
					if (arg.id)
						usedIds.insert (arg.id);
				}
			}

			HList<std::pair<HId, HArgument>> replacements;
			
			for (HSSAExpression& expr : function->ssaRep.expressions) {
				if(!(expr.type & HSSA_EXPR_CONTROL_FLOW)) {
					if (usedIds.find (expr.id) == usedIds.end())
						replacements.push_back (std::pair<HId, HArgument> (expr.id, HArgument::create()));
				}
			}

			function->ssaRep.replaceNodes (&replacements);
			if (replacements.empty())
				break;

		} while (true);

	}
}
