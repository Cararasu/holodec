#include "HSSADeadCodeEliminationTransformer.h"
#include <set>

#include "HSSA.h"
#include "HFunction.h"
#include "HArgument.h"
#include "HGeneral.h"

namespace holodec {

	void HSSADeadCodeEliminationTransformer::doTransformation (HFunction* function) {

		printf ("DCE for Function at Address 0x%llx\n", function->baseaddr);
		
		do {
			std::set<HId> usedIds;

			for (HSSAExpression& expr : function->ssaRep.expressions) {
				if(!expr.id)
					continue;
				for (HSSAArgument& arg : expr.subExpressions) {
					if (arg.id)
						usedIds.insert (arg.id);
				}
			}
			
			HList<std::pair<HId, HSSAArgument>> replacements;
			bool replaced = false;
			for (auto it = function->ssaRep.expressions.begin(); it != function->ssaRep.expressions.end();++it){
				if(it->id && !(it->type & HSSA_EXPR_CONTROL_FLOW)) {
					if (usedIds.find (it->id) == usedIds.end()){
						replacements.push_back(std::pair<HId, HSSAArgument>(it->id,HSSAArgument::create(HSSA_ARGTYPE_UNKN)));
					}
				}
			}
			
			function->ssaRep.replaceNodes(&replacements);
			if (!replaced)
				break;

		} while (true);

	}
}
