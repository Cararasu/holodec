#include "HSSADeadCodeEliminationTransformer.h"
#include <set>

#include "HSSA.h"
#include "HFunction.h"
#include "HArgument.h"
#include "HGeneral.h"

namespace holodec {

	void HSSADeadCodeEliminationTransformer::addNewUse(HId id, std::set<HId>* visited){
		HSSAExpression& expr = ssaRep->expressions[id];
		
		if(visited->find(id) != visited->end())
			return ;
		visited->insert(id);
		
		if (expr.type & HSSA_EXPR_TRANSIENT_NODE){
			++usecount[id - 1];
			for(HSSAArgument& arg : expr.subExpressions){
				if(arg.id){
					addNewUse(arg.id, visited);
				}
			}
		}else{
			++usecount[id - 1];
		}
	}
	
	void HSSADeadCodeEliminationTransformer::doTransformation (HFunction* function) {

		printf ("DCE for Function at Address 0x%llx\n", function->baseaddr);
		
		ssaRep = &function->ssaRep;
		do {
			usecount.clear();
			usecount.resize(ssaRep->expressions.size(), 0);

			for(auto it = ssaRep->expressions.begin(); it != ssaRep->expressions.end(); ++it){
				if (it->type & HSSA_EXPR_TRANSIENT_NODE)
					continue;
				for(HSSAArgument& arg : it->subExpressions){
					if(arg.id){
						std::set<HId> visited;
						visited.insert(it->id);
						addNewUse(arg.id, &visited);
					}
				}
			}
			HSet<HId> toRemove;
			for (auto it = function->ssaRep.expressions.begin(); it != function->ssaRep.expressions.end();++it){
				if(!it->id)
					continue;
				if(it->type & HSSA_EXPR_CONTROL_FLOW)
					continue;
				if(usecount[it->id - 1])
					continue;
				toRemove.insert(it->id);
			}
			if(toRemove.empty())
				break;
			function->ssaRep.removeNodes(&toRemove);
		}while(true);
	}
}
