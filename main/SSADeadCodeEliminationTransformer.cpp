#include "SSADeadCodeEliminationTransformer.h"
#include <set>

#include "SSA.h"
#include "Function.h"
#include "Argument.h"
#include "General.h"

namespace holodec {

	void SSADeadCodeEliminationTransformer::addNewUse(HId id, std::set<HId>* visited){
		SSAExpression& expr = ssaRep->expressions[id];
		
		if(visited->find(id) != visited->end())
			return ;
		visited->insert(id);
		
		if (expr.type & SSA_EXPR_TRANSIENT_NODE){
			++usecount[id - 1];
			for(SSAArgument& arg : expr.subExpressions){
				if(arg.ssaId){
					addNewUse(arg.ssaId, visited);
				}
			}
		}else{
			++usecount[id - 1];
		}
	}
	
	void SSADeadCodeEliminationTransformer::doTransformation (Function* function) {

		printf ("DCE for Function at Address 0x%llx\n", function->baseaddr);
		
		ssaRep = &function->ssaRep;
		do {
			usecount.clear();
			usecount.resize(ssaRep->expressions.size(), 0);

			for(auto it = ssaRep->expressions.begin(); it != ssaRep->expressions.end(); ++it){
				if (it->type & SSA_EXPR_TRANSIENT_NODE)
					continue;
				for(SSAArgument& arg : it->subExpressions){
					if(arg.ssaId){
						std::set<HId> visited;
						visited.insert(it->id);
						addNewUse(arg.ssaId, &visited);
					}
				}
			}
			HSet<HId> toRemove;
			for (auto it = function->ssaRep.expressions.begin(); it != function->ssaRep.expressions.end();++it){
				if(!it->id)
					continue;
				if(it->type & SSA_EXPR_CONTROL_FLOW)
					continue;
				if(usecount[it->id - 1])
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
