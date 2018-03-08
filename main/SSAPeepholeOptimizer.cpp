#include "SSAPeepholeOptimizer.h"
#include "Function.h"
#include <cassert>
#include <algorithm>

namespace holodec {


	SSAPeepholeOptimizer::SSAPeepholeOptimizer() {

		phOpt = parsePhOptimizer();
	}

	bool SSAPeepholeOptimizer::doTransformation(Binary* binary, Function* function) {

		bool applied = false;

		for (size_t i = 0; i < function->ssaRep.expressions.size();) {
			if (function->ssaRep.expressions.list[i].id && phOpt->ruleSet.match(arch, &function->ssaRep, &function->ssaRep.expressions.list[i])) {
				applied = true;
			}
			else {
				i++;
			}
		}
		return applied;
	}

}
