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
			SSAExpression& expr = function->ssaRep.expressions[i + 1];

			if (!phOpt->ruleSet.match(arch, &function->ssaRep, &expr)) {
				i++;
			}
			else {
				applied = true;
			}
		}
		return applied;
	}

}
