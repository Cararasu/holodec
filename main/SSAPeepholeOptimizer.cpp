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

		SSARepresentation copy = function->ssaRep;
		for (size_t i = 0; i < function->ssaRep.expressions.size();) {
			if (function->ssaRep.expressions.list[i].id && phOpt->ruleSet.match(arch, &function->ssaRep, &function->ssaRep.expressions.list[i])) {
				if (!function->ssaRep.checkIntegrity()) {
					printf("Old SSA ----------------------------------------------\n");
					copy.print(arch);
					printf("New SSA ----------------------------------------------\n");
					function->ssaRep.print(arch);
					fflush(stdout);
					*((char*)0) = 12;
				}
				applied = true;
			}
			else {
				i++;
			}
		}
		return applied;
	}

}
