#include "SSAPeepholeOptimizer.h"
#include "Function.h"
#include <cassert>
#include <algorithm>

namespace holodec {


	SSAPeepholeOptimizer::SSAPeepholeOptimizer() {

		phOpt = parsePhOptimizer();
	}

	bool SSAPeepholeOptimizer::doTransformation(Binary* binary, Function* function) {

		printf("Peephole Optimization\n");
		uint32_t rules_executed = 0;

		SSARepresentation copy = function->ssaRep;
		for (size_t i = 0; i < function->ssaRep.expressions.size();) {
			if (function->ssaRep.expressions.list[i].id && phOpt->ruleSet.match(arch, &function->ssaRep, &function->ssaRep.expressions.list[i])) {
				rules_executed++;
				//function->ssaRep.print(arch);
				//fflush(stdout);
				if (!function->ssaRep.checkIntegrity()) {
					printf("Old SSA ----------------------------------------------\n");
					copy.print(arch);
					printf("New SSA ----------------------------------------------\n");
					function->ssaRep.print(arch);
					fflush(stdout);
					*((char*)0) = 12;
				}
			}
			else {
				i++;
			}
		}
		printf("Rules Executed %" PRIu32 "\n", rules_executed);
		return rules_executed != 0;
	}

}
