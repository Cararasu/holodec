#ifndef PEEPHOLEOPTIMIZER_H
#define PEEPHOLEOPTIMIZER_H

#include "HString.h"
#include "Architecture.h"
#include "HoloIO.h"


namespace holodec {

	struct MatchContext{
		std::vector<HId> expressionsMatched;
	};

	extern Logger g_peephole_logger;

	typedef std::function<bool (Architecture*, SSARepresentation*, MatchContext*) > PhExecutor;


	struct PhRule {
		HId matchedIndex;//select the ith matched expression
		HId argIndex;//select the ith indexed expression
		SSAExprType type;
		SSAOpType opType;
		SSAFlagType flagType;

		PhRule (HId matchedIndex, HId argIndex, SSAExprType type, SSAOpType opType, SSAFlagType flagType) : matchedIndex (matchedIndex), argIndex (argIndex), type (type), opType (opType), flagType (flagType) {}

		bool matchRule (Architecture* arch, SSARepresentation* ssaRep, SSAExpression* expr, MatchContext* context);
	};
	struct PhRuleInstance {
		std::vector<PhRule> rules;
		PhExecutor executor;

		bool match(Architecture* arch, SSARepresentation* ssaRep, SSAExpression* expr);
	};
	
	struct PhRuleSet {
		std::vector<PhRuleInstance> ruleInstances;
		bool match(Architecture* arch, SSARepresentation* ssaRep, SSAExpression* expr) {
			if ((expr->isOp() && ssaRep->usedOnlyInFlags(*expr)) || !expr->directRefs.size()) return false;
			for (PhRuleInstance& inst : ruleInstances) {
				if (inst.match(arch, ssaRep, expr)) {
					return true;
				}
			}
			return false;
		}
	};
	
	struct PeepholeOptimizer {
		
		PhRuleSet ruleSet;
		
		PeepholeOptimizer(){
			
		}
		
		
	};
	
	PeepholeOptimizer* parsePhOptimizer();
}

#endif // PEEPHOLEOPTIMIZER_H
