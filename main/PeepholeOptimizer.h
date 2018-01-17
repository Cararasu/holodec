#ifndef PEEPHOLEOPTIMIZER_H
#define PEEPHOLEOPTIMIZER_H

#include "HString.h"
#include "Architecture.h"


namespace holodec {

	struct MatchContext{
		std::vector<HId> expressionsMatched;
	};

	typedef std::function<void (Architecture*, SSARepresentation*, MatchContext*) > PhExecutor;

	struct PhRule {
		HId matchedIndex;
		HId argIndex;
		SSAExprType type;
		SSAOpType opType;
		SSAFlagType flagType;
		std::vector<PhRule*> subRules;
		PhExecutor executor;

		PhRule (HId matchedIndex, HId argIndex, SSAExprType type, SSAOpType opType, SSAFlagType flagType) : matchedIndex (matchedIndex), argIndex (argIndex), type (type), opType (opType), flagType (flagType) {}

		bool matchRule (Architecture* arch, SSARepresentation* ssaRep, SSAExpression* expr, MatchContext* context);
	};
	
	struct PhRuleSet {
		PhRule baserule = PhRule (0, 0, SSAExprType::eInvalid, SSAOpType::eInvalid, SSAFlagType::eUnknown);
	};
	
	struct PeepholeOptimizer {
		
		PhRuleSet ruleSet;
		
		PeepholeOptimizer(){
			
		}
		
		
	};
	
	PeepholeOptimizer* parsePhOptimizer();
}

#endif // PEEPHOLEOPTIMIZER_H
