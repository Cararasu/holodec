#include "PeepholeOptimizer.h"


#include <fstream>
#include <cctype>
#include "SSAPeepholeOptimizer.h"

namespace holodec {

	
	typedef std::function<bool (Architecture*, SSARepresentation*, MatchContext*)> PhExecutor;
	
	struct PhRule {
		HId argIndex;
		SSAExprType type;
		std::vector<PhRule*> subRules;
		std::vector<PhExecutor> executors;
		
		PhRule(HId argIndex, SSAExprType type) : argIndex(argIndex), type(type){}
		
		bool matchRule(Architecture* arch, SSARepresentation* ssaRep, SSAExpression* expr, MatchContext* context){
			if(argIndex && argIndex <= expr->subExpressions.size() && expr->subExpressions[argIndex - 1].type == SSAArgType::eId)
				expr = &ssaRep->expressions[expr->subExpressions[argIndex - 1].ssaId];
			if(argIndex)
				printf("--------------------------- Arg %d\n", argIndex);
			if(type != SSAExprType::eInvalid){
				if(type != expr->type)
					return false;
				context->expressionsMatched.push_back(expr->id);
			}
			for(PhRule* rule : subRules){
				rule->matchRule(arch, ssaRep, expr, context);
			}
			for(PhExecutor& phExecutor : executors){
				phExecutor(arch, ssaRep, context);
			}
		}
	};
	
	struct PhRuleSet {
		PhRule baserule = PhRule(0, SSAExprType::eInvalid);
	};
	
	struct RuleBuilder {
		PhRuleSet* ruleSet;
		PhRule* rule;
		
		RuleBuilder(PhRuleSet& ruleSet): ruleSet(&ruleSet), rule(&ruleSet.baserule){}
		
		RuleBuilder& ssaType(HId index, SSAExprType type){
			for(PhRule* itRule : rule->subRules){
				if(itRule->argIndex == index && itRule->type == type){
					rule = itRule;
					return *this;
				}
			}
			PhRule* newRule = new PhRule(index, type);
			rule->subRules.push_back(newRule);
			rule = newRule;
			return *this;
		}
		
		RuleBuilder& execute(PhExecutor executor){
			if(rule)
				rule->executors.push_back(executor);
		}
		
		RuleBuilder& build(){
			rule = &ruleSet->baserule;
		}
	};

	PeepholeOptimizer* parsePhOptimizer (Architecture* arch, Function& func) {
		
		PhRuleSet ruleSet;
		
		RuleBuilder builder(ruleSet);
		builder.ssaType(0, SSAExprType::eCJmp).ssaType(1, SSAExprType::eFlag).execute([](Architecture*, SSARepresentation*, MatchContext*){printf("WWWWWWWWWWW\n");return false;});
		for(SSAExpression& expr : func.ssaRep.expressions){
			MatchContext context;
			ruleSet.baserule.matchRule(arch, &func.ssaRep, &expr, &context);
			
		}
		
		return nullptr;
	}

}
