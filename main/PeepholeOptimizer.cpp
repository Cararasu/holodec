#include "PeepholeOptimizer.h"


#include <fstream>
#include <cctype>
#include "SSAPeepholeOptimizer.h"

namespace holodec {


	typedef std::function<void (Architecture*, SSARepresentation*, MatchContext*) > PhExecutor;

	struct PhRule {
		HId argIndex;
		SSAExprType type;
		std::vector<PhRule*> subRules;
		PhExecutor executor;

		PhRule (HId argIndex, SSAExprType type) : argIndex (argIndex), type (type) {}

		bool matchRule (Architecture* arch, SSARepresentation* ssaRep, SSAExpression* expr, MatchContext* context) {
			if (argIndex && argIndex <= expr->subExpressions.size() && expr->subExpressions[argIndex - 1].type == SSAArgType::eId)
				expr = &ssaRep->expressions[expr->subExpressions[argIndex - 1].ssaId];
			if (type != SSAExprType::eInvalid) {
				if (type != expr->type)
					return false;
				context->expressionsMatched.push_back (expr->id);
			}
			for (PhRule* rule : subRules) {
				rule->matchRule (arch, ssaRep, expr, context);
			}
			if (executor)
				executor (arch, ssaRep, context);
		}
	};

	struct PhRuleSet {
		PhRule baserule = PhRule (0, SSAExprType::eInvalid);
	};

	struct RuleBuilder {
		PhRuleSet* ruleSet;
		PhRule* rule;

		RuleBuilder (PhRuleSet& ruleSet) : ruleSet (&ruleSet), rule (&ruleSet.baserule) {}

		RuleBuilder& ssaType (HId index, SSAExprType type) {
			for (PhRule* itRule : rule->subRules) {
				if (itRule->argIndex == index && itRule->type == type) {
					rule = itRule;
					return *this;
				}
			}
			PhRule* newRule = new PhRule (index, type);
			rule->subRules.push_back (newRule);
			rule = newRule;
			return *this;
		}

		RuleBuilder& execute (PhExecutor executor) {
			if (rule)
				rule->executor = executor;
		}

		RuleBuilder& build() {
			rule = &ruleSet->baserule;
		}
	};

	PeepholeOptimizer* parsePhOptimizer (Architecture* arch, Function& func) {

		PhRuleSet ruleSet;

		RuleBuilder builder (ruleSet);

		builder.ssaType (0, SSAExprType::eFlag).ssaType (1, SSAExprType::eOp).execute ([] (Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& flagExpr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& opExpr = ssaRep->expressions[context->expressionsMatched[1]];
			if (opExpr.opType == SSAOpType::eSub && flagExpr.flagType == SSAFlagType::eZ) {

				flagExpr.type = SSAExprType::eOp;
				flagExpr.opType = SSAOpType::eEq;
				
				if (opExpr.subExpressions.size() > 2) {
					SSAExpression addExpr;
					addExpr.type = SSAExprType::eOp;
					addExpr.size = opExpr.size;
					addExpr.returntype = opExpr.returntype;
					addExpr.opType = SSAOpType::eAdd;
					addExpr.subExpressions.insert (addExpr.subExpressions.begin(), opExpr.subExpressions.begin() + 1, opExpr.subExpressions.end());
					addExpr.instrAddr = opExpr.instrAddr;
					
					flagExpr.subExpressions = {opExpr.subExpressions[0], SSAArgument::create(ssaRep->addBefore (&addExpr, opExpr.id), addExpr.size)};
					
				} else if (opExpr.subExpressions.size() == 2) {
					flagExpr.subExpressions = opExpr.subExpressions;
				}

				ssaRep->changeRefCount(opExpr.id, -1);
			}
		});

		for (SSAExpression& expr : func.ssaRep.expressions) {
			MatchContext context;
			ruleSet.baserule.matchRule (arch, &func.ssaRep, &expr, &context);

		}

		return nullptr;
	}

}
