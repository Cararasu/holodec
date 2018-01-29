#include "PeepholeOptimizer.h"


#include <fstream>
#include <cctype>
#include "SSAPeepholeOptimizer.h"

namespace holodec {

	bool PhRule::matchRule (Architecture* arch, SSARepresentation* ssaRep, SSAExpression* expr, MatchContext* context) {
		bool matched = false;
		if (matchedIndex && matchedIndex <= context->expressionsMatched.size()) {
			expr = &ssaRep->expressions[context->expressionsMatched[matchedIndex - 1]];
			matched = true;
		}
		if (argIndex && argIndex <= expr->subExpressions.size() && expr->subExpressions[argIndex - 1].type == SSAArgType::eId) {
			expr = &ssaRep->expressions[expr->subExpressions[argIndex - 1].ssaId];
			matched = true;
		}
		if (type != SSAExprType::eInvalid && type == expr->type)
			matched = true;
		else if (type != SSAExprType::eInvalid)
			return false;
		if (opType != SSAOpType::eInvalid && opType == expr->opType)
			matched = true;
		else if (opType != SSAOpType::eInvalid)
			return false;
		if (flagType != SSAFlagType::eUnknown && flagType == expr->flagType)
			matched = true;
		else if (flagType != SSAFlagType::eUnknown)
			return false;
		if (matched)
			context->expressionsMatched.push_back (expr->id);
		for (PhRule* rule : subRules) {
			rule->matchRule (arch, ssaRep, expr, context);
		}
		if (executor)
			executor (arch, ssaRep, context);
		return true;
	}

	struct RuleBuilder {
		PhRuleSet* ruleSet;
		PhRule* rule;

		RuleBuilder (PhRuleSet& ruleSet) : ruleSet (&ruleSet), rule (&ruleSet.baserule) {}

		RuleBuilder& ssaType (HId matchIndex, HId index, SSAExprType type) {
			return ssaType (matchIndex, index, type, SSAOpType::eInvalid, SSAFlagType::eUnknown);
		}
		RuleBuilder& ssaType (HId matchIndex, HId index, SSAExprType type, SSAFlagType flagType) {
			return ssaType (matchIndex, index, type, SSAOpType::eInvalid, flagType);
		}
		RuleBuilder& ssaType (HId matchIndex, HId index, SSAExprType type, SSAOpType opType) {
			return ssaType (matchIndex, index, type, opType, SSAFlagType::eUnknown);
		}
		RuleBuilder& ssaType (HId matchIndex, HId index, SSAExprType type, SSAOpType opType, SSAFlagType flagType) {
			for (PhRule* itRule : rule->subRules) {
				if (itRule->argIndex == index && itRule->type == type && itRule->opType == opType && itRule->flagType == flagType) {
					rule = itRule;
					return *this;
				}
			}
			PhRule* newRule = new PhRule (matchIndex, index, type, opType, flagType);
			rule->subRules.push_back (newRule);
			rule = newRule;
			return *this;
		}

		RuleBuilder& execute (PhExecutor executor) {
			if (rule)
				rule->executor = executor;
			return *this;
		}

		RuleBuilder& build() {
			rule = &ruleSet->baserule;
			return *this;
		}
	};

	PeepholeOptimizer* parsePhOptimizer () {

		PeepholeOptimizer* peephole_optimizer = new PeepholeOptimizer();

		RuleBuilder builder (peephole_optimizer->ruleSet);

		builder
		.ssaType (0, 0, SSAExprType::eFlag, SSAFlagType::eC)
		.ssaType (0, 1, SSAExprType::eOp, SSAOpType::eSub)
		.execute ([] (Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& flagExpr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& opExpr = ssaRep->expressions[context->expressionsMatched[1]];
			flagExpr.type = SSAExprType::eOp;
			flagExpr.opType = SSAOpType::eLower;

			if (opExpr.subExpressions.size() > 2) {
				SSAExpression addExpr;
				addExpr.type = SSAExprType::eOp;
				addExpr.size = opExpr.size;
				addExpr.returntype = opExpr.returntype;
				addExpr.opType = SSAOpType::eAdd;
				addExpr.subExpressions.insert (addExpr.subExpressions.begin(), opExpr.subExpressions.begin() + 1, opExpr.subExpressions.end());
				addExpr.instrAddr = opExpr.instrAddr;

				flagExpr.subExpressions = {opExpr.subExpressions[0], SSAArgument::create (ssaRep->addBefore (&addExpr, opExpr.id), addExpr.size) };

			} else if (opExpr.subExpressions.size() == 2) {
				flagExpr.subExpressions = {opExpr.subExpressions[0], opExpr.subExpressions[1]};
			}
		});

		return peephole_optimizer;
	}

}
