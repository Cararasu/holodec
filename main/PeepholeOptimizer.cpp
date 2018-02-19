#include "PeepholeOptimizer.h"


#include <fstream>
#include <cctype>
#include "SSAPeepholeOptimizer.h"

namespace holodec {

	bool PhRule::matchRule (Architecture* arch, SSARepresentation* ssaRep, SSAExpression* expr, MatchContext* context) {
		bool matched = false;
		if (matchedIndex) {
			if (matchedIndex <= context->expressionsMatched.size()) {
				expr = &ssaRep->expressions[context->expressionsMatched[matchedIndex - 1]];
				matched = true;
			}
			else {
				return false;
			}
		}

		if (argIndex) {
			if (argIndex <= expr->subExpressions.size() && expr->subExpressions[argIndex - 1].type == SSAArgType::eId) {
				expr = &ssaRep->expressions[expr->subExpressions[argIndex - 1].ssaId];
				matched = true;
			}
			else {
				return false;
			}
		}

		if (type != SSAExprType::eInvalid)
			if(type == expr->type)
				matched = true;
			else
				return false;

		if (opType != SSAOpType::eInvalid)
			if (opType == expr->opType)
				matched = true;
			else
				return false;

		if (flagType != SSAFlagType::eUnknown)
			if (flagType == expr->flagType)
				matched = true;
			else
				return false;

		if (matched)
			context->expressionsMatched.push_back (expr->id);
		for (PhRule* rule : subRules) {
			if (rule->matchRule(arch, ssaRep, expr, context))
				return true;
		}
		if (executor && executor(arch, ssaRep, context)) {
			return true;
		}
		return false;
	}

	struct RuleBuilder {
		PhRuleSet* ruleSet;
		PhRule* rule;

		RuleBuilder (PhRuleSet& ruleSet) : ruleSet (&ruleSet), rule (&ruleSet.baserule) {}

		RuleBuilder& ssaType(HId matchIndex, HId index, SSAFlagType flagType) {
			return ssaType(matchIndex, index, SSAExprType::eFlag, SSAOpType::eInvalid, flagType);
		}
		RuleBuilder& ssaType(HId matchIndex, HId index, SSAOpType opType) {
			return ssaType(matchIndex, index, SSAExprType::eOp, opType, SSAFlagType::eUnknown);
		}
		RuleBuilder& ssaType (HId matchIndex, HId index, SSAExprType type, SSAOpType opType = SSAOpType::eInvalid, SSAFlagType flagType = SSAFlagType::eUnknown) {
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
	bool usedOnlyInFlags(SSARepresentation* ssaRep, SSAExpression& expr) {
		for (auto it = expr.refs.begin(); it != expr.refs.end();++it) {//iterate refs
			if (ssaRep->expressions[*it].type != SSAExprType::eFlag)
				return false;
		}
		return true;
	}

	void replaceValue(SSARepresentation* ssaRep, SSAExpression& origExpr, SSAArgument replaceArg) {
		for (auto it = origExpr.refs.begin(); it != origExpr.refs.end();) {//iterate refs
			SSAExpression& expr = ssaRep->expressions[*it];
			if (replaceArg.ssaId == *it)
				printf("-------------\n");
			if (expr.type == SSAExprType::eFlag) {//ignore flags because they are operation specific
				++it;
				continue;
			}
			if (replaceArg.type == SSAArgType::eId && replaceArg.ssaId == origExpr.id) {//don't replace refs and args if replace is the same
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id) {
						arg.replace(replaceArg);
					}
				}
				++it;
			}
			else {
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id) {
						arg.replace(replaceArg);
						if (replaceArg.type == SSAArgType::eId)
							ssaRep->expressions[replaceArg.ssaId].refs.push_back(*it);
					}
				}
				it = origExpr.refs.erase(it);
			}
		}
	}
	void replaceAllValues(SSARepresentation* ssaRep, SSAExpression& origExpr, SSAArgument replaceArg) {
		for (auto it = origExpr.refs.begin(); it != origExpr.refs.end();) {//iterate refs
			SSAExpression& expr = ssaRep->expressions[*it];
			if (replaceArg.ssaId == origExpr.id) {//don't replace refs and args if replace is the same
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id) {
						arg.replace(replaceArg);
					}
				}
				++it;
			}
			else {
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id) {
						arg.replace(replaceArg);
						if (replaceArg.type == SSAArgType::eId)
							ssaRep->expressions[replaceArg.ssaId].refs.push_back(*it);
					}
				}
				it = origExpr.refs.erase(it);
			}
		}
	}

	PeepholeOptimizer* parsePhOptimizer () {

		PeepholeOptimizer* peephole_optimizer = new PeepholeOptimizer();

		RuleBuilder builder (peephole_optimizer->ruleSet);
		
		builder
		.ssaType (0, 0, SSAFlagType::eC)
		.ssaType (1, 1, SSAOpType::eSub)
		.execute ([] (Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& flagExpr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& opExpr = ssaRep->expressions[context->expressionsMatched[1]];
			flagExpr.type = SSAExprType::eOp;
			flagExpr.opType = SSAOpType::eLower;

			if (opExpr.subExpressions.size() > 2) {
				SSAExpression addExpr;
				addExpr.type = SSAExprType::eOp;
				addExpr.size = opExpr.size;
				addExpr.exprtype = opExpr.exprtype;
				addExpr.opType = SSAOpType::eAdd;
				addExpr.subExpressions.insert (addExpr.subExpressions.begin(), opExpr.subExpressions.begin() + 1, opExpr.subExpressions.end());
				addExpr.instrAddr = opExpr.instrAddr;

				flagExpr.subExpressions = {opExpr.subExpressions[0], SSAArgument::createId(ssaRep->addBefore (&addExpr, opExpr.id), addExpr.size) };

			} else if (opExpr.subExpressions.size() == 2) {
				flagExpr.subExpressions = {opExpr.subExpressions[0], opExpr.subExpressions[1]};
			}
			return true;
		});
		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression&  expr = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr.type != SSAExprType::eAppend)
				return false;

			SSAArgument baseArg = expr.subExpressions[0];
			uint64_t offset = baseArg.offset;

			for (SSAArgument& arg : expr.subExpressions) {
				if (arg.type != SSAArgType::eId && arg.ssaId == baseArg.ssaId) {
					return false;
				}

				if (arg.offset == offset) {
					offset += arg.size;
				}
			}
			if (offset == expr.size) {
				expr.type = SSAExprType::eAssign;
				baseArg.size = offset - baseArg.offset;
				expr.subExpressions = { baseArg };
				return true;
			}
			return false;
		});
		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAOpType::eAdd)
		.ssaType(1, 3, SSAFlagType::eC)
		.ssaType(2, 1, SSAOpType::eAdd)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {

			SSAExpression& firstAdd = ssaRep->expressions[context->expressionsMatched[2]];
			SSAExpression& carryExpr = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& secondAdd = ssaRep->expressions[context->expressionsMatched[0]];
			if (firstAdd.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 || usedOnlyInFlags(ssaRep, secondAdd) || carryExpr.subExpressions[0].size != firstAdd.size)
				return false;

			SSAExpression combine1;
			combine1.type = SSAExprType::eAppend;
			combine1.exprtype = firstAdd.exprtype;
			combine1.instrAddr = firstAdd.instrAddr;
			combine1.subExpressions = {
				firstAdd.subExpressions[0],
				secondAdd.subExpressions[0]
			};
			combine1.size = firstAdd.subExpressions[0].size + secondAdd.subExpressions[0].size;

			SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addBefore(&combine1, secondAdd.id), combine1.size);

			SSAExpression combine2;
			combine2.type = SSAExprType::eAppend;
			combine2.exprtype = firstAdd.exprtype;
			combine2.instrAddr = firstAdd.instrAddr;
			combine2.subExpressions = {
				firstAdd.subExpressions[1],
				secondAdd.subExpressions[1]
			};
			combine2.size = firstAdd.subExpressions[1].size + secondAdd.subExpressions[1].size;

			SSAArgument combine2Arg = SSAArgument::createId(ssaRep->addAfter(&combine2, combine1Arg.ssaId), combine2.size);

			//SSAExpression addExpr;
			//addExpr.type = SSAExprType::eOp;
			//addExpr.opType = SSAOpType::eAdd;
			uint64_t secsize = secondAdd.size;
			secondAdd.exprtype = secondAdd.exprtype;
			secondAdd.instrAddr = secondAdd.instrAddr;
			secondAdd.subExpressions = { combine1Arg, combine2Arg };
			secondAdd.size += firstAdd.size;

			SSAArgument addArg = SSAArgument::createId(secondAdd.id, secsize);

			SSAArgument splitArg2 = addArg;
			splitArg2.size = secsize;
			splitArg2.offset = firstAdd.size;
			if (splitArg2.ssaId == 0x06 && splitArg2.size == 0x08 && splitArg2.offset == 0x10)
				printf("");
			replaceAllValues(ssaRep, secondAdd, splitArg2);

			SSAArgument splitArg1 = addArg;
			splitArg1.size = firstAdd.size;
			splitArg1.offset = 0;
			//assert(!(splitArg1.ssaId == 0x06 && splitArg1.size == 0x08 && splitArg1.offset == 0x10));
			replaceValue(ssaRep, firstAdd, splitArg1);

			return true;
		});
		builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAExprType::eOp)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if ((expr.opType == SSAOpType::eSub || expr.opType == SSAOpType::eXor) && expr.subExpressions.size() == 2 && expr.subExpressions[0] == expr.subExpressions[1] && !usedOnlyInFlags(ssaRep, expr)) {
				replaceValue(ssaRep, expr, SSAArgument::createUVal(0, expr.size));
				return true;
			}
			return false;
		});
		builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAExprType::eAssign)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAArgument& arg = expr.subExpressions[0];
			if (arg.isConst()) {
				if (arg.type == SSAArgType::eUInt) {
					replaceValue(ssaRep, expr, SSAArgument::createUVal(arg.uval >> arg.offset, arg.size));
					return true;
				}
				else if (arg.type == SSAArgType::eSInt) {
					replaceValue(ssaRep, expr, SSAArgument::createUVal(arg.sval >> arg.offset, arg.size));
					return true;
				}
			}
			return false;
		});/*
		builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAOpType::eAdd)
			.ssaType(0, 0, SSAOpType::eAdd)
			.ssaType(0, 0, SSAExprType::eAssign)
			.ssaType(0, 0, SSAExprType::eAssign)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAArgument& arg = expr.subExpressions[0];
			if (arg.isConst()) {
				if (arg.type == SSAArgType::eUInt) {
					replaceValue(ssaRep, expr, SSAArgument::createUVal(arg.uval >> arg.offset, arg.size));
					return true;
				}
				else if (arg.type == SSAArgType::eSInt) {
					replaceValue(ssaRep, expr, SSAArgument::createUVal(arg.sval >> arg.offset, arg.size));
					return true;
				}
			}
			return false;
		});*/
		return peephole_optimizer;
	}
}
