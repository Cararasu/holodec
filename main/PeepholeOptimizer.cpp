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

	void replaceValue(SSARepresentation* ssaRep, SSAExpression& origExpr, SSAArgument replaceArg) {
		for (auto it = origExpr.refs.begin(); it != origExpr.refs.end();) {//iterate refs
			SSAExpression& expr = ssaRep->expressions[*it];
			if (expr.type == SSAExprType::eFlag) {//ignore flags because they are operation specific
				++it;
				continue;
			}
			if (replaceArg.ssaId == origExpr.id) {//don't replace refs and args if replace is the same
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id)
						arg = replaceArg;
				}
				++it;
			}
			else {
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.type == SSAArgType::eId && arg.ssaId == origExpr.id) {
						arg = replaceArg;
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
		});
		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAExprType::eAppend)
		.ssaType(1, 1, SSAExprType::eSplit)
		.ssaType(1, 2, SSAExprType::eSplit)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			uint64_t offset = 0;
			SSAExpression&  expr = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr.type != SSAExprType::eAppend)
				return false;

			SSAArgument baseArg;
			{
				SSAArgument arg = expr.subExpressions[0];
				if (arg.type != SSAArgType::eId) {
					return false;
				}
				SSAExpression& splitExpr = ssaRep->expressions[arg.ssaId];
				if (splitExpr.type != SSAExprType::eSplit)
					return false;
				baseArg = splitExpr.subExpressions[0];
			}

			for (SSAArgument& arg : expr.subExpressions) {
				if (arg.type != SSAArgType::eId) {
					return false;
				}
				SSAExpression& splitExpr = ssaRep->expressions[arg.ssaId];
				if (splitExpr.type != SSAExprType::eSplit || baseArg != splitExpr.subExpressions[0])
					return false;

				if (splitExpr.subExpressions[1].uval == offset) {
					offset += splitExpr.subExpressions[2].uval;
				}
			}
			if (offset == expr.size) {
				assert(offset == baseArg.size);//TODO needs an additional split

				expr.type = SSAExprType::eAssign;
				expr.subExpressions = { baseArg };
			}
		});
		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAOpType::eAdd)
		.ssaType(1, 3, SSAFlagType::eC)
		.ssaType(2, 1, SSAOpType::eAdd)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {

			SSAExpression& firstAdd = ssaRep->expressions[context->expressionsMatched[2]];
			SSAExpression& secondAdd = ssaRep->expressions[context->expressionsMatched[0]];
			if (firstAdd.subExpressions.size() != 2)
				return;
			if (secondAdd.subExpressions.size() != 3)
				return;
			bool nonflag = false;
			for (auto it = secondAdd.refs.begin(); it != secondAdd.refs.end();++it) {
				SSAExpression& expr = ssaRep->expressions[*it];
				if (expr.type != SSAExprType::eFlag) {
					nonflag = true;
					break;
				}
			}
			if (!nonflag)
				return;

			SSAExpression combine1;
			combine1.type = SSAExprType::eAppend;
			combine1.exprtype = firstAdd.exprtype;
			combine1.instrAddr = firstAdd.instrAddr;
			combine1.subExpressions = {
				firstAdd.subExpressions[0],
				secondAdd.subExpressions[0]
			};
			combine1.size = firstAdd.subExpressions[0].size + firstAdd.subExpressions[0].size;

			SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addAfter(&combine1, secondAdd.id), combine1.size);

			SSAExpression combine2;
			combine2.type = SSAExprType::eAppend;
			combine2.exprtype = firstAdd.exprtype;
			combine2.instrAddr = firstAdd.instrAddr;
			combine2.subExpressions = {
				firstAdd.subExpressions[1],
				secondAdd.subExpressions[1]
			};
			combine2.size = firstAdd.subExpressions[1].size + firstAdd.subExpressions[1].size;

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

			SSAExpression split1;
			split1.type = SSAExprType::eSplit;
			split1.exprtype = firstAdd.exprtype;
			split1.instrAddr = firstAdd.instrAddr;
			split1.subExpressions = {
				SSAArgument::createId(addArg.ssaId, addArg.size),
				SSAArgument::createUVal(0, arch->bitbase),
				SSAArgument::createUVal(firstAdd.size, arch->bitbase)
			};
			split1.size = firstAdd.size;
			SSAArgument split1Arg = SSAArgument::createId(ssaRep->addAfter(&split1, addArg.ssaId), split1.size);
			replaceValue(ssaRep, firstAdd, split1Arg);

			SSAExpression split2;
			split2.type = SSAExprType::eSplit;
			split2.exprtype = secondAdd.exprtype;
			split2.instrAddr = secondAdd.instrAddr;
			split2.subExpressions = {
				SSAArgument::createId(addArg.ssaId, addArg.size),
				SSAArgument::createUVal(firstAdd.size, arch->bitbase),
				SSAArgument::createUVal(secondAdd.size, arch->bitbase)
			};
			split2.size = secsize;
			SSAArgument split2Arg = SSAArgument::createId(ssaRep->addAfter(&split2, split1Arg.ssaId), split2.size);
			replaceValue(ssaRep, secondAdd, split2Arg);
			return;
		});
		builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAExprType::eOp)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if ((expr.opType == SSAOpType::eSub || expr.opType == SSAOpType::eXor) && expr.subExpressions.size() == 2 && expr.subExpressions[0] == expr.subExpressions[0])
				replaceValue(ssaRep, expr, SSAArgument::createUVal(0, expr.size));

			return;
		});
		builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAExprType::eSplit)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr.subExpressions[0].isConst()) {
				if (expr.subExpressions[0].type == SSAArgType::eUInt)
					replaceValue(ssaRep, expr, SSAArgument::createUVal(expr.subExpressions[0].uval >> expr.subExpressions[1].uval, expr.subExpressions[2].uval));
				else if (expr.subExpressions[0].type == SSAArgType::eSInt)
					replaceValue(ssaRep, expr, SSAArgument::createUVal(expr.subExpressions[0].sval >> expr.subExpressions[1].uval, expr.subExpressions[2].uval));
			}

			return;
		});
		return peephole_optimizer;
	}
}
