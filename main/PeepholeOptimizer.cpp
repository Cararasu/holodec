#include "PeepholeOptimizer.h"


#include <fstream>
#include <cctype>
#include "SSAPeepholeOptimizer.h"

namespace holodec {

	Logger g_peephole_logger = Logger("Peephole");


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
			if (rule->matchRule(arch, ssaRep, expr, context)) {
				return true;
			}
		}
		if (executor) {
			if (executor(arch, ssaRep, context)) {
				//ssaRep->print(arch);
				return true;
			}
			//ssaRep->print(arch);
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
		for (HId id : expr.directRefs) {//iterate refs
			if (ssaRep->expressions[id].type != SSAExprType::eFlag)
				return false;
		}
		return true;
	}

	PeepholeOptimizer* parsePhOptimizer () {

		PeepholeOptimizer* peephole_optimizer = new PeepholeOptimizer();

		RuleBuilder builder (peephole_optimizer->ruleSet);
		
		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression&  expr = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr.type != SSAExprType::eAppend)
				return false;

			if (expr.subExpressions.size() == 2 && expr.subExpressions[1].type == SSAArgType::eUInt && expr.subExpressions[1].uval == 0) {
				expr.type = SSAExprType::eExtend;
				expr.exprtype = SSAType::eUInt;
				expr.subExpressions.pop_back();
				g_peephole_logger.log<LogLevel::eDebug>("Replace Appends with Extend");
				return true;
			}
			auto baseit = expr.subExpressions.begin();
			uint64_t offset = baseit->offset;

			bool replaced = false;

			for (auto it = baseit; it != expr.subExpressions.end(); it++) {
				if (it->type != SSAArgType::eId || (it->type == SSAArgType::eId && it->ssaId != baseit->ssaId)) {
					if (std::distance(baseit, it) > 1 && it->offset == offset) {
						SSAArgument arg = *baseit;
						arg.size = offset - arg.offset;
						it = expr.subExpressions.insert(expr.subExpressions.erase(baseit, it), arg);
						replaced = true;
					}
					baseit = it;
					offset = baseit->offset;
				}
				if (it->type != SSAArgType::eId) {
					baseit = it;
				}

				if (it->offset == offset) {
					offset += it->size;
				}
			}
			if (std::distance(baseit, expr.subExpressions.end()) > 1) {
				SSAArgument arg = *baseit;
				arg.size = offset - arg.offset;
				expr.subExpressions.insert(expr.subExpressions.erase(baseit, expr.subExpressions.end()), arg);
				if (expr.subExpressions.size() == 1) {
					expr.type = SSAExprType::eAssign;
				}
				g_peephole_logger.log<LogLevel::eDebug>("Replace Appends of same Expr at end");
				return true;
			}
			if (replaced) {
				g_peephole_logger.log<LogLevel::eDebug>("Replace Some Appends of same Expr");
			}
			return replaced;
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
			if (firstAdd.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 || carryExpr.subExpressions[0].offset + carryExpr.subExpressions[0].size != firstAdd.size)
				return false;
			g_peephole_logger.log<LogLevel::eDebug>("Replace Add - Carry Add");

			SSAExpression combine1;
			combine1.type = SSAExprType::eAppend;
			combine1.exprtype = firstAdd.exprtype;
			combine1.instrAddr = firstAdd.instrAddr;
			combine1.subExpressions = {
				firstAdd.subExpressions[0],
				secondAdd.subExpressions[0]
			};
			combine1.size = firstAdd.subExpressions[0].size + secondAdd.subExpressions[0].size;

			SSAExpression combine2;
			combine2.type = SSAExprType::eAppend;
			combine2.exprtype = firstAdd.exprtype;
			combine2.instrAddr = firstAdd.instrAddr;
			combine2.subExpressions = {
				firstAdd.subExpressions[1],
				secondAdd.subExpressions[1]
			};
			combine2.size = firstAdd.subExpressions[1].size + secondAdd.subExpressions[1].size;

			assert(combine1.size == combine2.size);

			uint64_t secsize = secondAdd.size;
			secondAdd.exprtype = secondAdd.exprtype;
			secondAdd.instrAddr = secondAdd.instrAddr;
			secondAdd.size += firstAdd.size;

			SSAArgument addArg = SSAArgument::createId(secondAdd.id, secsize);

			SSAArgument splitArg2 = addArg;
			splitArg2.size = secsize;
			splitArg2.offset = firstAdd.size;

			SSAArgument splitArg1 = addArg;
			splitArg1.size = firstAdd.size;
			splitArg1.offset = 0;

			//Expression references invalidated
			SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addBefore(&combine1, secondAdd.id), combine1.size);
			SSAArgument combine2Arg = SSAArgument::createId(ssaRep->addAfter(&combine2, combine1Arg.ssaId), combine2.size);

			//set arguments of second arg
			ssaRep->expressions[context->expressionsMatched[0]].subExpressions = { combine1Arg, combine2Arg };

			ssaRep->replaceAllArgs(firstAdd, splitArg1);
			ssaRep->replaceAllArgs(secondAdd, splitArg2);

			return true;
		});
		builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAOpType::eSub)
			.ssaType(1, 3, SSAFlagType::eC)
			.ssaType(2, 1, SSAOpType::eSub)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& firstSub = ssaRep->expressions[context->expressionsMatched[2]];
			SSAExpression& carryExpr = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& secondSub = ssaRep->expressions[context->expressionsMatched[0]];
			if (firstSub.subExpressions.size() != 2 || secondSub.subExpressions.size() != 3 || carryExpr.subExpressions[0].offset + carryExpr.subExpressions[0].size != firstSub.size)
				return false;
			g_peephole_logger.log<LogLevel::eDebug>("Replace Sub - Carry Sub");

			SSAExpression combine1;
			combine1.type = SSAExprType::eAppend;
			combine1.exprtype = firstSub.exprtype;
			combine1.instrAddr = firstSub.instrAddr;
			combine1.subExpressions = {
				firstSub.subExpressions[0],
				secondSub.subExpressions[0]
			};
			combine1.size = firstSub.subExpressions[0].size + secondSub.subExpressions[0].size;

			SSAExpression combine2;
			combine2.type = SSAExprType::eAppend;
			combine2.exprtype = firstSub.exprtype;
			combine2.instrAddr = firstSub.instrAddr;
			combine2.subExpressions = {
				firstSub.subExpressions[1],
				secondSub.subExpressions[1]
			};
			combine2.size = firstSub.subExpressions[1].size + secondSub.subExpressions[1].size;

			assert(combine1.size == combine2.size);

			SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addBefore(&combine1, secondSub.id), combine1.size);
			SSAArgument combine2Arg = SSAArgument::createId(ssaRep->addAfter(&combine2, combine1Arg.ssaId), combine2.size);

			uint64_t secsize = secondSub.size;
			secondSub.exprtype = secondSub.exprtype;
			secondSub.instrAddr = secondSub.instrAddr;
			secondSub.subExpressions = { combine1Arg, combine2Arg };
			secondSub.size += firstSub.size;

			SSAArgument addArg = SSAArgument::createId(secondSub.id, secsize);

			SSAArgument splitArg2 = addArg;
			splitArg2.size = secsize;
			splitArg2.offset = firstSub.size;

			SSAArgument splitArg1 = addArg;
			splitArg1.size = firstSub.size;
			splitArg1.offset = 0;

			splitArg2.print(arch);
			splitArg1.print(arch);
			ssaRep->replaceAllArgs(firstSub, splitArg1);
			ssaRep->replaceAllArgs(secondSub, splitArg2);

			return true;
		});
		/*
		builder
			.ssaType(0, 0, SSAFlagType::eC)
			.ssaType(1, 1, SSAOpType::eSub)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& flagExpr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& opExpr = ssaRep->expressions[context->expressionsMatched[1]];
			flagExpr.type = SSAExprType::eOp;
			flagExpr.opType = SSAOpType::eLower;
			g_peephole_logger.log<LogLevel::eDebug>("Replace Sub - Carry");

			if (opExpr.subExpressions.size() > 2) {
				SSAExpression addExpr;
				addExpr.type = SSAExprType::eOp;
				addExpr.size = opExpr.size;
				addExpr.exprtype = opExpr.exprtype;
				addExpr.opType = SSAOpType::eAdd;
				addExpr.subExpressions.insert(addExpr.subExpressions.begin(), opExpr.subExpressions.begin() + 1, opExpr.subExpressions.end());
				addExpr.instrAddr = opExpr.instrAddr;

				flagExpr.subExpressions = { opExpr.subExpressions[0], SSAArgument::createId(ssaRep->addBefore(&addExpr, opExpr.id), addExpr.size) };

			}
			else if (opExpr.subExpressions.size() == 2) {
				flagExpr.subExpressions = { opExpr.subExpressions[0], opExpr.subExpressions[1] };
			}
			return true;
		});*/
		builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAExprType::eOp)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if ((expr.opType == SSAOpType::eSub || expr.opType == SSAOpType::eBXor) && expr.subExpressions.size() == 2 && expr.subExpressions[0] == expr.subExpressions[1] && !usedOnlyInFlags(ssaRep, expr)) {
				g_peephole_logger.log<LogLevel::eDebug>("Zero-Op");
				ssaRep->replaceArg(expr, SSAArgument::createUVal(0, expr.size));
				return true;
			}
			return false;
		});
		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAExprType::eAppend)
		.ssaType(1, 1, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr1 = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& expr2 = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr2.subExpressions[0].offset == 0 && expr2.subExpressions[0].size == expr1.size) {
				g_peephole_logger.log<LogLevel::eDebug>("Append %d - Append %d ", context->expressionsMatched[0], context->expressionsMatched[1]);
				HList<SSAArgument> args(expr2.subExpressions.begin() + 1, expr2.subExpressions.end());
				expr2.subExpressions = expr1.subExpressions;
				expr2.subExpressions.insert(expr2.subExpressions.end(), args.begin(), args.end());
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
			if (expr.directRefs.size()) {
				if (arg.isConst()) {
					if (arg.type == SSAArgType::eUInt) {
						g_peephole_logger.log<LogLevel::eDebug>("Replace Const Assigns");
						ssaRep->replaceAllArgs(expr, SSAArgument::createUVal(arg.uval >> arg.offset, arg.size));
						return true;
					}
					else if (arg.type == SSAArgType::eSInt) {
						g_peephole_logger.log<LogLevel::eDebug>("Replace Const Assigns");
						ssaRep->replaceAllArgs(expr, SSAArgument::createUVal(arg.sval >> arg.offset, arg.size));
						return true;
					}
				}
				
				ssaRep->replaceAllArgs(expr, arg);
				return true;
			}
			return false;
		});
		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAExprType::eFlag)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAArgument& arg = expr.subExpressions[0];
			if (arg.offset) {
				g_peephole_logger.log<LogLevel::eDebug>("Set Flag-offset to 0");
				arg.size += arg.offset;
				arg.offset = 0;
				return true;
			}
			return false;
		});
		builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAExprType::eReturn)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			bool replaced = false;
			for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end();) {
				SSAArgument& arg = *it;
				if (arg.type == SSAArgType::eId) {
					SSAExprType type = ssaRep->expressions[arg.ssaId].type;
					if (arg.type == SSAArgType::eId && type == SSAExprType::eInput) {
						it = expr.subExpressions.erase(it);
						replaced = true;
						continue;
					}
				}
				++it;
			}
			if(replaced)
				g_peephole_logger.log<LogLevel::eDebug>("Removed non used Return-args");
			return replaced;
		});
		builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAExprType::eLoadAddr)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr.subExpressions.size() == 5) {
				SSAArgument &arg0 = expr.subExpressions[0], &arg1 = expr.subExpressions[1], &arg2 = expr.subExpressions[2], &arg3 = expr.subExpressions[3], &arg4 = expr.subExpressions[4];
				if (arg0.isValue(0)) {
					if (arg1.isValue(0)) {
						if (arg2.isValue(0) || arg3.isValue(0)) {
							ssaRep->replaceAllArgs(expr, arg4);
							g_peephole_logger.log<LogLevel::eDebug>("Const LoadAddr");
							return true;
						}
					}
					else if (arg4.isValue(0)) {
						if (arg2.isValue(0) || arg3.isValue(0)) {
							ssaRep->replaceAllArgs(expr, arg1);
							g_peephole_logger.log<LogLevel::eDebug>("Const LoadAddr");
							return true;
						}
					}
				}
			}
			return false;
		});
		/*builder = peephole_optimizer->ruleSet;
		builder
			.ssaType(0, 0, SSAExprType::ePhi)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr.directRefs.size() == 0)
				return false;

			bool undef = true;
			SSAArgument& firstArg = expr.subExpressions[1];
			bool alwaysTheSame = true;

			for (size_t i = 0; i < expr.subExpressions.size(); i += 2) {
				//SSAArgument& blockArg = expr.subExpressions[i];
				SSAArgument& arg = expr.subExpressions[i + 1];
				if (arg.type != SSAArgType::eUndef) {
					undef = false;
				}
				if (arg != firstArg) {
					alwaysTheSame = false;
				}
			}
			if (undef) {
				g_peephole_logger.log<LogLevel::eDebug>("undef Phi");
				ssaRep->replaceAllArgs(expr, SSAArgument::createUndef(expr.location, expr.locref, expr.size));
				return true;
			}
			else if (alwaysTheSame) {
				g_peephole_logger.log<LogLevel::eDebug>("Same Phi Args at %d, UId 0x%x Refs: %d", expr.id, expr.uniqueId, expr.directRefs.size());
				ssaRep->replaceAllArgs(expr, firstArg);
				return true;
			}
			return false;
		});*/
		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAExprType::eUndef)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			ssaRep->replaceAllArgs(expr, SSAArgument::createUndef(expr.location, expr.locref, expr.size));
			g_peephole_logger.log<LogLevel::eDebug>("Replace Undefs");
			return true;
		});
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
					ssaRep->replaceArg(expr, SSAArgument::createUVal(arg.uval >> arg.offset, arg.size));
					return true;
				}
				else if (arg.type == SSAArgType::eSInt) {
					ssaRep->replaceArg(expr, SSAArgument::createUVal(arg.sval >> arg.offset, arg.size));
					return true;
				}
			}
			return false;
		});
		return peephole_optimizer;
	}
}
