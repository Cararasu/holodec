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
		return matched;
	}
	bool PhRuleInstance::match(Architecture* arch, SSARepresentation* ssaRep, SSAExpression* expr) {
		MatchContext context;
		for (PhRule& rule : rules) {
			if (!rule.matchRule(arch, ssaRep, expr, &context))
				return false;
		}
		return executor(arch, ssaRep, &context);
	}

	struct RuleBuilder {
		PhRuleSet* ruleSet;
		PhRuleInstance ruleInstance;

		RuleBuilder (PhRuleSet& ruleSet) : ruleSet (&ruleSet), ruleInstance() {}

		RuleBuilder& ssaType(HId matchIndex, HId index, SSAFlagType flagType) {
			return ssaType(matchIndex, index, SSAExprType::eFlag, SSAOpType::eInvalid, flagType);
		}
		RuleBuilder& ssaType(HId matchIndex, HId index, SSAOpType opType) {
			return ssaType(matchIndex, index, SSAExprType::eOp, opType, SSAFlagType::eUnknown);
		}
		RuleBuilder& ssaType (HId matchIndex, HId index, SSAExprType type, SSAOpType opType = SSAOpType::eInvalid, SSAFlagType flagType = SSAFlagType::eUnknown) {
			ruleInstance.rules.push_back (PhRule(matchIndex, index, type, opType, flagType));
			return *this;
		}

		RuleBuilder& execute (PhExecutor executor) {
			ruleInstance.executor = executor;
			ruleSet->ruleInstances.push_back(std::move(ruleInstance));
			ruleInstance = std::move(PhRuleInstance());
			return *this;
		}
	}; 

	PeepholeOptimizer* parsePhOptimizer () {

		PeepholeOptimizer* peephole_optimizer = new PeepholeOptimizer();

		RuleBuilder builder (peephole_optimizer->ruleSet);
		
		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAExprType::eExtend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression&  expr = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr.directRefs.size() && expr.subExpressions[0].isConst()) {
				expr.subExpressions[0].size = expr.size;
				ssaRep->replaceAllArgs(expr, expr.subExpressions[0]);
				return true;
			}
			return false;
		})/*
		.ssaType(0, 0, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression&  expr = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr.directRefs.size() && expr.subExpressions[0].type == SSAArgType::eUInt && expr.subExpressions[1].type == SSAArgType::eUInt) {
				uint64_t mask = std::numeric_limits<uint64_t>::max();
				if (expr.subExpressions[2].uval + expr.subExpressions[1].size > 64)
					return false;
				if (expr.subExpressions[2].uval + expr.subExpressions[1].size == 64)
					mask = 0x0;
				else
					mask ^= (1 << (expr.subExpressions[2].uval + expr.subExpressions[1].size)) - 1;

				if (expr.subExpressions[2].uval == 64)
					return false;
				else
					mask ^= (1 << expr.subExpressions[2].uval) - 1;

				SSAArgument replaceArg = expr.subExpressions[0];
				replaceArg.uval &= mask;
				replaceArg.uval |= expr.subExpressions[1].uval << expr.subExpressions[2].uval;
				ssaRep->replaceAllArgs(expr, replaceArg);
				return true;
			}
			return false;
		})*/
		.ssaType(0, 0, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {

			//TODO the appends seem to not be simplified correctly and sometimes even completely removed

			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			bool subAppends = false;

			for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end();) {
				SSAArgument arg = *it;
				if (arg.type != SSAArgType::eId) {
					++it;
					continue;
				}
				SSAExpression& subExpr = ssaRep->expressions[arg.ssaId];
				if (subExpr.type != SSAExprType::eAppend) {
					++it;
					continue;
				}
				subAppends = true;
				uint32_t offset = it->offset;
				int64_t valueOffset = it->valueoffset;
				assert(it->offset + it->size <= subExpr.size);
				expr.print(arch);
				printf("Sub: %d-%d\n", offset, arg.size);
				subExpr.print(arch);
				uint32_t offsetlimit = it->offset + it->size;
				it = expr.removeArgument(ssaRep, it);
				uint32_t innerOffset = 0;
				for (auto innerIt = subExpr.subExpressions.begin(); innerIt != subExpr.subExpressions.end(); ++innerIt) {
					if (innerOffset >= offsetlimit)
						break;
					if (offset < innerOffset + innerIt->size) {
						SSAArgument innerArg = *innerIt;

						if(innerOffset < offset)
							innerArg.offset += offset - innerOffset;
						if (offsetlimit < innerOffset + innerIt->size)
							innerArg.size -= (innerOffset + innerIt->size) - offsetlimit;
						innerArg.valueoffset += valueOffset;
						innerArg.print(arch);
						printf("\n");
						it = expr.insertArgument(ssaRep, it, innerArg);
					}
					innerOffset += innerIt->size;
				}
				expr.print(arch);
				fflush(stdout);
				printf("\n");
			}
			return subAppends;
		})
		.ssaType(0, 0, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression&  expr = ssaRep->expressions[context->expressionsMatched[0]];

			if (expr.subExpressions.size() == 2 && expr.subExpressions[1].type == SSAArgType::eUInt && expr.subExpressions[1].uval == 0) {
				expr.type = SSAExprType::eExtend;
				expr.exprtype = SSAType::eUInt;
				expr.removeArgument(ssaRep, expr.subExpressions.end() - 1);
				g_peephole_logger.log<LogLevel::eDebug>("Replace Appends with Extend");
				return true;
			}
			bool replaced = false;
			if (expr.subExpressions.size() > 1) {
				for (auto it = expr.subExpressions.begin() + 1; it != expr.subExpressions.end(); ) {
					auto lastit = expr.subExpressions.begin();
					if (it->isConst() && it->type == lastit->type) {
						switch (it->type) {
						case SSAArgType::eSInt:
							lastit->sval |= (it->sval >> lastit->offset) << lastit->size;
							break;
						case SSAArgType::eUInt:
							lastit->uval |= (it->uval >> lastit->offset) << lastit->size;
							break;
						default:
							++it;
							continue;
						}
						lastit->size += it->size;
						it = expr.removeArgument(ssaRep, it);
						continue;
					}
					++it;
				}
			}
			assert(expr.subExpressions.size());
			auto baseit = expr.subExpressions.begin();
			for (auto it = baseit; it != expr.subExpressions.end();) {
				//if ssaId does not change and offset fits
				if (baseit + 1 == it && consecutive_arg(*baseit, *it)) {
					SSAArgument arg = *baseit;
					arg.size = it->offset - baseit->offset;
					arg.valueoffset += it->valueoffset * (1 << baseit->size);
					it = expr.insertArgument(ssaRep, expr.removeArguments(ssaRep, baseit, it + 1), arg);//replace range with arg
					replaced = true;
					continue;
				}
				baseit = it;
				it++;
			}
			if (replaced) {
				g_peephole_logger.log<LogLevel::eDebug>("Replace Some Appends of same Expr");
			}
			if (expr.subExpressions.size() == 1) {
				expr.type = SSAExprType::eAssign;
				return true;
			}
			return replaced;
		});

		builder
		.ssaType(0, 0, SSAOpType::eSub)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& opExpr = ssaRep->expressions[context->expressionsMatched[0]];
			if (!ssaRep->usedOnlyInFlags(opExpr) && opExpr.subExpressions.size() == 2) {
				if (opExpr.subExpressions[1].type == SSAArgType::eUInt) {
					SSAArgument arg = opExpr.subExpressions[0];
					arg.valueoffset -= opExpr.subExpressions[1].uval;
					ssaRep->replaceArg(ssaRep->expressions[context->expressionsMatched[0]], arg);
					return true;
				}
				else if (opExpr.subExpressions[1].type == SSAArgType::eUInt) {
					SSAArgument arg = opExpr.subExpressions[0];
					arg.valueoffset -= opExpr.subExpressions[1].sval;
					ssaRep->replaceArg(ssaRep->expressions[context->expressionsMatched[0]], arg);
					return true;
				}
			}
			return false;
		})
		.ssaType(0, 0, SSAOpType::eAdd)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& opExpr = ssaRep->expressions[context->expressionsMatched[0]];
			if (!ssaRep->usedOnlyInFlags(opExpr) && opExpr.subExpressions.size() == 2) {
				if (opExpr.subExpressions[1].type == SSAArgType::eUInt) {
					SSAArgument arg = opExpr.subExpressions[0];
					arg.valueoffset += opExpr.subExpressions[1].uval;
					ssaRep->replaceArg(ssaRep->expressions[context->expressionsMatched[0]], arg);
					return true;
				}
				else if (opExpr.subExpressions[1].type == SSAArgType::eUInt) {
					SSAArgument arg = opExpr.subExpressions[0];
					arg.valueoffset += opExpr.subExpressions[1].sval;
					ssaRep->replaceArg(ssaRep->expressions[context->expressionsMatched[0]], arg);
					return true;
				}
			}
			return false;
		})

		.ssaType(0, 0, SSAOpType::eAdd)
		.ssaType(1, 3, SSAFlagType::eC)
		.ssaType(2, 1, SSAOpType::eAdd)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& firstAdd = ssaRep->expressions[context->expressionsMatched[2]];
			SSAExpression& carryExpr = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& secondAdd = ssaRep->expressions[context->expressionsMatched[0]];
			if (!secondAdd.directRefs.size() || firstAdd.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 || carryExpr.subExpressions[0].offset + carryExpr.subExpressions[0].size != firstAdd.size)
				return false;
			//TODO check if arguments of secondAdd are before firstAdd
			//and replace firstAdd not secondAdd
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

			uint64_t firstsize = firstAdd.size;
			firstAdd.size += secondAdd.size;

			SSAArgument addArg = SSAArgument::createId(firstAdd.id, firstsize);

			SSAArgument splitArg1 = addArg;
			splitArg1.size = firstsize;
			splitArg1.offset = 0;

			SSAArgument splitArg2 = addArg;
			splitArg2.size = secondAdd.size;
			splitArg2.offset = firstsize;

			//Expression references invalidated
			SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addBefore(&combine1, secondAdd.id), combine1.size);
			SSAArgument combine2Arg = SSAArgument::createId(ssaRep->addAfter(&combine2, combine1Arg.ssaId), combine2.size);

			//set arguments of second arg
			ssaRep->expressions[context->expressionsMatched[2]].subExpressions = { combine1Arg, combine2Arg };

			ssaRep->replaceAllArgs(ssaRep->expressions[context->expressionsMatched[2]], splitArg1);
			ssaRep->replaceAllArgs(ssaRep->expressions[context->expressionsMatched[0]], splitArg2);
			return true;
		})
		.ssaType(0, 0, SSAOpType::eSub)
		.ssaType(1, 3, SSAFlagType::eC)
		.ssaType(2, 1, SSAOpType::eSub)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& firstSub = ssaRep->expressions[context->expressionsMatched[2]];
			SSAExpression& carryExpr = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& secondSub = ssaRep->expressions[context->expressionsMatched[0]];
			
			if (!secondSub.directRefs.size() || firstSub.subExpressions.size() != 2 || secondSub.subExpressions.size() != 3 || carryExpr.subExpressions[0].offset + carryExpr.subExpressions[0].size != firstSub.size)
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

			uint64_t firstsize = firstSub.size;
			firstSub.size += secondSub.size;

			SSAArgument addArg = SSAArgument::createId(firstSub.id, firstsize);

			SSAArgument splitArg1 = addArg;
			splitArg1.size = firstsize;
			splitArg1.offset = 0;

			SSAArgument splitArg2 = addArg;
			splitArg2.size = firstsize;
			splitArg2.offset = secondSub.size;

			//Expression references invalidated
			SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addBefore(&combine1, firstSub.id), combine1.size);
			SSAArgument combine2Arg = SSAArgument::createId(ssaRep->addAfter(&combine2, combine1Arg.ssaId), combine2.size);

			//set arguments of first arg
			ssaRep->expressions[context->expressionsMatched[2]].setAllArguments( ssaRep, { combine1Arg, combine2Arg });

			ssaRep->replaceAllArgs(ssaRep->expressions[context->expressionsMatched[2]], splitArg1);
			ssaRep->replaceAllArgs(ssaRep->expressions[context->expressionsMatched[0]], splitArg2);
			return true;
		})
		.ssaType(0, 0, SSAExprType::eOp)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if ((expr.opType == SSAOpType::eSub || expr.opType == SSAOpType::eBXor) && expr.subExpressions.size() == 2 && expr.subExpressions[0] == expr.subExpressions[1] && !ssaRep->usedOnlyInFlags(expr)) {
				g_peephole_logger.log<LogLevel::eDebug>("Zero-Op");
				ssaRep->replaceArg(expr, SSAArgument::createUVal(0, expr.size));
				return true;
			}
			return false;
		})
		.ssaType(0, 0, SSAExprType::eAppend)
		.ssaType(1, 1, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr1 = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& expr2 = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr2.subExpressions[0].offset == 0 && expr2.subExpressions[0].size == expr1.size) {
				g_peephole_logger.log<LogLevel::eDebug>("Append %d - Append %d ", context->expressionsMatched[0], context->expressionsMatched[1]);
				HList<SSAArgument> args(expr2.subExpressions.begin() + 1, expr2.subExpressions.end());
				expr2.subExpressions = expr1.subExpressions;
				for (SSAArgument& arg : args) {
					expr2.addArgument(ssaRep, arg);
				}
				return true;
			}
			return false;
		})
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
		})
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
		})
		.ssaType(0, 0, SSAExprType::eReturn)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			bool replaced = false;
			for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end();) {
				SSAArgument& arg = *it;
				if (arg.type == SSAArgType::eId) {
					SSAExprType type = ssaRep->expressions[arg.ssaId].type;
					if (arg.type == SSAArgType::eId && arg.valueoffset == 0 && type == SSAExprType::eInput) {
						it = expr.removeArgument(ssaRep, it);
						replaced = true;
						continue;
					}
				}
				++it;
			}
			if(replaced)
				g_peephole_logger.log<LogLevel::eDebug>("Removed non used Return-args");
			return replaced;
		})
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
		})
		.ssaType(0, 0, SSAExprType::eUndef)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			ssaRep->replaceAllArgs(expr, SSAArgument::createUndef(expr.location, expr.locref, expr.size));
			g_peephole_logger.log<LogLevel::eDebug>("Replace Undefs");
			return true;
		})
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
