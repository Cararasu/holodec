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
			if (!rule.matchRule(arch, ssaRep, expr, &context)){
				return false;
			}
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
#pragma optimize("", off)
	PeepholeOptimizer* parsePhOptimizer() {

		PeepholeOptimizer* peephole_optimizer = new PeepholeOptimizer();

		RuleBuilder builder(peephole_optimizer->ruleSet);

		builder = peephole_optimizer->ruleSet;
		builder
		.ssaType(0, 0, SSAExprType::eCast)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			/*if (expr.directRefs.size() && expr.subExpressions[0].isConst(expr.exprtype)) {
				expr.subExpressions[0].size = expr.size;
				ssaRep->replaceAllArgs(expr, expr.subExpressions[0]);
				return true;
			}*/
			return false;
		})
		.ssaType(0, 0, SSAExprType::eAssign)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			return ssaRep->replaceExpr(expr, expr.subExpressions[0]) != 0;
		})
		.ssaType(0, 0, SSAExprType::ePhi)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) -> bool {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr.type == SSAExprType::ePhi && expr.subExpressions.size()) {
				bool undef = true;
				SSAArgument cmpArg = expr.subExpressions[1];
				bool alwaysTheSame = true;

				for (size_t i = 1; i < expr.subExpressions.size(); i += 2) {
					//SSAArgument& blockArg = expr.subExpressions[i];
					SSAArgument& arg = expr.subExpressions[i];
					if (arg.type == SSAArgType::eId && arg.ssaId == expr.id)
						continue;
					if (ssaRep->expressions[arg.ssaId].type != SSAExprType::eUndef) {
						undef = false;
					}
					if (!weak_equals(arg, cmpArg)) {
						alwaysTheSame = false;
					}
				}
				if (undef) {
					expr.type = SSAExprType::eUndef;
					expr.subExpressions.clear();
					return true;
				}
				else if (alwaysTheSame) {
					return ssaRep->replaceExpr(expr, expr.subExpressions[1]) != 0;
				}
			}
			return false;
		})/*
		.ssaType(0, 0, SSAExprType::eAppend)
		.ssaType(1, 1, SSAExprType::eLoad)
		.ssaType(1, 2, SSAExprType::eLoad)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression&  appendexpr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression&  load1 = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression*  loadaddr1 = find_baseexpr(ssaRep, load1.subExpressions[1]);
			SSAExpression&  load2 = ssaRep->expressions[context->expressionsMatched[2]];
			SSAExpression*  loadaddr2 = find_baseexpr(ssaRep, load2.subExpressions[1]);

			if (load1.id == load2.id)
				return false;
			if (loadaddr1->size % arch->bitbase != 0)
				return false;
			if (load1.subExpressions[0].ssaId != load2.subExpressions[0].ssaId)
				return false;

			int64_t diff;
			if (
				(loadaddr1->isConst(SSAType::eUInt) && loadaddr2->isConst(SSAType::eUInt) &&
				(loadaddr1->uval + (load1.size / arch->bitbase)) == loadaddr2->uval)
				||
				(load1.subExpressions[1].type == SSAArgType::eId && load2.subExpressions[1].type == SSAArgType::eId &&
					calculante_difference(ssaRep, load1.subExpressions[1].ssaId, load2.subExpressions[1].ssaId, &diff) && diff == (load1.size / arch->bitbase))
				) {
				SSAExpression splitexpr1;
				splitexpr1.type = SSAExprType::eSplit;
				splitexpr1.exprtype = load1.exprtype;
				splitexpr1.size = load1.size;
				splitexpr1.subExpressions = { SSAArgument::createId(load1.id) };

				SSAExpression splitexpr2;
				splitexpr2.type = SSAExprType::eSplit;
				splitexpr2.exprtype = load1.exprtype;
				splitexpr2.size = load1.size;
				splitexpr2.subExpressions = { SSAArgument::createId(load2.id) };


				load1.size += load2.size;
				HId firstId = ssaRep->addAfter(&splitexpr1, load1.id);
				HId secId = ssaRep->addAfter(&splitexpr2, firstId);
				ssaRep->replaceAllArgs(ssaRep->expressions[context->expressionsMatched[1]], SSAArgument::createId(firstId));
				ssaRep->replaceAllArgs(ssaRep->expressions[context->expressionsMatched[2]], SSAArgument::createId(secId));
				return true;
			}
			return false;
		})*/
		.ssaType(0, 0, SSAOpType::eAdd)
		.ssaType(1, 3, SSAFlagType::eC)
		.ssaType(2, 1, SSAOpType::eAdd)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& firstAdd = ssaRep->expressions[context->expressionsMatched[2]];
			SSAExpression& carryExpr = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& secondAdd = ssaRep->expressions[context->expressionsMatched[0]];
			if (!secondAdd.directRefs.size() || firstAdd.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 ||
				firstAdd.exprtype == secondAdd.exprtype)
				return false;
			{
				uint32_t offsetfirst, offsetsecond;
				SSAExpression& firstparam = ssaRep->expressions[firstAdd.subExpressions[0].ssaId];
				SSAExpression& secparam = ssaRep->expressions[secondAdd.subExpressions[0].ssaId];
				offsetfirst = firstparam.type == SSAExprType::eSplit ? firstparam.offset : 0;
				offsetsecond = secparam.type == SSAExprType::eSplit ? secparam.offset : 0;
				if (offsetsecond - offsetfirst != firstparam.size)
					return false;
			}
			{
				uint32_t offsetfirst, offsetsecond;
				SSAExpression& firstparam = ssaRep->expressions[firstAdd.subExpressions[0].ssaId];
				SSAExpression& secparam = ssaRep->expressions[secondAdd.subExpressions[0].ssaId];
				offsetfirst = firstparam.type == SSAExprType::eSplit ? firstparam.offset : 0;
				offsetsecond = secparam.type == SSAExprType::eSplit ? secparam.offset : 0;
				if (offsetsecond - offsetfirst != firstparam.size)
					return false;
			}

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
			combine1.size = firstAdd.size + secondAdd.size;

			SSAExpression combine2;
			combine2.type = SSAExprType::eAppend;
			combine2.exprtype = firstAdd.exprtype;
			combine2.instrAddr = firstAdd.instrAddr;
			combine2.subExpressions = {
				firstAdd.subExpressions[1],
				secondAdd.subExpressions[1]
			};
			combine2.size = firstAdd.size + secondAdd.size;

			assert(combine1.size == combine2.size);

			if (ssaRep->isNotUsedBefore(firstAdd, secondAdd)) {
				uint32_t secsize = secondAdd.size;
				secondAdd.size += firstAdd.size;

				SSAArgument addArg = SSAArgument::createId(secondAdd.id);

				HId secId = secondAdd.id;

				SSAExpression split1;
				split1.type = SSAExprType::eSplit;
				split1.exprtype = firstAdd.exprtype;
				split1.instrAddr = firstAdd.instrAddr;
				split1.subExpressions = { SSAArgument::createId(secId) };
				split1.size = firstAdd.size;

				SSAExpression split2;
				split2.type = SSAExprType::eSplit;
				split2.exprtype = firstAdd.exprtype;
				split2.instrAddr = firstAdd.instrAddr;
				split2.subExpressions = { SSAArgument::createId(secId) };
				split2.size = secondAdd.size;

				//Expression references invalidated
				SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addBefore(&combine1, secId));
				SSAArgument combine2Arg = SSAArgument::createId(ssaRep->addBefore(&combine2, secId));

				SSAArgument split1Arg = SSAArgument::createId(ssaRep->addAfter(&split1, secId));
				SSAArgument split2Arg = SSAArgument::createId(ssaRep->addAfter(&split2, secId));

				//set arguments of second arg
				ssaRep->expressions[context->expressionsMatched[0]].subExpressions = { combine1Arg, combine2Arg };

				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[2]], split1Arg);
				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], split2Arg);

				return true;
			}
			else {
				return false;
			}
		})
		.ssaType(0, 0, SSAOpType::eSub)
		.ssaType(1, 3, SSAFlagType::eC)
		.ssaType(2, 1, SSAOpType::eSub)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& firstAdd = ssaRep->expressions[context->expressionsMatched[2]];
			SSAExpression& carryExpr = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& secondAdd = ssaRep->expressions[context->expressionsMatched[0]];
			if (!secondAdd.directRefs.size() || firstAdd.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 ||
				firstAdd.exprtype == secondAdd.exprtype)
				return false;
			{
				uint32_t offsetfirst, offsetsecond;
				SSAExpression& firstparam = ssaRep->expressions[firstAdd.subExpressions[0].ssaId];
				SSAExpression& secparam = ssaRep->expressions[secondAdd.subExpressions[0].ssaId];
				offsetfirst = firstparam.type == SSAExprType::eSplit ? firstparam.offset : 0;
				offsetsecond = secparam.type == SSAExprType::eSplit ? secparam.offset : 0;
				if (offsetsecond - offsetfirst != firstparam.size)
					return false;
			}
			{
				uint32_t offsetfirst, offsetsecond;
				SSAExpression& firstparam = ssaRep->expressions[firstAdd.subExpressions[0].ssaId];
				SSAExpression& secparam = ssaRep->expressions[secondAdd.subExpressions[0].ssaId];
				offsetfirst = firstparam.type == SSAExprType::eSplit ? firstparam.offset : 0;
				offsetsecond = secparam.type == SSAExprType::eSplit ? secparam.offset : 0;
				if (offsetsecond - offsetfirst != firstparam.size)
					return false;
			}

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
			combine1.size = firstAdd.size + secondAdd.size;

			SSAExpression combine2;
			combine2.type = SSAExprType::eAppend;
			combine2.exprtype = firstAdd.exprtype;
			combine2.instrAddr = firstAdd.instrAddr;
			combine2.subExpressions = {
				firstAdd.subExpressions[1],
				secondAdd.subExpressions[1]
			};
			combine2.size = firstAdd.size + secondAdd.size;

			assert(combine1.size == combine2.size);

			if (ssaRep->isNotUsedBefore(firstAdd, secondAdd)) {
				uint32_t secsize = secondAdd.size;
				secondAdd.size += firstAdd.size;

				SSAArgument addArg = SSAArgument::createId(secondAdd.id);

				HId secId = secondAdd.id;

				SSAExpression split1;
				split1.type = SSAExprType::eSplit;
				split1.exprtype = firstAdd.exprtype;
				split1.instrAddr = firstAdd.instrAddr;
				split1.subExpressions = { SSAArgument::createId(secId) };
				split1.size = firstAdd.size;

				SSAExpression split2;
				split2.type = SSAExprType::eSplit;
				split2.exprtype = firstAdd.exprtype;
				split2.instrAddr = firstAdd.instrAddr;
				split2.subExpressions = { SSAArgument::createId(secId) };
				split2.size = secondAdd.size;

				//Expression references invalidated
				SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addBefore(&combine1, secId));
				SSAArgument combine2Arg = SSAArgument::createId(ssaRep->addBefore(&combine2, secId));

				SSAArgument split1Arg = SSAArgument::createId(ssaRep->addAfter(&split1, secId));
				SSAArgument split2Arg = SSAArgument::createId(ssaRep->addAfter(&split2, secId));

				//set arguments of second arg
				ssaRep->expressions[context->expressionsMatched[0]].setAllArguments(ssaRep, { combine1Arg, combine2Arg });

				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[2]], split1Arg);
				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], split2Arg);

				return true;
			}
			else {
				return false;
			}
		})
		.ssaType(0, 0, SSAExprType::eSplit)
		.ssaType(1, 1, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& splitexpr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& appendexpr = ssaRep->expressions[context->expressionsMatched[1]];

			uint32_t offset = 0;
			for (SSAArgument& arg : appendexpr.subExpressions) {
				SSAExpression& subexpr = ssaRep->expressions[arg.ssaId];
				if (offset == splitexpr.offset && subexpr.size == splitexpr.size) {
					splitexpr.type = SSAExprType::eAssign;
					splitexpr.setArgument(ssaRep, 0, arg);
					return true;
				}
				else if (offset <= splitexpr.offset && splitexpr.offset + splitexpr.size <= offset + subexpr.size) {
					splitexpr.offset = splitexpr.offset - offset;
					splitexpr.setArgument(ssaRep, 0, arg);
				}
				offset += subexpr.size;
			}

			return false;
		})
		.ssaType(0, 0, SSAExprType::eOp)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& subexpr = ssaRep->expressions[context->expressionsMatched[0]];
			int64_t change = 0;
			HId baseExprId;
			if (ssaRep->usedOnlyInFlags(subexpr))
				return false;
			uint64_t distance = calculate_basearg_plus_offset(ssaRep, context->expressionsMatched[0], &change, &baseExprId);
			if (distance == 0)// distance travelled should be at leased 1
				return false;
			for (SSAArgument& arg : subexpr.subExpressions) {//check if it is one of the arguments so we just duplicate values
				if (arg.type == SSAArgType::eId && arg.ssaId == baseExprId) {
					return false;
				}
			}
			if (change != 0) {
				HId subId = subexpr.id;

				SSAExpression valExpr;
				valExpr.type = SSAExprType::eValue;
				valExpr.uval = change < 0 ? change * -1 : change;
				valExpr.exprtype = SSAType::eUInt;
				valExpr.size = arch->bitbase * arch->bytebase;

				SSAExpression newExpr;
				newExpr.type = SSAExprType::eOp;
				newExpr.opType = change > 0 ? SSAOpType::eAdd : SSAOpType::eSub;
				newExpr.exprtype = subexpr.exprtype;
				newExpr.instrAddr = subexpr.instrAddr;
				newExpr.size = subexpr.size;
				newExpr.subExpressions = {
					SSAArgument::createId(baseExprId),
					SSAArgument::createId(ssaRep->addBefore(&valExpr, subId))
				};
				int cchange = ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], SSAArgument::createId(ssaRep->addBefore(&newExpr, subId)));
				return cchange != 0;
			}
			else {
				return ssaRep->replaceExpr(subexpr, SSAArgument::createId(baseExprId)) != 0;
			}
			return false;
		})
		.ssaType(0, 0, SSAExprType::eSplit)
		.ssaType(1, 1, SSAExprType::eSplit)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& firstexpr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& subexpr = ssaRep->expressions[context->expressionsMatched[1]];
			printf("%d\n", context->expressionsMatched[0]);
			firstexpr.setArgument(ssaRep, 0, subexpr.subExpressions[0]);
			firstexpr.offset += subexpr.offset;
			return true;
		})
		.ssaType(0, 0, SSAExprType::eSplit)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& splitexpr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& subexpr = ssaRep->expressions[splitexpr.subExpressions[0].ssaId];
			if (splitexpr.size == subexpr.size && splitexpr.offset == 0) {
				splitexpr.type = SSAExprType::eAssign;
				return true;
			}
			return false;
		})
		.ssaType(0, 0, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {

			//TODO the appends seem to not be simplified correctly and sometimes even completely removed
			HId exprId = context->expressionsMatched[0];
			SSAExpression* expr = &ssaRep->expressions[exprId];
			bool subAppends = false;

			HList<SSAExpression> toinsertexprs;
			for (size_t index = 0; index < expr->subExpressions.size(); index++) {
				SSAArgument arg = expr->subExpressions[index];
				SSAExpression* splitExpr = &ssaRep->expressions[arg.ssaId];
				if (splitExpr->type != SSAExprType::eSplit) {
					continue;
				}
				SSAExpression* appExpr = &ssaRep->expressions[splitExpr->subExpressions[0].ssaId];
				if (appExpr->type != SSAExprType::eAppend) {
					continue;
				}
				uint32_t offset = splitExpr->offset;
				uint32_t offsetlimit = splitExpr->offset + splitExpr->size;
				assert(splitExpr->offset + splitExpr->size <= subExpr.size);
				expr->removeArgument(ssaRep, index);
				uint32_t innerOffset = 0;
				for (size_t innerIndex = 0; innerIndex < appExpr->subExpressions.size(); innerIndex++) {
					SSAArgument innerArg = expr->subExpressions[innerIndex];
					SSAExpression& innerExpr = ssaRep->expressions[innerArg.ssaId];
					if (innerOffset >= offsetlimit)
						break;
					uint32_t subsize = ssaRep->expressions[innerArg.ssaId].size;
					if (offset < innerOffset + subsize) {
						if (innerOffset < offset || offsetlimit < innerOffset + innerExpr.size) {
							SSAExpression splitexpr;
							splitexpr.type = SSAExprType::eSplit;
							splitexpr.size = innerExpr.size - ((innerOffset + innerExpr.size) - offsetlimit);
							splitexpr.offset = offset - innerOffset;
							splitexpr.subExpressions = { innerArg };
							toinsertexprs.push_back(splitexpr);
						}
						expr->insertArgument(ssaRep, index, innerArg);
						index++;
					}
					innerOffset += subsize;
				}
				for (SSAExpression& expr : toinsertexprs) {
					index = ssaRep->expressions[exprId].insertArgument(ssaRep, index, SSAArgument::createId(ssaRep->addBefore(&expr, exprId)));
				}
				if(toinsertexprs.size())
					subAppends = true;
				toinsertexprs.clear();
				expr = &ssaRep->expressions[exprId];
			}
			return subAppends;
		})
		.ssaType(0, 0, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			HId exprId = context->expressionsMatched[0];
			SSAExpression* expr = &ssaRep->expressions[exprId];

			if (expr->subExpressions.size() == 2) {
				SSAExpression& secExpr = ssaRep->expressions[expr->subExpressions[1].ssaId];
				if (secExpr.isConst(SSAType::eUInt) && secExpr.uval == 0) {
					//if second parameter is a 0
					expr->type = SSAExprType::eCast;
					expr->exprtype = SSAType::eUInt;
					expr->sourcetype = SSAType::eUInt;
					expr->removeArgument(ssaRep, expr->subExpressions.end() - 1);
					g_peephole_logger.log<LogLevel::eDebug>("Replace Appends with Extend");
					return true;
				}
			}
			bool replaced = false;
			if (expr->subExpressions.size() > 1) {
				for (size_t index = 1; index < expr->subExpressions.size();) {
					SSAExpression* thisexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];
					SSAExpression* lastexpr = &ssaRep->expressions[expr->subExpressions[index - 1].ssaId];
					if (thisexpr->isConst(SSAType::eUInt) && lastexpr->isConst(SSAType::eUInt) && thisexpr->size + lastexpr->size <= 64) {
						SSAExpression newexpr;
						newexpr.type = SSAExprType::eValue;
						newexpr.exprtype = SSAType::eUInt;
						newexpr.uval |= (thisexpr->uval >> lastexpr->offset) << lastexpr->size;
						newexpr.size = thisexpr->size + lastexpr->size;

						index = ssaRep->expressions[exprId].removeArgument(ssaRep, index);
						ssaRep->expressions[exprId].setArgument(ssaRep, index, SSAArgument::createId(ssaRep->addBefore(&newexpr, exprId)));
						expr = &ssaRep->expressions[exprId];
						replaced = true;
						continue;
					}
					index++;
				}
			}
			if (expr->subExpressions.size() > 1) {
				for (size_t index = 1; index < expr->subExpressions.size(); ) {
					SSAExpression* thisexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];
					SSAExpression* lastexpr = &ssaRep->expressions[expr->subExpressions[index - 1].ssaId];
					if (thisexpr->type == SSAExprType::eLoad && lastexpr->type == SSAExprType::eLoad && thisexpr->subExpressions[0].ssaId == lastexpr->subExpressions[0].ssaId) {
						assert(thisexpr->subExpressions[0].location == SSALocation::eMem && lastexpr->subExpressions[0].location == SSALocation::eMem);
						Memory* mem = arch->getMemory(thisexpr->subExpressions[0].locref.refId);
						if (!mem || (thisexpr->size % (mem->wordsize * arch->bitbase)) != 0 || (lastexpr->size % (mem->wordsize * arch->bitbase)) != 0) {
							index++;
							continue;
						}
						uint64_t difference = lastexpr->size / (mem->wordsize * arch->bitbase);

						int64_t diff;
						if (calculante_difference(ssaRep, thisexpr->subExpressions[1].ssaId, lastexpr->subExpressions[1].ssaId, &diff)) {
							if (difference == diff) {
								SSAExpression newexpr;
								newexpr.type = SSAExprType::eLoad;
								newexpr.exprtype = SSAType::eUInt;
								newexpr.size = thisexpr->size + lastexpr->size;
								newexpr.subExpressions = lastexpr->subExpressions;

								index = ssaRep->expressions[exprId].removeArgument(ssaRep, index);
								ssaRep->expressions[exprId].setArgument(ssaRep, index, SSAArgument::createId(ssaRep->addAfter(&newexpr, thisexpr->id)));
								expr = &ssaRep->expressions[exprId];
								replaced = true;
								continue;
							}
						}
						index++;
						continue;
					}
					index++;
				}
			}
			if (expr->subExpressions.size() > 1) {
				//compress same ids together with different offsets
				for (size_t index = 1; index < expr->subExpressions.size(); ) {
					SSAExpression* thisexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];
					SSAExpression* lastexpr = &ssaRep->expressions[expr->subExpressions[index - 1].ssaId];
					uint32_t offset = 0;
					HId baseId = lastexpr->id;
					if (lastexpr->type == SSAExprType::eSplit) {
						offset = lastexpr->offset;
						baseId = lastexpr->subExpressions[0].ssaId;
					}
					if (thisexpr->type != SSAExprType::eSplit) {
						index++;
						continue;
					}
					if (thisexpr->subExpressions[0].ssaId != baseId || offset + lastexpr->size != thisexpr->offset) {
						index++;
						continue;
					}
					//if ssaId does not change and offset fits
					SSAExpression newexpr;
					newexpr.type = SSAExprType::eSplit;

					newexpr.exprtype = SSAType::eUInt;
					newexpr.size = thisexpr->size + lastexpr->size;
					newexpr.offset = offset;
					newexpr.subExpressions = thisexpr->subExpressions;

					index = ssaRep->expressions[exprId].removeArgument(ssaRep, index);
					ssaRep->expressions[exprId].setArgument(ssaRep, index - 1, SSAArgument::createId(ssaRep->addAfter(&newexpr, thisexpr->id)));
					expr = &ssaRep->expressions[exprId];
					replaced = true;
					continue;
				}
			}
			if (replaced) {
				g_peephole_logger.log<LogLevel::eDebug>("Replace Some Appends of same Expr");
			}
			if (expr->subExpressions.size() == 1) {
				expr->type = SSAExprType::eAssign;
				return true;
			}
			return replaced;
		})
		/*
		.ssaType(0, 0, SSAExprType::eOp)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if ((expr.opType == SSAOpType::eSub || expr.opType == SSAOpType::eBXor) && expr.subExpressions.size() == 2 && expr.subExpressions[0] == expr.subExpressions[1] && !ssaRep->usedOnlyInFlags(expr)) {
				g_peephole_logger.log<LogLevel::eDebug>("Zero-Op");
				return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], SSAArgument::createId(ssaRep->addBefore(, expr.size))) != 0;
			}
			return false;
		})*/
		.ssaType(0, 0, SSAOpType::eEq)
		.ssaType(1, 1, SSAOpType::eSub)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr1 = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& expr2 = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& secarg1 = ssaRep->expressions[expr1.subExpressions[1].ssaId];
			if (expr1.subExpressions.size() == 2 &&
				expr2.subExpressions.size() == 2 &&
				((secarg1.isConst(SSAType::eUInt) && secarg1.uval == 0) ||
				(secarg1.isConst(SSAType::eInt) && secarg1.sval == 0))) {
				g_peephole_logger.log<LogLevel::eDebug>("Eq %d - Sub %d ", context->expressionsMatched[0], context->expressionsMatched[1]);

				expr2.setAllArguments(ssaRep, expr1.subExpressions);
				return true;
			}
			return false;
		})/*
		.ssaType(0, 0, SSAExprType::eAppend)
		.ssaType(1, 2, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr1 = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& expr2 = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr2.subExpressions.size() == 2 && expr2.subExpressions[1].offset == 0 && expr2.subExpressions[1].size == expr1.size) {
				g_peephole_logger.log<LogLevel::eDebug>("Append %d - Append %d ", context->expressionsMatched[0], context->expressionsMatched[1]);
				HList<SSAArgument> args(expr2.subExpressions.begin() + 1, expr2.subExpressions.end());
				expr2.subExpressions = expr1.subExpressions;
				for (SSAArgument& arg : args) {
					expr2.addArgument(ssaRep, arg);
				}
				return true;
			}
			return false;
		})*/
		.ssaType(0, 0, SSAExprType::eReturn)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			bool replaced = false;
			for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end();) {
				SSAArgument& arg = *it;
				if (arg.type == SSAArgType::eId) {
					SSAExprType type = ssaRep->expressions[arg.ssaId].type;
					if (arg.type == SSAArgType::eId && type == SSAExprType::eInput) {
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
		});
		/*
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
		});*/
		return peephole_optimizer;
	}
}
