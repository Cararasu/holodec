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
		.ssaType(1, 1, SSAExprType::eCast)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& cast1expr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& cast2expr = ssaRep->expressions[context->expressionsMatched[1]];
			if (cast1expr.exprtype == cast1expr.sourcetype && cast2expr.exprtype == cast2expr.sourcetype && cast1expr.exprtype == cast2expr.exprtype) {
				cast1expr.setArgument(ssaRep, 0, cast2expr.subExpressions[0]);
			}
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
					HId baseExprId = 0;
					int64_t change = 0;
					calculate_basearg_plus_offset(ssaRep, expr.subExpressions[1].ssaId, &change, &baseExprId);
					bool alwaysTheSame = true;

					for (size_t i = 1; i < expr.subExpressions.size(); i += 2) {
						SSAArgument arg = expr.subExpressions[i];
						if (arg.type == SSAArgType::eId && arg.ssaId == expr.id)
							continue;
						if (ssaRep->expressions[arg.ssaId].type != SSAExprType::eUndef) {
							undef = false;
						}
						HId baseExprId2 = 0;
						int64_t change2 = 0;
						calculate_basearg_plus_offset(ssaRep, arg.ssaId, &change2, &baseExprId2);
						if (baseExprId != baseExprId2 || change != change2) {
							alwaysTheSame = false;
						}
					}
					if (undef) {
						expr.type = SSAExprType::eUndef;
						expr.subExpressions.clear();
						return true;
					}
					else if (alwaysTheSame) {
						if(change == 0)
							return ssaRep->replaceExpr(expr, expr.subExpressions[1]) != 0;
						else {
							SSAExpression valexpr;
							valexpr.type = SSAExprType::eValue;
							valexpr.exprtype = SSAType::eUInt;
							valexpr.size = arch->bitbase * arch->bytebase;
							if (change > 0) {
								expr.type = SSAExprType::eOp;
								expr.opType = SSAOpType::eAdd;
								valexpr.uval = change;
							}
							else {
								expr.type = SSAExprType::eOp;
								expr.opType = SSAOpType::eSub;
								valexpr.uval = -change;
							}
							HId exprId = expr.id;
							HId newId = ssaRep->addBefore(&valexpr, expr.id);
							ssaRep->expressions[exprId].setAllArguments(ssaRep, { SSAArgument::createId(baseExprId), SSAArgument::createId(newId) });
							return true;
						}
					}
				}
				return false;
			})
			.ssaType(0, 0, SSAExprType::eStore)
			.ssaType(1, 3, SSAExprType::eSplit)
			.ssaType(1, 1, SSAExprType::eStore)
			.ssaType(3, 3, SSAExprType::eSplit)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression&  store1expr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression&  split1expr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression&  store2expr = ssaRep->expressions[context->expressionsMatched[2]];
				SSAExpression&  split2expr = ssaRep->expressions[context->expressionsMatched[3]];

				if (split1expr.subExpressions[0].ssaId != split2expr.subExpressions[0].ssaId)
					return false;
				int64_t change = 0;
				if (calculate_difference(ssaRep, store1expr.subExpressions[1].ssaId, store2expr.subExpressions[1].ssaId, &change)) {
					if (change * arch->bitbase == split1expr.size && split1expr.offset + split1expr.size == split2expr.offset) {
						SSAExpression appendexpr;
						appendexpr.type = SSAExprType::eAppend;
						appendexpr.exprtype = SSAType::eUInt;
						appendexpr.size = split1expr.size + split2expr.size;
						appendexpr.subExpressions = { SSAArgument::createId(split1expr.id), SSAArgument::createId(split2expr.id)};
						appendexpr.instrAddr = split2expr.instrAddr;

						SSAArgument apparg = SSAArgument::createId(ssaRep->addAfter(&appendexpr, store1expr.id));

						SSAExpression storeexpr = ssaRep->expressions[context->expressionsMatched[2]];
						storeexpr.subExpressions[0] = ssaRep->expressions[context->expressionsMatched[2]].subExpressions[0];
						storeexpr.subExpressions[2] = apparg;
						storeexpr.directRefs.clear();

						SSAArgument storearg = SSAArgument::createId(ssaRep->addAfter(&storeexpr, apparg.ssaId));

						ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], storearg);
						ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[2]], storearg);
						return true;
					}
					else if (change * arch->bitbase == split2expr.size && split2expr.offset + split2expr.size == split1expr.offset) {
						SSAExpression appendexpr;
						appendexpr.type = SSAExprType::eAppend;
						appendexpr.exprtype = SSAType::eUInt;
						appendexpr.size = split1expr.size + split2expr.size;
						appendexpr.subExpressions = { SSAArgument::createId(split1expr.id), SSAArgument::createId(split2expr.id) };
						appendexpr.instrAddr = split2expr.instrAddr;

						SSAArgument apparg = SSAArgument::createId(ssaRep->addAfter(&appendexpr, store1expr.id));

						SSAExpression storeexpr = ssaRep->expressions[context->expressionsMatched[0]];
						storeexpr.subExpressions[0] = ssaRep->expressions[context->expressionsMatched[2]].subExpressions[0];
						storeexpr.subExpressions[2] = apparg;
						storeexpr.directRefs.clear();

						SSAArgument storearg = SSAArgument::createId(ssaRep->addAfter(&storeexpr, apparg.ssaId));

						ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], storearg);
						ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[2]], storearg);
						return true;
					}
				}
				return false;
			})
			//pattern for signed lower
			.ssaType(0, 0, SSAOpType::eNe)
			.ssaType(1, 1, SSAOpType::eLower)
			.ssaType(1, 2, SSAFlagType::eO)
			.ssaType(3, 1, SSAOpType::eSub)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression&  neexpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression&  lexpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression&  oexpr = ssaRep->expressions[context->expressionsMatched[2]];
				SSAExpression&  subexpr = ssaRep->expressions[context->expressionsMatched[3]];

				if (!ssaRep->isReplaceable(neexpr))
					return false;
				if (lexpr.subExpressions.size() != 2 || subexpr.subExpressions.size() != 2)
					return false;

				SSAExpression* baseexpr = nullptr;
				if (ssaRep->expressions[lexpr.subExpressions[0].ssaId].isValue(0)) {
					baseexpr = &ssaRep->expressions[lexpr.subExpressions[1].ssaId];
				}
				else if (ssaRep->expressions[lexpr.subExpressions[1].ssaId].isValue(0)) {
					baseexpr = &ssaRep->expressions[lexpr.subExpressions[0].ssaId];
				}
				if (!baseexpr)
					return false;

				if (baseexpr->type == SSAExprType::eSplit) {
					if (baseexpr->offset + baseexpr->size != subexpr.size)
						return false;
					baseexpr = &ssaRep->expressions[baseexpr->subExpressions[0].ssaId];
				}
				if (baseexpr->id != subexpr.id)
					return false;

				SSAExpression lowerexpression = subexpr;
				lowerexpression.opType = SSAOpType::eLower;
				lowerexpression.exprtype = lexpr.exprtype;
				lowerexpression.size = 1;
				lowerexpression.directRefs.clear();

				//This is made to replace SF != ZF patterns but for multibyte subtracts it may produce weird results
				SSAArgument lowerarg = SSAArgument::createId(ssaRep->addAfter(&lowerexpression, context->expressionsMatched[0]));
				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], lowerarg);

				return true;
			})
			//pattern for signed greater equals
			.ssaType(0, 0, SSAOpType::eEq)
			.ssaType(1, 1, SSAOpType::eLower)
			.ssaType(1, 2, SSAFlagType::eO)
			.ssaType(3, 1, SSAOpType::eSub)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression&  eqexpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression&  lexpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression&  oexpr = ssaRep->expressions[context->expressionsMatched[2]];
				SSAExpression&  subexpr = ssaRep->expressions[context->expressionsMatched[3]];

				if (!ssaRep->isReplaceable(eqexpr) || lexpr.subExpressions.size() != 2 || subexpr.subExpressions.size() != 2) {
					return false;
				}
				SSAExpression* baseexpr = nullptr;
				if (ssaRep->expressions[eqexpr.subExpressions[0].ssaId].isValue(0)) {
					baseexpr = &ssaRep->expressions[eqexpr.subExpressions[1].ssaId];
				}
				else if (ssaRep->expressions[eqexpr.subExpressions[1].ssaId].isValue(0)) {
					baseexpr = &ssaRep->expressions[eqexpr.subExpressions[0].ssaId];
				}
				else {
					return false;
				}
				//TODO here it should be checked that the sign does not change if we look at the whole value instead of only a part
				//maybe add a flag for types if that is possible
				if (baseexpr->type == SSAExprType::eSplit) {
					if (baseexpr->offset + baseexpr->size != subexpr.size)
						return false;
					baseexpr = &ssaRep->expressions[baseexpr->subExpressions[0].ssaId];
				}
				if (baseexpr->id != subexpr.id)
					return false;

				SSAExpression lowerexpression = subexpr;
				lowerexpression.opType = SSAOpType::eGe;
				lowerexpression.exprtype = lexpr.exprtype;
				lowerexpression.size = 1;
				lowerexpression.directRefs.clear();

				//This is made to replace SF != ZF patterns but for multibyte subtracts it may produce weird results
				SSAArgument lowerarg = SSAArgument::createId(ssaRep->addAfter(&lowerexpression, context->expressionsMatched[0]));
				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], lowerarg);

				return true;
			})
			//Pattern for unsigned lower
			.ssaType(0, 0, SSAFlagType::eC)
			.ssaType(1, 1, SSAOpType::eSub)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression&  cexpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression&  subexpr = ssaRep->expressions[context->expressionsMatched[1]];

				if (!ssaRep->isReplaceable(cexpr) || subexpr.subExpressions.size() != 2 || subexpr.exprtype != SSAType::eUInt)
					return false;

				SSAExpression lowerexpression = subexpr;
				lowerexpression.opType = SSAOpType::eLower;
				lowerexpression.exprtype = SSAType::eUInt;
				lowerexpression.size = 1;
				lowerexpression.directRefs.clear();

				SSAArgument lowerarg = SSAArgument::createId(ssaRep->addAfter(&lowerexpression, context->expressionsMatched[0]));
				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], lowerarg);

				return true;
			})
			//Pattern for unsigned greater equals
			.ssaType(0, 0, SSAOpType::eEq)
			.ssaType(1, 1, SSAOpType::eLower)
			.ssaType(1, 2, SSAOpType::eEq)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				//or not
				return false;
			})
			.ssaType(0, 0, SSAOpType::eAdd)
			.ssaType(1, 3, SSAFlagType::eC)
			.ssaType(2, 1, SSAOpType::eAdd)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& firstAdd = ssaRep->expressions[context->expressionsMatched[2]];
				SSAExpression& carryExpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& secondAdd = ssaRep->expressions[context->expressionsMatched[0]];
				if (!secondAdd.directRefs.size() || firstAdd.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 || firstAdd.exprtype != secondAdd.exprtype)
					return false;

				g_peephole_logger.log<LogLevel::eDebug>("Replace Add - Carry Add");

				if (firstAdd.size == carryExpr.flagbit && ssaRep->isNotUsedBefore(firstAdd, secondAdd)) {

					HId exprsToReplace[2] = { firstAdd.id, secondAdd.id };
					SSAArgument firstargss[2] = { firstAdd.subExpressions[0], secondAdd.subExpressions[0] };
					SSAArgument secargss[2] = { firstAdd.subExpressions[1], secondAdd.subExpressions[1] };

					return combine_operations(ssaRep, exprsToReplace, firstargss, secargss, 2, secondAdd, secondAdd.instrAddr);
				}
				return false;
			})
			.ssaType(0, 0, SSAOpType::eSub)
			.ssaType(1, 3, SSAOpType::eLower)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& lowerExpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& secondAdd = ssaRep->expressions[context->expressionsMatched[0]];
				if (!secondAdd.directRefs.size() || lowerExpr.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 || lowerExpr.exprtype != secondAdd.exprtype ||
					(lowerExpr.exprtype != SSAType::eUInt && lowerExpr.exprtype != SSAType::eInt)) {
					return false;
				}

				g_peephole_logger.log<LogLevel::eDebug>("Replace Sub - Carry Sub");

				if (ssaRep->isNotUsedBefore(lowerExpr, secondAdd)) {
					HId exprsToReplace[2] = { lowerExpr.id, secondAdd.id };
					SSAArgument firstargss[2] = { lowerExpr.subExpressions[0], secondAdd.subExpressions[0] };
					SSAArgument secargss[2] = { lowerExpr.subExpressions[1], secondAdd.subExpressions[1] };

					return combine_operations(ssaRep, exprsToReplace, firstargss, secargss, 2, secondAdd, secondAdd.instrAddr);
				}
				return false;
			})
			//This appears because of a different rule that compresses carry(sub(x,y)) to lower(x,y)
			.ssaType(0, 0, SSAExprType::eCast)
			.ssaType(1, 1, SSAExprType::eValue)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& castExpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression& valueExpr = ssaRep->expressions[context->expressionsMatched[1]];
				if (castExpr.exprtype == SSAType::eUInt && valueExpr.isConst(SSAType::eUInt)) {
					castExpr.removeArgument(ssaRep, 0);
					castExpr.type = SSAExprType::eValue;
					castExpr.uval = valueExpr.uval;
					return true;
				}
				return false;
			})
			//This simplifies compare + compare with carry expressions
			//The pattern: (((u8 var15 >> 8)) == (tmp48 + ((u8 var15) < 0x6c))) && ((u8 var15) == 0x6c)
			.ssaType(0, 0, SSAOpType::eAnd)
			.ssaType(1, 1, SSAOpType::eEq)
			.ssaType(1, 2, SSAOpType::eEq)
			.ssaType(2, 2, SSAOpType::eAdd)
			.ssaType(4, 2, SSAOpType::eLower)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& andExpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression& eq1Expr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& eq2Expr = ssaRep->expressions[context->expressionsMatched[2]];
				SSAExpression& addExpr = ssaRep->expressions[context->expressionsMatched[3]];
				SSAExpression& lowerExpr = ssaRep->expressions[context->expressionsMatched[4]];

				if (andExpr.subExpressions.size() != 2 || eq1Expr.subExpressions.size() != 2 || eq2Expr.subExpressions.size() != 2)
					return false;
				
				if (lowerExpr.subExpressions[0].ssaId == eq2Expr.subExpressions[0].ssaId && 
					lowerExpr.subExpressions[1].ssaId == eq2Expr.subExpressions[1].ssaId) {
					SSAExpression appExpr1;
					appExpr1.type = SSAExprType::eAppend;
					appExpr1.exprtype = SSAType::eUInt;
					appExpr1.instrAddr = andExpr.instrAddr;
					appExpr1.size = ssaRep->expressions[lowerExpr.subExpressions[0].ssaId].size + ssaRep->expressions[eq1Expr.subExpressions[0].ssaId].size;
					appExpr1.subExpressions = { lowerExpr.subExpressions[0], eq1Expr.subExpressions[0] };
					SSAExpression appExpr2;
					appExpr2.type = SSAExprType::eAppend;
					appExpr2.exprtype = SSAType::eUInt;
					appExpr2.instrAddr = andExpr.instrAddr;
					appExpr2.size = ssaRep->expressions[lowerExpr.subExpressions[1].ssaId].size + ssaRep->expressions[addExpr.subExpressions[0].ssaId].size;
					appExpr2.subExpressions = { lowerExpr.subExpressions[1], addExpr.subExpressions[0] };

					if (appExpr1.size != appExpr2.size)
						return false;
					SSAExpression compareExpr;
					compareExpr.type = SSAExprType::eOp;
					compareExpr.opType = SSAOpType::eEq;
					compareExpr.exprtype = SSAType::eUInt;
					compareExpr.size = 1;
					compareExpr.instrAddr = andExpr.instrAddr;
					compareExpr.subExpressions = { 
						SSAArgument::createId(ssaRep->addBefore(&appExpr1, context->expressionsMatched[0])), 
						SSAArgument::createId(ssaRep->addBefore(&appExpr2, context->expressionsMatched[0])) 
					};
					SSAArgument comparearg = SSAArgument::createId(ssaRep->addBefore(&compareExpr, context->expressionsMatched[0]));
					return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], comparearg) != 0;
				}
				return false;
			})
			//eq(0x0, -(xx, yy)) -> -(xx, yy)
			//eq(-(xx, yy), 0x0) -> -(xx, yy)
			.ssaType(0, 0, SSAOpType::eEq)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& eqExpr = ssaRep->expressions[context->expressionsMatched[0]];

				if (eqExpr.subExpressions.size() != 2)
					return false;

				SSAExpression* firstArgExpr = &ssaRep->expressions[eqExpr.subExpressions[0].ssaId];
				SSAExpression* secArgExpr = &ssaRep->expressions[eqExpr.subExpressions[1].ssaId];
				if (firstArgExpr->isValue(0x0) && secArgExpr->isOp(SSAOpType::eSub)) {
					SSAExpression newExpr;
					newExpr.type = SSAExprType::eOp;
					newExpr.opType = SSAOpType::eSub;
					newExpr.subExpressions = secArgExpr->subExpressions;
					newExpr.size = 1;

					SSAArgument newarg = SSAArgument::createId(ssaRep->addBefore(&newExpr, context->expressionsMatched[0]));
					return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], newarg) != 0;
				}else if (firstArgExpr->isOp(SSAOpType::eSub) && secArgExpr->isValue(0x0)) {
					SSAExpression newExpr;
					newExpr.type = SSAExprType::eOp;
					newExpr.opType = SSAOpType::eSub;
					newExpr.subExpressions = firstArgExpr->subExpressions;
					newExpr.size = 1;

					SSAArgument newarg = SSAArgument::createId(ssaRep->addBefore(&newExpr, context->expressionsMatched[0]));
					return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], newarg) != 0;
				}
				return false;
			})
			.ssaType(0, 0, SSAOpType::eNot)
			.ssaType(1, 1, SSAOpType::eEq)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& notExpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression& eqExpr = ssaRep->expressions[context->expressionsMatched[1]];

				SSAExpression neqExpr;
				neqExpr.type = SSAExprType::eOp;
				neqExpr.opType = SSAOpType::eNe;
				neqExpr.exprtype = SSAType::eUInt;
				neqExpr.size = 1;
				neqExpr.instrAddr = notExpr.instrAddr;
				neqExpr.subExpressions = eqExpr.subExpressions;
				
				SSAArgument neqarg = SSAArgument::createId(ssaRep->addBefore(&neqExpr, context->expressionsMatched[0]));
				return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], neqarg) != 0;
			})
			.ssaType(0, 0, SSAOpType::eNot)
			.ssaType(1, 1, SSAOpType::eNe)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& notExpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression& neqExpr = ssaRep->expressions[context->expressionsMatched[1]];

				SSAExpression eqExpr;
				eqExpr.type = SSAExprType::eOp;
				eqExpr.opType = SSAOpType::eEq;
				eqExpr.exprtype = SSAType::eUInt;
				eqExpr.size = 1;
				eqExpr.instrAddr = notExpr.instrAddr;
				eqExpr.subExpressions = neqExpr.subExpressions;
				
				SSAArgument eqarg = SSAArgument::createId(ssaRep->addBefore(&eqExpr, context->expressionsMatched[0]));
				return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], eqarg) != 0;
			})
			//((((arg16 | arg17 << 8)) == ((arg1 | arg1 << 8))) && (arg16 == arg1)) -> (((arg16 | arg17 << 8)) == ((arg1 | arg1 << 8)))
			.ssaType(0, 0, SSAOpType::eAnd)
			.ssaType(1, 1, SSAOpType::eEq)
			.ssaType(1, 2, SSAOpType::eEq)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& andExpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression& eq1Expr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& eq2Expr = ssaRep->expressions[context->expressionsMatched[2]];

				if (andExpr.subExpressions.size() != 2 || eq1Expr.subExpressions.size() != 2 || eq2Expr.subExpressions.size() != 2)
					return false;

				if (is_part_of(ssaRep, eq1Expr.subExpressions[0], eq2Expr.subExpressions[0]) && is_part_of(ssaRep, eq1Expr.subExpressions[1], eq2Expr.subExpressions[1])) {
					return ssaRep->replaceExpr(andExpr, SSAArgument::create(&eq2Expr)) != 0;
				}
				if (is_part_of(ssaRep, eq2Expr.subExpressions[0], eq1Expr.subExpressions[0]) && is_part_of(ssaRep, eq2Expr.subExpressions[1], eq1Expr.subExpressions[1])) {
					return ssaRep->replaceExpr(andExpr, SSAArgument::create(&eq1Expr)) != 0;
				}
				return false;
			})
			//arg19 == (arg1 + (arg18 < arg1)) -> (arg18 | arg19 << 8) == (arg1 | arg1 << 8)
			.ssaType(0, 0, SSAOpType::eEq)
			.ssaType(1, 2, SSAOpType::eAdd)
			.ssaType(2, 2, SSAOpType::eLower)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& eqExpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression& addExpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& lowerExpr = ssaRep->expressions[context->expressionsMatched[2]];

				if (eqExpr.subExpressions.size() != 2 || addExpr.subExpressions.size() != 2 || lowerExpr.subExpressions.size() != 2)
					return false;
				{//check if the a <(xx, +(yy, <(...))) chain was resolved, if not don't do anything
					for (SSAArgument& arg : lowerExpr.subExpressions) {
						SSAExpression* sExpr = &ssaRep->expressions[arg.ssaId];
						if (sExpr->isOp(SSAOpType::eAdd)) {
							for (SSAArgument& arg : sExpr->subExpressions) {
								SSAExpression* ssExpr = &ssaRep->expressions[arg.ssaId];
								if (sExpr->isOp(SSAOpType::eLower)) return false;
							}
						}
					}
				}

				SSAExpression app1Expr;
				app1Expr.type = SSAExprType::eAppend;
				app1Expr.instrAddr = eqExpr.instrAddr;
				app1Expr.size = 0;
				SSAExpression app2Expr = app1Expr;
				app1Expr.subExpressions = { lowerExpr.subExpressions[0], eqExpr.subExpressions[0] };
				app2Expr.subExpressions = { lowerExpr.subExpressions[1], addExpr.subExpressions[0] };

				for (SSAArgument& arg : app1Expr.subExpressions) app1Expr.size += ssaRep->expressions[arg.ssaId].size;
				for (SSAArgument& arg : app2Expr.subExpressions) app2Expr.size += ssaRep->expressions[arg.ssaId].size;

				SSAArgument app1arg = SSAArgument::createId(ssaRep->addBefore(&app1Expr, context->expressionsMatched[0]));
				eqExpr.replaceArgument(ssaRep, 0, app1arg);
				
				SSAArgument app2arg = SSAArgument::createId(ssaRep->addBefore(&app2Expr, context->expressionsMatched[0]));
				eqExpr.replaceArgument(ssaRep, 1, app2arg);

				return true;
			})
			//arg19 < (arg1 + (arg18 < arg1)) -> (arg18 | arg19 << 8) < (arg1 | arg1 << 8)
			.ssaType(0, 0, SSAOpType::eLower)
			.ssaType(1, 2, SSAOpType::eAdd)
			.ssaType(2, 2, SSAOpType::eLower)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& lower1Expr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression& addExpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& lower2Expr = ssaRep->expressions[context->expressionsMatched[2]];

				if (lower1Expr.subExpressions.size() != 2 || addExpr.subExpressions.size() != 2 || lower2Expr.subExpressions.size() != 2)
					return false;
				{//check if we are not the tail of a < + < chain
					SSAExpression* sExpr = &ssaRep->expressions[lower2Expr.subExpressions[1].ssaId];
					if (sExpr->type == SSAExprType::eOp && sExpr->opType == SSAOpType::eAdd)
						return false;
				}

				SSAExpression app1Expr;
				app1Expr.type = SSAExprType::eAppend;
				app1Expr.instrAddr = lower1Expr.instrAddr;
				app1Expr.size = 0;
				SSAExpression app2Expr = app1Expr;
				app1Expr.subExpressions = { lower2Expr.subExpressions[0], lower1Expr.subExpressions[0] };
				app2Expr.subExpressions = { lower2Expr.subExpressions[1], addExpr.subExpressions[0] };

				for (SSAArgument& arg : app1Expr.subExpressions) app1Expr.size += ssaRep->expressions[arg.ssaId].size;
				for (SSAArgument& arg : app2Expr.subExpressions) app2Expr.size += ssaRep->expressions[arg.ssaId].size;

				SSAArgument app1arg = SSAArgument::createId(ssaRep->addBefore(&app1Expr, context->expressionsMatched[0]));
				ssaRep->expressions[context->expressionsMatched[0]].replaceArgument(ssaRep, 0, app1arg);

				SSAArgument app2arg = SSAArgument::createId(ssaRep->addBefore(&app2Expr, context->expressionsMatched[0]));
				ssaRep->expressions[context->expressionsMatched[0]].replaceArgument(ssaRep, 1, app2arg);

				return true;
			})
			//u8 tmp111 = (arg1 + (arg16 < arg1))
			//u8 tmp94 = (arg17 - tmp111)
			.ssaType(0, 0, SSAOpType::eSub)
			.ssaType(1, 2, SSAOpType::eAdd)
			.ssaType(2, 2, SSAOpType::eLower)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& subExpr = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression& addExpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& lowerExpr = ssaRep->expressions[context->expressionsMatched[2]];

				if (subExpr.subExpressions.size() != 2 || addExpr.subExpressions.size() != 2 || lowerExpr.subExpressions.size() != 2)
					return false;

				HId exprsToReplace[2] = { 0, subExpr.id };
				SSAArgument firstargss[2] = { lowerExpr.subExpressions[0], subExpr.subExpressions[0] };
				SSAArgument secargss[2] = { lowerExpr.subExpressions[1], addExpr.subExpressions[0] };

				return combine_operations(ssaRep, exprsToReplace, firstargss, secargss, 2, subExpr, subExpr.instrAddr);
			})
			.ssaType(0, 0, SSAOpType::eSub)
			.ssaType(1, 3, SSAOpType::eLower)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& lowerExpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& subOp = ssaRep->expressions[context->expressionsMatched[0]];

				if (!subOp.directRefs.size() || lowerExpr.subExpressions.size() != 2 || subOp.subExpressions.size() != 3 || lowerExpr.exprtype != subOp.exprtype)
					return false;

				g_peephole_logger.log<LogLevel::eDebug>("Replace Sub - Carry Sub");

				if (lowerExpr.size == subOp.size && ssaRep->isNotUsedBefore(lowerExpr, subOp)) {
					HId exprsToReplace[2] = { lowerExpr.id, subOp.id };
					SSAArgument firstargss[2] = { lowerExpr.subExpressions[0], subOp.subExpressions[0] };
					SSAArgument secargss[2] = { lowerExpr.subExpressions[1], subOp.subExpressions[1] };

					return combine_operations(ssaRep, exprsToReplace, firstargss, secargss, 2, subOp, subOp.instrAddr);
				}
				return false;
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
					valExpr.instrAddr = subexpr.instrAddr;

					SSAExpression newExpr;
					newExpr.type = SSAExprType::eOp;
					newExpr.opType = change >= 0 ? SSAOpType::eAdd : SSAOpType::eSub;
					newExpr.exprtype = subexpr.exprtype;
					newExpr.instrAddr = subexpr.instrAddr;
					newExpr.size = subexpr.size;
					newExpr.instrAddr = subexpr.instrAddr;
					newExpr.subExpressions = {
						SSAArgument::createId(baseExprId),
						SSAArgument::createId(ssaRep->addBefore(&valExpr, subId))
					};
					SSAArgument newarg = SSAArgument::createId(ssaRep->addBefore(&newExpr, subId));
					return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], newarg) != 0;
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
				printf("Split %d - %d\n", context->expressionsMatched[0], context->expressionsMatched[1]);
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
			.ssaType(0, 0, SSAExprType::eOp)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& opExpr = ssaRep->expressions[context->expressionsMatched[0]];
				for (SSAArgument& arg : opExpr.subExpressions) {
					if (!ssaRep->expressions[arg.ssaId].isConst(SSAType::eUInt)) return false;
				}
				SSAExpression valexpr;
				valexpr.type = SSAExprType::eValue;
				valexpr.exprtype = SSAType::eUInt;
				valexpr.size = opExpr.size;
				valexpr.instrAddr = opExpr.instrAddr;
				valexpr.uval = ssaRep->expressions[opExpr.subExpressions[0].ssaId].uval;
				switch (opExpr.opType) {
				case SSAOpType::eAdd: {
					for (auto it = opExpr.subExpressions.begin() + 1; it != opExpr.subExpressions.end(); ++it) {
						valexpr.uval += ssaRep->expressions[it->ssaId].uval;
					}
				}break;
				case SSAOpType::eSub: {
					for (auto it = opExpr.subExpressions.begin() + 1; it != opExpr.subExpressions.end(); ++it) {
						valexpr.uval -= ssaRep->expressions[it->ssaId].uval;
					}
				}break;
				case SSAOpType::eShl: {
					for (auto it = opExpr.subExpressions.begin() + 1; it != opExpr.subExpressions.end(); ++it) {
						valexpr.uval <<= ssaRep->expressions[it->ssaId].uval;
					}
				}break;
				case SSAOpType::eShr: {
					for (auto it = opExpr.subExpressions.begin() + 1; it != opExpr.subExpressions.end(); ++it) {
						valexpr.uval >>= ssaRep->expressions[it->ssaId].uval;
					}
				}break;
				case SSAOpType::eBNot: {
					valexpr.uval = ~valexpr.uval;
				}break;
				case SSAOpType::eBAnd: {
					for (auto it = opExpr.subExpressions.begin() + 1; it != opExpr.subExpressions.end(); ++it) {
						valexpr.uval &= ssaRep->expressions[it->ssaId].uval;
					}
				}break;
				case SSAOpType::eBOr: {
					for (auto it = opExpr.subExpressions.begin() + 1; it != opExpr.subExpressions.end(); ++it) {
						valexpr.uval |= ssaRep->expressions[it->ssaId].uval;
					}
				}break;
				case SSAOpType::eBXor: {
					for (auto it = opExpr.subExpressions.begin() + 1; it != opExpr.subExpressions.end(); ++it) {
						SSAArgument& arg = *it;
						valexpr.uval ^= ssaRep->expressions[it->ssaId].uval;
					}
				}break;
				default: {
					return false;
				}break;
				}
				valexpr.uval &= (1 << valexpr.size) - 1;
				SSAArgument valarg = SSAArgument::createId(ssaRep->addBefore(&valexpr, context->expressionsMatched[0]));
				return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], valarg) != 0;
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
					assert(splitExpr->offset + splitExpr->size <= appExpr->size);
					expr->removeArgument(ssaRep, index);
					uint32_t innerOffset = 0;
					for (size_t innerIndex = 0; innerIndex < appExpr->subExpressions.size(); innerIndex++) {
						SSAArgument innerArg = appExpr->subExpressions[innerIndex];
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
						SSAArgument newarg = SSAArgument::createId(ssaRep->addBefore(&expr, exprId));
						index = ssaRep->expressions[exprId].insertArgument(ssaRep, index, newarg);
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
				//combine multiple appends stacked
				for (size_t index = 0; index < expr->subExpressions.size();) {
					SSAExpression* thisexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];
					if (thisexpr->type == SSAExprType::eAppend) {
						HList<SSAArgument> args;
						args.reserve(expr->subExpressions.size() + thisexpr->subExpressions.size() - 1);
						for (size_t subindex = 0; subindex < index; subindex++) {
							args.push_back(expr->subExpressions[subindex]);
						}
						for (size_t subindex = 0; subindex < thisexpr->subExpressions.size(); subindex++) {
							args.push_back(thisexpr->subExpressions[subindex]);
						}
						for (size_t subindex = index + 1; subindex < expr->subExpressions.size(); subindex++) {
							args.push_back(expr->subExpressions[subindex]);
						}
						expr->setAllArguments(ssaRep, args);
						replaced = true;
						index++;
						continue;
					}
					index++;
				}
				//append(phi, phi, phi, phi) -> phi(append, append, append, append)
				//this propagates the append upstream
				{
					bool all_phinodes = true;
					for (size_t index = 0; index < expr->subExpressions.size(); index++) {
						all_phinodes &= ssaRep->expressions[expr->subExpressions[index].ssaId].type == SSAExprType::ePhi;
					}
					if (all_phinodes) {
						SSAExpression* firstphi = &ssaRep->expressions[expr->subExpressions[0].ssaId];
						size_t count = firstphi->subExpressions.size();

						SSAExpression newphiexpr;
						newphiexpr.type = SSAExprType::ePhi;
						newphiexpr.instrAddr = expr->instrAddr;
						newphiexpr.subExpressions = firstphi->subExpressions;
						newphiexpr.size = expr->size;

						for (size_t argi = 0; argi < count; argi += 2) {//for every block
							SSABB* block = &ssaRep->bbs[firstphi->subExpressions[argi].ssaId];
							SSAExpression* lastexpr = &ssaRep->expressions[block->exprIds.back()];

							SSAExpression appendexpr;
							appendexpr.type = SSAExprType::eAppend;
							appendexpr.instrAddr = expr->instrAddr;
							appendexpr.size = expr->size;

							//gather all input from one input
							for (size_t index = 0; index < expr->subExpressions.size(); index++) {
								SSAExpression* phiexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];
								appendexpr.subExpressions.push_back(phiexpr->subExpressions[argi + 1]);
							}

							SSAArgument arg = SSAArgument::createId(ssaRep->addBefore(&appendexpr, block->exprIds.back()));
							//reload
							expr = &ssaRep->expressions[exprId];
							firstphi = &ssaRep->expressions[expr->subExpressions[0].ssaId];

							newphiexpr.subExpressions[argi + 1] = arg;
						}
						HId phiId = ssaRep->addBefore(&newphiexpr, *ssaRep->bbs[expr->blockId].exprIds.begin());

						//reload
						expr = &ssaRep->expressions[exprId];

						uint32_t offset = 0;
						for (size_t index = 0; index < expr->subExpressions.size(); index++) {//for every phi node block
							SSAExpression* phiexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];

							SSAExpression split;
							split.type = SSAExprType::eSplit;
							split.exprtype = phiexpr->exprtype;
							split.instrAddr = phiexpr->instrAddr;
							split.size = phiexpr->size;
							split.subExpressions = { SSAArgument::createId(phiId) };
							split.ref = phiexpr->ref;
							split.offset = offset;

							offset += phiexpr->size;
							HId smallerphiId = phiexpr->id;

							SSAArgument newarg = SSAArgument::createId(ssaRep->addAfter(&split, phiId));
							ssaRep->replaceAllExprs(ssaRep->expressions[smallerphiId], newarg);

							//reload
							expr = &ssaRep->expressions[exprId];
						}
						replaced = true;
					}
				}
				uint32_t offset = 0;
				//combine multiple values in an append
				for (size_t index = 1; index < expr->subExpressions.size();) {
					SSAExpression* thisexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];
					SSAExpression* lastexpr = &ssaRep->expressions[expr->subExpressions[index - 1].ssaId];
					offset += lastexpr->size;
					if (thisexpr->isConst(SSAType::eUInt) && lastexpr->isConst(SSAType::eUInt) && thisexpr->size + lastexpr->size <= 64) {
						SSAExpression newexpr;
						newexpr.type = SSAExprType::eValue;
						newexpr.exprtype = SSAType::eUInt;
						newexpr.uval = lastexpr-> uval | (thisexpr->uval << offset);
						newexpr.size = thisexpr->size + lastexpr->size;

						index = ssaRep->expressions[exprId].removeArgument(ssaRep, index);
						
						SSAArgument newarg = SSAArgument::createId(ssaRep->addBefore(&newexpr, exprId));
						ssaRep->expressions[exprId].setArgument(ssaRep, index - 1, newarg);
						expr = &ssaRep->expressions[exprId];
						replaced = true;
						continue;
					}
					index++;
				}
				//combine multiple loads
				for (size_t index = 1; index < expr->subExpressions.size();) {
					SSAExpression* thisexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];
					SSAExpression* lastexpr = &ssaRep->expressions[expr->subExpressions[index - 1].ssaId];
					if (thisexpr->type == SSAExprType::eLoad && lastexpr->type == SSAExprType::eLoad) {
						if (thisexpr->subExpressions[0].ssaId == lastexpr->subExpressions[0].ssaId) {
							//printf("");
						}
					}
					index++;
				}
				//combine multiple loads in an append
				for (size_t index = 1; index < expr->subExpressions.size(); ) {
					SSAExpression* thisexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];
					SSAExpression* lastexpr = &ssaRep->expressions[expr->subExpressions[index - 1].ssaId];
					if (thisexpr->type == SSAExprType::eLoad && lastexpr->type == SSAExprType::eLoad && thisexpr->subExpressions[0].ssaId == lastexpr->subExpressions[0].ssaId) {
						assert(thisexpr->subExpressions[0].ref.isLocation(SSALocation::eMem) && lastexpr->subExpressions[0].ref.isLocation(SSALocation::eMem));
						Memory* mem = arch->getMemory(thisexpr->subExpressions[0].ref.id);
						if (!mem || (thisexpr->size % (mem->wordsize * arch->bitbase)) != 0 || (lastexpr->size % (mem->wordsize * arch->bitbase)) != 0) {
							index++;
							continue;
						}
						uint64_t difference = lastexpr->size / (mem->wordsize * arch->bitbase);

						int64_t diff;
						int64_t change;
						if (calculate_difference(ssaRep, thisexpr->subExpressions[1].ssaId, lastexpr->subExpressions[1].ssaId, &change)) {
							if (change * arch->bitbase == thisexpr->size) {
								//printf("");
							}
							if ((-change) * arch->bitbase == lastexpr->size) {
								//printf("");
							}
						}
						if (calculate_difference(ssaRep, lastexpr->subExpressions[1].ssaId, thisexpr->subExpressions[1].ssaId, &diff)){
							if (difference == diff) {
								SSAExpression newexpr;
								newexpr.type = SSAExprType::eLoad;
								newexpr.exprtype = SSAType::eUInt;
								newexpr.size = thisexpr->size + lastexpr->size;
								newexpr.subExpressions = lastexpr->subExpressions;
								newexpr.instrAddr = lastexpr->instrAddr;

								index = ssaRep->expressions[exprId].removeArgument(ssaRep, index);
								SSAArgument newarg = SSAArgument::createId(ssaRep->addAfter(&newexpr, thisexpr->id));
								ssaRep->expressions[exprId].setArgument(ssaRep, index - 1, newarg);
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
				//combine multiple loads in an append
				for (size_t index = 1; index < expr->subExpressions.size(); ) {
					SSAExpression* thisexpr = &ssaRep->expressions[expr->subExpressions[index].ssaId];
					SSAExpression* lastexpr = &ssaRep->expressions[expr->subExpressions[index - 1].ssaId];
					uint32_t lastoffset = 0, lastsize = lastexpr->size;
					SSAExpression* lastbase = lastexpr;
					{
						if (lastexpr->type == SSAExprType::eSplit) {
							lastoffset = lastexpr->offset;
							lastbase = &ssaRep->expressions[lastexpr->subExpressions[0].ssaId];
						}
					}
					uint32_t thisoffset = 0, thissize = thisexpr->size;
					SSAExpression* thisbase = thisexpr;
					{
						if (thisexpr->type == SSAExprType::eSplit) {
							thisoffset = thisexpr->offset;
							thisbase = &ssaRep->expressions[thisexpr->subExpressions[0].ssaId];
						}
					}
					if (thisbase->isOp() && lastbase->isOp() && (thisbase->opType == lastbase->opType) &&
							//check that we only look at the last part
							(lastoffset + lastsize == lastbase->size) && (thisoffset + thissize == thisbase->size) && (lastoffset + lastsize == thisoffset) &&
							(lastbase->subExpressions.size()) == 2 && (thisbase->subExpressions.size() == 2)) {

						if (is_part_of(ssaRep, lastbase->subExpressions[0], thisbase->subExpressions[0]) && is_part_of(ssaRep, lastbase->subExpressions[1], thisbase->subExpressions[1])) {
							if (lastoffset) {
								//TODO insert split before replacing the argument
							}
							else {
								index = expr->removeArgument(ssaRep, index - 1);
								expr->replaceArgument(ssaRep, index, SSAArgument::create(thisbase));
								replaced = true;
							}
						}
					}
					index++;
				}
				//combine same ids together with different offsets
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
					//split these because apparently
					SSAArgument arg = SSAArgument::createId(ssaRep->addAfter(&newexpr, thisexpr->id));
					ssaRep->expressions[exprId].setArgument(ssaRep, index - 1, arg);
					expr = &ssaRep->expressions[exprId];
					replaced = true;
					continue;
				}
				if (replaced) {
					g_peephole_logger.log<LogLevel::eDebug>("Replace Some Arguments of Append");
				}

				if (expr->subExpressions.size() == 1) {
					expr->type = SSAExprType::eAssign;
					return true;
				}
				return replaced;
			})
			.ssaType(0, 0, SSAExprType::eOp)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
				if ((expr.opType == SSAOpType::eSub || expr.opType == SSAOpType::eBXor) && expr.subExpressions.size() == 2 && expr.subExpressions[0] == expr.subExpressions[1] && !ssaRep->usedOnlyInFlags(expr)) {
					g_peephole_logger.log<LogLevel::eDebug>("Zero-Op");
					SSAExpression zeroexpr;
					zeroexpr.type = SSAExprType::eValue;
					zeroexpr.exprtype = SSAType::eUInt;
					zeroexpr.uval = 0x0;
					SSAArgument zeroarg = SSAArgument::createId(ssaRep->addBefore(&zeroexpr, expr.size));
					return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], zeroarg) != 0;
				}
				/*This is bad as it prevents other better optimizations at the moment
				if ( (expr.opType == SSAOpType::eSub || expr.opType == SSAOpType::eAdd) && expr.subExpressions.size() == 2) {
					SSAExpression& arg1 = ssaRep->expressions[expr.subExpressions[0].ssaId];
					SSAExpression& arg2 = ssaRep->expressions[expr.subExpressions[1].ssaId];
					if (arg1.isValue(0)) {
						return ssaRep->replaceExpr(expr, expr.subExpressions[1]) != 0;
					}
					else if (arg2.isValue(0)) {
						return ssaRep->replaceExpr(expr, expr.subExpressions[0]) != 0;
					}
				}*/
				return false;
			})
			.ssaType(0, 0, SSAOpType::eEq)
			.ssaType(1, 1, SSAOpType::eSub)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& expr1 = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& expr2 = ssaRep->expressions[context->expressionsMatched[0]];
				SSAExpression& secarg1 = ssaRep->expressions[expr1.subExpressions[1].ssaId];
				if (expr1.subExpressions.size() == 2 && expr2.subExpressions.size() == 2 &&
					((secarg1.isConst(SSAType::eUInt) && secarg1.uval == 0) || (secarg1.isConst(SSAType::eInt) && secarg1.sval == 0))) {

					g_peephole_logger.log<LogLevel::eDebug>("Eq %d - Sub %d ", context->expressionsMatched[0], context->expressionsMatched[1]);
					expr2.setAllArguments(ssaRep, expr1.subExpressions);
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
			})
			.ssaType(0, 0, SSAExprType::eLoadAddr)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
				if (expr.subExpressions.size() == 5) {
					SSAExpression& arg0 = ssaRep->expressions[expr.subExpressions[0].ssaId];
					SSAExpression& arg1 = ssaRep->expressions[expr.subExpressions[1].ssaId];
					SSAExpression& arg2 = ssaRep->expressions[expr.subExpressions[2].ssaId];
					SSAExpression& arg3 = ssaRep->expressions[expr.subExpressions[3].ssaId];
					SSAExpression& arg4 = ssaRep->expressions[expr.subExpressions[4].ssaId];
					if (arg0.isValue(0)) {
						if (arg1.isValue(0)) {
							if (arg2.isValue(0) || arg3.isValue(0)) {
								expr.setAllArguments(ssaRep, { SSAArgument::createId(arg4.id) });
								expr.type = SSAExprType::eAssign;
								g_peephole_logger.log<LogLevel::eDebug>("Const LoadAddr");
								return true;
							}
						}
						else if (arg4.isValue(0)) {
							if (arg2.isValue(0) || arg3.isValue(0)) {
								expr.setAllArguments(ssaRep, { SSAArgument::createId(arg1.id) });
								expr.type = SSAExprType::eAssign;
								g_peephole_logger.log<LogLevel::eDebug>("Const LoadAddr");
								return true;
							}
						}
					}
				}
				return false;
			});
		return peephole_optimizer;
	}
}
