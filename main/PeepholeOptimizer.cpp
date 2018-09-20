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

						SSAExpression storeexpr = ssaRep->expressions[context->expressionsMatched[0]];
						storeexpr.subExpressions[2] = apparg;

						SSAArgument storearg = SSAArgument::createId(ssaRep->addAfter(&storeexpr, apparg.ssaId));

						ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], storearg);
						ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[2]], storearg);
						return true;
					}
					else if (change * arch->bitbase == -split2expr.size && split2expr.offset + split2expr.size == split1expr.offset) {
						SSAExpression appendexpr;
						appendexpr.type = SSAExprType::eAppend;
						appendexpr.exprtype = SSAType::eUInt;
						appendexpr.size = split1expr.size + split2expr.size;
						appendexpr.subExpressions = { SSAArgument::createId(split1expr.id), SSAArgument::createId(split2expr.id) };
						appendexpr.instrAddr = split2expr.instrAddr;

						SSAArgument apparg = SSAArgument::createId(ssaRep->addAfter(&appendexpr, store1expr.id));

						SSAExpression storeexpr = ssaRep->expressions[context->expressionsMatched[2]];
						storeexpr.subExpressions[2] = apparg;

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

				if (lexpr.subExpressions.size() != 2 || subexpr.subExpressions.size() != 2) {
					return false;
				}
				SSAExpression* baseexpr = nullptr;
				if (ssaRep->expressions[lexpr.subExpressions[0].ssaId].isValue(0)) {
					baseexpr = &ssaRep->expressions[lexpr.subExpressions[1].ssaId];
				}
				else if (ssaRep->expressions[lexpr.subExpressions[1].ssaId].isValue(0)) {
					baseexpr = &ssaRep->expressions[lexpr.subExpressions[0].ssaId];
				}
				if (!baseexpr) {
					return false;
				}

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


				//This is made to replace SF != ZF patterns but for multibyte subtracts it may produce weird results
				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], SSAArgument::createId(ssaRep->addAfter(&lowerexpression, context->expressionsMatched[0])));

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

				//This is made to replace SF != ZF patterns but for multibyte subtracts it may produce weird results
				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], SSAArgument::createId(ssaRep->addAfter(&lowerexpression, context->expressionsMatched[0])));

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

				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], SSAArgument::createId(ssaRep->addAfter(&lowerexpression, context->expressionsMatched[0])));

				return true;
			})
			//Pattern for unsigned greater equals
			.ssaType(0, 0, SSAOpType::eEq)
			.ssaType(1, 1, SSAOpType::eLower)
			.ssaType(1, 2, SSAOpType::eEq)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				return false;
			})
				/*
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
						calculate_difference(ssaRep, load1.subExpressions[1].ssaId, load2.subExpressions[1].ssaId, &diff) && diff == (load1.size / arch->bitbase))
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
				if (!secondAdd.directRefs.size() || firstAdd.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 || firstAdd.exprtype != secondAdd.exprtype)
					return false;
				if (!consecutive_exprs(arch, ssaRep, firstAdd.subExpressions[0].ssaId, secondAdd.subExpressions[0].ssaId))
					return false;
				if (!consecutive_exprs(arch, ssaRep, firstAdd.subExpressions[1].ssaId, secondAdd.subExpressions[1].ssaId))
					return false;

				g_peephole_logger.log<LogLevel::eDebug>("Replace Add - Carry Add");

				if (firstAdd.size == carryExpr.flagbit && ssaRep->isNotUsedBefore(firstAdd, secondAdd)) {

					HId exprsToReplace[2] = { firstAdd.id, secondAdd.id };
					SSAArgument firstargss[2] = { firstAdd.subExpressions[0], secondAdd.subExpressions[0] };
					SSAArgument secargss[2] = { firstAdd.subExpressions[1], secondAdd.subExpressions[1] };

					combine_operations(ssaRep, exprsToReplace, firstargss, secargss, 2, secondAdd, secondAdd.instrAddr);
					return true;
				}
				return false;
			})
			.ssaType(0, 0, SSAOpType::eSub)
			.ssaType(1, 3, SSAFlagType::eC)
			.ssaType(2, 1, SSAOpType::eSub)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& firstAdd = ssaRep->expressions[context->expressionsMatched[2]];
				SSAExpression& carryExpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& secondAdd = ssaRep->expressions[context->expressionsMatched[0]];
				if (!secondAdd.directRefs.size() || firstAdd.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 || firstAdd.exprtype != secondAdd.exprtype)
					return false;
				if (!consecutive_exprs(arch, ssaRep, firstAdd.subExpressions[0].ssaId, secondAdd.subExpressions[0].ssaId))
					return false;
				if (!consecutive_exprs(arch, ssaRep, firstAdd.subExpressions[1].ssaId, secondAdd.subExpressions[1].ssaId))
					return false;

				g_peephole_logger.log<LogLevel::eDebug>("Replace Sub - Carry Sub");

				if (firstAdd.size == carryExpr.flagbit && ssaRep->isNotUsedBefore(firstAdd, secondAdd)) {
					HId exprsToReplace[2] = { firstAdd.id, secondAdd.id };
					SSAArgument firstargss[2] = { firstAdd.subExpressions[0], secondAdd.subExpressions[0] };
					SSAArgument secargss[2] = { firstAdd.subExpressions[1], secondAdd.subExpressions[1] };

					combine_operations(ssaRep, exprsToReplace, firstargss, secargss, 2, secondAdd, secondAdd.instrAddr);
					return true;
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

				if (consecutive_exprs(arch, ssaRep, lowerExpr.subExpressions[0].ssaId, eq1Expr.subExpressions[0].ssaId) &&
					consecutive_exprs(arch, ssaRep, eq2Expr.subExpressions[0].ssaId, eq1Expr.subExpressions[0].ssaId) &&
					consecutive_exprs(arch, ssaRep, lowerExpr.subExpressions[1].ssaId, addExpr.subExpressions[0].ssaId) &&
					consecutive_exprs(arch, ssaRep, eq2Expr.subExpressions[1].ssaId, addExpr.subExpressions[0].ssaId)) {
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
					return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], SSAArgument::createId(ssaRep->addBefore(&compareExpr, context->expressionsMatched[0]))) != 0;
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
				return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], SSAArgument::createId(ssaRep->addBefore(&neqExpr, context->expressionsMatched[0]))) != 0;
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
				return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], SSAArgument::createId(ssaRep->addBefore(&eqExpr, context->expressionsMatched[0]))) != 0;
			})
			.ssaType(0, 0, SSAOpType::eSub)
			.ssaType(1, 3, SSAOpType::eLower)
			.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
				SSAExpression& lowerExpr = ssaRep->expressions[context->expressionsMatched[1]];
				SSAExpression& subOp = ssaRep->expressions[context->expressionsMatched[0]];
				if (!subOp.directRefs.size() || lowerExpr.subExpressions.size() != 2 || subOp.subExpressions.size() != 3 || lowerExpr.exprtype != subOp.exprtype)
					return false;
				if (!consecutive_exprs(arch, ssaRep, lowerExpr.subExpressions[0].ssaId, subOp.subExpressions[0].ssaId)) {
					if (!ssaRep->expressions[lowerExpr.subExpressions[0].ssaId].isConst(SSAType::eUInt) || !ssaRep->expressions[subOp.subExpressions[0].ssaId].isConst(SSAType::eUInt)) {
						return false;
					}
				}
				if (!consecutive_exprs(arch, ssaRep, lowerExpr.subExpressions[1].ssaId, subOp.subExpressions[1].ssaId)) {
					if (!ssaRep->expressions[lowerExpr.subExpressions[1].ssaId].isConst(SSAType::eUInt) || !ssaRep->expressions[subOp.subExpressions[1].ssaId].isConst(SSAType::eUInt)) {
						return false;
					}
				}

				g_peephole_logger.log<LogLevel::eDebug>("Replace Sub - Carry Sub");

				if (lowerExpr.size == subOp.size && ssaRep->isNotUsedBefore(lowerExpr, subOp)) {
					HId exprsToReplace[2] = { lowerExpr.id, subOp.id };
					SSAArgument firstargss[2] = { lowerExpr.subExpressions[0], subOp.subExpressions[0] };
					SSAArgument secargss[2] = { lowerExpr.subExpressions[1], subOp.subExpressions[1] };

					combine_operations(ssaRep, exprsToReplace, firstargss, secargss, 2, subOp, subOp.instrAddr);
					return true;
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
					return ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], SSAArgument::createId(ssaRep->addBefore(&newExpr, subId))) != 0;
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
						ssaRep->expressions[exprId].setArgument(ssaRep, index - 1, SSAArgument::createId(ssaRep->addBefore(&newexpr, exprId)));
						expr = &ssaRep->expressions[exprId];
						replaced = true;
						continue;
					}
					index++;
				}
				//combine multiple loads in an append
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
						if (calculate_difference(ssaRep, lastexpr->subExpressions[1].ssaId, thisexpr->subExpressions[1].ssaId, &diff) && difference == diff) {
							SSAExpression newexpr;
							newexpr.type = SSAExprType::eLoad;
							newexpr.exprtype = SSAType::eUInt;
							newexpr.size = thisexpr->size + lastexpr->size;
							newexpr.subExpressions = lastexpr->subExpressions;
							newexpr.instrAddr = lastexpr->instrAddr;

							index = ssaRep->expressions[exprId].removeArgument(ssaRep, index);
							ssaRep->expressions[exprId].setArgument(ssaRep, index - 1, SSAArgument::createId(ssaRep->addAfter(&newexpr, thisexpr->id)));
							expr = &ssaRep->expressions[exprId];
							replaced = true;
							continue;
						}
						index++;
						continue;
					}
					index++;
				}
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
								g_peephole_logger.log<LogLevel::eDebug>("Const LoadAddr");
								return true;
							}
						}
						else if (arg4.isValue(0)) {
							if (arg2.isValue(0) || arg3.isValue(0)) {
								expr.setAllArguments(ssaRep, { SSAArgument::createId(arg1.id) });
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
