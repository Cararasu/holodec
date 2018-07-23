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
				uint32_t offsetlimit = it->offset + it->size;
				assert(it->offset + it->size <= subExpr.size);
				expr.print(arch);
				it = expr.removeArgument(ssaRep, it);
				uint32_t innerOffset = 0;
				for (auto innerIt = subExpr.subExpressions.begin(); innerIt != subExpr.subExpressions.end(); ++innerIt) {
					if (innerOffset >= offsetlimit)
						break;
					if (offset < innerOffset + innerIt->size) {
						SSAArgument innerArg = *innerIt;
						if (innerOffset < offset)
							innerArg.offset += offset - innerOffset;
						if (offsetlimit < innerOffset + innerIt->size)
							innerArg.size -= (innerOffset + innerIt->size) - offsetlimit;
						it = expr.insertArgument(ssaRep, it, innerArg);
					}
					innerOffset += innerIt->size;
				}
			}
			return subAppends;
		})
		
		.ssaType(0, 0, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression&  expr = ssaRep->expressions[context->expressionsMatched[0]];

			if (expr.subExpressions.size() == 2 && expr.subExpressions[1].isConst(SSAType::eUInt) && expr.subExpressions[1].uval == 0) {
				//if second parameter is a 0
				expr.type = SSAExprType::eExtend;
				expr.exprtype = SSAType::eUInt;
				expr.removeArgument(ssaRep, expr.subExpressions.end() - 1);
				g_peephole_logger.log<LogLevel::eDebug>("Replace Appends with Extend");
				return true;
			}
			bool replaced = false;
			if (expr.subExpressions.size() > 1) {
				auto lastit = expr.subExpressions.begin();
				for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end(); ) {
					if (it == expr.subExpressions.begin()) {
						lastit = it++;
						continue;
					}
					if (it->isConst() && it->type == lastit->type && it->isConst(SSAType::eUInt)) {
						lastit->uval |= (it->uval >> lastit->offset) << lastit->size;
						lastit->size += it->size;
						it = expr.removeArgument(ssaRep, it);
						continue;
					}
					lastit = it++;
				}
			}
			if (expr.subExpressions.size() > 1) {
				auto lastit = expr.subExpressions.begin();
				for (auto it = expr.subExpressions.begin() + 1; it != expr.subExpressions.end(); ) {
					//the mem location shouldn't happen but still...
					if (it->type != SSAArgType::eId || 
						it->location == SSALocation::eMem || 
						lastit->type != SSAArgType::eId || 
						lastit->location == SSALocation::eMem ||
						it->offset || lastit->offset) {
						lastit = it++;
						continue;
					}
					SSAExpression& firstExpr = ssaRep->expressions[lastit->ssaId];
					SSAExpression& secExpr = ssaRep->expressions[it->ssaId];
					//both are not load
					if (firstExpr.type != SSAExprType::eLoad || secExpr.type != SSAExprType::eLoad) {
						lastit = it++;
						continue;
					}

					SSAArgument& firstMemArg = firstExpr.subExpressions[0];
					SSAArgument& secMemArg = secExpr.subExpressions[0];
					//we load from different memories
					if (firstMemArg.type != SSAArgType::eId || secMemArg.type != SSAArgType::eId ||
						firstMemArg.location != SSALocation::eMem || secMemArg.location != SSALocation::eMem ||
						firstMemArg.locref.refId != secMemArg.locref.refId ) {
						lastit = it++;
						continue;
					}
					Memory* mem = arch->getMemory(firstMemArg.locref.refId);
					if (!mem || (it->size % (mem->wordsize * arch->bitbase)) != 0) {
						lastit = it++;
						continue;
					}

					uint64_t difference = it->size / (mem->wordsize * arch->bitbase);

					SSAArgument& firstPtrArg = firstExpr.subExpressions[1];
					SSAArgument& secPtrArg = secExpr.subExpressions[1];

					SSAArgument replacedsecarg = SSAArgument::createId(firstExpr.id, SSAType::eUInt, lastit->size, it->size);

					if (firstPtrArg.type == secPtrArg.type) {
						if (firstPtrArg.isConst(SSAType::eUInt)){
							if ((firstPtrArg.uval + difference) == secPtrArg.uval) {
								//make load bigger
								firstExpr.size = std::max(firstExpr.size, (it->size + lastit->size));
								replaced |= ssaRep->replaceExpr(secExpr, replacedsecarg) != 0;
							}
						}
						else if (firstPtrArg.type == SSAArgType::eId) {
							int64_t diff;
							if (firstPtrArg.size == secPtrArg.size && firstPtrArg.offset == secPtrArg.offset &&
								calculante_difference(ssaRep, firstPtrArg.ssaId, secPtrArg.ssaId, &diff)) {
								if (difference == diff) {
									//make load bigger
									firstExpr.size = std::max(firstExpr.size, (it->size + lastit->size));
									replaced |= ssaRep->replaceExpr(secExpr, replacedsecarg) != 0;
								}
							}
						}
					}
					lastit = it++;
				}
			}
			assert(expr.subExpressions.size());
			if (expr.subExpressions.size() > 1) {
				//compress same ids together
				auto baseit = expr.subExpressions.begin();
				for (auto it = baseit; it != expr.subExpressions.end();) {
					//if ssaId does not change and offset fits
					if (baseit + 1 == it && consecutive_arg(*baseit, *it)) {
						SSAArgument arg = *baseit;
						arg.size = it->offset - baseit->offset;
						it = expr.insertArgument(ssaRep, expr.removeArguments(ssaRep, baseit, it + 1), arg);//replace range with arg
						replaced = true;
						continue;
					}
					baseit = it;
					it++;
				}
			}
			if (replaced) {
				g_peephole_logger.log<LogLevel::eDebug>("Replace Some Appends of same Expr");
			}
			if (expr.subExpressions.size() == 1) {
				expr.type = SSAExprType::eAssign;
				return true;
			}
			return replaced;
		})
		/* Probably remove
		.ssaType(0, 0, SSAExprType::eStore)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& storeExpr = ssaRep->expressions[context->expressionsMatched[0]];
			for (HId id : storeExpr.directRefs) {
				SSAExpression& secExpr = ssaRep->expressions[id];
				if (secExpr.type == SSAExprType::eStore) {
					SSAArgument& firstPtrArg = storeExpr.subExpressions[1];
					SSAArgument & secPtrArg = secExpr.subExpressions[1];
					if (firstPtrArg.type == secPtrArg.type) {
						switch (firstPtrArg.type) {
						case SSAArgType::eUInt: {
							if (firstPtrArg.uval + 1 == secPtrArg.uval|| firstPtrArg.uval == secPtrArg.uval) {
								//secExpr.size += storeExpr.size;
								//secExpr.setArgument(ssaRep, 0, storeExpr.subExpressions[0]);
								//secExpr.setArgument(ssaRep, 1, storeExpr.subExpressions[1]);
								//ssaRep->replaceAllArgs(storeExpr, storeExpr.subExpressions[0]);
								//ssaRep->removeExpr(storeExpr);
								fflush(stdout);
							}
						}break;
						case SSAArgType::eId: {
							if (firstPtrArg.ssaId == secPtrArg.ssaId) {
								//storeExpr.size += secExpr.size;
								//ssaRep->removeExpr(storeExpr);
								fflush(stdout);
							}
						}break;
						default:
							break;
						}
					}
				}
			}

			return false;
		})*/

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
					if (arg.type != SSAArgType::eUndef) {
						undef = false;
					}
					if (!weak_equals(arg, cmpArg)) {
						alwaysTheSame = false;
					}
				}
				if (undef) {
					return ssaRep->replaceExpr(expr, SSAArgument::createUndef(SSAType::eUInt, expr.location, expr.locref, expr.size)) != 0;
				}
				else if (alwaysTheSame) {
					return ssaRep->replaceExpr(expr, expr.subExpressions[1]) != 0;
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
			if (!secondAdd.directRefs.size() || firstAdd.subExpressions.size() != 2 || secondAdd.subExpressions.size() != 3 || 
				carryExpr.subExpressions[0].offset + carryExpr.subExpressions[0].size != firstAdd.size ||
				firstAdd.exprtype == secondAdd.exprtype)
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

			if (ssaRep->isNotUsedBefore(firstAdd, secondAdd)) {
				uint32_t secsize = secondAdd.size;
				secondAdd.size += firstAdd.size;

				SSAArgument addArg = SSAArgument::createId(secondAdd.id, firstAdd.exprtype, 0);

				SSAArgument splitArg1 = addArg;
				splitArg1.size = firstAdd.size;
				splitArg1.offset = 0;

				SSAArgument splitArg2 = addArg;
				splitArg2.size = secsize;
				splitArg2.offset = firstAdd.size;

				//Expression references invalidated
				SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addBefore(&combine1, secondAdd.id), secondAdd.exprtype, combine1.size);
				SSAArgument combine2Arg = SSAArgument::createId(ssaRep->addAfter(&combine2, combine1Arg.ssaId), secondAdd.exprtype, combine2.size);

				//set arguments of second arg
				ssaRep->expressions[context->expressionsMatched[0]].subExpressions = { combine1Arg, combine2Arg };

				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[2]], splitArg1);
				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], splitArg2);

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
			SSAExpression& firstSub = ssaRep->expressions[context->expressionsMatched[2]];
			SSAExpression& carryExpr = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& secondSub = ssaRep->expressions[context->expressionsMatched[0]];
			if (!secondSub.directRefs.size() || firstSub.subExpressions.size() != 2 || secondSub.subExpressions.size() != 3 || carryExpr.subExpressions[0].offset + carryExpr.subExpressions[0].size != firstSub.size)
				return false;
			//TODO check if arguments of secondAdd are before firstAdd
			//and replace firstAdd not secondAdd
			g_peephole_logger.log<LogLevel::eDebug>("Replace Add - Carry Add");

			SSAExpression combine1;
			combine1.type = SSAExprType::eAppend;
			combine1.exprtype = secondSub.exprtype;
			combine1.instrAddr = secondSub.instrAddr;
			combine1.subExpressions = {
				firstSub.subExpressions[0],
				secondSub.subExpressions[0]
			};
			combine1.size = firstSub.subExpressions[0].size + secondSub.subExpressions[0].size;

			SSAExpression combine2;
			combine2.type = SSAExprType::eAppend;
			combine2.exprtype = secondSub.exprtype;
			combine2.instrAddr = secondSub.instrAddr;
			combine2.subExpressions = {
				firstSub.subExpressions[1],
				secondSub.subExpressions[1]
			};
			combine2.size = firstSub.subExpressions[1].size + secondSub.subExpressions[1].size;

			assert(combine1.size == combine2.size);

			if (ssaRep->isNotUsedBefore(firstSub, secondSub)) {
				uint32_t secsize = secondSub.size;
				secondSub.size += firstSub.size;

				SSAArgument addArg = SSAArgument::createId(secondSub.id, secondSub.exprtype, 0);

				SSAArgument splitArg1 = addArg;
				splitArg1.size = firstSub.size;
				splitArg1.offset = 0;

				SSAArgument splitArg2 = addArg;
				splitArg2.size = secsize;
				splitArg2.offset = firstSub.size;

				//Expression references invalidated
				SSAArgument combine1Arg = SSAArgument::createId(ssaRep->addBefore(&combine1, secondSub.id), secondSub.exprtype, combine1.size);
				SSAArgument combine2Arg = SSAArgument::createId(ssaRep->addAfter(&combine2, combine1Arg.ssaId), secondSub.exprtype, combine2.size);

				//set arguments of second arg
				ssaRep->expressions[context->expressionsMatched[0]].subExpressions = { combine1Arg, combine2Arg };

				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[2]], splitArg1);
				ssaRep->replaceExpr(ssaRep->expressions[context->expressionsMatched[0]], splitArg2);

				return true;
			}
			else {
				return false;
			}
		})
		.ssaType(0, 0, SSAExprType::eOp)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			if ((expr.opType == SSAOpType::eSub || expr.opType == SSAOpType::eBXor) && expr.subExpressions.size() == 2 && expr.subExpressions[0] == expr.subExpressions[1] && !ssaRep->usedOnlyInFlags(expr)) {
				g_peephole_logger.log<LogLevel::eDebug>("Zero-Op");
				return ssaRep->replaceExpr(expr, SSAArgument::createUVal(0, expr.size)) != 0;
			}
			return false;
		})
		.ssaType(0, 0, SSAExprType::eOp)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& subexpr = ssaRep->expressions[context->expressionsMatched[0]];
			int64_t change = 0;
			SSAArgument basearg;

			if (subexpr.opType != SSAOpType::eAdd && subexpr.opType != SSAOpType::eSub)
				return false;
			if (!ssaRep->isReplaceable(subexpr))
				return false;
			uint64_t distance = calculate_basearg_plus_offset(ssaRep, context->expressionsMatched[0], &change, &basearg);
			if (distance < 2)// distance travelled should be at leased 2 otherwise we just duplicate values
				return false;
			for (SSAArgument& arg : subexpr.subExpressions) {//this would be useless
				if (arg.type == SSAArgType::eId && arg.ssaId == basearg.ssaId) {
					return false;
				}
			}
			if (basearg.type == SSAArgType::eUndef)
				return false;
			if (change != 0) {
				SSAExpression newExpr;
				newExpr.type = SSAExprType::eOp;
				newExpr.opType = change > 0 ? SSAOpType::eAdd : SSAOpType::eSub;
				newExpr.exprtype = subexpr.exprtype;
				newExpr.instrAddr = subexpr.instrAddr;
				newExpr.subExpressions = {
					basearg,
					SSAArgument::createUVal(change < 0 ? change * -1 : change, arch->bitbase * arch->bytebase)
				};
				newExpr.size = subexpr.size;
				SSAArgument arg = SSAArgument::createId(ssaRep->addBefore(&newExpr, subexpr.id), SSAType::eUInt, newExpr.size);
				SSAExpression& reloadedsubexpr = ssaRep->expressions[context->expressionsMatched[0]];
				uint32_t count = ssaRep->replaceExpr(reloadedsubexpr, arg);
				return count != 0;
			}
			else {
				return ssaRep->replaceExpr(subexpr, basearg) != 0;
			}
		})
		.ssaType(0, 0, SSAOpType::eEq)
		.ssaType(1, 1, SSAOpType::eSub)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr1 = ssaRep->expressions[context->expressionsMatched[1]];
			SSAExpression& expr2 = ssaRep->expressions[context->expressionsMatched[0]];
			if (expr1.subExpressions.size() == 2 &&
				expr2.subExpressions.size() == 2 &&
				((expr2.subExpressions[1].isConst(SSAType::eUInt) && expr2.subExpressions[1].uval == 0) ||
				(expr2.subExpressions[1].isConst(SSAType::eInt) && expr2.subExpressions[1].sval == 0))) {
				g_peephole_logger.log<LogLevel::eDebug>("Eq %d - Sub %d ", context->expressionsMatched[0], context->expressionsMatched[1]);

				expr2.setAllArguments(ssaRep, expr1.subExpressions);
				return true;
			}
			return false;
		})
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
		})
		.ssaType(0, 0, SSAExprType::eAssign)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& expr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAArgument& arg = expr.subExpressions[0];
			if (expr.directRefs.size()) {
				if (arg.isConst()) {
					if (arg.argtype == expr.exprtype) {
						return ssaRep->replaceExpr(expr, arg) != 0;
					}
				}
				return ssaRep->replaceExpr(expr, arg) != 0;
			}
			return false;
		})
			//TODO fix
			//TODO append(x[0,8], x[8,8])
		.ssaType(0, 0, SSAExprType::eAssign)
		.ssaType(1, 1, SSAExprType::eAppend)
		.execute([](Architecture * arch, SSARepresentation * ssaRep, MatchContext * context) {
			SSAExpression& assignExpr = ssaRep->expressions[context->expressionsMatched[0]];
			SSAExpression& appendExpr = ssaRep->expressions[context->expressionsMatched[1]];
			SSAArgument& refArg = assignExpr.subExpressions[0];
			if (!(refArg.offset == 0 && refArg.size == appendExpr.size)) {
				uint32_t offset = 0;
				for (SSAArgument& arg : appendExpr.subExpressions) {
					if (offset == refArg.offset && arg.size == refArg.size) {
						SSAArgument newArg = SSAArgument::replace(refArg, arg);
						return ssaRep->replaceExpr(assignExpr, newArg) != 0;
					}
					offset += arg.size;
				}
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
			ssaRep->replaceAllArgs(expr, SSAArgument::createUndef(SSAType::eUInt, expr.location, expr.locref, expr.size));
			g_peephole_logger.log<LogLevel::eDebug>("Replace Undefs");
			return true;
		});
		return peephole_optimizer;
	}
}
