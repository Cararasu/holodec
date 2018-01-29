#include "SSACallingConvApplier.h"
#include "CallingConvention.h"
#include "Architecture.h"
#include <assert.h>

namespace holodec {

	void SSACallingConvApplier::doTransformation (Function* function) {

		printf ("Apply Calling Convention in Function at Address 0x%" PRIx64 "\n", function->baseaddr);

		CallingConvention* cc = arch->getCallingConvention (function->callingconvention);

		Stack* stack = cc->stack ? arch->getStack (cc->stack) : nullptr;
		Register* stackreg = stack && stack->trackingReg ? arch->getRegister (stack->trackingReg) : nullptr;

		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (!expr.id)
				continue;
			if (expr.type == SSAExprType::eOutput) {
				//TODO get Call method and get the calling convention of the target
				//currently HACK to use own calling convention
				assert (expr.subExpressions[0].type == SSAArgType::eId);
				SSAExpression* callExpr = function->ssaRep.expressions.get (expr.subExpressions[0].ssaId);
				assert (callExpr && callExpr->type == SSAExprType::eCall);

				//TODO get correct stackreg
				Register* localStackReg = stackreg;

				bool isParam = false;
				switch (expr.location) {
				case SSAExprLocation::eReg: {
					for (StringRef& regStr : cc->nonVolatileReg) {
						Register* reg = arch->getRegister (regStr);
						if (expr.locref.refId == reg->id) {
							assert (expr.subExpressions[0].type == SSAArgType::eId);

							expr.type = SSAExprType::eAssign;
							for (SSAArgument& arg : callExpr->subExpressions) {
								if (arg.location == SSAExprLocation::eReg && arg.locref == expr.locref) {
									expr.subExpressions[0] = arg;
								}
							}
							isParam = true;
							break;
						}
					}
					if (!isParam && localStackReg && expr.locref.refId == localStackReg->id && cc->callerstackadjust == CCStackAdjust::eCallee) {
						expr.type = SSAExprType::eAssign;
						for (SSAArgument& arg : callExpr->subExpressions) {
							if (arg.location == SSAExprLocation::eReg && arg.locref == expr.locref) {
								expr.subExpressions[0] = arg;
							}
						}
						//leave the arg
						isParam = true;
					}
					if (!isParam) {
						for (CCParameter& para : cc->returns) {
							Register* reg = arch->getRegister (para.regref);
							if (expr.locref.refId == reg->id) {
								expr.subExpressions.push_back (SSAArgument::createUVal ( (uint64_t) para.index, arch->bitbase));
								isParam = true;
								break;
							}
						}
					}
				}
				break;
				case SSAExprLocation::eMem: {
					for (Memory& mem : arch->memories) {
						if (expr.locref.refId == mem.id) {
							expr.subExpressions.push_back (SSAArgument::createUVal ( (uint64_t) 0, arch->bitbase));
							isParam = true;
						}
					}
				}
				break;
				default:
					break;
				}
				if (!isParam) {
					expr.type = SSAExprType::eUndef;
					if (!expr.subExpressions.empty())
						expr.subExpressions.clear();
				}
			}
			if (expr.type == SSAExprType::eReturn) {
				for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end();) {
					SSAArgument& arg = *it;
					bool isParam = false;

					if (arg.location == SSAExprLocation::eReg) {
						if (!isParam) {
							for (CCParameter& para : cc->returns) {
								Register* reg = arch->getRegister (para.regref);
								if (arg.locref.refId == reg->id) {
									//leave as arg
									isParam = true;
									break;
								}
							}
						}
					} else if (arg.location == SSAExprLocation::eMem) {
						isParam = true;
					}
					if (!isParam) {
						it = expr.subExpressions.erase (it);
						continue;
					}
					it++;
				}
			}
			if (expr.type == SSAExprType::eInput) {

				bool isParam = false;
				switch (expr.location) {
				case SSAExprLocation::eReg: {
					for (CCParameter& para : cc->parameters) {
						Register* reg = arch->getRegister (para.regref);
						if (expr.locref.refId == reg->id) {
							expr.subExpressions.push_back (SSAArgument::createUVal ( (uint64_t) para.index, arch->bitbase));
							isParam = true;
							break;
						}
					}
					if (!isParam && expr.locref.refId == stackreg->id) {
						expr.subExpressions.push_back (SSAArgument::createUVal ( (uint64_t) 0, arch->bitbase));
						isParam = true;
					}
				}
				break;
				case SSAExprLocation::eMem: {
					for (Memory& mem : arch->memories) {
						if (expr.locref.refId == mem.id) {
							expr.subExpressions.push_back (SSAArgument::createUVal ( (uint64_t) 0, arch->bitbase));
							isParam = true;
						}
					}
				}
				break;
				default:
					break;
				}

				if (!isParam) {
					expr.type = SSAExprType::eUndef;
					if (!expr.subExpressions.empty())
						expr.subExpressions.clear();
				}
			}
		}

		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (!expr.id)
				continue;
			if (expr.type == SSAExprType::eCall) {
				//TODO get the calling convention of the target
				//currently HACK to use own calling convention

				for (auto it = expr.subExpressions.begin() + 1/* skip first parameter*/; it != expr.subExpressions.end();) {
					SSAArgument& arg = *it;
					bool isParam = false;

					if (arg.location == SSAExprLocation::eMem)
						isParam = true;
					if (!isParam) {
						for (CCParameter& para : cc->parameters) {
							Register* reg = arch->getRegister (para.regref);
							if (arg.locref.refId == reg->id) {
								//leave the arg
								isParam = true;
								break;
							}
						}
					}
					if (!isParam && stackreg && arg.locref.refId == stackreg->id) {
						//leave the arg
						isParam = true;
					}
					if (!isParam) {
						//remove from arg list
						it = expr.subExpressions.erase (it);
						continue;
					}
					it++;
				}
			}
		}
		function->ssaRep.compress();
	}
}
