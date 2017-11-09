#include "SSACallingConvApplier.h"
#include "CallingConvention.h"
#include "Architecture.h"
#include <assert.h>

namespace holodec {

	void SSACallingConvApplier::doTransformation (Function* function) {

		printf ("Apply Calling Convention in Function at Address 0x%x\n", function->baseaddr);

		CallingConvention* cc = arch->getCallingConvention (function->callingconvention);

		Stack* stack = cc->stack ? arch->getStack (cc->stack) : nullptr;
		Register* stackreg = stack && stack->trackingReg ? arch->getRegister (stack->trackingReg) : nullptr;

		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (!expr.id)
				continue;
			if (expr.type == SSA_EXPR_OUTPUT) {
				//TODO get Call method and get the calling convention of the target
				//currently HACK to use own calling convention
				SSAExpression* callExpr = function->ssaRep.expressions.get (expr.subExpressions[0].ssaId);
				assert (callExpr && callExpr->type == SSA_EXPR_CALL);

				//TODO get correct stackreg
				Register* localStackReg = stackreg;

				bool isParam = false;
				switch (expr.location) {
				case SSA_LOCATION_REG: {
					for (StringRef& regStr : cc->nonVolatileReg) {
						Register* reg = arch->getRegister (regStr);
						if (expr.locref.refId == reg->id) {
							assert (expr.subExpressions[0].type == SSA_ARGTYPE_ID);

							expr.type = SSA_EXPR_ASSIGN;
							for (SSAArgument& arg : callExpr->subExpressions) {
								if (arg.type == SSA_ARGTYPE_REG && arg.ref.refId == expr.locref.refId) {
									expr.subExpressions[0] = arg;
								}
							}
							isParam = true;
							break;
						}
					}
					if (!isParam && localStackReg && expr.locref.refId == localStackReg->id && cc->callerstackadjust == H_CC_STACK_ADJUST_CALLEE) {
						expr.type = SSA_EXPR_ASSIGN;
						for (SSAArgument& arg : callExpr->subExpressions) {
							if (arg.type == SSA_ARGTYPE_REG && arg.ref.refId == expr.locref.refId) {
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
								expr.subExpressions.push_back (SSAArgument::createVal ( (uint64_t) para.index, arch->bitbase));
								isParam = true;
								break;
							}
						}
					}
				}
				break;
				case SSA_LOCATION_MEM: {
					for (Memory& mem : arch->memories) {
						if (expr.locref.refId == mem.id) {
							expr.subExpressions.push_back (SSAArgument::createVal ( (uint64_t) 0, arch->bitbase));
							isParam = true;
						}
					}
				}
				break;
				}
				if (!isParam) {
					expr.type = SSA_EXPR_UNDEF;
					if (!expr.subExpressions.empty())
						expr.subExpressions.clear();
				}
			}
			if (expr.type == SSA_EXPR_RETURN) {
				for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end();) {
					SSAArgument& arg = *it;
					bool isParam = false;

					if (arg.type == SSA_ARGTYPE_REG) {
						if (!isParam) {
							for (CCParameter& para : cc->returns) {
								Register* reg = arch->getRegister (para.regref);
								if (arg.ref.refId == reg->id) {
									//leave as arg
									isParam = true;
									break;
								}
							}
						}
					} else if (arg.type == SSA_ARGTYPE_MEM) {
						isParam = true;
					}
					if (!isParam) {
						expr.subExpressions.erase (it);
						continue;
					}
					it++;
				}
			}
			if (expr.type == SSA_EXPR_INPUT) {

				bool isParam = false;
				switch (expr.location) {
				case SSA_LOCATION_REG: {
					for (CCParameter& para : cc->parameters) {
						Register* reg = arch->getRegister (para.regref);
						if (expr.locref.refId == reg->id) {
							expr.subExpressions.push_back (SSAArgument::createVal ( (uint64_t) para.index, arch->bitbase));
							isParam = true;
							break;
						}
					}
					if (!isParam && expr.locref.refId == stackreg->id) {
						expr.subExpressions.push_back (SSAArgument::createVal ( (uint64_t) 0, arch->bitbase));
						isParam = true;
					}
				}
				break;
				case SSA_LOCATION_MEM:
					for (Memory& mem : arch->memories) {
						if (expr.locref.refId == mem.id) {
							expr.subExpressions.push_back (SSAArgument::createVal ( (uint64_t) 0, arch->bitbase));
							isParam = true;
						}
					}
				}

				if (!isParam) {
					expr.type = SSA_EXPR_UNDEF;
					if (!expr.subExpressions.empty())
						expr.subExpressions.clear();
				}
			}
		}

		for (SSAExpression& expr : function->ssaRep.expressions) {
			if (!expr.id)
				continue;
			if (expr.type == SSA_EXPR_CALL) {
				//TODO get the calling convention of the target
				//currently HACK to use own calling convention

				for (auto it = expr.subExpressions.begin() + 1/* skip first parameter*/; it != expr.subExpressions.end();) {
					SSAArgument& arg = *it;
					bool isParam = false;

					if (arg.type == SSA_ARGTYPE_MEM)
						isParam = true;
					if (!isParam) {
						for (CCParameter& para : cc->parameters) {
							Register* reg = arch->getRegister (para.regref);
							if (arg.ref.refId == reg->id) {
								//leave the arg
								isParam = true;
								break;
							}
						}
					}
					if (!isParam && stackreg && arg.ref.refId == stackreg->id) {
						//leave the arg
						isParam = true;
					}
					if (!isParam) {
						//remove from arg list
						expr.subExpressions.erase (it);
						continue;
					}
					it++;
				}
			}
		}
		function->ssaRep.compress();
	}
}