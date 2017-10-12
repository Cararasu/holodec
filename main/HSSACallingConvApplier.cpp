#include "HSSACallingConvApplier.h"
#include "HCallingConvention.h"
#include "HArchitecture.h"
#include <assert.h>

namespace holodec {

	void HSSACallingConvApplier::doTransformation (HFunction* function) {

		printf ("Apply Calling Convention in Function at Address 0x%x\n", function->baseaddr);

		HCallingConvention* cc = arch->getCallingConvention (function->callingconvention);

		HStack* stack = cc->stack ? arch->getStack (cc->stack) : nullptr;
		HRegister* stackreg = stack && stack->trackingReg ? arch->getRegister (stack->trackingReg) : nullptr;

		for (HSSAExpression& expr : function->ssaRep.expressions) {
			if (expr.type == HSSA_EXPR_OUTPUT) {
				//TODO get Call method and get the calling convention of the target
				//currently HACK to use own calling convention
				HSSAExpression* callExpr = function->ssaRep.expressions.get (expr.subExpressions[0].id);
				assert (callExpr && callExpr->type == HSSA_EXPR_CALL);

				//TODO get correct stackreg
				HRegister* localStackReg = stackreg;

				bool isParam = false;
				if (expr.regId) {
					for (HString& regStr : cc->nonVolatileReg) {
						HRegister* reg = arch->getRegister (regStr);
						if (expr.regId == reg->id) {
							assert (expr.subExpressions[0].type == HSSA_ARGTYPE_ID);

							expr.type = HSSA_EXPR_ASSIGN;
							for (HArgument& arg : callExpr->subExpressions) {
								if (arg.type == H_ARGTYPE_REG && arg.reg == expr.regId) {
									expr.subExpressions[0] = arg;
								}
							}
							isParam = true;
							break;
						}
					}
					if (!isParam && localStackReg && expr.regId == localStackReg->id && cc->callerstackadjust == H_CC_STACK_ADJUST_CALLEE) {
						expr.type = HSSA_EXPR_ASSIGN;
						for (HArgument& arg : callExpr->subExpressions) {
							if (arg.type == H_ARGTYPE_REG && arg.reg == expr.regId) {
								expr.subExpressions[0] = arg;
							}
						}
						//leave the arg
						isParam = true;
					}
					if (!isParam) {
						for (HCCParameter& para : cc->returns) {
							HRegister* reg = arch->getRegister (para.regname);
							if (expr.regId == reg->id) {
								expr.subExpressions.push_back (HArgument::createVal ( (uint64_t) para.index, arch->bitbase));
								isParam = true;
								break;
							}
						}
					}
				} else if (expr.memId) {
					for (HMemory& mem : arch->memories) {
						if (expr.memId == mem.id) {
							expr.subExpressions.push_back (HArgument::createVal ( (uint64_t) 0, arch->bitbase));
							isParam = true;
						}
					}
				}

				if (!isParam) {
					expr.type = HSSA_EXPR_UNDEF;
					if (!expr.subExpressions.empty())
						expr.subExpressions.clear();
				}
			}
			if (expr.type == HSSA_EXPR_RETURN) {
				for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end();) {
					HArgument& arg = *it;
					bool isParam = false;

					if ( (arg.type & ~H_ARGTYPE_UNKN) == H_ARGTYPE_MEM)
						isParam = true;

					if (!isParam) {
						for (HCCParameter& para : cc->returns) {
							HRegister* reg = arch->getRegister (para.regname);
							if (arg.reg == reg->id) {
								//leave as arg
								isParam = true;
								break;
							}
						}
					}
					if (!isParam) {
						expr.subExpressions.erase (it);
						continue;
					}
					it++;
				}
			}
			if (expr.type == HSSA_EXPR_INPUT) {

				bool isParam = false;
				if (expr.regId) {
					for (HCCParameter& para : cc->parameters) {
						HRegister* reg = arch->getRegister (para.regname);
						if (expr.regId == reg->id) {
							expr.subExpressions.push_back (HArgument::createVal ( (uint64_t) para.index, arch->bitbase));
							isParam = true;
							break;
						}
					}
					if (!isParam && expr.regId == stackreg->id) {
						expr.subExpressions.push_back (HArgument::createVal ( (uint64_t) 0, arch->bitbase));
						isParam = true;
					}
				} else if (expr.memId) {
					for (HMemory& mem : arch->memories) {
						if (expr.memId == mem.id) {
							expr.subExpressions.push_back (HArgument::createVal ( (uint64_t) 0, arch->bitbase));
							isParam = true;
						}
					}
				}

				if (!isParam) {
					expr.type = HSSA_EXPR_UNDEF;
					if (!expr.subExpressions.empty())
						expr.subExpressions.clear();
				}
			}
		}

		for (HSSAExpression& expr : function->ssaRep.expressions) {
			if (expr.type == HSSA_EXPR_CALL) {
				//TODO get the calling convention of the target
				//currently HACK to use own calling convention

				for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end();) {
					HArgument& arg = *it;
					bool isParam = false;
					if ( (arg.type & ~H_ARGTYPE_UNKN) == H_ARGTYPE_MEM)
						isParam = true;
					if (!isParam) {
						for (HCCParameter& para : cc->parameters) {
							HRegister* reg = arch->getRegister (para.regname);
							if (arg.reg == reg->id) {
								//leave the arg
								isParam = true;
								break;
							}
						}
					}
					if (!isParam && stackreg && arg.reg == stackreg->id) {
						printf ("%s\n", stackreg->name.cstr());
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

	}
}
