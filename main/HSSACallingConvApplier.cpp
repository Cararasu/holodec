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
			if(!expr.id)
				continue;
			if (expr.type == HSSA_EXPR_OUTPUT) {
				//TODO get Call method and get the calling convention of the target
				//currently HACK to use own calling convention
				HSSAExpression* callExpr = function->ssaRep.expressions.get (expr.subExpressions[0].id);
				assert (callExpr && callExpr->type == HSSA_EXPR_CALL);

				//TODO get correct stackreg
				HRegister* localStackReg = stackreg;

				bool isParam = false;
				switch(expr.location){
				case HSSA_LOCATION_REG:{
					for (HStringRef& regStr : cc->nonVolatileReg) {
						HRegister* reg = arch->getRegister (regStr);
						if (expr.locref.refId == reg->id) {
							assert (expr.subExpressions[0].type == HSSA_ARGTYPE_ID);

							expr.type = HSSA_EXPR_ASSIGN;
							for (HSSAArgument& arg : callExpr->subExpressions) {
								if (arg.type == HSSA_ARGTYPE_REG && arg.ref.refId == expr.locref.refId) {
									expr.subExpressions[0] = arg;
								}
							}
							isParam = true;
							break;
						}
					}
					if (!isParam && localStackReg && expr.locref.refId == localStackReg->id && cc->callerstackadjust == H_CC_STACK_ADJUST_CALLEE) {
						expr.type = HSSA_EXPR_ASSIGN;
						for (HSSAArgument& arg : callExpr->subExpressions) {
							if (arg.type == HSSA_ARGTYPE_REG && arg.ref.refId == expr.locref.refId) {
								expr.subExpressions[0] = arg;
							}
						}
						//leave the arg
						isParam = true;
					}
					if (!isParam) {
						for (HCCParameter& para : cc->returns) {
							HRegister* reg = arch->getRegister (para.regref);
							if (expr.locref.refId == reg->id) {
								expr.subExpressions.push_back (HSSAArgument::createVal ( (uint64_t) para.index, arch->bitbase));
								isParam = true;
								break;
							}
						}
					}
				}
				break;
				case HSSA_LOCATION_MEM:{
					for (HMemory& mem : arch->memories) {
						if (expr.locref.refId == mem.id) {
							expr.subExpressions.push_back (HSSAArgument::createVal ( (uint64_t) 0, arch->bitbase));
							isParam = true;
						}
					}
				}
				break;
				}
				if (!isParam) {
					expr.type = HSSA_EXPR_UNDEF;
					if (!expr.subExpressions.empty())
						expr.subExpressions.clear();
				}
			}
			if (expr.type == HSSA_EXPR_RETURN) {
				for (auto it = expr.subExpressions.begin(); it != expr.subExpressions.end();) {
					HSSAArgument& arg = *it;
					bool isParam = false;

					if (arg.type == HSSA_ARGTYPE_REG) {
						if (!isParam) {
							for (HCCParameter& para : cc->returns) {
								HRegister* reg = arch->getRegister (para.regref);
								if (arg.ref.refId == reg->id) {
									//leave as arg
									isParam = true;
									break;
								}
							}
						}
					} else if (arg.type == HSSA_ARGTYPE_MEM) {
						isParam = true;
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
				switch(expr.location){
				case HSSA_LOCATION_REG:{
					for (HCCParameter& para : cc->parameters) {
						HRegister* reg = arch->getRegister (para.regref);
						if (expr.locref.refId == reg->id) {
							expr.subExpressions.push_back (HSSAArgument::createVal ( (uint64_t) para.index, arch->bitbase));
							isParam = true;
							break;
						}
					}
					if (!isParam && expr.locref.refId == stackreg->id) {
						expr.subExpressions.push_back (HSSAArgument::createVal ( (uint64_t) 0, arch->bitbase));
						isParam = true;
					}
				}break;
				case HSSA_LOCATION_MEM:{
					for (HMemory& mem : arch->memories) {
						if (expr.locref.refId == mem.id) {
							expr.subExpressions.push_back (HSSAArgument::createVal ( (uint64_t) 0, arch->bitbase));
							isParam = true;
						}
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
			if(!expr.id)
				continue;
			if (expr.type == HSSA_EXPR_CALL) {
				//TODO get the calling convention of the target
				//currently HACK to use own calling convention

				for (auto it = expr.subExpressions.begin() + 1/* skip first parameter*/; it != expr.subExpressions.end();) {
					HSSAArgument& arg = *it;
					bool isParam = false;
					
					if (arg.type == HSSA_ARGTYPE_MEM)
						isParam = true;
					if (!isParam) {
						for (HCCParameter& para : cc->parameters) {
							HRegister* reg = arch->getRegister (para.regref);
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
