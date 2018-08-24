

#include "SSACalleeCallerRegs.h"

namespace holodec{

	bool SSACalleeCallerRegs::isInputMem(HId memId, CalleeArgument arg, uint32_t outoffset, std::set<HId>& exprvisited, CalleeArgument* retArg, CalleeArgument ptrArg) {
		SSAExpression* expr = &ssaRep->expressions[memId];
		exprvisited.insert(expr->id);
		if (expr->type == SSAExprType::ePhi) {
			for (SSAArgument& exprArg : expr->subExpressions) {
				if (exprArg.type == SSAArgType::eBlock)
					continue;
				if (exprArg.type != SSAArgType::eId || exprArg.location != SSALocation::eMem)
					return false;
				if (exprvisited.find(exprArg.ssaId) == exprvisited.end()) {
					if (!isInputMem(exprArg.ssaId, arg, outoffset, exprvisited, retArg, ptrArg)) {
						return false;
					}
				}
			}
			return true;
		}
		else if (expr->type == SSAExprType::eStore) {
			if (expr->subExpressions[1].type == SSAArgType::eId && expr->subExpressions[1].ssaId == ptrArg.ssaId) {
				//TODO check if the ptrArg is a stack???
				return isInput(arg.replace(expr->subExpressions[2]), outoffset, exprvisited, retArg);
			}
			return isInputMem(expr->subExpressions[0].ssaId, arg, outoffset, exprvisited, retArg, ptrArg);
		}
		else if (expr->type == SSAExprType::eLoad) {
			return isInputMem(expr->subExpressions[0].ssaId, arg, outoffset, exprvisited, retArg, ptrArg);
		}
		else if (expr->type == SSAExprType::eMemOutput) {
			SSAExpression* callExpr = &ssaRep->expressions[expr->subExpressions[0].ssaId];
			for (SSAArgument& arg : callExpr->subExpressions) {
				if (ptrArg.equals(arg)) {
					return false;
				}
			}
			return isInputMem(expr->subExpressions[1].ssaId, arg, outoffset, exprvisited, retArg, ptrArg);

		}
		return false;
	}
	bool SSACalleeCallerRegs::isInput(CalleeArgument arg, uint32_t outoffset, std::set<HId>& exprvisited, CalleeArgument* retArg) {
		SSAExpression* expr = &ssaRep->expressions[arg.ssaId];
		exprvisited.insert(expr->id);
		if (expr->size < arg.size)
			return false;
		if (expr->type == SSAExprType::eAppend) {
			uint32_t poffset = outoffset;
			for (SSAArgument& argIt : expr->subExpressions) {
				if (argIt.type != SSAArgType::eId || !isInput(arg.replace(argIt), poffset, exprvisited, retArg)) {
					return false;
				}
				poffset += ssaRep->expressions[argIt.ssaId].size;
			}
			return true;
		}
		else if (expr->type == SSAExprType::eLoad) {
			return isInputMem(expr->subExpressions[0].ssaId, arg, outoffset, exprvisited, retArg, expr->subExpressions[1]);
		}
		else if (expr->type == SSAExprType::eInput) {
			if (expr->location == SSALocation::eReg) {
				if (!retArg->ssaId)
					retArg[0] = arg;
				return *retArg == arg && arg.offset == outoffset;
			}
		}
		return false;
	}
	bool SSACalleeCallerRegs::doTransformation(Binary* binary, Function* function) {// interprocedural liveness analysis for callee saved registers

		//function->print(arch);
		printf("Resolving Callee-saved-Registers in Function at Address 0x%" PRIx64 "\n", function->baseaddr);

		ssaRep = &function->ssaRep;
		ssaRep->checkIntegrity();
		for (SSAExpression& expr : ssaRep->expressions) {
			if (expr.type != SSAExprType::eReturn)
				continue;
			std::set<HId> visited;
			for (SSAArgument& arg : expr.subExpressions) {
				if (!(arg.type == SSAArgType::eId && arg.location == SSALocation::eReg))
					continue;
				Register* reg = arch->getRegister(arg.locref.refId);
				HId id = 0;
				CalleeArgument retArg;
				bool succ = isInput(arg, 0, visited, &retArg);
				visited.clear();
				if (succ) {
					retArg.print();
					printf("%s ----> %d\n", reg->name.cstr(), retArg.ssaId);
					arg.ssaId = retArg.ssaId;
				}
			}
		}
		return false;
		//this is dangerous
		//remove non used by caller is probably better
		bool changed = false;
		for (SSAExpression& expr : ssaRep->expressions) {
			if (expr.type == SSAExprType::eReturn) {
				//first argument is the return argument so skip it
				for (auto it = expr.subExpressions.begin() + 1; it != expr.subExpressions.end();) {
					if (it->location == SSALocation::eReg) {
						bool removed = false;
						for (StringRef& ref : volatileRegs) {
							printf("RemoveShit %d %d\n", ref.refId, it->locref.refId);
							if (ref.refId == it->locref.refId) {
								printf("RemoveShit\n");
								it = expr.removeArgument(ssaRep, it);
								changed = removed = true;
								break;
							}
						}
						if (removed) {
							continue;
						}
					}
					++it;
				}
			}
		}
		return changed;
	}

}