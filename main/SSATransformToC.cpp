#include "SSATransformToC.h"


namespace holodec{
	

	bool SSATransformToC::shouldResolve(SSAExpression& expr) {
		if (resolveIds.find(expr.id) != resolveIds.end()) {
			return true;
		}
		if (expr.refs.size() > 1) {
			return true;
		}
		if (EXPR_HAS_SIDEEFFECT(expr.type)) {
			return true;
		}
		return false;
	}


	void SSATransformToC::printBasicBlock(SSABB& bb) {
		printf("Basic Block %d\n", bb.id);
		for (HId id : bb.exprIds) {
			SSAExpression& expr = function->ssaRep.expressions[id];
			if (shouldResolve(expr))
				printExpression(expr);
		}

		if(bb.fallthroughId)
			printf("goto %d\n", bb.fallthroughId);
	}
	void SSATransformToC::resolveArgs(SSAExpression& expr, const char* delimiter) {
		printf("(");
		for (size_t i = 0; i < expr.subExpressions.size(); i++) {
			SSAArgument& arg = expr.subExpressions[i];
			resolveArg(arg);
			if(i + 1 != expr.subExpressions.size())
				printf("%s", delimiter);
		}
		printf(")");
	}
	void SSATransformToC::resolveArg(SSAArgument& arg) {

		switch (arg.type) {
		case SSAArgType::eUndef:
			printf("undef");
			break;
		case SSAArgType::eSInt:
			printf("%d", arg.sval);
			break;
		case SSAArgType::eUInt:
			printf("%u", arg.uval);
			break;
		case SSAArgType::eFloat:
			printf("%f", arg.fval);
			break;
		case SSAArgType::eId: {
			SSAExpression& subExpr = function->ssaRep.expressions[arg.ssaId];
			bool nonZeroOffset = (arg.offset != 0), nonFullSize = (arg.offset + arg.size != subExpr.size);
			if (nonFullSize) {
				printf("(");
				if (subExpr.exprtype == SSAType::eFloat)
					printf("(float_%d) ", arg.size);
				else if (subExpr.exprtype == SSAType::eUInt)
					printf("(uint%d_t) ", arg.size);
				else if (subExpr.exprtype == SSAType::eInt)
					printf("(int%d_t) ", arg.size);
			}
			if (nonZeroOffset)
				printf("(");
			if (resolveIds.find(arg.ssaId) == resolveIds.end()) {
				if(subExpr.type != SSAExprType::eInput)
					printf("(");
				resolveExpression(subExpr);
				if (subExpr.type != SSAExprType::eInput)
					printf(")");
			}
			else {
				printf("var%d", arg.ssaId);
			}
			if (nonZeroOffset)
				printf(" >> %d)", arg.offset);
			if (nonFullSize)
				printf(")");
		}break;
		case SSAArgType::eOther:
			break;
		}
	}
	void SSATransformToC::resolveExpression(SSAExpression& expr) {
		switch (expr.type) {
		case SSAExprType::eInvalid:
			break;
		case SSAExprType::eLabel:
			break;
		case SSAExprType::eUndef:
			printf("undef ");
			break;
		case SSAExprType::eNop:
			break;
		case SSAExprType::eOp: {
			for (size_t i = 0; i < expr.subExpressions.size(); ++i) {
				SSAArgument& arg = expr.subExpressions[i];
				resolveArg(arg);
				if (i + 1 != expr.subExpressions.size()) {
					switch (expr.opType) {
					case SSAOpType::eMul:
						printf(" * ");
						break;
					case SSAOpType::eDiv:
						printf(" / ");
						break;
					case SSAOpType::eSub:
						printf(" - ");
						break;
					case SSAOpType::eAdd:
						printf(" + ");
						break;
					case SSAOpType::eAnd:
						printf(" && ");
						break;
					case SSAOpType::eOr:
						printf(" || ");
						break;
					case SSAOpType::eEq:
						printf(" == ");
						break;
					case SSAOpType::eNe:
						printf(" != ");
						break;
					case SSAOpType::eLe:
						printf(" <= ");
						break;
					case SSAOpType::eLower:
						printf(" < ");
						break;
					case SSAOpType::eGe:
						printf(" >= ");
						break;
					case SSAOpType::eGreater:
						printf(" > ");
						break;
					default:
						printf(" op ");
					}
				}
			}
		}break;
		case SSAExprType::eLoadAddr:
			printf("[");
			resolveArg(expr.subExpressions[1]);
			printf("+");
			resolveArg(expr.subExpressions[2]);
			printf("*");
			resolveArg(expr.subExpressions[3]);
			printf("+");
			resolveArg(expr.subExpressions[4]);
			printf("]");
			break;
		case SSAExprType::eFlag:
			printf("Flag-");
			switch (expr.flagType) {
			case SSAFlagType::eC:
				printf("Carry");
				break;
			case SSAFlagType::eO:
				printf("Overflow");
				break;
			case SSAFlagType::eU:
				printf("Underflow");
				break;
			}
			printf("(");
			resolveArg(expr.subExpressions[0]);
			printf(")");
			break;
		case SSAExprType::eBuiltin:{
			printf("%s ", arch->getBuiltin(expr.builtinId)->name.cstr());
			resolveArgs(expr);
		}break;
		case SSAExprType::eExtend: {
			if (expr.exprtype == SSAType::eFloat)
				printf("(float_%d)", expr.size);
			else if (expr.exprtype == SSAType::eInt)
				printf("(int%d_t)", expr.size);
			else if (expr.exprtype == SSAType::eUInt)
				printf("(uint%d_t)", expr.size);
			else
				printf("extend%d", expr.size);
			resolveArgs(expr);
		}break;
		case SSAExprType::eUpdatePart: {
			printf("UpdatePart");
		}break;
		case SSAExprType::eAppend: {
			printf("(");
			uint32_t offset = 0;
			for (size_t i = 0; i < expr.subExpressions.size(); i++) {
				SSAArgument& arg = expr.subExpressions[i];
				resolveArg(arg);
				if(offset)
					printf(" << %d", offset);
				offset += arg.size;
				if (i + 1 != expr.subExpressions.size())
					printf(" | ");
			}
			printf(")");
		}break;
		case SSAExprType::eCast: {
			if (expr.exprtype == SSAType::eFloat)
				printf("F");
			else if (expr.exprtype == SSAType::eInt)
				printf("S");
			else if (expr.exprtype == SSAType::eUInt)
				printf("U");
			printf("Cast%d ");
			resolveArgs(expr);
		}break;

		case SSAExprType::eInput:
			for (CArgument& arg : arguments) {
				if (arg.ssaId == expr.id) {
					printf("arg%d", arg.id);
				}
			}
			break;
		case SSAExprType::eOutput:
			break;

		case SSAExprType::eCall: {
			printf("Call ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eReturn: {
			printf("Return ");
			printf("(");
			for (size_t i = 0; i < expr.subExpressions.size(); i++) {
				SSAArgument& arg = expr.subExpressions[i];
				if (arg.location == SSALocation::eReg) {
					printf("%s: ", arch->getRegister(arg.locref.refId)->name.cstr());
				}
				resolveArg(arg);
				if (i + 1 != expr.subExpressions.size())
					printf(", ");
			}
			printf(")");
		}break;
		case SSAExprType::eSyscall: {
			printf("Syscall ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eTrap: {
			printf("Trap ");
			resolveArgs(expr);
		}break;

		case SSAExprType::ePhi: {
			printf("Phi ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eAssign: {
			resolveArg(expr.subExpressions[0]);
		}break;

		case SSAExprType::eJmp: {
			printf("Jmp ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eCJmp: {
			printf("CJmp ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eMultiBranch:
			printf("Multibranch");
			break;
		case SSAExprType::eMemAccess: {
			printf("MemAccess ");
			resolveArgs(expr);
		}break;
		case SSAExprType::ePush: {
			printf("Push ");
			resolveArgs(expr);
		}break;
		case SSAExprType::ePop: {
			printf("Pop ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eStore: {
			printf("Store ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eLoad: {
			printf("Load ");
			resolveArgs(expr);
		}break;
		}
	}
	void SSATransformToC::printExpression(SSAExpression& expr) {
		resolveIds.insert(expr.id);
		printIndent(1);
		printf("var%d = ", expr.id);
		resolveExpression(expr);
		puts("");
	}

	void SSATransformToC::doTransformation (Binary* binary, Function* function){
		printf("Transform To C\n");

		this->binary = binary;
		this->function = function;

		//function->print(binary->arch);
		Symbol *sym = binary->getSymbol(function->symbolref);

		arguments.clear();
		resolveIds.clear();
		printf("Function: %s\n", sym->name.cstr());
		printf("Calling Functions: ");
		for (uint64_t addr : function->funcsCall) {
			printf("0x%x ", addr);
		}
		printf("\n");
		printf("CalledFunctions: ");
		for (uint64_t addr : function->funcsCalled) {
			printf("0x%x ", addr);
		}
		printf("\n");
		{
			SSABB& bb = function->ssaRep.bbs[1];
			for (HId id : bb.exprIds) {
				SSAExpression& expr = function->ssaRep.expressions[id];
				if (expr.type == SSAExprType::eInput) {
					if (expr.location == SSALocation::eReg) {
						CArgument arg = { 0, expr.id, { binary->arch->getRegister(expr.locref.refId)->name.cstr(), expr.locref.refId } };
						arguments.push_back(arg);
					}
				}
			}
			printIndent(1);
			printf("Input (");
			for (CArgument arg : arguments) {
				printf("arg%d: %s ", arg.id, arg.regRef.name.cstr());
			}
			puts(")\n");
			for (HId id = 2; id < function->ssaRep.bbs.size(); ++id) {
				SSABB& bb = function->ssaRep.bbs[id];
				for (HId id : bb.exprIds) {
					SSAExpression& expr = function->ssaRep.expressions[id];
					if (expr.type == SSAExprType::ePhi) {
						resolveIds.insert(expr.id);
						for (SSAArgument& arg : expr.subExpressions) {
							if (arg.type == SSAArgType::eId) {
								resolveIds.insert(arg.ssaId);
							}
						}
					}
				}
			}

		}
		
		for (size_t index = 1; index < function->ssaRep.bbs.list.size(); ++index) {
			printBasicBlock(function->ssaRep.bbs.list[index]);
		}
	}
}

