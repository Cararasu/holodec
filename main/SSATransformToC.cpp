#include "SSATransformToC.h"


namespace holodec{
	



	void SSATransformToC::doTransformation (Binary* binary, Function* function){
		printf("Transform To C\n");
		//function->print(binary->arch);
		Symbol *sym = binary->getSymbol(function->symbolref);

		printf("function %s\n", sym->name.cstr());
		{
			printIndent(1);
			puts("Input (");
			SSABB& bb = function->ssaRep.bbs[1];
			for (HId id : bb.exprIds) {
				SSAExpression& expr = function->ssaRep.expressions[id];
				if (expr.type == SSAExprType::eInput) {
					if (expr.location == SSALocation::eReg) {
						printf("Reg: %s, ", binary->arch->getRegister(expr.locref.refId)->name.cstr());
					}
				}
			}
			puts(")\n");
		}
		for (HId id = 2; id < function->ssaRep.bbs.size(); ++id) {
			SSABB& bb = function->ssaRep.bbs[id];
			for (HId id : bb.exprIds) {
				SSAExpression& expr = function->ssaRep.expressions[id];
				switch (expr.type) {
				case SSAExprType::eInvalid:
				case SSAExprType::eLabel:
				case SSAExprType::eUndef:
				case SSAExprType::eNop:
					break;
				case SSAExprType::eOp: {

					for (size_t i = 1; i < expr.subExpressions.size(); ++i) {
						SSAArgument& arg = expr.subExpressions[i];

						switch (arg.type) {
						case SSAArgType::eUndef:
							break;
						case SSAArgType::eSInt:
							break;
						case SSAArgType::eUInt:
							break;
						case SSAArgType::eFloat:
							break;
						case SSAArgType::eId:
							break;
						case SSAArgType::eOther:
							break;
						}
					}
				}break;
				case SSAExprType::eLoadAddr:
				case SSAExprType::eFlag:
				case SSAExprType::eBuiltin:
				case SSAExprType::eExtend:
				case SSAExprType::eSplit:
				case SSAExprType::eUpdatePart:
				case SSAExprType::eAppend:
				case SSAExprType::eCast:

				case SSAExprType::eInput:
				case SSAExprType::eOutput:

				case SSAExprType::eCall:
				case SSAExprType::eReturn:
				case SSAExprType::eSyscall:
				case SSAExprType::eTrap:

				case SSAExprType::ePhi:
				case SSAExprType::eAssign:

				case SSAExprType::eJmp:
				case SSAExprType::eCJmp:
				case SSAExprType::eMultiBranch:
				case SSAExprType::eMemAccess:
				case SSAExprType::ePush:
				case SSAExprType::ePop:
				case SSAExprType::eStore:
				case SSAExprType::eLoad:
					break;
				}
			}
		}
	}
}

