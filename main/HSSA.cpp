
#include "HSSA.h"
#include "HArchitecture.h"

namespace holodec {


	void HSSAExpression::print (HArchitecture* arch, int indent) {
		printIndent(indent);
		switch(type){
		case HSSA_EXPR_INVALID:
			printf("---------------------------------------");
			printf("Invalid%d ",type);
			break;
		case HSSA_EXPR_LABEL:
			printf("Label ");
			break;
		case HSSA_EXPR_INPUT:
			printf("Input ");
			break;
		case HSSA_EXPR_UNDEF:
			printf("Undef ");
			break;
		case HSSA_EXPR_NOP:
			printf("Nop ");
			break;
		case HSSA_EXPR_PHI:
			printf("Phi ");
			break;
		case HSSA_EXPR_IDENT:
			printf("Ident ");
			break;
		case HSSA_EXPR_JMP:
			printf("Jmp ");
			break;
		case HSSA_EXPR_CJMP:
			printf("Cjmp ");
			break;
		case HSSA_EXPR_OP:
			printf("Op ");
			
			break;
		case HSSA_EXPR_COND:
			printf("Cond ");
			break;
		case HSSA_EXPR_CALL:
			printf("Call ");
			break;
		case HSSA_EXPR_RETURN:
			printf("Return ");
			break;
		case HSSA_EXPR_SYSCALL:
			printf("Syscall ");
			break;
		case HSSA_EXPR_TRAP:
			printf("Trap ");
			break;
		case HSSA_EXPR_BUILTIN:
			printf("Builtin ");
			break;
		case HSSA_EXPR_EXTEND:
			printf("Extend ");
			break;
		case HSSA_EXPR_SPLIT:
			printf("Split ");
			break;
		case HSSA_EXPR_APPEND:
			printf("Append ");
			break;
		case HSSA_EXPR_CAST:
			printf("Cast ");
			break;
		case HSSA_EXPR_STORE:
			printf("Store ");
			break;
		case HSSA_EXPR_LOAD:
			printf("Load ");
			break;
		case HSSA_EXPR_FLAG:
			printf("Flag ");
			break;
		}
		if(regId){
			printf("Reg %s ",arch->getRegister(regId)->name.cstr());
		}
		if(stackId.id){
			printf("Stack %s[%d] ",arch->getStack(stackId.id)->name.cstr(),stackId.index);
		}
		printf("%d = ",id);
		for(int i = 0; i < subExpressions.size();i++){
			subExpressions[i].print(arch);
			printf(", ");
		}
		printf("\n");
	}
}
