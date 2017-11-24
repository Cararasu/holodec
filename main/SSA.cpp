
#include "SSA.h"
#include "Architecture.h"

namespace holodec {

	void SSAExpression::print (Architecture* arch, int indent) {
		printIndent (indent);
		printf ("0x%x:", instrAddr);

		switch (this->returntype) {
		case SSA_TYPE_UNKNOWN:
			printf ("Unknown Type");
			break;
		case SSA_TYPE_INT:
			printf ("int");
			break;
		case SSA_TYPE_UINT:
			printf ("uint");
			break;
		case SSA_TYPE_FLOAT:
			printf ("float");
			break;
		case SSA_TYPE_PC:
			printf ("pc");
			break;
		case SSA_TYPE_MEMACCESS:
			printf ("memaccess");
			break;
		}
		printf ("%d ", this->size);

		switch (type) {
		case SSA_EXPR_INVALID:
			printf ("---------------------------------------");
			printf ("Invalid%d ", type);
			break;
		case SSA_EXPR_LABEL:
			printf ("Label ");
			break;
		case SSA_EXPR_INPUT:
			printf ("Input ");
			break;
		case SSA_EXPR_UNDEF:
			printf ("Undef ");
			break;
		case SSA_EXPR_NOP:
			printf ("Nop ");
			break;
		case SSA_EXPR_PHI:
			printf ("Phi ");
			break;
		case SSA_EXPR_ASSIGN:
			printf ("Assign ");
			break;
		case SSA_EXPR_JMP:
			printf ("Jmp ");
			break;
		case SSA_EXPR_CJMP:
			printf ("Cjmp ");
			break;
		case SSA_EXPR_MULTIBR:
			printf ("Multi-Branch ");
			break;
		case SSA_EXPR_OP:
			printf ("Op ");
			switch (opType) {
			case H_OP_INVALID:
				printf("Invalid ");
				break;
			case H_OP_ADD:
				printf("+ ");
				break;
			case H_OP_SUB:
				printf("- ");
				break;
			case H_OP_MUL:
				printf("* ");
				break;
			case H_OP_DIV:
				printf("/ ");
				break;
			case H_OP_MOD:
				printf("% ");
				break;
			case H_OP_AND:
				printf("&& ");
				break;
			case H_OP_OR:
				printf("|| ");
				break;
			case H_OP_XOR:
				printf("xor ");
				break;
			case H_OP_NOT:
				printf("! ");
				break;
			case H_OP_EQ:
				printf("== ");
				break;
			case H_OP_NE:
				printf("!= ");
				break;
			case H_OP_L:
				printf("< ");
				break;
			case H_OP_LE:
				printf("<= ");
				break;
			case H_OP_G:
				printf("> ");
				break;
			case H_OP_GE:
				printf(">= ");
				break;
			case H_OP_BAND:
				printf("& ");
				break;
			case H_OP_BOR:
				printf("| ");
				break;
			case H_OP_BXOR:
				printf("^ ");
				break;
			case H_OP_BNOT:
				printf("~ ");
				break;
			case H_OP_SHR:
				printf(">> ");
				break;
			case H_OP_SHL:
				printf("<< ");
				break;
			case H_OP_SAR:
				printf("pow ");
				break;
			case H_OP_SAL:
				printf("sqrt2 ");
				break;
			case H_OP_ROR:
				printf(">>> ");
				break;
			case H_OP_ROL:
				printf("<<< ");
				break;
			}
			break;
		case SSA_EXPR_LOADADDR:
			printf ("Load Effective Addr ");
			break;
		case SSA_EXPR_CALL:
			printf ("Call ");
			break;
		case SSA_EXPR_OUTPUT:
			printf ("Output ");
			break;
		case SSA_EXPR_RETURN:
			printf ("Return ");
			break;
		case SSA_EXPR_SYSCALL:
			printf ("Syscall ");
			break;
		case SSA_EXPR_TRAP:
			printf ("Trap ");
			break;
		case SSA_EXPR_BUILTIN:
			printf ("Builtin ");
			break;
		case SSA_EXPR_UPDATEPART:
			printf ("Update Part ");
			break;
		case SSA_EXPR_EXTEND:
			printf ("Extend ");
			break;
		case SSA_EXPR_SPLIT:
			printf ("Split ");
			break;
		case SSA_EXPR_APPEND:
			printf ("Append ");
			break;
		case SSA_EXPR_CAST:
			printf ("Cast ");
			break;
		case SSA_EXPR_MEMACCESS:
			printf ("MemAccess ");
			break;
		case SSA_EXPR_STORE:
			printf ("Store ");
			break;
		case SSA_EXPR_LOAD:
			printf ("Load ");
			break;
		case SSA_EXPR_FLAG:
			printf ("Flag ");
			break;
		}
		switch(location){
		case SSA_LOCATION_REG:
			printf ("Reg: %s, ", arch->getRegister (locref.refId)->name.cstr());
		break;
		case SSA_LOCATION_STACK:
			printf ("Stack: %s[%d], ", arch->getStack (locref.refId)->name.cstr(), locref.index);
		break;
		case SSA_LOCATION_MEM:
			printf ("Mem: %d, ", locref.refId);
		break;
		case SSA_LOCATION_NONE:
		break;
		}
		printf ("%d = ", id);
		for (SSAArgument& arg : subExpressions) {
			arg.print (arch);
			printf (", ");
		}
		printf ("\n");
	}
	
	void SSARepresentation::print (Architecture* arch, int indent) {
		printIndent (indent);
		printf ("------------------\n");
		printIndent (indent);
		printf ("Printing SSA-Gen Data\n");
		printIndent (indent);
		printf("Number Of Expressions: %d\n", expressions.size());
		
		for (SSABB& bb : bbs) {
			printIndent (indent + 1);
			printf ("Block bb Id: %d 0x%x - 0x%x\n", bb.id, bb.startaddr, bb.endaddr);
			
			printIndent (indent + 1);
			printf ("InBlocks ");
			for(HId id : bb.inBlocks) printf("%d, ", id);
			printf ("\n");
			
			printIndent (indent + 1);
			printf ("OutBlocks ");
			for(HId id : bb.outBlocks) printf("%d, ", id);
			printf ("\n");
			
			printIndent (indent + 1);
			printf ("Fallthrough: %d\n", bb.fallthroughId);
			for (HId id : bb.exprIds) {
				expressions[id].print (arch, indent + 2);
			}
		}
		

	}
}
