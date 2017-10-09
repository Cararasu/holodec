
#include "HSSA.h"
#include "HArchitecture.h"

namespace holodec {

	void HSSAExpression::print (HArchitecture* arch, int indent) {
		printIndent (indent);
		printf ("0x%x:", instrAddr);

		switch (this->exprtype) {
		case HSSA_TYPE_UNKNOWN:
			printf ("Unknown Type");
			break;
		case HSSA_TYPE_INT:
			printf ("int");
			break;
		case HSSA_TYPE_UINT:
			printf ("uint");
			break;
		case HSSA_TYPE_FLOAT:
			printf ("float");
			break;
		case HSSA_TYPE_PC:
			printf ("pc");
			break;
		case HSSA_TYPE_MEM:
			printf ("mem");
			break;
		}
		printf ("%d ", this->size);

		switch (type) {
		case HSSA_EXPR_INVALID:
			printf ("---------------------------------------");
			printf ("Invalid%d ", type);
			break;
		case HSSA_EXPR_LABEL:
			printf ("Label ");
			break;
		case HSSA_EXPR_INPUT:
			printf ("Input ");
			break;
		case HSSA_EXPR_UNDEF:
			printf ("Undef ");
			break;
		case HSSA_EXPR_NOP:
			printf ("Nop ");
			break;
		case HSSA_EXPR_PHI:
			printf ("Phi ");
			break;
		case HSSA_EXPR_ASSIGN:
			printf ("Assign ");
			break;
		case HSSA_EXPR_JMP:
			printf ("Jmp ");
			break;
		case HSSA_EXPR_CJMP:
			printf ("Cjmp ");
			break;
		case HSSA_EXPR_MULTIBR:
			printf ("Multi-Branch ");
			break;
		case HSSA_EXPR_OP:
			printf ("Op ");
			switch (opType) {
			case HSSA_OP_INVALID:
				printf("Invalid ");
				break;
			case HSSA_OP_ADD:
				printf("+ ");
				break;
			case HSSA_OP_SUB:
				printf("- ");
				break;
			case HSSA_OP_MUL:
				printf("* ");
				break;
			case HSSA_OP_DIV:
				printf("/ ");
				break;
			case HSSA_OP_MOD:
				printf("% ");
				break;
			case HSSA_OP_AND:
				printf("&& ");
				break;
			case HSSA_OP_OR:
				printf("|| ");
				break;
			case HSSA_OP_XOR:
				printf("xor ");
				break;
			case HSSA_OP_NOT:
				printf("! ");
				break;
			case HSSA_OP_E:
				printf("== ");
				break;
			case HSSA_OP_NE:
				printf("!= ");
				break;
			case HSSA_OP_L:
				printf("< ");
				break;
			case HSSA_OP_LE:
				printf("<= ");
				break;
			case HSSA_OP_G:
				printf("> ");
				break;
			case HSSA_OP_GE:
				printf(">= ");
				break;
			case HSSA_OP_BAND:
				printf("& ");
				break;
			case HSSA_OP_BOR:
				printf("| ");
				break;
			case HSSA_OP_BXOR:
				printf("^ ");
				break;
			case HSSA_OP_BNOT:
				printf("~ ");
				break;
			case HSSA_OP_SHR:
				printf(">> ");
				break;
			case HSSA_OP_SHL:
				printf("<< ");
				break;
			case HSSA_OP_SAR:
				printf("pow ");
				break;
			case HSSA_OP_SAL:
				printf("sqrt2 ");
				break;
			case HSSA_OP_ROR:
				printf(">>> ");
				break;
			case HSSA_OP_ROL:
				printf("<<< ");
				break;
			}
			break;
		case HSSA_EXPR_COND:
			printf ("Cond ");
			break;
		case HSSA_EXPR_MEM:
			printf ("Mem ");
			break;
		case HSSA_EXPR_CALL:
			printf ("Call ");
			break;
		case HSSA_EXPR_OUTPUT:
			printf ("Output ");
			break;
		case HSSA_EXPR_RETURN:
			printf ("Return ");
			break;
		case HSSA_EXPR_SYSCALL:
			printf ("Syscall ");
			break;
		case HSSA_EXPR_TRAP:
			printf ("Trap ");
			break;
		case HSSA_EXPR_BUILTIN:
			printf ("Builtin ");
			break;
		case HSSA_EXPR_UPDATEPART:
			printf ("Update Part ");
			break;
		case HSSA_EXPR_EXTEND:
			printf ("Extend ");
			break;
		case HSSA_EXPR_SPLIT:
			printf ("Split ");
			break;
		case HSSA_EXPR_APPEND:
			printf ("Append ");
			break;
		case HSSA_EXPR_CAST:
			printf ("Cast ");
			break;
		case HSSA_EXPR_STORE:
			printf ("Store ");
			break;
		case HSSA_EXPR_LOAD:
			printf ("Load ");
			break;
		case HSSA_EXPR_FLAG:
			printf ("Flag ");
			break;
		}
		if (regId) {
			printf ("Reg %s ", arch->getRegister (regId)->name.cstr());
		}
		if (stackId.id) {
			printf ("Stack %s[%d] ", arch->getStack (stackId.id)->name.cstr(), stackId.index);
		}
		printf ("%d = ", id);
		for (int i = 0; i < subExpressions.size(); i++) {
			subExpressions[i].print (arch);
			printf (", ");
		}
		printf ("\n");
	}
	void HSSARepresentation::print (HArchitecture* arch, int indent) {
		printIndent (indent);
		printf ("------------------\n");
		printIndent (indent);
		printf ("Printing SSA-Gen Data\n");
		printIndent (indent + 1);
		for (HSSABB& bb : bbs) {
			printIndent (indent + 1);
			printf ("Block bb Id: %d 0x%x - 0x%x\n", bb.id, bb.startaddr, bb.endaddr);
			printIndent (indent + 1);
			printf ("Fallthrough: %d\n", bb.fallthroughId);
			for (HId id : bb.exprIds) {
				expressions.get (id)->print (arch, indent + 2);
			}
		}
		

	}
}
