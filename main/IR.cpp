
#include "IR.h"

#include "Architecture.h"
namespace holodec {

	void IRExpression::print (Architecture* arch, int indent, bool recursive) {
		if (recursive) {
			for (IRArgument& arg : subExpressions) {
				if (arg.type == IR_ARGTYPE_ID) {
					arch->getIrExpr (arg.ref.refId)->print (arch);
				}
			}
		}

		printf ("%d = ", this->id);

		switch (this->type) {
		case IR_EXPR_INVALID:
			printf ("Inv");
			break;
		case IR_EXPR_UNDEF:
			printf ("Undef");
			break;
		case IR_EXPR_NOP:
			printf ("Nop");
			break;
		case IR_EXPR_ASSIGN:
			printf ("Assign");
			break;
		case IR_EXPR_IF://jump depending on value
			printf ("If");
			break;
		case IR_EXPR_JMP://jump depending on value
			printf ("Jmp");
			break;
		case IR_EXPR_CJMP://jump depending on value
			printf ("C_Jmp");
			break;
		case IR_EXPR_OP:
			printf ("Op");
			break;
		// Call - Return
		case IR_EXPR_CALL:  // a call to a function
			printf ("Call");
			break;
		case IR_EXPR_RETURN:  // a return
			printf ("Ret");
			break;
		case IR_EXPR_SYSCALL:  // a syscall
			printf ("Syscall");
			break;
		case IR_EXPR_TRAP:  // a trap
			printf ("Trap");
			break;

		case IR_EXPR_BUILTIN:  // call a builtin(invalidates all previous variables and creates a new def)
			printf ("Builtin");
			break;
		case IR_EXPR_EXTEND:  // zero extend a value
			printf ("Ext");
			break;
		case IR_EXPR_SPLIT:  // access to part of a variable
			printf ("Split");
			break;
		case IR_EXPR_APPEND:  // combine variables
			printf ("App");
			break;
		case IR_EXPR_CAST:  // cast to other type
			printf ("Cast");
			break;

		case IR_EXPR_MEM:  // addr = base, index, scale, disp, ?segment?
			printf ("Mem");
			break;
		// Memory
		case IR_EXPR_STORE: //mem = mem, addr, value
			printf ("St");
			break;
		case IR_EXPR_LOAD: //value = mem, addr
			printf ("Ld");
			break;

		//IR only
		case IR_EXPR_PUSH:
			printf ("Push");
			break;
		case IR_EXPR_POP:
			printf ("Pop");
			break;

		case IR_EXPR_VALUE:
			printf ("Val");
			break;
		case IR_EXPR_REC:
			printf ("Rec[%s]", arch->getInstrDef (this->mod.instrId)->mnemonics.cstr());
			break;
		case IR_EXPR_REP:
			printf ("Rep");
			break;
		case IR_EXPR_SIZE:
			printf ("Size");
			break;
		case IR_EXPR_BSIZE:
			printf ("BSize");
			break;
		case IR_EXPR_SEQUENCE:
			printf ("Seq");
			break;

		case IR_EXPR_FLAG:
			printf ("Flag ");
			switch (this->mod.flagType) {
			case SSA_FLAG_C:
				printf ("C");
				break;
			case SSA_FLAG_A:
				printf ("A");
				break;
			case SSA_FLAG_P:
				printf ("P");
				break;
			case SSA_FLAG_O:
				printf ("O");
				break;
			case SSA_FLAG_Z:
				printf ("Z");
				break;
			case SSA_FLAG_S:
				printf ("S");
				break;
			}
			break;
		}
		printf ("(");
		for (IRArgument& arg : subExpressions) {
			arg.print (arch);
			printf (", ");
		}
		printf (")\n");
	}
}
