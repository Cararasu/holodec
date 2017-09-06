
#include "HIR.h"

#include "HArchitecture.h"
namespace holodec {

	void HIRExpression::print (HArchitecture* arch, int indent) {

		for (int i = 0; i < this->subExpressions.size(); i++) {
			if (this->subExpressions[i].type == HIR_ARGTYPE_IR) {
				arch->getIrExpr (this->subExpressions[i].irId)->print (arch);
			}
		}

		printf ("%d = ", this->id);

		switch (this->type) {
		case HIR_EXPR_INVALID:
			printf ("Inv");
			break;
		case HIR_EXPR_UNDEF:
			printf ("Undef");
			break;
		case HIR_EXPR_NOP:
			printf ("Nop");
			break;
		case HIR_EXPR_ASSIGN:
			printf ("Assign");
			break;

		case HIR_EXPR_IF://jump depending on value
			printf ("If");
			break;
		case HIR_EXPR_JMP://jump depending on value
			printf ("Jmp");
			break;
		case HIR_EXPR_CJMP://jump depending on value
			printf ("C_Jmp");
			break;
		case HIR_EXPR_OP:
			printf ("Op");
			break;
		// Call - Return
		case HIR_EXPR_CALL:  // a call to a function
			printf ("Call");
			break;
		case HIR_EXPR_RETURN:  // a return
			printf ("Ret");
			break;
		case HIR_EXPR_SYSCALL:  // a syscall
			printf ("Syscall");
			break;
		case HIR_EXPR_TRAP:  // a trap
			printf ("Trap");
			break;

		case HIR_EXPR_BUILTIN:  // call a builtin(invalidates all previous variables and creates a new def)
			printf ("Builtin");
			break;
		case HIR_EXPR_EXTEND:  // zero extend a value
			printf ("Ext");
			break;
		case HIR_EXPR_SPLIT:  // access to part of a variable
			printf ("Split");
			break;
		case HIR_EXPR_APPEND:  // combine variables
			printf ("App");
			break;
		case HIR_EXPR_CAST:  // cast to other type
			printf ("Cast");
			break;

		case HIR_EXPR_MEM:  // addr = base, index, scale, disp, ?segment?
			printf ("Mem");
			break;
		// Memory
		case HIR_EXPR_STORE: //mem = mem, addr, value
			printf ("St");
			break;
		case HIR_EXPR_LOAD: //value = mem, addr
			printf ("Ld");
			break;

		//IR only
		case HIR_EXPR_PUSH:
			printf ("Push");
			break;
		case HIR_EXPR_POP:
			printf ("Pop");
			break;

		case HIR_EXPR_VALUE:
			printf ("Val");
			break;
		case HIR_EXPR_REC:
			printf ("Rec[%s]", arch->getInstrDef (this->mod.instrId)->mnemonics.cstr());
			break;
		case HIR_EXPR_REP:
			printf ("Rep");
			break;
		case HIR_EXPR_SIZE:
			printf ("Size");
			break;
		case HIR_EXPR_BSIZE:
			printf ("BSize");
			break;
		case HIR_EXPR_SEQUENCE:
			printf ("Seq");
			break;

		case HIR_EXPR_FLAG:
			printf ("Flag ");
			switch (this->mod.flagType) {
			case HSSA_FLAG_C:
				printf ("C");
				break;
			case HSSA_FLAG_A:
				printf ("A");
				break;
			case HSSA_FLAG_P:
				printf ("P");
				break;
			case HSSA_FLAG_O:
				printf ("O");
				break;
			case HSSA_FLAG_Z:
				printf ("Z");
				break;
			case HSSA_FLAG_S:
				printf ("S");
				break;
			}
			break;
		}
		printf ("(");
		for (int i = 0; i < this->subExpressions.size(); i++) {
			this->subExpressions[i].print (arch);
			printf (",");
		}
		printf (")\n");
	}
	void HIRArg::print (HArchitecture* arch, int indent) {
		printIndent (indent);
		switch (this->type) {
		case HIR_ARGTYPE_INVALID:
			printf ("None");
			break;
		case HIR_ARGTYPE_INT:
			printf ("%d", this->sval);
			break;
		case HIR_ARGTYPE_UINT:
			printf ("0x%x", this->uval);
			break;
		case HIR_ARGTYPE_FLOAT:
			printf ("%f", this->fval);
			break;
		case HIR_ARGTYPE_IR:
			printf ("IR: %d", this->irId);
			break;
		case HIR_ARGTYPE_STACK:
			if (this->stackId.index)
				printf ("%s[%d]", arch->getStack (this->stackId.id)->name.cstr(), this->stackId.index);
			else
				printf ("%s", arch->getStack (this->stackId.id)->name.cstr());
			break;
		case HIR_ARGTYPE_ARG:
			printf ("arg[%d]", this->index);
			break;
		case HIR_ARGTYPE_TMP:
			printf ("tmp[%d]", this->index);
			break;
		case HIR_ARGTYPE_REG:
			printf ("%s", arch->getRegister (this->regId)->name.cstr());
			break;
		}
	}
}
