#include "HFunction.h"


void holodec::HInstArgument::print () {
	switch (type.type) {
	case H_LOCAL_TYPE_REGISTER:
		if (reg)
			printf ("%s", reg->name.cstr());
		else
			printf ("No Reg Def");
		break;
	case H_LOCAL_TYPE_STACK:
		printf ("Stack[%d]", stackindex);
		break;
	case H_LOCAL_TYPE_MEM: {
		bool pre = false;
		if (mem.segment) {
			printf ("%s:", mem.segment->name.cstr());
		}
		printf ("[");
		if (mem.base) {
			printf ("%s", mem.base->name.cstr());
			pre = true;
		}
		if (mem.index && mem.scale) {
			if (pre)
				printf (" + ");
			printf ("%s*%d", mem.index->name.cstr(), mem.scale);
			pre = true;
		}
		if (mem.disp) {
			if (pre)
				printf (" + ");
			if (mem.disp >= 0)
				printf ("0x%X", mem.disp);
			else
				printf ("%d", mem.disp);
		}
		printf ("]");
	}
	break;
	case H_LOCAL_TYPE_IMM_SIGNED:
		printf ("%d", ival);
		break;
	case H_LOCAL_TYPE_IMM_UNSIGNED:
		printf ("0x%X", ival);
		break;
	case H_LOCAL_TYPE_IMM_FLOAT:
		printf ("%f", fval);
		break;
	}
}

void holodec::HInstruction::print (int indent) {
	if (instrdef) {
		printIndent (indent);
		printf ("0x%X: %s ", addr, instrdef->mnemonics.cstr());
		for (int i = 0; i < opcount; i++) {
			printf (" Args%d: ", i + 1);
			operands[i].print ();
		}
		printf ("\n");
		instrdef->il_string[opcount].print (indent + 1);
	} else {
		printIndent (indent);
		printf ("No Def\n");
	}
}

