#include "HFunction.h"
#include "HArchitecture.h"


void holodec::HInstArgument::print (HArchitecture* arch) {
	switch (type) {
	case H_LOCAL_TYPE_REGISTER:
		if (reg)
			printf ("%s", arch->getRegister (reg)->name.cstr());
		else
			printf ("No Reg Def");
		break;
	case H_LOCAL_TYPE_STACK:
		printf ("Stack-%s[%d]", arch->getStack (stack.id)->name.cstr(), stack.index);
		break;
	case H_LOCAL_TYPE_MEM: {
		bool pre = false;
		if (mem.segment) {
			printf ("%s:", arch->getRegister (mem.segment)->name.cstr());
		}
		printf ("[");
		if (mem.base) {
			printf ("%s", arch->getRegister (mem.base)->name.cstr());
			pre = true;
		}
		if (mem.index && mem.scale) {
			if (pre)
				printf (" + ");
			printf ("%s*%d", arch->getRegister (mem.index)->name.cstr(), mem.scale);
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
	printf (" S%d", size);
}

void holodec::HInstruction::print (HArchitecture* arch, int indent) {
	if (instrdef) {
		printIndent (indent);
		printf ("0x%X: %s ", addr, instrdef->mnemonics.cstr());
		for (int i = 0; i < opcount; i++) {
			printf (" Args%d: ", i + 1);
			operands[i].print (arch);
		}
		instrdef->irs[opcount].print (arch, indent + 1);
	} else {
		printIndent (indent);
		printf ("No Def\n");
	}
}
