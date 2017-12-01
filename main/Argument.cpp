
#include "Argument.h"
#include "Architecture.h"


namespace holodec {
	
	
	void IRArgument::print (Architecture* arch) {
		switch (type) {
		case IR_ARGTYPE_UNKN:
			printf ("Undef");
			break;
		case IR_ARGTYPE_REG:
			if (ref.refId)
				printf ("%s", arch->getRegister (ref.refId)->name.cstr());
			else
				printf ("No Reg Def");
			break;
		case IR_ARGTYPE_STACK:
			printf ("Stack-%s[%d]", arch->getStack (ref.refId)->name.cstr(), ref.index);
			break;
		case IR_ARGTYPE_MEM: 
			printf("Memory %d", ref.refId);
			break;
		case IR_ARGTYPE_SINT:
			if(sval < 0)
				printf ("-0x%x", -sval);
			else
				printf ("0x%x", sval);
			break;
		case IR_ARGTYPE_UINT:
			printf ("0x%X", uval);
			break;
		case IR_ARGTYPE_FLOAT:
			printf ("%f", fval);
			break;
		case IR_ARGTYPE_ID:
			printf ("IR %d", ref.refId);
			break;
		case IR_ARGTYPE_SSAID:
			printf ("SSA");
			break;
		case IR_ARGTYPE_MEMOP: {
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
				if (pre) printf (" + ");
				printf ("%s*%d", arch->getRegister (mem.index)->name.cstr(), mem.scale);
				pre = true;
			}
			if (mem.disp) {
				if (mem.disp >= 0) {
					if (pre) printf (" + ");
					printf ("0x%X", mem.disp);
				} else {
					if (pre) printf (" - ");
					printf ("%d", mem.disp * -1);
				}
			}
			printf ("]");
		}break;
		case IR_ARGTYPE_ARG:
			printf ("arg[%d]", ref.refId);
			break;
		case IR_ARGTYPE_TMP:
			printf ("tmp[%d]", ref.refId);
			break;
		default:
			printf ("Unknown Argtype %x ", type);
		}
		if (size) printf (" S%d", size);
	}
}
