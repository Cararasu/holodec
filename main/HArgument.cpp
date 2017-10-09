
#include "HArgument.h"
#include "HArchitecture.h"


namespace holodec {
	
	void HArgument::print (HArchitecture* arch) {
		switch (type) {
		case H_ARGTYPE_REG:
			if (reg)
				printf ("%s", arch->getRegister (reg)->name.cstr());
			else
				printf ("No Reg Def");
			break;
		case H_ARGTYPE_STACK:
			printf ("Stack-%s[%d]", arch->getStack (stack.id)->name.cstr(), stack.index);
			break;
		case H_ARGTYPE_MEM: {
			printf("Memory %d", index);
		}break;
		case H_ARGTYPE_SINT:
			printf ("%d", sval);
			break;
		case H_ARGTYPE_UINT:
			printf ("0x%X", uval);
			break;
		case H_ARGTYPE_FLOAT:
			printf ("%f", fval);
			break;
		case HIR_ARGTYPE_ID:
			printf ("IR");
			break;
		case HSSA_ARGTYPE_ID:
			printf ("SSA");
			break;
		case HSSA_ARGTYPE_BLOCK:
			printf ("Block %d", index);
			break;
		case HIR_ARGTYPE_MEMOP: {
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
		case HIR_ARGTYPE_ARG:
			printf ("arg[%d]", index);
			break;
		case HIR_ARGTYPE_TMP:
			printf ("tmp[%d]", index);
			break;
		default:
			printf ("Unknown Argtype %d ", type);
		}
		if (id) printf (" id: %d", id);
		if (size) printf (" S%d", size);
	}
	/*
	void HSSAArgument::print (HArchitecture* arch) {
		switch (type) {
		case H_ARGTYPE_REG:
			if (reg)
				printf ("%s", arch->getRegister (reg)->name.cstr());
			else
				printf ("No Reg Def");
			break;
		case H_ARGTYPE_STACK:
			printf ("Stack-%s[%d]", arch->getStack (stack.id)->name.cstr(), stack.index);
			break;
		case H_ARGTYPE_SINT:
			printf ("%d", sval);
			break;
		case H_ARGTYPE_UINT:
			printf ("0x%X", uval);
			break;
		case H_ARGTYPE_FLOAT:
			printf ("%f", fval);
			break;
		case HSSA_ARGTYPE_ID:
			printf ("SSA");
			break;
		case HSSA_ARGTYPE_BLOCK:
			printf ("Block %d", index);
			break;
		case H_ARGTYPE_MEM: {
			printf("Memory %d", index);
		}break;
		case HIR_ARGTYPE_INSTR:
			printf ("instr[%s]", arch->getInstrDef (index)->mnemonics.cstr());
			break;
		case HIR_ARGTYPE_ARG:
			printf ("arg[%d]", index);
			break;
		case HIR_ARGTYPE_TMP:
			printf ("tmp[%d]", index);
			break;
		default:
			printf ("Unknown Argtype %d ", type);
		}
		if (id) printf (" ID: %d", id);
		if (size) printf (" S%d", size);
	}*/
}
