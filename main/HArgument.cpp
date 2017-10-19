
#include "HArgument.h"
#include "HArchitecture.h"


namespace holodec {
	
	void HSSAArgument::print (HArchitecture* arch) {
		switch (type) {
		case HSSA_ARGTYPE_UNKN:
			printf ("Undef");
			break;
		case HSSA_ARGTYPE_REG:
			if (ref.refId)
				printf ("%s", arch->getRegister (ref.refId)->name.cstr());
			else
				printf ("No Reg Def");
			break;
		case HSSA_ARGTYPE_STACK:
			printf ("Stack-%s[%d]", arch->getStack (ref.refId)->name.cstr(), ref.index);
			break;
		case HSSA_ARGTYPE_MEM: 
			printf("Memory %d", ref.refId);
			break;
		case HSSA_ARGTYPE_SINT:
			if(sval < 0)
				printf ("-0x%x", -sval);
			else
				printf ("0x%x", sval);
			break;
		case HSSA_ARGTYPE_UINT:
			printf ("0x%X", uval);
			break;
		case HSSA_ARGTYPE_FLOAT:
			printf ("%f", fval);
			break;
		case HSSA_ARGTYPE_ID:
			printf ("SSA");
			break;
		case HSSA_ARGTYPE_BLOCK:
			printf ("Block %d", ref.refId);
			break;
		default:
			printf ("Unknown Argtype %x ", type);
		}
		if (id) printf (" id: %d", id);
		if (size) printf (" S%d", size);
	}
	
	
	
	void HIRArgument::print (HArchitecture* arch) {
		switch (type) {
		case HIR_ARGTYPE_UNKN:
			printf ("Undef");
			break;
		case HIR_ARGTYPE_REG:
			if (ref.refId)
				printf ("%s", arch->getRegister (ref.refId)->name.cstr());
			else
				printf ("No Reg Def");
			break;
		case HIR_ARGTYPE_STACK:
			printf ("Stack-%s[%d]", arch->getStack (ref.refId)->name.cstr(), ref.index);
			break;
		case HIR_ARGTYPE_MEM: 
			printf("Memory %d", ref.refId);
			break;
		case HIR_ARGTYPE_SINT:
			if(sval < 0)
				printf ("-0x%x", -sval);
			else
				printf ("0x%x", sval);
			break;
		case HIR_ARGTYPE_UINT:
			printf ("0x%X", uval);
			break;
		case HIR_ARGTYPE_FLOAT:
			printf ("%f", fval);
			break;
		case HIR_ARGTYPE_ID:
			printf ("IR %d", ref.refId);
			break;
		case HIR_ARGTYPE_SSAID:
			printf ("SSA");
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
			printf ("arg[%d]", ref.refId);
			break;
		case HIR_ARGTYPE_TMP:
			printf ("tmp[%d]", ref.refId);
			break;
		default:
			printf ("Unknown Argtype %x ", type);
		}
		if (size) printf (" S%d", size);
	}
}
