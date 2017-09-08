#include "HFunction.h"
#include "HArchitecture.h"


void holodec::HInstruction::print (HArchitecture* arch, int indent) {
	if (instrdef) {
		printIndent (indent);
		printf ("0x%X: %s ", addr, instrdef->mnemonics.cstr());
		for (int i = 0; i < operands.size(); i++) {
			printf (" Args%d: ", i + 1);
			operands[i].print (arch);
		}
		printf("\n");
	} else {
		printIndent (indent);
		printf ("No Def\n");
	}
}
