#include "Function.h"
#include "Architecture.h"


void holodec::Instruction::print (Architecture* arch, int indent) {
	if (instrdef) {
		printIndent (indent);
		printf ("0x%" PRIx64 ": %s ", addr, instrdef->mnemonics.cstr());
		for (size_t i = 0; i < operands.size(); i++) {
			printf (" Args%" PRIx64 ": ", i + 1);
			operands[i].print (arch);
		}
		printf("\n");
	} else {
		printIndent (indent);
		printf ("No Def\n");
	}
}
