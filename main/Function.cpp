#include "Function.h"
#include "Architecture.h"


void holodec::Instruction::print (Architecture* arch, int indent) {
	if (instrdef) {
		printIndent (indent);
		printf ("0x%" PRIx64 ": %s ", addr, instrdef->mnemonics.cstr());
		for (size_t i = 0; i < operands.size(); i++) {
			operands[i].print (arch);
			printf(", ");
		}
		printf("\n");
	} else {
		printIndent (indent);
		printf ("No Def\n");
	}
}

void holodec::Function::print(holodec::Architecture* arch, int indent) {
	printIndent(indent);
	printf("Printing Function\n");
	printIndent(indent + 1);
	printf("Calling Functions: ");

	for (uint64_t addr : funcsCalled) {
		printf("0x%" PRIx64 ", ", addr);
	}
	printf("\n");

	printIndent(indent + 1);
	printf("RegisterState\n");
	for (RegisterState& regState : regStates.states) {
		printIndent(indent + 2);
		printf("%s ", arch->getRegister(regState.regId)->name.cstr());
		if (regState.flags.contains(RegisterUsedFlag::eWrite)) {
			printf("Write, ");
		}
		if (regState.flags.contains(RegisterUsedFlag::eRead)) {
			printf("Read, ");
		}
		printf("\n");
	}
	for (DisAsmBasicBlock& bb : basicblocks) {
		bb.print(arch, indent + 1);
	}

	ssaRep.print(arch, indent + 1);
}