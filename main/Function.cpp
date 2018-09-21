#include "Function.h"
#include "Architecture.h"


void holodec::Instruction::print(Architecture* arch, int indent) {
	if (instrdef) {
		printIndent(indent);
		printf("0x%" PRIx64 ": %s ", addr, instrdef->mnemonics.cstr());
		for (size_t i = 0; i < operands.size(); i++) {
			operands[i].print(arch);
			printf(", ");
		}
		printf("\n");
	}
	else {
		printIndent(indent);
		printf("No Def\n");
	}
}

void holodec::Function::print(holodec::Architecture* arch, int indent) {
	printIndent(indent);
	printf("Printing Function 0x%" PRIx64 "\n", baseaddr);
	printIndent(indent + 1);
	printf("Calling Functions: ");

	for (uint64_t addr : funcsCaller) {
		printf("0x%" PRIx64 ", ", addr);
	}
	printf("\n");
	printIndent(indent + 1);
	printf("Called from Functions: ");

	for (uint64_t addr : funcsCallee) {
		printf("0x%" PRIx64 ", ", addr);
	}
	printf("\n");

	printIndent(indent);
	puts("Changed RegisterState");
	regStates.print(arch, indent + 1);

	printIndent(indent);
	puts("Used RegisterState");
	usedRegStates.print(arch, indent + 1);

	for (DisAsmBasicBlock& bb : basicblocks) {
		bb.print(arch, indent + 1);
	}

	ssaRep.print(arch, indent + 1);
}
void holodec::Function::printSimple(holodec::Architecture* arch, int indent) {
	printIndent(indent);
	printf("Printing Function 0x%" PRIx64 " simple\n", baseaddr);

	for (DisAsmBasicBlock& bb : basicblocks) {
		bb.printSimple(arch, indent + 1);
	}

	ssaRep.printSimple(arch, indent + 1);
}

void holodec::FuncRegState::print(holodec::Architecture* arch, int indent) {
	for (RegisterState& regState : reg_states) {
		printIndent(indent + 1);
		printf("%s ", arch->getRegister(regState.regId)->name.cstr());
		if (regState.flags.contains(UsageFlags::eWrite)) {
			printf("Write, ");
		}

		if (regState.arithChange > 0)
			printf("Arith + %" PRId64 ", ", regState.arithChange);
		else if (regState.arithChange < 0)
			printf("Arith - %" PRId64 ", ", regState.arithChange*-1);

		if (regState.flags.contains(UsageFlags::eRead)) {
			printf("Read, ");
		}
		printf("\n");
	}
	printIndent(indent);
	puts("MemoryState");
	for (MemoryState& memState : mem_states) {
		printIndent(indent + 1);
		printf("%s ", arch->getMemory(memState.memId)->name.cstr());
		if (memState.flags.contains(UsageFlags::eWrite)) {
			printf("Write, ");
		}
		if (memState.flags.contains(UsageFlags::eRead)) {
			printf("Read, ");
		}
		printf("\n");
	}
}