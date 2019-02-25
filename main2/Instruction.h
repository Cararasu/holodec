#pragma once

#include "String.h"

namespace holodec {

#ifndef MAX_LOCAL_INSTRUCTION_ARGUMENTS
#define MAX_LOCAL_INSTRUCTION_ARGUMENTS 4
#endif

	enum class InstrArgType {
		eValue,
		eRegister
	};
	struct MemoryAddress;

	struct InstrArgument {
		InstrArgType type;
		BitValue value;
		ProxyString str_ref;
		MemoryAddress* mem_address;
	};

	struct MemoryAddress {
		InstrArgument args[5];
	};

	struct Instruction {
		u64 address, size;
		ProxyString mnemonic;
		StaticDynArray<InstrArgument, MAX_LOCAL_INSTRUCTION_ARGUMENTS> arguments;
	};


}