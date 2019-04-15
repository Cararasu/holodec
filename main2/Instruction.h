#pragma once

#include "String.h"
#include "BitValue.h"

namespace holodec {

	constexpr u32 MAX_LOCAL_INSTRUCTION_ARGUMENTS = 4;

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