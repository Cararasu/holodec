#pragma once

#include "String.h"
#include "Array.h"
#include "File.h"
#include "Binary.h"
#include "IRTranslation.h"
#include <map>


namespace holodec {

	struct Instruction {
		u32 id;
		ProxyString mnemonic;
		DynArray<translation::IRTranslation> translations;

		void print(u32 indent = 0, FILE * file = stdout);
	};

	struct PrimitiveType {
		u32 id;
		ProxyString name;
		ProxyString shorthand;
		DynArray<u32> bitsizes;
		StringRef consteval;

		void print(u32 indent = 0, FILE * file = stdout);
	};

	struct Register {
		u32 id = 0;
		ProxyString name;
		u32 offset = 0, size = 0;
		StringRef parent_register;

		void print(u32 indent = 0, FILE * file = stdout);
	};
	struct Argument {
		ProxyString name;
		StringRef type;
		u32 size;
	};
	struct Builtin {
		u32 id = 0;
		ProxyString name;
		DynArray<Argument> arguments;
		DynArray<Argument> returns;

		void print(u32 indent = 0, FILE * file = stdout);
	};
	struct Memory {
		u32 id;
		ProxyString name;
		u32 wordsize;

		void print(u32 indent = 0, FILE * file = stdout);
	};

	enum class StackType {
		eRegBacked,
		eMemory
	};
	enum class StackPolicy {
		eBottom,
		eTop
	};
	struct Stack {
		u32 id;
		ProxyString name;
		StackPolicy policy = StackPolicy::eBottom;

		StringRef backing_mem;
		StringRef stackpointer;
		DynArray<StringRef> backing_regs;

		void print(u32 indent = 0, FILE * file = stdout);
	};

	struct Architecture {
		u32 id;
		ProxyString name;
		StringRef instrptr;
		u32 wordbase = 0;

		IdArray<Register> registers;
		IdArray<Memory> memories;
		IdArray<Stack> stacks;
		IdArray<PrimitiveType> primitivetypes;
		IdArray<Builtin> builtins;
		IdArray<Instruction> instructions;

		Register* get_register(StringRef* ref);
		Memory* get_memory(StringRef* ref);
		Stack* get_stack(StringRef* ref);
		PrimitiveType* get_primitivetype(StringRef* ref);
		Builtin* get_builtin(StringRef* ref);
		Instruction* get_instruction(StringRef* ref);

		Map<String, u32> instr_mnemonic_map;

		Instruction* get_instruction_by_mnemonic(String* str);

		Map<String, u32> reg_name_map;
		Map<String, u32> mem_name_map;
		Map<String, u32> stack_name_map;

		void print(u32 indent = 0, FILE * file = stdout);
		void update_ids();
	};

	struct DecompContext {
		Architecture* arch = nullptr;
		File* file = nullptr;
		Binary* binary = nullptr;
		StringStore* string_store = nullptr;
	};
}