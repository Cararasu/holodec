#pragma once

#include "String.h"
#include "Array.h"
#include "File.h"
#include "Binary.h"
#include "IRTranslation.h"
#include "BitValue.h"
#include <map>


namespace holodec {

	struct InstructionDefinition {
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
		//the name of the architecture
		ProxyString name;
		//the register that is the instructionpointer
		StringRef instrptr;
		//the number of bits a single word has
		u32 wordbase = 0;
		//the default type of expressions
		StringRef default_type;

		//registers
		SparseDynArray<Register> registers;
		Map<String, u32> reg_name_map;

		Register* get_register(StringRef* ref);

		//memories
		SparseDynArray<Memory> memories;
		Map<String, u32> mem_name_map;

		Memory* get_memory(StringRef* ref);

		//stacks
		SparseDynArray<Stack> stacks;
		Map<String, u32> stack_name_map;

		Stack* get_stack(StringRef* ref);

		//primitivetypes
		SparseDynArray<PrimitiveType> primitivetypes;

		PrimitiveType* get_primitivetype(StringRef* ref);

		//builtins
		SparseDynArray<Builtin> builtins;

		Builtin* get_builtin(StringRef* ref);

		//instructions
		translation::IRExprStore ir_expr_store;
		IdArray<InstructionDefinition> instruction_defs;
		Map<String, u32> instr_def_mnemonic_map;

		InstructionDefinition* get_instruction_def_by_mnemonic(StringRef* ref);
		InstructionDefinition* get_instruction_def_by_mnemonic(String* str);


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