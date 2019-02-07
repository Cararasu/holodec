#include "pch.h"

#include "Architecture.h"

namespace holodec {

	Register* Architecture::get_register(StringRef* ref) {
		if (ref->id) return registers.get(ref->id);
		for (Register& reg : registers) {
			if (reg.id && reg.name == ref->name) {
				ref->id = reg.id;
				return &reg;
			}
		}
		return nullptr;
	}
	Memory* Architecture::get_memory(StringRef* ref) {
		if (ref->id) return memories.get(ref->id);
		for (Memory& mem : memories) {
			if (mem.id && mem.name == ref->name) {
				ref->id = mem.id;
				return &mem;
			}
		}
		return nullptr;
	}
	Stack* Architecture::get_stack(StringRef* ref) {
		if (ref->id) return stacks.get(ref->id);
		for (Stack& stack : stacks) {
			if (stack.id && stack.name == ref->name) {
				ref->id = stack.id;
				return &stack;
			}
		}
		return nullptr;
	}
	PrimitiveType* Architecture::get_primitivetype(StringRef* ref) {
		if (ref->id) return primitivetypes.get(ref->id);
		for (PrimitiveType& primitivetype : primitivetypes) {
			if (primitivetype.id && primitivetype.name == ref->name) {
				ref->id = primitivetype.id;
				return &primitivetype;
			}
		}
		return nullptr;
	}
	Builtin* Architecture::get_builtin(StringRef* ref) {
		if (ref->id) return builtins.get(ref->id);
		for (Builtin& builtin : builtins) {
			if (builtin.id && builtin.name == ref->name) {
				ref->id = builtin.id;
				return &builtin;
			}
		}
		return nullptr;
	}
	Instruction* Architecture::get_instruction(StringRef* ref) {
		if (ref->id) return instructions.get(ref->id);
		for (Instruction& instruction : instructions) {
			if (instruction.id && instruction.mnemonic == ref->name) {
				ref->id = instruction.id;
				return &instruction;
			}
		}
		return nullptr;
	}

	void Architecture::update_ids() {

		for (Register& reg : registers) {
			reg.parent_register.id = 0;
			if (reg.parent_register.name) get_register(&reg.parent_register);
		}
		for (Stack& stack : stacks) {
			stack.backing_mem.id = 0;
			if (stack.backing_mem.name) get_memory(&stack.backing_mem);

			stack.stackpointer.id = 0;
			if (stack.stackpointer.name) get_register(&stack.stackpointer);
		}
		for (PrimitiveType& primitivetype : primitivetypes) {
			//primitivetype.consteval
		}
		for (Builtin& builtin : builtins) {
			for (Argument& argument : builtin.arguments) {
				argument.type.id = 0;
				if (argument.type.name) get_primitivetype(&argument.type);
			}
			for (Argument& argument : builtin.returns) {
				argument.type.id = 0;
				if (argument.type.name) get_primitivetype(&argument.type);
			}
		}
		for (Instruction& instruction : instructions) {
			for (translation::IRTranslation& translation : instruction.translations) {

			}
			instr_mnemonic_map.insert(std::make_pair(instruction.mnemonic, instruction.id));
		}
	}
}