#include "pch.h"

#include "Architecture.h"
#include "IRTranslation.h"

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
	InstructionDefinition* Architecture::get_instruction_def_by_mnemonic(StringRef* ref) {
		if (ref->id) return instruction_defs.get(ref->id);
		for (InstructionDefinition& instruction_def : instruction_defs) {
			if (instruction_def.id && instruction_def.mnemonic == ref->name) {
				ref->id = instruction_def.id;
				return &instruction_def;
			}
		}
		return nullptr;
	}
	InstructionDefinition* Architecture::get_instruction_def_by_mnemonic(String* str) {
		auto it = instr_def_mnemonic_map.find(*str);
		if (it != instr_def_mnemonic_map.end()) {
			return &instruction_defs[it->second];
		}
		for (InstructionDefinition& instruction_def : instruction_defs) {
			if (instruction_def.id && instruction_def.mnemonic == *str) {
				return &instruction_def;
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
		for (InstructionDefinition& instruction_def : instruction_defs) {
			instr_def_mnemonic_map.insert(std::make_pair(instruction_def.mnemonic, instruction_def.id));
		}
		default_type.id = 0;
		if (default_type.name) get_primitivetype(&default_type);

		DecompContext context;
		context.arch = this;
		StringStore stringstore;
		context.string_store = &stringstore;
		translation::parse_all_ir_strings(&context);
	}
}