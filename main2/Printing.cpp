#include "pch.h"

#include "Architecture.h"


namespace holodec {

	inline void print_indent(u32 indent, FILE * file) {
		if(indent) fprintf(file, "%*c", indent * 4, ' ');
	}
	inline void print_ref(StringRef* ref, FILE * file) {
		fprintf(file, "%" STRING_FORMAT "", (int)ref->name.size(), ref->name.str());
	}

	void Architecture::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "architecture\n");
		print_indent(indent + 1, file);
		fprintf(file, "name; %" STRING_FORMAT "\n", (int)name.size(), name.str());
		print_indent(indent + 1, file);
		fprintf(file, "instrptr %" STRING_FORMAT "\n", (int)instrptr.name.size(), instrptr.name.str());
		print_indent(indent + 1, file);
		fprintf(file, "wordbase; %" PRIu32 "\n", wordbase);

		for (Register& reg : registers) {
			reg.print(indent + 1, file);
		}
		for (Memory& memory : memories) {
			memory.print(indent + 1, file);
		}
		for (Stack& stack : stacks) {
			stack.print(indent + 1, file);
		}
		for (PrimitiveType& primtype : primitivetypes) {
			primtype.print(indent + 1, file);
		}
		for (Builtin& builtin : builtins) {
			builtin.print(indent + 1, file);
		}
		for (Instruction& instr : instructions) {
			instr.print(indent + 1, file);
		}
	}
	void Register::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "register\n");
		print_indent(indent + 1, file);
		fprintf(file, "name; %" STRING_FORMAT "\n", (int)name.size(), name.str());
		print_indent(indent + 1, file);
		fprintf(file, "size; %" PRIu32 "\n", size);
		print_indent(indent + 1, file);
		fprintf(file, "offset; %" PRIu32 "\n", offset);
		if (parent_register) {
			print_indent(indent + 1, file);
			fprintf(file, "parentreg; ");
			print_ref(&parent_register, file);
			fprintf(file, "\n");
		}
	}
	void Memory::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "memory\n");
		print_indent(indent + 1, file);
		fprintf(file, "name; %" STRING_FORMAT "\n", (int)name.size(), name.str());
		print_indent(indent + 1, file);
		fprintf(file, "wordsize; %" PRIu32 "\n", wordsize);
	}
	void Stack::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "stack\n");
		print_indent(indent + 1, file);
		fprintf(file, "name; %" STRING_FORMAT "\n", (int)name.size(), name.str());
		print_indent(indent + 1, file);
		switch (policy) {
		case StackPolicy::eBottom:
			fprintf(file, "pushlocation; bottom\n");
			break;
		case StackPolicy::eTop:
			fprintf(file, "pushlocation; top\n");
			break;
		}
		if (backing_mem) {
			print_indent(indent + 1, file);
			fprintf(file, "backingmem; ");
			print_ref(&backing_mem, file);
			fprintf(file, "\n");
		}
		if (stackpointer) {
			print_indent(indent + 1, file);
			fprintf(file, "stackpointer; ");
			print_ref(&stackpointer, file);
			fprintf(file, "\n");
		}
		if (backing_regs.size == 1) {
			print_indent(indent + 1, file);
			fprintf(file, "backingregs;");
			print_ref(&backing_regs[0], file);
			fprintf(file, "\n");
		}
		if (backing_regs.size > 1) {
			print_indent(indent + 1, file);
			fprintf(file, "backingregs;\n");
			for (StringRef& ref : backing_regs) {
				print_indent(indent + 2, file);
				print_ref(&ref, file);
				fprintf(file, "\n");
			}
		}
	}
	void PrimitiveType::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "primitivetype\n");
		print_indent(indent + 1, file);
		fprintf(file, "name; %" STRING_FORMAT "\n", (int)name.size(), name.str());
		print_indent(indent + 1, file);
		fprintf(file, "shorthand; %" STRING_FORMAT "\n", (int)shorthand.size(), shorthand.str());
		if (bitsizes.size > 1) {
			print_indent(indent + 1, file);
			fprintf(file, "bitsizes;\n");
			for (u32 bitsize : bitsizes) {
				print_indent(indent + 2, file);
				fprintf(file, "%" PRIu32 "\n", bitsize);
			}
		} else if (bitsizes.size == 1) {
			print_indent(indent + 1, file);
			fprintf(file, "bitsizes; %" PRIu32 "\n", bitsizes[0]);
		}

		print_indent(indent + 1, file);
		fprintf(file, "consteval; ");

		print_ref(&consteval, file);
		fputs("\n", file);
	}
	void Builtin::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "builtin\n");
		print_indent(indent + 1, file);
		fprintf(file, "name; %" STRING_FORMAT "\n", (int)name.size(), name.str());
		for (Argument& arg : arguments) {
			print_indent(indent + 1, file);
			fprintf(file, "argument\n");
			print_indent(indent + 2, file);
			fprintf(file, "name; %" STRING_FORMAT "\n", (int)arg.name.size(), arg.name.str());
			print_indent(indent + 2, file);
			fprintf(file, "type; ");
			print_ref(&arg.type, file);
			fprintf(file, "\n");
			print_indent(indent + 2, file);
			fprintf(file, "size; %" PRIu32 "\n", arg.size);
		}
		for (Argument& arg : returns) {
			print_indent(indent + 1, file);
			fprintf(file, "return\n");
			print_indent(indent + 2, file);
			fprintf(file, "name; %" STRING_FORMAT "\n", (int)arg.name.size(), arg.name.str());
			print_indent(indent + 2, file);
			fprintf(file, "type; ");
			print_ref(&arg.type, file);
			fprintf(file, "\n");
			print_indent(indent + 2, file);
			fprintf(file, "size; %" PRIu32 "\n", arg.size);
		}
	}
	void Instruction::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "instruction\n");
		print_indent(indent + 1, file);
		fprintf(file, "mnemonic; %" STRING_FORMAT "\n", (int)mnemonic.size(), mnemonic.str());
		if (translations.size) {
			for (translation::IRTranslation& translation : translations) {
				translation.print(indent + 1, file);
			}
		}
	}
	void translation::Expression::print(u32 indent, FILE* file) {

	}
	void translation::IRLine::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "%.*s\n", (int)str.size(), str.str());
	}
	void translation::IRTranslation::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "translation\n");
		print_indent(indent + 1, file);
		fprintf(file, "argcount; %" PRIu32 "\n", argcount);
		if (condition.size == 1) {
			print_indent(indent + 1, file);
			fprintf(file, "cond; ");
			condition[0].print(0, file);
		}
		else if (condition.size > 1) {
			print_indent(indent + 1, file);
			fprintf(file, "cond;\n");
			for (translation::IRLine& irline : condition) {
				irline.print(indent + 2, file);
			}
		}
		if (code.size == 1) {
			print_indent(indent + 1, file);
			fprintf(file, "cond; ");
			code[0].print(0, file);
		}
		else if (code.size > 0) {
			print_indent(indent + 1, file);
			fprintf(file, "code;\n");
			for (translation::IRLine& irline : code) {
				irline.print(indent + 2, file);
			}
		}
	}
}