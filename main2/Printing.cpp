#include "pch.h"

#include "Architecture.h"


namespace holodec {

	inline void print_indent(u32 indent, FILE * file) {
		if(indent) fprintf(file, "%*c", indent * 4, ' ');
	}
	inline void print_ref(StringRef* ref, FILE * file) {
		fprintf(file, "%s", ref->name.str());
	}

	void Architecture::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "architecture\n");
		print_indent(indent + 1, file);
		fprintf(file, "name; %s\n", name.str());
		print_indent(indent + 1, file);
		fprintf(file, "instrptr %s\n", instrptr.name.str());
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
		for (InstructionDefinition& instr_def : instruction_defs) {
			instr_def.print(indent + 1, file);
		}
	}
	void Register::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "register\n");
		print_indent(indent + 1, file);
		fprintf(file, "name; %s\n", name.str());
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
		fprintf(file, "name; %s\n",  name.str());
		print_indent(indent + 1, file);
		fprintf(file, "wordsize; %" PRIu32 "\n", wordsize);
	}
	void Stack::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "stack\n");
		print_indent(indent + 1, file);
		fprintf(file, "name; %s\n", name.str());
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
		if (backing_regs.size() == 1) {
			print_indent(indent + 1, file);
			fprintf(file, "backingregs;");
			print_ref(&backing_regs[0], file);
			fprintf(file, "\n");
		}
		if (backing_regs.size() > 1) {
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
		fprintf(file, "name; %s\n", name.str());
		print_indent(indent + 1, file);
		fprintf(file, "shorthand; %s\n", shorthand.str());
		if (bitsizes.size() > 1) {
			print_indent(indent + 1, file);
			fprintf(file, "bitsizes;\n");
			for (u32 bitsize : bitsizes) {
				print_indent(indent + 2, file);
				fprintf(file, "%" PRIu32 "\n", bitsize);
			}
		} else if (bitsizes.size() == 1) {
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
		fprintf(file, "name; %s\n", name.str());
		for (Argument& arg : arguments) {
			print_indent(indent + 1, file);
			fprintf(file, "argument\n");
			print_indent(indent + 2, file);
			fprintf(file, "name; %s\n", arg.name.str());
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
			fprintf(file, "name; %s\n", arg.name.str());
			print_indent(indent + 2, file);
			fprintf(file, "type; ");
			print_ref(&arg.type, file);
			fprintf(file, "\n");
			print_indent(indent + 2, file);
			fprintf(file, "size; %" PRIu32 "\n", arg.size);
		}
	}
	void InstructionDefinition::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "instruction\n");
		print_indent(indent + 1, file);
		fprintf(file, "mnemonic; %s\n", mnemonic.str());
		if (translations.size()) {
			for (translation::IRTranslation& translation : translations) {
				translation.print(indent + 1, file);
			}
		}
	}
	void print_expr(DecompContext* context, u32 expr_id, FILE* file);
	void print_expr_arguments(DecompContext* context, translation::Expression* expr, FILE* file) {
		if (expr->sub_expressions[0]) {
			fprintf(file, "(");
			print_expr(context, expr->sub_expressions[0], file);
			for (u32 i = 1; i < translation::MAX_SUBEXPRESSIONS; i++) {
				if (expr->sub_expressions[i]) {
					fprintf(file, ", ");
					print_expr(context, expr->sub_expressions[i], file);
				}
				else {
					break;
				}
			}
			fprintf(file, ")");
		}
	}
	void print_expr_modifiers(DecompContext* context, translation::Expression* expr, FILE* file) {
		bool first_expr = true;
		if (expr->typeref) {
			if (first_expr) printf("[");
			fprintf(file, "t:%.*s", (int)expr->typeref.name.size(), expr->typeref.name.str());
			first_expr = false;
		}
		if (expr->offset_id) {
			if (first_expr) printf("[");
			else fprintf(file, ", ");
			fprintf(file, "o:");
			print_expr(context, expr->offset_id, file);
			first_expr = false;
		}
		if (expr->addr_id) {
			if (first_expr) printf("[");
			else fprintf(file, ", ");
			fprintf(file, "addr:");
			print_expr(context, expr->addr_id, file);
			first_expr = false;
		}
		if (expr->size_id) {
			if (first_expr) printf("[");
			else fprintf(file, ", ");
			fprintf(file, "s:");
			print_expr(context, expr->size_id, file);
			first_expr = false;
		}
		if (!first_expr) printf("]");
	}
	void print_expr_cast_modifiers(DecompContext* context, translation::Expression* expr, FILE* file) {
		fprintf(file, "[");
		bool first_expr = true;
		if (expr->cast_typeref) {
			fprintf(file, "t: %.*s", (int)expr->cast_typeref.name.size(), expr->cast_typeref.name.str());
			first_expr = false;
		}
		if (expr->cast_size_id) {
			if (first_expr) fprintf(file, ", ");
			fprintf(file, "s: ");
			print_expr(context, expr->cast_size_id, file);
			first_expr = false;
		}
		fprintf(file, "]");
	}
	void print_type(translation::OpType op_type, FILE* file) {
		switch (op_type) {
		default:
		case translation::OpType::eInvalid: {
			fprintf(file, "Invalid Op-Type");
		}break;
		case translation::OpType::eExtend: {
			fprintf(file, "#ext");
		}break;
		case translation::OpType::eAppend: {
			fprintf(file, "#app");
		}break;
		case translation::OpType::eCarryFlag: {
			fprintf(file, "#carry");
		}break;
		case translation::OpType::eOverflowFlag: {
			fprintf(file, "#overflow");
		}break;
		case translation::OpType::eUnderflowFlag: {
			fprintf(file, "#underflow");
		}break;
		case translation::OpType::eAdd: {
			fprintf(file, "#add");
		}break;
		case translation::OpType::eSub: {
			fprintf(file, "#sub");
		}break;
		case translation::OpType::eMul: {
			fprintf(file, "#mul");
		}break;
		case translation::OpType::eDiv: {
			fprintf(file, "#div");
		}break;
		case translation::OpType::eMod: {
			fprintf(file, "#mod");
		}break;
		case translation::OpType::eAnd: {
			fprintf(file, "#and");
		}break;
		case translation::OpType::eOr: {
			fprintf(file, "#or");
		}break;
		case translation::OpType::eNot: {
			fprintf(file, "#not");
		}break;
		case translation::OpType::eEq: {
			fprintf(file, "#eq");
		}break;
		case translation::OpType::eLess: {
			fprintf(file, "#less");
		}break;
		case translation::OpType::eGreater: {
			fprintf(file, "#greater");
		}break;
		case translation::OpType::eBAnd: {
			fprintf(file, "#band");
		}break;
		case translation::OpType::eBOr: {
			fprintf(file, "#bor");
		}break;
		case translation::OpType::eBXor: {
			fprintf(file, "#bxor");
		}break;
		case translation::OpType::eBNot: {
			fprintf(file, "#bnot");
		}break;
		case translation::OpType::eShr: {
			fprintf(file, "#shr");
		}break;
		case translation::OpType::eShl: {
			fprintf(file, "#shl");
		}break;
		case translation::OpType::eRor: {
			fprintf(file, "#ror");
		}break;
		case translation::OpType::eRol: {
			fprintf(file, "#rol");
		}break;
		}
	}
	void print_expr(DecompContext* context, u32 expr_id, FILE* file) {
		translation::Expression* expr = context->arch->ir_expr_store.get(expr_id);
		if (!expr) {
			fprintf(file, "Invalid Expression-Id");
			return;
		}
		switch (expr->type) {
		default:
		case translation::ExpressionType::eInvalid: {
			fprintf(file, "Invalid Expression-Type");
		}break;
		case translation::ExpressionType::eNop: {
			fprintf(file, "#nop");
		}break;
		case translation::ExpressionType::eValue: {
			if (expr->value.bitcount <= 64) {
				fprintf(file, "%" PRIu64, expr->value.value[0]);
			}
			else {
				expr->value.print(file);
			}
			print_expr_modifiers(context, expr, file);
		}break;
		case translation::ExpressionType::eArgument: {
			fprintf(file, "$%" PRIu32, expr->index);
			print_expr_modifiers(context, expr, file);
		}break;
		case translation::ExpressionType::eTemporary: {
			fprintf(file, "#%" PRIu32, expr->index);
			print_expr_modifiers(context, expr, file);
		}break;
		case translation::ExpressionType::eRegister: {
			fprintf(file, "$%.*s", (int)expr->ref.name.size(), expr->ref.name.str());
			print_expr_modifiers(context, expr, file);
		}break;
		case translation::ExpressionType::eMemory: {
			fprintf(file, "$mem[%.*s]", (int)expr->ref.name.size(), expr->ref.name.str());
			print_expr_modifiers(context, expr, file);
		}break;
		case translation::ExpressionType::eStack: {
			fprintf(file, "$stack[%.*s]", (int)expr->ref.name.size(), expr->ref.name.str());
			print_expr_modifiers(context, expr, file);
		}break;
		case translation::ExpressionType::eBuiltin: {
			fprintf(file, "$builtin[%.*s]", (int)expr->ref.name.size(), expr->ref.name.str());
			print_expr_arguments(context, expr, file);
		}break;
		case translation::ExpressionType::eRecursive: {
			fprintf(file, "#rec[%.*s]", (int)expr->ref.name.size(), expr->ref.name.str());
			print_expr_arguments(context, expr, file);
		}break;
		case translation::ExpressionType::eTrap: {
			fprintf(file, "#trap");
			print_expr_arguments(context, expr, file);
		}break;
		case translation::ExpressionType::eOp: {
			print_type(expr->op_type, file);
			print_expr_modifiers(context, expr, file);
			print_expr_arguments(context, expr, file);
		}break;
		case translation::ExpressionType::eExtract: {
			fprintf(file, "#extract[%.*s]", (int)expr->ref.name.size(), expr->ref.name.str());
			print_expr_arguments(context, expr, file);
		}break;
		case translation::ExpressionType::eCast: {
			fprintf(file, "#cast");
			print_expr_modifiers(context, expr, file);
			fprintf(file, "->");
			print_expr_cast_modifiers(context, expr, file);
			print_expr_arguments(context, expr, file);
		}break;
		case translation::ExpressionType::eInstructionSize: {
			fprintf(file, "#isize");
			print_expr_modifiers(context, expr, file);
		}break;
		case translation::ExpressionType::eWordSize: {
			fprintf(file, "#size");
			print_expr_arguments(context, expr, file);
		}break;
		case translation::ExpressionType::eBitSize: {
			fprintf(file, "#bsize");
			print_expr_arguments(context, expr, file);
		}break;
		}
	}
	void translation::IRLine::print(DecompContext* context, u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "%.*s\n", (int)str.size(), str.str());

		if (label_id) {
			fprintf(file, "§% " PRIu32, label_id);
		}
		if (write_id) {
			print_expr(context, write_id, file);
			fprintf(file, " = ");
		}
		if (expr_id) {
			print_expr(context, expr_id, file);
		}
		if (cond_id) {
			fprintf(file, " ? ");
			print_expr(context, cond_id, file);
		}
		fprintf(file, "\n");
	}
	void translation::IRTranslation::print(u32 indent, FILE* file) {
		print_indent(indent, file);
		fprintf(file, "translation\n");
		print_indent(indent + 1, file);
		fprintf(file, "argcount; %" PRIu32 "\n", argcount);
		if (condition.size() == 1) {
			print_indent(indent + 1, file);
			fprintf(file, "cond; ");
			//condition[0].print(0, file);
		}
		else if (condition.size() > 1) {
			print_indent(indent + 1, file);
			fprintf(file, "cond;\n");
			for (translation::IRLine& irline : condition) {
				//irline.print(indent + 2, file);
			}
		}
		if (code.size() == 1) {
			print_indent(indent + 1, file);
			fprintf(file, "cond; ");
			//code[0].print(0, file);
		}
		else if (code.size() > 0) {
			print_indent(indent + 1, file);
			fprintf(file, "code;\n");
			for (translation::IRLine& irline : code) {
				//irline.print(indent + 2, file);
			}
		}
	}
}