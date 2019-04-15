#include "pch.h"

#include "Parser.h"
#include "File.h"
#include "Architecture.h"


namespace holodec {


	bool parse_string_value_rec(DecompContext* context, FileData* fdata, Line* line, String* string) {
		if (line->value) {
			*string = ProxyString(line->value.ptr, line->value.size, context->string_store);
			return true;
		}
		else {
			//error
			return false;
		}
	}
	bool parse_string_value(DecompContext* context, FileData* fdata, Line* line, String* string) {
		if (parse_string_value_rec(context, fdata, line, string)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<String>(context, fdata, parse_string_value_rec, string, line);
		}
		else {
			return false;
		}
	}
	bool parse_string_value_rec(DecompContext* context, FileData* fdata, Line* line, ProxyString* string) {
		if (line->value) {
			*string = ProxyString(line->value.ptr, line->value.size, context->string_store);
			return true;
		}
		else {
			//error
			return false;
		}
	}
	bool parse_string_value(DecompContext* context, FileData* fdata, Line* line, ProxyString* string) {
		if (parse_string_value_rec(context, fdata, line, string)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<ProxyString>(context, fdata, parse_string_value_rec, string, line);
		}
		else {
			return false;
		}
	}
	bool parse_stringref_value_rec(DecompContext* context, FileData* fdata, Line* line, StringRef* string) {
		if (line->value) {
			*string = StringRef(line->value.ptr, line->value.size, context->string_store);
			return true;
		}
		else {
			//error
			return false;
		}
	}
	bool parse_stringref_value(DecompContext* context, FileData* fdata, Line* line, StringRef* ref) {
		if (parse_stringref_value_rec(context, fdata, line, ref)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<StringRef>(context, fdata, parse_stringref_value_rec, ref, line);
		}
		else {
			return false;
		}
	}
	bool parse_stringreflist_value_rec(DecompContext* context, FileData* fdata, Line* line, DynArray<StringRef>* strlist) {
		if (line->value) {
			strlist->emplace_back(line->value.ptr, line->value.size, context->string_store);
			return true;
		}
		else {
			//error
			return false;
		}
	}
	bool parse_stringreflist_value(DecompContext* context, FileData* fdata, Line* line, DynArray<StringRef>* strlist) {
		if (parse_stringreflist_value_rec(context, fdata, line, strlist)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<DynArray<StringRef>>(context, fdata, parse_stringreflist_value_rec, strlist, line);
		}
		else {
			return false;
		}
	}
	bool parse_stringlist_value_rec(DecompContext* context, FileData* fdata, Line* line, DynArray<ProxyString>* strings) {
		if (line->value) {
			strings->emplace_back(line->value.ptr, line->value.size, context->string_store);
			return true;
		}
		else {
			//error
			return false;
		}
	}
	bool parse_stringlist_value(DecompContext* context, FileData* fdata, Line* line, DynArray<ProxyString>* strlist) {
		if (parse_stringlist_value_rec(context, fdata, line, strlist)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<DynArray<ProxyString>>(context, fdata, parse_stringlist_value_rec, strlist, line);
		}
		else {
			return false;
		}
	}
	bool parse_int_value_rec(DecompContext* context, FileData* fdata, Line* line, u64* i) {
		if (line->value) {
			FileData valdata(line->value.ptr, line->value.size);
			return valdata.integer(i);
		}
		else {
			//error
			return false;
		}
	}
	bool parse_int_value_rec(DecompContext* context, FileData* fdata, Line* line, u32* i) {
		if (line->value) {
			FileData valdata(line->value.ptr, line->value.size);
			u64 li;
			bool res = valdata.integer(&li);
			*i = static_cast<u32>(li);
			return res;
		}
		else {
			//error
			return false;
		}
	}
	bool parse_int_value(DecompContext* context, FileData* fdata, Line* line, u64* i) {
		if (parse_int_value_rec(context, fdata, line, i)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<u64>(context, fdata, parse_int_value_rec, i, line);
		}
		else {
			return false;
		}
	}
	bool parse_int_value(DecompContext* context, FileData* fdata, Line* line, u32* i) {
		if (parse_int_value_rec(context, fdata, line, i)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<u32>(context, fdata, parse_int_value_rec, i, line);
		}
		else {
			return false;
		}
	}
	bool parse_intlist_value_rec(DecompContext* context, FileData* fdata, Line* line, DynArray<u64>* ilist) {
		if (line->value) {
			u64 i;
			bool res = parse_int_value(context, fdata, line, &i);
			if (res) {
				ilist->push_back(i);
			}
			return res;
		}
		return false;
	}
	bool parse_intlist_value_rec(DecompContext* context, FileData* fdata, Line* line, DynArray<u32>* ilist) {
		if (line->value) {
			u32 i;
			bool res = parse_int_value(context, fdata, line, &i);
			if (res) {
				ilist->push_back(i);
			}
			return res;
		}
		return false;
	}
	bool parse_intlist_value(DecompContext* context, FileData* fdata, Line* line, DynArray<u64>* ilist) {
		if (parse_intlist_value_rec(context, fdata, line, ilist)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<DynArray<u64>>(context, fdata, parse_intlist_value_rec, ilist, line);
		}
		else {
			return false;
		}
	}
	bool parse_intlist_value(DecompContext* context, FileData* fdata, Line* line, DynArray<u32>* ilist) {
		if (parse_intlist_value_rec(context, fdata, line, ilist)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<DynArray<u32>>(context, fdata, parse_intlist_value_rec, ilist, line);
		}
		else {
			return false;
		}
	}
	bool parse_ir_value_rec(DecompContext* context, FileData* fdata, Line* line, DynArray<translation::IRLine>* linelist) {
		if (line->value) {
			linelist->emplace_back(String(line->value.ptr, line->value.size));
			return true;
		}
		return false;
	}
	bool parse_ir_value(DecompContext* context, FileData* fdata, Line* line, DynArray<translation::IRLine>* linelist) {
		if (parse_ir_value_rec(context, fdata, line, linelist)) {
			return true;
		}
		else if (line->valuetoken) {
			return parse_token_args<DynArray<translation::IRLine>>(context, fdata, parse_ir_value_rec, linelist, line);
		}
		else {
			return false;
		}
	}

	bool parse_translation_token(DecompContext* context, FileData* fdata, Line* line, translation::IRTranslation* translation) {
		if (!line->token) return false;
		if (match_part(&line->token, "argcount")) {
			return parse_int_value(context, fdata, line, &translation->argcount);
		}
		else if (match_part(&line->token, "cond")) {
			return parse_ir_value(context, fdata, line, &translation->condition);
		}
		else if (match_part(&line->token, "code")) {
			return parse_ir_value(context, fdata, line, &translation->code);
		}
		else {
			printf("Translation-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("Translation-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}
	bool parse_instruction_token(DecompContext* context, FileData* fdata, Line* line, InstructionDefinition* instruction_def) {
		if (!line->token) return false;
		if (match_part(&line->token, "mnemonic")) {
			return parse_string_value(context, fdata, line, &instruction_def->mnemonic);
		}
		else if (match_part(&line->token, "translation")) {
			instruction_def->translations.emplace_back();
			return parse_token_args<translation::IRTranslation>(context, fdata, parse_translation_token, &instruction_def->translations.back(), line);
		}
		else {
			printf("Instruction-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("Instruction-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}
	bool parse_argument_token(DecompContext* context, FileData* fdata, Line* line, Argument* arg) {
		if (!line->token) return false;
		if (match_part(&line->token, "name")) {
			return parse_string_value(context, fdata, line, &arg->name);
		}
		else if (match_part(&line->token, "type")) {
			return parse_stringref_value(context, fdata, line, &arg->type);
		}
		else if (match_part(&line->token, "size")) {
			return parse_int_value(context, fdata, line, &arg->size);
		}
		else {
			printf("Argument-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("Argument-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}
	bool parse_builtin_token(DecompContext* context, FileData* fdata, Line* line, Builtin* builtin) {
		if (!line->token) return false;
		if (match_part(&line->token, "name")) {
			return parse_string_value(context, fdata, line, &builtin->name);
		}
		else if (match_part(&line->token, "argument")) {
			builtin->arguments.emplace_back();
			return parse_token_args<Argument>(context, fdata, parse_argument_token, &builtin->arguments.back(), line);
		}
		else if (match_part(&line->token, "return")) {
			builtin->returns.emplace_back();
			return parse_token_args<Argument>(context, fdata, parse_argument_token, &builtin->returns.back(), line);
		}
		else {
			printf("Builtin-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("Builtin-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}
	bool parse_primitivetype_token(DecompContext* context, FileData* fdata, Line* line, PrimitiveType* primitivetype) {
		if (!line->token) return false;
		if (match_part(&line->token, "name")) {
			return parse_string_value(context, fdata, line, &primitivetype->name);
		}
		else if (match_part(&line->token, "shorthand")) {
			return parse_string_value(context, fdata, line, &primitivetype->shorthand);
		}
		else if (match_part(&line->token, "bitsizes")) {
			return parse_intlist_value(context, fdata, line, &primitivetype->bitsizes);
		}
		else if (match_part(&line->token, "consteval")) {
			return parse_stringref_value(context, fdata, line, &primitivetype->consteval);
		}
		else {
			printf("PrimitiveType-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("PrimitiveType-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}
	bool parse_register_token(DecompContext* context, FileData* fdata, Line* line, Register* reg) {
		if (!line->token) return false;
		if (match_part(&line->token, "name")) {
			return parse_string_value(context, fdata, line, &reg->name);
		}
		else if (match_part(&line->token, "size")) {
			return parse_int_value(context, fdata, line, &reg->size);
		}
		else if (match_part(&line->token, "offset")) {
			return parse_int_value(context, fdata, line, &reg->offset);
		}
		else if (match_part(&line->token, "parentreg")) {
			return parse_stringref_value(context, fdata, line, &reg->parent_register);
		}
		else {
			printf("Register-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("Register-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}
	bool parse_memory_token(DecompContext* context, FileData* fdata, Line* line, Memory* memory) {
		if (!line->token) return false;
		if (match_part(&line->token, "name")) {
			return parse_string_value(context, fdata, line, &memory->name);
		}
		else if (match_part(&line->token, "wordsize")) {
			return parse_int_value(context, fdata, line, &memory->wordsize);
		}
		else {
			printf("Memory-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("Memory-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}
	bool parse_stack_token(DecompContext* context, FileData* fdata, Line* line, Stack* stack) {
		if (!line->token) return false;
		if (match_part(&line->token, "name")) {
			return parse_string_value(context, fdata, line, &stack->name);
		}
		else if (match_part(&line->token, "pushlocation")) {
			String val;
			bool res = parse_string_value(context, fdata, line, &val);
			if (res) {
				if (val == "top") {
					stack->policy = StackPolicy::eTop;
				} else if (val == "bottom") {
					stack->policy = StackPolicy::eBottom;
				} else {
					//Warning
				}
			}
			return res;
		}
		else if (match_part(&line->token, "backingregs")) {
			return parse_stringreflist_value(context, fdata, line, &stack->backing_regs);
		}
		else if (match_part(&line->token, "backingmem")) {
			return parse_stringref_value(context, fdata, line, &stack->backing_mem);
		}
		else if (match_part(&line->token, "stackpointer")) {
			return parse_stringref_value(context, fdata, line, &stack->stackpointer);
		}
		else {
			printf("Stack-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("Stack-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}

	bool parse_arch_token(DecompContext* context, FileData* fdata, Line* line, Architecture* arch) {
		if (!line->token) return false;
		if (match_part(&line->token, "name")) {
			return parse_string_value(context, fdata, line, &arch->name);
		}
		else if (match_part(&line->token, "instrptr")) {
			return parse_stringref_value(context, fdata, line, &arch->instrptr);
		}
		else if (match_part(&line->token, "wordbase")) {
			return parse_int_value(context, fdata, line, &arch->wordbase);
		}
		else if (match_part(&line->token, "defaulttype")) {
			return parse_stringref_value(context, fdata, line, &arch->default_type);
		}
		else if (match_part(&line->token, "stack")) {
			Stack stack;
			bool res = parse_token_args<Stack>(context, fdata, parse_stack_token, &stack, line);
			arch->stacks.insert(stack);
			return res;
		}
		else if (match_part(&line->token, "memory")) {
			Memory memory;
			bool res = parse_token_args<Memory>(context, fdata, parse_memory_token, &memory, line);
			arch->memories.insert(memory);
			return res;
		}
		else if (match_part(&line->token, "register")) {
			Register reg;
			bool res = parse_token_args<Register>(context, fdata, parse_register_token, &reg, line);
			arch->registers.insert(reg);
			return res;
		}
		else if (match_part(&line->token, "primitivetype")) {
			PrimitiveType primitivetype;
			bool res = parse_token_args<PrimitiveType>(context, fdata, parse_primitivetype_token, &primitivetype, line);
			arch->primitivetypes.insert(primitivetype);
			return res;
		}
		else if (match_part(&line->token, "builtin")) {
			Builtin builtin;
			bool res = parse_token_args<Builtin>(context, fdata, parse_builtin_token, &builtin, line);
			arch->builtins.insert(builtin);
			return res;
		}
		else if (match_part(&line->token, "instruction")) {
			InstructionDefinition instr;
			bool res = parse_token_args<InstructionDefinition>(context, fdata, parse_instruction_token, &instr, line);
			arch->instruction_defs.insert(instr);
			return res;
		}
		else {
			printf("Arch-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("Arch-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}
	bool parse_base_token(DecompContext* context, FileData* fdata, Line* line, void* data) {
		if (!line->token) return false;
		if (match_part(&line->token, "architecture")) {

			Architecture arch;
			context->arch = &arch;
			bool res = parse_token_args<Architecture>(context, fdata, parse_arch_token, &arch, line);
			//arch.print(0);
			arch.update_ids();
			context->arch = nullptr;
			context->string_store->print();

			return res;
		}
		else {
			printf("Base-Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
			printf("Base-Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
			return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		}
		return true;
	}

	bool parse_conf_file(const char* filename) {
		FileData fdata = read_file(filename);

		StringStore string_store;
		DecompContext context;
		context.string_store = &string_store;

		return parse_token_args<void>(&context, &fdata, parse_base_token, nullptr, nullptr);
	}

}

