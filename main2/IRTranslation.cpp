#include "pch.h"

#include "File.h"
#include "IRTranslation.h"
#include "Architecture.h"
#include "BitValue.h"



namespace holodec {

namespace translation {

	u32 parse_expression(DecompContext* context, FileData* fdata);

	template<typename T>
	using MODIFIER_PARSER = bool(*) (DecompContext* context, FileData*, DataPart*, T*);


	bool parse_arguments(DecompContext* context, FileData* fdata, translation::Expression* expr) {
		fdata->whitespaces();
		u32 i = 0;
		if (fdata->character('(')) {
			fdata->whitespaces();
			if (fdata->character(')')) return true;
			do {
				fdata->whitespaces();
				expr->sub_expressions[i] = parse_expression(context, fdata);
				if (!expr->sub_expressions[i]) {
					//ERROR
					printf("ERROR: Badly Formatted Expression in Modifier-value %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
					return false;
				}
				fdata->whitespaces();
				i++;
			} while (i < MAX_SUBEXPRESSIONS && fdata->character(','));

			if (!fdata->character(')')) {
				//ERROR
				printf("ERROR: Badly Formatted Arguments %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
			return true;
		}
		return true;
	}
	bool parse_generic_modifier(DecompContext* context, FileData* fdata, DataPart* token, Expression* expr) {
		if (match_part(token, "t")) {
			DataPart typetoken;
			fdata->whitespaces();
			if (!fdata->token(&typetoken)) {
				//ERROR
				printf("ERROR: Badly Formatted Type-string in Modifier-value %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
			expr->typeref = typetoken.to_proxystring(context->string_store);
		}
		else if (match_part(token, "s")) {
			fdata->whitespaces();
			expr->size_id = parse_expression(context, fdata);
			return expr->size_id != 0;
		}
		else if (match_part(token, "o")) {
			fdata->whitespaces();
			expr->offset_id = parse_expression(context, fdata);
			return expr->offset_id != 0;
		}
		else if (match_part(token, "addr")) {
			fdata->whitespaces();
			expr->addr_id = parse_expression(context, fdata);
			return expr->addr_id != 0;
		}
		else {
			printf("ERROR: Unknown Modifier %.*s\n", (int)token->size, token->ptr);
			return false;
		}
		return true;
	}
	bool parse_cast_modifier(DecompContext* context, FileData* fdata, DataPart* token, Expression* expr) {
		if (match_part(token, "t")) {
			DataPart typetoken;
			fdata->whitespaces();
			if (!fdata->token(&typetoken)) {
				//ERROR
				printf("ERROR: Badly Formatted Type-string in Modifier-value %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
			expr->cast_typeref = typetoken.to_proxystring(context->string_store);
		}
		else if (match_part(token, "s")) {
			fdata->whitespaces();
			expr->cast_size_id = parse_expression(context, fdata);
			return expr->cast_size_id != 0;
		}
		else {
			fdata->whitespaces();
			if (!parse_expression(context, fdata)) {
				//ERROR
				printf("ERROR: Badly Formatted Expression in Modifier-value %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
		}
		return true;
	}
	template<typename T>
	bool parse_modifiers(DecompContext* context, FileData* fdata, MODIFIER_PARSER<T> modify_parser, T* data) {
		fdata->whitespaces();
		if (fdata->character('[')) {
			do {
				fdata->whitespaces();
				DataPart token;
				if (!fdata->token(&token)) {
					//ERROR
					printf("ERROR: Expected token in Modifiers %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
					return false;
				}
				fdata->whitespaces();
				if (!fdata->character(':')) {
					//ERROR
					printf("ERROR: Expected : in Modifiers %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
					return false;
				}
				fdata->whitespaces();
				modify_parser(context, fdata, &token, data);
				fdata->whitespaces();
			} while (fdata->character(','));

			if (!fdata->character(']')) {
				//ERROR
				printf("ERROR: Badly Formatted Modifiers %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
			return true;
		}
		return true;
	}
	bool parse_string_modifier(DecompContext* context, FileData* fdata, DataPart* token) {
		fdata->whitespaces();
		if (fdata->character('[')) {
			fdata->whitespaces();
			if (fdata->token(token)) {
				fdata->whitespaces();
				if (!fdata->character(']')) {
					//ERROR
					printf("ERROR: Badly Formatted String-Modifier %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
					return false;
				}
				return true;
			}
		}
		return true;
	}
	bool parse_op(DecompContext* context, FileData* fdata, DataPart* token, translation::Expression* expr) {
		fdata->whitespaces();
		if (match_part(token, "extract")) {
			expr->type = ExpressionType::eExtract;
			DataPart strmod;
			if (!parse_string_modifier(context, fdata, &strmod)) return false;
			expr->ref = strmod.to_proxystring(context->string_store);
		}
		else if (match_part(token, "cast")) {
			expr->type = ExpressionType::eCast;
			if (!parse_modifiers<Expression>(context, fdata, parse_generic_modifier, expr)) return false;
			fdata->whitespaces();
			if (!(fdata->character('-') && fdata->character('>'))) {
				//ERROR
				return false;
			}
			if (!parse_modifiers<Expression>(context, fdata, parse_cast_modifier, expr)) return false;
		}
		else if (match_part(token, "isize")) {
			expr->type = ExpressionType::eInstructionSize;
		}
		else if (match_part(token, "size")) {
			expr->type = ExpressionType::eWordSize;
		}
		else if (match_part(token, "bsize")) {
			expr->type = ExpressionType::eBitSize;
		}
		else {
			expr->type = ExpressionType::eOp;
			if (match_part(token, "ext"))		expr->op_type = OpType::eExtend;
			else if (match_part(token, "app"))	expr->op_type = OpType::eAppend;
			else if (match_part(token, "add"))	expr->op_type = OpType::eAdd;
			else if (match_part(token, "sub"))	expr->op_type = OpType::eSub;
			else if (match_part(token, "mul"))	expr->op_type = OpType::eMul;
			else if (match_part(token, "div"))	expr->op_type = OpType::eDiv;
			else if (match_part(token, "mod"))	expr->op_type = OpType::eMod;
			else if (match_part(token, "and"))	expr->op_type = OpType::eAnd;
			else if (match_part(token, "or"))	expr->op_type = OpType::eOr;
			else if (match_part(token, "not"))	expr->op_type = OpType::eNot;
			else if (match_part(token, "eq"))	expr->op_type = OpType::eEq;
			else if (match_part(token, "less"))	expr->op_type = OpType::eLess;
			else if (match_part(token, "greater"))	expr->op_type = OpType::eGreater;
			else if (match_part(token, "band"))	expr->op_type = OpType::eBAnd;
			else if (match_part(token, "bor"))	expr->op_type = OpType::eBOr;
			else if (match_part(token, "bxor"))	expr->op_type = OpType::eBXor;
			else if (match_part(token, "bnot"))	expr->op_type = OpType::eBNot;
			else if (match_part(token, "shr"))	expr->op_type = OpType::eShr;
			else if (match_part(token, "shl"))	expr->op_type = OpType::eShl;
			else if (match_part(token, "ror"))	expr->op_type = OpType::eRor;
			else if (match_part(token, "rol"))	expr->op_type = OpType::eRol;
			else if (match_part(token, "carry"))	expr->op_type = OpType::eCarryFlag;
			else if (match_part(token, "overflow"))	expr->op_type = OpType::eOverflowFlag;
			else if (match_part(token, "underflow"))	expr->op_type = OpType::eUnderflowFlag;
			else {
				printf("ERROR: unknown token %.*s\n", (int)token->size, token->ptr);
				expr->op_type = OpType::eInvalid;
				expr->ref = token->to_proxystring(context->string_store);
			}
			if (!parse_modifiers<Expression>(context, fdata, parse_generic_modifier, expr)) return 0;
		}
		if (!parse_arguments(context, fdata, expr)) return false;
		return true;
	}
	u32 parse_expression(DecompContext* context, FileData* fdata) {
		DataPart token;
		u32 index;
		u64 ival;

		if (fdata->character('#')) {
			if (fdata->token(&token)) { //ir-defined operations
				Expression expr;
				if (!parse_op(context, fdata, &token, &expr)) {
					printf("ERROR: Not a #-op %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
					return 0;
				}
				return context->arch->ir_expr_store.insert(expr);
			}
			else if (fdata->integer(&index)) { //temporary
				Expression expr;
				expr.type = ExpressionType::eTemporary;
				expr.index = index;
				if (!parse_modifiers<Expression>(context, fdata, parse_generic_modifier, &expr)) return 0;
				return context->arch->ir_expr_store.insert(expr);
			}
			else {
				//ERROR
				printf("ERROR: #-Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return 0;
			}
		}
		else if (fdata->character('$')) { //arch-defined
			if (fdata->token(&token)) {
				fdata->whitespaces();
				if (match_part(&token, "mem")) {
					Expression expr;
					expr.type = ExpressionType::eMemory;

					DataPart stringtoken;
					if (!parse_string_modifier(context, fdata, &stringtoken)) return 0;
					expr.ref = stringtoken.to_proxystring(context->string_store);
					if (!parse_modifiers<Expression>(context, fdata, parse_generic_modifier, &expr)) return 0;
					return context->arch->ir_expr_store.insert(expr);
				}
				else if (match_part(&token, "stack")) {
					Expression expr;
					expr.type = ExpressionType::eStack;

					DataPart stringtoken;
					if (!parse_string_modifier(context, fdata, &stringtoken)) return 0;
					expr.ref = stringtoken.to_proxystring(context->string_store);
					if (!parse_modifiers<Expression>(context, fdata, parse_generic_modifier, &expr)) return 0;
					return context->arch->ir_expr_store.insert(expr);
				}
				else if (match_part(&token, "builtin")) {
					Expression expr;
					expr.type = ExpressionType::eBuiltin;

					DataPart stringtoken;
					if (!parse_string_modifier(context, fdata, &stringtoken)) {
						//ERROR
						return 0;
					}
					expr.ref = stringtoken.to_proxystring(context->string_store);
					if (!parse_arguments(context, fdata, &expr)) return 0;
					return context->arch->ir_expr_store.insert(expr);
				}
				else {//register
					Expression expr;
					expr.type = ExpressionType::eRegister;
					if (match_part(&token, "reg")) {
						DataPart stringtoken;
						if (!parse_string_modifier(context, fdata, &stringtoken)) return 0;
						expr.ref = stringtoken.to_proxystring(context->string_store);
					}
					else {
						expr.ref = token.to_proxystring(context->string_store);
					}
					if (!parse_modifiers<Expression>(context, fdata, parse_generic_modifier, &expr)) return 0;
					return context->arch->ir_expr_store.insert(expr);
				}
			}
			else if (fdata->integer(&index)) { //argument
				Expression expr;
				expr.type = ExpressionType::eArgument;
				expr.index = index;
				if (!parse_modifiers<Expression>(context, fdata, parse_generic_modifier, &expr)) return 0;
				return context->arch->ir_expr_store.insert(expr);
			}
			else {
				printf("ERROR: $-Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return 0;
			}
		}
		else if (fdata->integer(&ival)) { //value
			Expression expr;
			expr.type = ExpressionType::eValue;
			expr.value.set_value(ival, context->arch->wordbase);
			if (!parse_modifiers<Expression>(context, fdata, parse_generic_modifier, &expr)) return 0;
			return context->arch->ir_expr_store.insert(expr);
		}
		//ERROR
		printf("ERROR: Unknown Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
		return 0;
	}
	bool is_ending(FileData* fdata) {
		fdata->whitespaces();
		if (!fdata->eof()) {
			printf("ERROR: Not parsed whole line %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
			return false;
		}
		return true;
	}

	bool parse_ir_string(DecompContext* context, FileData* fdata, IRLine* line) {
		printf("%.*s\n", (int)fdata->size, fdata->data);
		DataPart token;
		u32 index;

		fdata->whitespaces();
		if (fdata->character('§')) {
			if (!fdata->integer(&line->label_id)) { //label
				//ERROR
				return false;
			}
		}
		fdata->whitespaces();
		if (fdata->character('#')) {
			if (fdata->token(&token)) { //ir-defined operations
				if (match_part(&token, "rec")) { //Parse recursive instruction
					Expression expr;
					expr.type = ExpressionType::eRecursive;

					DataPart stringtoken;
					if (!parse_string_modifier(context, fdata, &stringtoken)) {
						//ERROR
						return false;
					}
					expr.ref = stringtoken.to_proxystring(context->string_store);
					if (!parse_arguments(context, fdata, &expr)) {
						//ERROR
						return false;
					}
					line->expr_id = context->arch->ir_expr_store.insert(expr);
					return is_ending(fdata);
				}
				if (match_part(&token, "trap")) { //Parse recursive instruction
					Expression expr;
					expr.type = ExpressionType::eTrap;

					if (!parse_arguments(context, fdata, &expr)) {
						//ERROR
						return false;
					}
					line->expr_id = context->arch->ir_expr_store.insert(expr);
					return is_ending(fdata);
				}
				else {
					//ERROR
					printf("ERROR: Not a standalone #-op %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
					return false;
				}
			}
			else if (fdata->integer(&index)) { //temporary
				Expression expr;
				expr.type = ExpressionType::eTemporary;
				expr.index = index;
				line->write_id = context->arch->ir_expr_store.insert(expr);
			}
			else {
				//ERROR
				printf("ERROR: #-Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
		}
		else if (fdata->character('$')) { //arch-defined
			if (fdata->token(&token)) {
				if (match_part(&token, "mem")) {
					Expression expr;
					expr.type = ExpressionType::eMemory;

					DataPart stringtoken;
					if (!parse_string_modifier(context, fdata, &stringtoken)) {
						//ERROR
						return false;
					}
					expr.ref = stringtoken.to_proxystring(context->string_store);
					if (!parse_modifiers<Expression>(context, fdata, parse_generic_modifier, &expr)) {
						//ERROR
						return false;
					}

					line->write_id = context->arch->ir_expr_store.insert(expr);
				}
				else if (match_part(&token, "stack")) {
					Expression expr;
					expr.type = ExpressionType::eStack;

					DataPart stringtoken;
					if (!parse_string_modifier(context, fdata, &stringtoken)) {
						//ERROR
						return false;
					}
					expr.ref = stringtoken.to_proxystring(context->string_store);

					line->write_id = context->arch->ir_expr_store.insert(expr);
				}
				else if (match_part(&token, "builtin")) {
					Expression expr;
					expr.type = ExpressionType::eBuiltin;

					DataPart stringtoken;
					if (!parse_string_modifier(context, fdata, &stringtoken)) {
						//ERROR
						return false;
					}
					expr.ref = stringtoken.to_proxystring(context->string_store);
					if (!parse_arguments(context, fdata, &expr)) {
						//ERROR
						return false;
					}

					line->expr_id = context->arch->ir_expr_store.insert(expr);
					return is_ending(fdata);
				}
				else {//register
					Expression expr;
					expr.type = ExpressionType::eRegister;
					if (match_part(&token, "reg")) {
						DataPart stringtoken;
						if (!parse_string_modifier(context, fdata, &stringtoken)) {
							//ERROR
							return false;
						}
						expr.ref = stringtoken.to_proxystring(context->string_store);
					}
					else {
						expr.ref = token.to_proxystring(context->string_store);
					}
					line->write_id = context->arch->ir_expr_store.insert(expr);
				}
			}
			else if (fdata->integer(&index)) { //argument
				Expression expr;
				expr.type = ExpressionType::eArgument;
				expr.index = index;
				line->write_id = context->arch->ir_expr_store.insert(expr);
			}
			else {
				//ERROR
				printf("ERROR: $-Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
		}
		else {
			//ERROR
			printf("ERROR: Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
			return false;
		}
		fdata->whitespaces();
		if (!fdata->character('=')) {
			//ERROR
			printf("ERROR: Expected '=' %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
			return false;
		}
		fdata->whitespaces();
		line->expr_id = parse_expression(context, fdata);
		if (!line->expr_id) {
			//ERROR
			return false;
		}
		fdata->whitespaces();
		if (fdata->character('?')) {
			fdata->whitespaces();
			line->cond_id = parse_expression(context, fdata);
			if (!line->cond_id) {
				//ERROR
				return false;
			}
		}
		return is_ending(fdata);
	}
	bool parse_ir_string(DecompContext* context, IRLine* line) {
		FileData fdata(line->str);
		return parse_ir_string(context, &fdata, line);
	}
	bool validate_ir_expression(DecompContext* context, u32 id);

	bool validate_ir_arguments(DecompContext* context, Expression* expr, u32 minval, u32 maxvalue) {
		u32 i = 0;
		for (; i < MAX_SUBEXPRESSIONS; i++) {
			if (!expr->sub_expressions[i]) break;
			if (!validate_ir_expression(context, expr->sub_expressions[i])) return false;
		}
		return i >= minval && i <= maxvalue;
	}
	bool validate_ir_op(DecompContext* context, Expression* expr) {
		switch (expr->op_type) {
		default:
		case OpType::eInvalid:
			return false;
		case OpType::eExtend:
			return validate_ir_arguments(context, expr, 1, 1);
		case OpType::eAppend:
			return validate_ir_arguments(context, expr, 1, MAX_SUBEXPRESSIONS);
		case OpType::eAdd:
		case OpType::eSub:
		case OpType::eMul:
		case OpType::eDiv:
		case OpType::eMod:
			return validate_ir_arguments(context, expr, 2, 2);
		case OpType::eEq:
		case OpType::eLess:
		case OpType::eGreater:
			return validate_ir_arguments(context, expr, 2, 2);
		case OpType::eAnd:
		case OpType::eOr:
			return validate_ir_arguments(context, expr, 2, 2);
		case OpType::eNot:
			return validate_ir_arguments(context, expr, 1, 1);
		case OpType::eCarryFlag:
		case OpType::eOverflowFlag:
		case OpType::eUnderflowFlag:
			return validate_ir_arguments(context, expr, 1, 1);
		case OpType::eBAnd:
		case OpType::eBOr:
		case OpType::eBXor:
			return validate_ir_arguments(context, expr, 2, 2);
		case OpType::eBNot:
			return validate_ir_arguments(context, expr, 1, 1);
		case OpType::eShr:
		case OpType::eShl:
		case OpType::eRor:
		case OpType::eRol:
			return validate_ir_arguments(context, expr, 2, 2);
		}
	}
	bool validate_ir_expression(DecompContext* context, u32 id) {
		if (id) {
			Expression* expr = context->arch->ir_expr_store.get(id);
			if (!expr) return false;
			switch (expr->type) {
			default:
			case ExpressionType::eInvalid:
				return false;
			case ExpressionType::eArgument:
			case ExpressionType::eTemporary:
				return validate_ir_arguments(context, expr, 0, 0) && expr->index;
			case ExpressionType::eValue:
				return validate_ir_arguments(context, expr, 0, 0) && expr->value.bitcount;
			case ExpressionType::eRegister:
			case ExpressionType::eMemory:
			case ExpressionType::eStack:
				return validate_ir_arguments(context, expr, 0, 0) && expr->ref;
			case ExpressionType::eBuiltin:
				//TODO check argument count
				return true;
			case ExpressionType::eRecursive:
				return true;
			case ExpressionType::eTrap:
				return validate_ir_arguments(context, expr, 0, 0);
			case ExpressionType::eExtract:
				return validate_ir_arguments(context, expr, 1, 1);
			case ExpressionType::eCast:
				return validate_ir_arguments(context, expr, 1, 1) && expr->typeref && expr->cast_typeref;
			case ExpressionType::eOp:
				return validate_ir_op(context, expr);
			case ExpressionType::eInstructionSize:
			case ExpressionType::eWordSize:
			case ExpressionType::eBitSize:
				return validate_ir_arguments(context, expr, 1, 1);
			}
		}
		return false;
	}
	bool validate_ir_write(DecompContext* context, u32 id) {
		if (id) {
			Expression* expr = context->arch->ir_expr_store.get(id);
			if (!expr) return false;
			switch (expr->type) {
			case ExpressionType::eValue:
			case ExpressionType::eArgument:
			case ExpressionType::eTemporary:
			case ExpressionType::eRegister:
			case ExpressionType::eMemory:
			case ExpressionType::eStack:
				return validate_ir_expression(context, id);
			default:
				return false;
			}
		}
		return false;
	}

	bool validate_ir_line(DecompContext* context, IRLine* line) {
		if (line->write_id) {
			if (!validate_ir_write(context, line->write_id)) {
				return false;
			}
		}
		if (line->expr_id) {
			if (!validate_ir_expression(context, line->expr_id)) {
				return false;
			}
		}
		if (line->cond_id) {
			if (!validate_ir_expression(context, line->cond_id)) {
				return false;
			}
		}
		return true;
	}

	bool parse_all_ir_strings(DecompContext* context) {
		if (!context->arch) {
			//ERROR
			return false;
		}

		for (InstructionDefinition& instr_def : context->arch->instruction_defs) {
			for (IRTranslation& translation : instr_def.translations) {
				for (IRLine& line : translation.condition) {
					if (parse_ir_string(context, &line)) {
						if (!validate_ir_line(context, &line)) {
							printf("Validation failed\n");
						}
						line.print(context);
					}
				}
				for (IRLine& line : translation.code) {
					if (parse_ir_string(context, &line)) {
						if (!validate_ir_line(context, &line)) {
							printf("Validation failed\n");
						}
						line.print(context);
					}
				}
			}
		}
		return true;
	}
}

}