#include "pch.h"

#include "File.h"
#include "IRTranslation.h"



namespace holodec {

namespace translation {

	bool parse_expression(FileData* fdata);

	template<typename T>
	using MODIFIER_PARSER = bool(*) (FileData*, DataPart*, T*);

	bool parse_arguments(FileData* fdata) {
		fdata->whitespaces();
		if (fdata->character('(')) {
			do {
				fdata->whitespaces();
				if (!parse_expression(fdata)) {
					//ERROR
					printf("ERROR: Badly Formatted Expression in Modifier-value %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
					return false;
				}
				fdata->whitespaces();
			} while (fdata->character(','));

			if (!fdata->character(')')) {
				//ERROR
				printf("ERROR: Badly Formatted Arguments %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
			return true;
		}
		return true;
	}
	bool parse_generic_modifier(FileData* fdata, DataPart* token, void* data) {
		printf("    Parsed Modifier %.*s\n", (int)token->size, token->ptr);
		if (match_part(token, "t")) {
			DataPart typetoken;
			fdata->whitespaces();
			if (!fdata->token(&typetoken)) {
				//ERROR
				printf("ERROR: Badly Formatted Type-string in Modifier-value %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
		}
		else {
			fdata->whitespaces();
			if (!parse_expression(fdata)) {
				//ERROR
				printf("ERROR: Badly Formatted Expression in Modifier-value %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
		}
		return true;
	}
	template<typename T>
	bool parse_modifiers(FileData* fdata, MODIFIER_PARSER<T> modify_parser, T* data) {
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
				modify_parser(fdata, &token, data);
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
	bool parse_string_modifier(FileData* fdata, DataPart* token) {
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
	bool parse_expression(FileData* fdata) {
		DataPart token;
		u64 i;
		s64 si;
		if (fdata->character('#')) {
			if (fdata->token(&token)) { //ir-defined operations
				printf("Parsed ir-defined operation %.*s\n", (int)token.size, token.ptr);
				if (match_part(&token, "extract")) {
					printf("Parsed Extract\n");
					DataPart strmod;
					if (!parse_string_modifier(fdata, &strmod)) return false;
				}
				else if (match_part(&token, "isize")) {
					printf("Parsed Instructionsize\n");
				}
				else {
					if (!parse_modifiers<void>(fdata, parse_generic_modifier, nullptr)) return false;
				}
				if (!parse_arguments(fdata)) return false;
			}
			else if (fdata->integer(&i)) { //temporary
				printf("Parsed Temporary %" PRIu64 "\n", i);
			}
			else {
				//ERROR
				printf("ERROR: #-Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
		}
		else if (fdata->character('§')) {
			if (fdata->integer(&i)) { //temporary
				printf("Parsed Label %" PRIu64 "\n", i);
			}
			else {
				//ERROR
				printf("ERROR: §-Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
		}
		else if (fdata->character('$')) { //arch-defined
			if (fdata->token(&token)) {
				fdata->whitespaces();
				DataPart strmod;
				if (match_part(&token, "mem")) {
					printf("Parsed Memory %.*s\n", (int)token.size, token.ptr);
					if (!parse_string_modifier(fdata, &strmod) || !parse_modifiers<void>(fdata, parse_generic_modifier, nullptr)) return false;
				}
				else if (match_part(&token, "stack")) {
					printf("Parsed Stack %.*s\n", (int)token.size, token.ptr);
					if (!parse_string_modifier(fdata, &strmod)) return false;
				}
				else if (match_part(&token, "builtin")) {
					printf("Parsed Builtin %.*s\n", (int)token.size, token.ptr);
					if (!parse_string_modifier(fdata, &strmod) || !parse_arguments(fdata)) return false;
				}
				else {//register
					if (match_part(&token, "reg")) {
						if (!parse_string_modifier(fdata, &strmod)) return false;
					}
					printf("Parsed Register %.*s\n", (int)token.size, token.ptr);
				}
			}
			else if (fdata->integer(&i)) { //argument
				printf("Parsed Argument %" PRIu64 "\n", i);
			}
			else {
				printf("ERROR: $-Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
				return false;
			}
		}
		else if (fdata->integer(&i)) { //value
			printf("Parsed Value %" PRIu64 "\n", i);
		}
		else if (fdata->signed_integer(&si)) { //value
			printf("Parsed Signed Value %" PRId64 "\n", si);
		}
		else {
			//ERROR
			printf("ERROR: Unknown Expression %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
			fdata->integer(&i);
			return false;
		}
		if (!parse_modifiers<void>(fdata, parse_generic_modifier, nullptr)) return false;
		return true;
	}

	bool parse_ir_string(FileData* fdata) {
		printf("%.*s\n", (int)fdata->size, fdata->data);
		DataPart token;
		u64 i;

		fdata->whitespaces();
		if (fdata->character('§')) {
			if (fdata->integer(&i)) { //label
				printf("Parsed Label %" PRIu64 "\n", i);
			}
			else {
				//ERROR
				return false;
			}
		}
		fdata->whitespaces();
		if (fdata->character('#')) {
			if (fdata->token(&token)) { //ir-defined operations
				if (match_part(&token, "rec")) { //Parse recursive instruction
					DataPart stringtoken;
					if (!parse_string_modifier(fdata, &stringtoken)) {
						//ERROR
						return false;
					}
					printf("Parsed recursive operation of instruction %.*s\n", (int)stringtoken.size, stringtoken.ptr);
					if (!parse_arguments(fdata)) {
						//ERROR
						return false;
					}
				}
				else {
					//ERROR
					return false;
				}
			}
			else if (fdata->integer(&i)) { //temporary
				printf("Parsed Temporary %" PRIu64 "\n", i);
			}
			else {
				//ERROR
				return false;
			}
		}
		else if (fdata->character('$')) { //arch-defined
			if (fdata->token(&token)) {
				if (match_part(&token, "mem")) {
					printf("Parsed Memory\n");
				}
				else if (match_part(&token, "stack")) {
					printf("Parsed Stack\n");
				}
				else if (match_part(&token, "builtin")) {
					printf("Parsed Builtin\n");
					if (!parse_arguments(fdata)) {
						//ERROR
						return false;
					}
				}
				else {//register
					if (match_part(&token, "reg")) {
						printf("Parsed Register\n");
					}
					else {
						printf("Parsed Register\n");
					}
				}
			}
			else if (fdata->integer(&i)) { //argument
				printf("Parsed Argument %" PRIu64 "\n", i);
			}
			else {
				//ERROR
				return false;
			}
		}
		else {
			//ERROR
			return false;
		}
		fdata->whitespaces();
		if (!fdata->character('=')) {
			//ERROR
			return false;
		}
		fdata->whitespaces();
		if (!parse_expression(fdata)) {
			//ERROR
			return false;
		}
		fdata->whitespaces();
		if (fdata->character('?')) {
			printf("Parsing Condition\n");
			fdata->whitespaces();
			if (!parse_expression(fdata)) {
				//ERROR
				return false;
			}
		}
		fdata->whitespaces();
		if (!fdata->eof()) {
			printf("ERROR: Not parsed whole line %.*s\n", (int)(fdata->size - fdata->offset), fdata->current_ptr());
			return false;
		}
		return true;
	}

}

}