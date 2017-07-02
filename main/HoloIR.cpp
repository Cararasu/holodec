#include "HoloIR.h"
#include "HArchitecture.h"
#include "HFunction.h"


holodec::HMap<holodec::HString, holodec::holoir::HIRTokenType> holodec::holoir::tokenmap = {
	{"c", { holodec::holoir::H_IR_TOKEN_FLAG_C, 0, 0}},
	{"a", { holodec::holoir::H_IR_TOKEN_FLAG_A, 0, 0}},
	{"p", { holodec::holoir::H_IR_TOKEN_FLAG_P, 0, 0}},
	{"o", { holodec::holoir::H_IR_TOKEN_FLAG_O, 0, 0}},
	{"z", { holodec::holoir::H_IR_TOKEN_FLAG_Z, 0, 0}},
	{"s", { holodec::holoir::H_IR_TOKEN_FLAG_S, 0, 0}},

	{"arg", { holodec::holoir::H_IR_TOKEN_OP_ARG}},
	{"stck", { holodec::holoir::H_IR_TOKEN_OP_STCK}},
	{"t", { holodec::holoir::H_IR_TOKEN_OP_TMP}},

	{"jmp", { holodec::holoir::H_IR_TOKEN_OP_JMP, 1, 1}},
	{"call", { holodec::holoir::H_IR_TOKEN_OP_CALL, 1, 1}},
	{"ret", { holodec::holoir::H_IR_TOKEN_OP_RET, 0, 0}},
	{"syscall", { holodec::holoir::H_IR_TOKEN_OP_SYSCALL, 0, 1}},
	{"trap", { holodec::holoir::H_IR_TOKEN_OP_TRAP, 0, 0}},
	{"call", { holodec::holoir::H_IR_TOKEN_OP_CALL, 1, 1}},

	{"assign", { holodec::holoir::H_IR_TOKEN_OP_ASSIGN, 2, 2}},
	{"size", { holodec::holoir::H_IR_TOKEN_OP_SIZE, 1, 1}},
	{"popcnt", { holodec::holoir::H_IR_TOKEN_OP_POPCNT, 1, 1}},
	{"loop", { holodec::holoir::H_IR_TOKEN_OP_LOOP, 2, 2}},
	{"if", { holodec::holoir::H_IR_TOKEN_OP_IF, 2, 3}},
	{"rec", { holodec::holoir::H_IR_TOKEN_OP_REC}},
	{"ext", { holodec::holoir::H_IR_TOKEN_OP_EXTEND, 1, 2}},
	{"sext", { holodec::holoir::H_IR_TOKEN_OP_SEXTEND, 1, 2}},

	{"add", { holodec::holoir::H_IR_TOKEN_OP_ADD, 2}},
	{"fadd", { holodec::holoir::H_IR_TOKEN_OP_FADD, 2}},
	{"sub", { holodec::holoir::H_IR_TOKEN_OP_SUB, 2}},
	{"fsub", { holodec::holoir::H_IR_TOKEN_OP_FSUB, 2}},
	{"mul", { holodec::holoir::H_IR_TOKEN_OP_MUL, 2}},
	{"smul", { holodec::holoir::H_IR_TOKEN_OP_SMUL, 2}},
	{"fmul", { holodec::holoir::H_IR_TOKEN_OP_FMUL, 2}},
	{"div", { holodec::holoir::H_IR_TOKEN_OP_DIV, 2, 2}},
	{"sdiv", { holodec::holoir::H_IR_TOKEN_OP_SDIV, 2, 2}},
	{"fdiv", { holodec::holoir::H_IR_TOKEN_OP_FDIV, 2, 2}},

	{"st", { holodec::holoir::H_IR_TOKEN_OP_STORE, 2}},
	{"ld", { holodec::holoir::H_IR_TOKEN_OP_LOAD, 1, 2}},

	{"eq", { holodec::holoir::H_IR_TOKEN_CMP_E, 2, 2}},
	{"neq", { holodec::holoir::H_IR_TOKEN_CMP_NE, 2, 2}},
	{"l", { holodec::holoir::H_IR_TOKEN_CMP_L, 2, 2}},
	{"le", { holodec::holoir::H_IR_TOKEN_CMP_LE, 2, 2}},
	{"g", { holodec::holoir::H_IR_TOKEN_CMP_G, 2, 2}},
	{"ge", { holodec::holoir::H_IR_TOKEN_CMP_GE, 2, 2}},
	{"not", { holodec::holoir::H_IR_TOKEN_CMP_NOT, 1, 1}},

	{"and", { holodec::holoir::H_IR_TOKEN_OP_AND, 2}},
	{"or", { holodec::holoir::H_IR_TOKEN_OP_OR, 2}},
	{"xor", { holodec::holoir::H_IR_TOKEN_OP_XOR, 2}},

	{"band", { holodec::holoir::H_IR_TOKEN_BINOP_AND, 2}},
	{"bor", { holodec::holoir::H_IR_TOKEN_BINOP_OR, 2}},
	{"bxor", { holodec::holoir::H_IR_TOKEN_BINOP_XOR, 2}},
	{"bnot", { holodec::holoir::H_IR_TOKEN_BINOP_NOT, 1, 1}},

	{"shr", { holodec::holoir::H_IR_TOKEN_BINOP_SHR, 2, 2}},
	{"shl", { holodec::holoir::H_IR_TOKEN_BINOP_SHL, 2, 2}},
	{"sar", { holodec::holoir::H_IR_TOKEN_BINOP_SAR, 2, 2}},
	{"sal", { holodec::holoir::H_IR_TOKEN_BINOP_SAL, 2, 2}},
	{"ror", { holodec::holoir::H_IR_TOKEN_BINOP_ROR, 2, 2}},
	{"rol", { holodec::holoir::H_IR_TOKEN_BINOP_ROL, 2, 2}},

	{"i2f", { holodec::holoir::H_IR_TOKEN_CAST_I2F, 1, 2}},
	{"f2i", { holodec::holoir::H_IR_TOKEN_CAST_F2I, 1, 2}},
};

void holodec::holoir::HIRParser::skipWhitespaces() {
	while (parseCharacter (' '));
}
void holodec::holoir::HIRParser::printParseFailure (const char* str) {
	printf ("%s\n", string.cstr());
	printf ("Invalid Token at '%s' expected %s\n", string.cstr() + index, str);
}
bool holodec::holoir::HIRParser::parseIdentifier (char *buffer, size_t buffersize) {
	size_t current_index = index;
	for (size_t i = 0; i < buffersize; i++) {
		char c = peek();
		if ( ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || ('A' <= c && c <= 'Z')) {
			buffer[i] = c;
		} else {
			buffer[i] = '\0';
			if (i == 0)
				return false;
			return true;
		}
		consume();
	}
	return false;
}
bool holodec::holoir::HIRParser::parseCharacter (char character) {
	if (character == pop()) {
		return true;
	}
	pushback();
	return false;
}
bool holodec::holoir::HIRParser::parseIndex (HIRExpression* expr) {
	size_t current_index = index;
	skipWhitespaces();
	if (parseCharacter ('[')) {
		const char* x = string.cstr() + index;
		if (! (expr->mod.index = parseExpression()))
			return false;
		x = string.cstr() + index;
		skipWhitespaces();
		if (parseCharacter (',')) {
			if (! (expr->mod.size = parseExpression()))
				return false;
		}
		skipWhitespaces();
		x = string.cstr() + index;
		if (parseCharacter (']')) {
			return true;
		}
		printParseFailure ("']'");
		return false;
	}
	return true;
}
bool holodec::holoir::HIRParser::parseNumberIndex (HIRExpression* expr) {
	size_t current_index = index;
	skipWhitespaces();
	if (parseCharacter ('[')) {
		int64_t number;
		if (!parseNumber (&number))
			return false;
		expr->mod.var_index = number;
		if (parseCharacter (']')) {
			return true;
		}
		printParseFailure ("']'");
		return false;
	} else {
		return true;
	}
}
bool holodec::holoir::HIRParser::parseStringIndex (HIRExpression* expr) {
	size_t current_index = index;
	skipWhitespaces();
	if (parseCharacter ('[')) {
		char buffer[100];
		if (!parseIdentifier (buffer, 100))
			return false;
		HString s = HString::create (buffer);
		expr->mod.name_index = s;
		skipWhitespaces();
		if (parseCharacter (']')) {
			return true;
		}
		printParseFailure ("']'");
		return false;
	} else {
		return true;
	}
}
bool holodec::holoir::HIRParser::parseNumber (int64_t* num) {
	size_t current_index = index;
	skipWhitespaces();
	int64_t pos;
	int parsed = sscanf (string.cstr() + index, "%d%n", num, &pos);
	if (parsed != 1) {
		return false;
	} else {
		consume (pos);
	}
	return true;
}
int holodec::holoir::HIRParser::parseArguments (HIRExpression* expr) {
	size_t current_index = index;
	skipWhitespaces();
	int i = 0;
	if (parseCharacter ('(')) {
		skipWhitespaces();
		if (parseCharacter (')')) {
			return 0;
		}
		do {
			i++;
			HIRExpression* parsedExpr = parseExpression();
			if (expr)
				expr->subexpressions.push_back (parsedExpr);
			else {
				printf ("%s\n", string.cstr());
				printf ("%s\n", string.cstr() + index);
				printf ("Failed to parse Argument %d\n", i);
				return -1;
			}
			skipWhitespaces();
		} while (parseCharacter (','));
		skipWhitespaces();
		if (!parseCharacter (')')) {
			printParseFailure ("',', ')'");
			return -1;
		}
	}
	return i;
}
holodec::holoir::HIRTokenType holodec::holoir::HIRParser::parseBuiltin() {
	size_t current_index = index;
	char buffer[100];
	if (parseIdentifier (buffer, 100)) {
		HString string (buffer);
		auto i = tokenmap.find (string);
		if (i != tokenmap.end()) {
			//printf ("Parsed Identifier: %s\n", buffer);
			return (*i).second;
		}
	}
	return H_IR_TOKEN_INVALID;
}
holodec::holoir::HIRTokenType holodec::holoir::HIRParser::parseToken() {
	skipWhitespaces();
	while (char c = pop()) {
		size_t current_index = index;
		switch (c) {
		case '#':
			return parseBuiltin();
		case '$':
			return H_IR_TOKEN_CUSTOM;
		case '?':
			//printf ("Parsed If\n");
			return {H_IR_TOKEN_OP_IF, 1, 3};
		case '+':
			//printf ("Parsed Add\n");
			return {H_IR_TOKEN_OP_ADD, 2};
		case '*':
			//printf ("Parsed Mul\n");
			return {H_IR_TOKEN_OP_MUL, 2};
		case '=':
			if (parseCharacter ('=')) {
				//printf ("Parsed Eq\n");
				return {H_IR_TOKEN_CMP_E, 2, 2};
			}
			//printf ("Parsed Assign\n");
			return {H_IR_TOKEN_OP_ASSIGN, 2, 2};
			break;
		case '<':
			if (parseCharacter ('=')) {
				//printf ("Parsed LE\n");
				return {H_IR_TOKEN_CMP_LE, 2, 2};
			} else if (parseCharacter ('>')) {
				//printf ("Parsed NE\n");
				return {H_IR_TOKEN_CMP_NE, 2, 2};
			}
			//printf ("Parsed L\n");
			return {H_IR_TOKEN_CMP_L, 2, 2};
		case '>':
			if (parseCharacter ('=')) {
				//printf ("Parsed GE\n");
				return {H_IR_TOKEN_CMP_GE, 2, 2};
			}
			//printf ("Parsed G\n");
			return {H_IR_TOKEN_CMP_G, 2, 2};
		case ' ':
			break;
		case '-': {
			char c2 = peek();
			if (c2 < '0' || '9' < c2) {
				//printf ("Parsed Sub\n");
				return {H_IR_TOKEN_OP_SUB, 2};
			}
		}
		default: {
			int64_t num;
			pushback();
			if (!parseNumber (&num)) {
				//printf ("Unexpected Token %c in %s\n", c, string.cstr() + index);
				return H_IR_TOKEN_INVALID;
			}
			//printf ("Parsed Number %d\n", num);
			return {H_IR_TOKEN_NUMBER, 0, 0};
		}
		}
	}
	return H_IR_TOKEN_INVALID;
}
holodec::holoir::HIRExpression* holodec::holoir::HIRParser::parseExpression() {
	HIRExpression* returnexpr = new HIRExpression();
	HIRExpression* seqexpr = 0;
	do {
		if (!seqexpr)
			seqexpr = returnexpr;
		else {
			seqexpr = seqexpr->sequence = new HIRExpression();
		}
		HIRExpression* appdexpr = 0;
		do {
			if (!appdexpr)
				appdexpr = seqexpr;
			else {
				appdexpr = appdexpr->append = new HIRExpression();
			}
			size_t current_index = index;
			HIRTokenType tokentype = parseToken();

			appdexpr->token = tokentype.token;
			switch (tokentype.token) {
			case H_IR_TOKEN_OP_REC:
				if (!parseStringIndex (appdexpr)) {
					returnexpr->free();
					return nullptr;
				}
				break;
			case H_IR_TOKEN_INVALID:
				break;
			case H_IR_TOKEN_CUSTOM: {
				char buffer[100];
				if (parseIdentifier (buffer, 100)) {

					appdexpr->regacces = arch->getRegister (buffer);
					if (!appdexpr->regacces)
						printf ("NNNNN %s\n", buffer);
					//printf ("Parsed Custom %s\n", buffer);
				} else {
					printf ("No custom token");
				}
			}
			break;
			case H_IR_TOKEN_OP_ARG:
			case H_IR_TOKEN_OP_STCK:
			case H_IR_TOKEN_OP_TMP:
				if (!parseNumberIndex (appdexpr)) {
					returnexpr->free();
					return nullptr;
				}
				break;
			default:
				break;
			}
			int i = parseArguments (appdexpr);

			if (i < tokentype.minargs && tokentype.maxargs < i) {
				printf ("%s\n", string.cstr());
				printf ("Wrong number of arguments Min: %u Max: %u Actual Arguments: %d\n", tokentype.minargs, tokentype.maxargs, i);
				returnexpr->free();
				return nullptr;
			}
			if (!parseIndex (appdexpr)) {
				returnexpr->free();
				return nullptr;
			}
		} while (parseCharacter (':'));
	} while (parseCharacter ('&'));
	return returnexpr;
}


void holodec::holoir::HIRParser::parse (holodec::holoir::HIRRepresentation* rep) {
	string = rep->string;
	index = 0;
	rep->expression = parseExpression();
}




void holodec::holoir::HIRExpression::free() {
	for (HIRExpression* expr : subexpressions) {
		expr->free();
	}
	subexpressions.clear();
	regacces = nullptr;
	mod.name_index.del();
	if (mod.index)
		delete mod.index;
	if (mod.size)
		delete mod.size;
	if (append)
		append->free();
	if (sequence)
		sequence->free();
	delete this;
}

void holodec::holoir::HIRExpression::print () {
	for (auto& entry : tokenmap) {
		if (entry.second.token == token) {
			printf ("#%s", entry.first.cstr());
			break;
		}
	}
	switch (token) {
	case H_IR_TOKEN_NUMBER:
		printf ("%d", value);
		break;
	case H_IR_TOKEN_CUSTOM:
		if (regacces)
			printf ("$%s", regacces->name.cstr());
		else
			printf ("RegFail");
		break;
	}
	if (mod.var_index)
		printf ("[%d]", mod.var_index);
	if (subexpressions.size()) {
		printf ("(");
		bool first = true;
		for (HIRExpression* expr : subexpressions) {
			if (!first)
				printf (",");
			else
				first = false;
			expr->print();
		}
		printf (")");
	}
	printf ("[%d,%d]", mod.index, mod.size);
	if (append) {
		printf (":");
		append->print();
	}
	if (sequence) {
		printf ("&");
		sequence->print();
	}
}
