#include "HoloIR.h"
#include "HArchitecture.h"
#include "HFunction.h"


holodec::HMap<holodec::HString, holodec::holoir::HIRTokenType> holodec::holoir::tokenmap = {
	{"c", { holodec::holoir::HIR_TOKEN_FLAG_C, 0, 0}},
	{"a", { holodec::holoir::HIR_TOKEN_FLAG_A, 0, 0}},
	{"p", { holodec::holoir::HIR_TOKEN_FLAG_P, 0, 0}},
	{"o", { holodec::holoir::HIR_TOKEN_FLAG_O, 0, 0}},
	{"z", { holodec::holoir::HIR_TOKEN_FLAG_Z, 0, 0}},
	{"s", { holodec::holoir::HIR_TOKEN_FLAG_S, 0, 0}},

	{"arg", { holodec::holoir::HIR_TOKEN_OP_ARG}},
	{"stck", { holodec::holoir::HIR_TOKEN_OP_STCK}},
	{"t", { holodec::holoir::HIR_TOKEN_OP_TMP}},
	
	{"pop", { holodec::holoir::HIR_TOKEN_POP}},
	{"push", { holodec::holoir::HIR_TOKEN_PUSH}},

	{"val", { holodec::holoir::HIR_TOKEN_VALUE, 1, 1}},

	{"jmp", { holodec::holoir::HIR_TOKEN_OP_JMP, 1, 1}},
	{"call", { holodec::holoir::HIR_TOKEN_OP_CALL, 1, 1}},
	{"ret", { holodec::holoir::HIR_TOKEN_OP_RET, 0, 0}},
	{"syscall", { holodec::holoir::HIR_TOKEN_OP_SYSCALL, 0, 1}},
	{"trap", { holodec::holoir::HIR_TOKEN_OP_TRAP, 0, 0}},
	{"call", { holodec::holoir::HIR_TOKEN_OP_CALL, 1, 1}},

	{"assign", { holodec::holoir::HIR_TOKEN_OP_ASSIGN, 2, 2}},
	{"size", { holodec::holoir::HIR_TOKEN_OP_SIZE, 1, 1}},
	{"popcnt", { holodec::holoir::HIR_TOKEN_OP_POPCNT, 1, 1}},
	{"loop", { holodec::holoir::HIR_TOKEN_OP_LOOP, 2, 2}},
	{"if", { holodec::holoir::HIR_TOKEN_OP_IF, 2, 3}},
	{"rec", { holodec::holoir::HIR_TOKEN_OP_REC}},
	{"ext", { holodec::holoir::HIR_TOKEN_OP_EXTEND, 1, 2}},
	{"sext", { holodec::holoir::HIR_TOKEN_OP_SEXTEND, 1, 2}},

	{"add", { holodec::holoir::HIR_TOKEN_OP_ADD, 2}},
	{"fadd", { holodec::holoir::HIR_TOKEN_OP_FADD, 2}},
	{"sub", { holodec::holoir::HIR_TOKEN_OP_SUB, 2}},
	{"fsub", { holodec::holoir::HIR_TOKEN_OP_FSUB, 2}},
	{"mul", { holodec::holoir::HIR_TOKEN_OP_MUL, 2}},
	{"smul", { holodec::holoir::HIR_TOKEN_OP_SMUL, 2}},
	{"fmul", { holodec::holoir::HIR_TOKEN_OP_FMUL, 2}},
	{"div", { holodec::holoir::HIR_TOKEN_OP_DIV, 2, 2}},
	{"sdiv", { holodec::holoir::HIR_TOKEN_OP_SDIV, 2, 2}},
	{"fdiv", { holodec::holoir::HIR_TOKEN_OP_FDIV, 2, 2}},

	{"st", { holodec::holoir::HIR_TOKEN_OP_STORE, 2}},
	{"ld", { holodec::holoir::HIR_TOKEN_OP_LOAD, 1, 2}},

	{"eq", { holodec::holoir::HIR_TOKEN_CMP_E, 2, 2}},
	{"neq", { holodec::holoir::HIR_TOKEN_CMP_NE, 2, 2}},
	{"l", { holodec::holoir::HIR_TOKEN_CMP_L, 2, 2}},
	{"le", { holodec::holoir::HIR_TOKEN_CMP_LE, 2, 2}},
	{"g", { holodec::holoir::HIR_TOKEN_CMP_G, 2, 2}},
	{"ge", { holodec::holoir::HIR_TOKEN_CMP_GE, 2, 2}},
	{"not", { holodec::holoir::HIR_TOKEN_CMP_NOT, 1, 1}},

	{"and", { holodec::holoir::HIR_TOKEN_OP_AND, 2}},
	{"or", { holodec::holoir::HIR_TOKEN_OP_OR, 2}},
	{"xor", { holodec::holoir::HIR_TOKEN_OP_XOR, 2}},

	{"band", { holodec::holoir::HIR_TOKEN_BINOP_AND, 2}},
	{"bor", { holodec::holoir::HIR_TOKEN_BINOP_OR, 2}},
	{"bxor", { holodec::holoir::HIR_TOKEN_BINOP_XOR, 2}},
	{"bnot", { holodec::holoir::HIR_TOKEN_BINOP_NOT, 1, 1}},

	{"shr", { holodec::holoir::HIR_TOKEN_BINOP_SHR, 2, 2}},
	{"shl", { holodec::holoir::HIR_TOKEN_BINOP_SHL, 2, 2}},
	{"sar", { holodec::holoir::HIR_TOKEN_BINOP_SAR, 2, 2}},
	{"sal", { holodec::holoir::HIR_TOKEN_BINOP_SAL, 2, 2}},
	{"ror", { holodec::holoir::HIR_TOKEN_BINOP_ROR, 2, 2}},
	{"rol", { holodec::holoir::HIR_TOKEN_BINOP_ROL, 2, 2}},

	{"i2f", { holodec::holoir::HIR_TOKEN_CAST_I2F, 1, 2}},
	{"f2i", { holodec::holoir::HIR_TOKEN_CAST_F2I, 1, 2}},
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
			HId parsedExpr = parseExpression();
			if (expr && parsedExpr)
				expr->addSubExpression (parsedExpr);
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
	return HIR_TOKEN_INVALID;
}
holodec::holoir::HIRTokenType holodec::holoir::HIRParser::parseToken() {
	skipWhitespaces();
	while (char c = pop()) {
		size_t current_index = index;
		switch (c) {
		case '#':
			return parseBuiltin();
		case '$':
			return HIR_TOKEN_REGISTER;
		case '?':
			//printf ("Parsed If\n");
			return {HIR_TOKEN_OP_IF, 1, 3};
		case '+':
			//printf ("Parsed Add\n");
			return {HIR_TOKEN_OP_ADD, 2};
		case '*':
			//printf ("Parsed Mul\n");
			return {HIR_TOKEN_OP_MUL, 2};
		case '=':
			if (parseCharacter ('=')) {
				//printf ("Parsed Eq\n");
				return {HIR_TOKEN_CMP_E, 2, 2};
			}
			//printf ("Parsed Assign\n");
			return {HIR_TOKEN_OP_ASSIGN, 2, 2};
			break;
		case '<':
			if (parseCharacter ('=')) {
				//printf ("Parsed LE\n");
				return {HIR_TOKEN_CMP_LE, 2, 2};
			} else if (parseCharacter ('>')) {
				//printf ("Parsed NE\n");
				return {HIR_TOKEN_CMP_NE, 2, 2};
			}
			//printf ("Parsed L\n");
			return {HIR_TOKEN_CMP_L, 2, 2};
		case '>':
			if (parseCharacter ('=')) {
				//printf ("Parsed GE\n");
				return {HIR_TOKEN_CMP_GE, 2, 2};
			}
			//printf ("Parsed G\n");
			return {HIR_TOKEN_CMP_G, 2, 2};
		case ' ':
			break;
		case '-': {
			char c2 = peek();
			if (c2 < '0' || '9' < c2) {
				//printf ("Parsed Sub\n");
				return {HIR_TOKEN_OP_SUB, 2};
			}
		}
		default: {
			int64_t num;
			pushback();
			if (!parseNumber (&num)) {
				//printf ("Unexpected Token %c in %s\n", c, string.cstr() + index);
				return HIR_TOKEN_INVALID;
			}
			//printf ("Parsed Number %d\n", num);
			return {HIR_TOKEN_NUMBER, 0, 0};
		}
		}
	}
	return HIR_TOKEN_INVALID;
}
holodec::HId holodec::holoir::HIRParser::parseExpression() {
	HId returnExpr = 0;
	HId lastPassedExpression = 0;
	HId seqexpr = 0;
	do {
		HId appdexpr = 0;
		do {
			HIRExpression expression = HIRExpression();
			size_t current_index = index;
			HIRTokenType tokentype = parseToken();

			expression.token = tokentype.token;
			switch (tokentype.token) {
			case HIR_TOKEN_OP_REC:
				if (!parseStringIndex (&expression)) {
					return 0;
				}
				break;
			case HIR_TOKEN_INVALID:
				break;
			case HIR_TOKEN_REGISTER: {
				char buffer[100];
				if (parseIdentifier (buffer, 100)) {
					HRegister* reg = arch->getRegister (buffer);
					expression.regacces = reg->id;
					expression.mod.size = reg->size;
					//printf ("Parsed Custom %s\n", buffer);
				} else {
					printf ("No custom token");
				}
			}
			break;
			case HIR_TOKEN_OP_ARG:
			case HIR_TOKEN_OP_STCK:
			case HIR_TOKEN_OP_TMP:
				if (!parseNumberIndex (&expression)) {
					return 0;
				}
				break;
			default:
				break;
			}
			int i = parseArguments (&expression);

			if (i < tokentype.minargs && tokentype.maxargs < i) {
				printf ("%s\n", string.cstr());
				printf ("Wrong number of arguments Min: %u Max: %u Actual Arguments: %d\n", tokentype.minargs, tokentype.maxargs, i);
				return 0;
			}
			if (!parseIndex (&expression)) {
				return 0;
			}
			lastPassedExpression = rep->addExpr (expression);
			if (!returnExpr)
				returnExpr = lastPassedExpression;
			if (!appdexpr) {
				appdexpr = lastPassedExpression;
			} else {
				appdexpr = rep->getExpr (appdexpr)->append = lastPassedExpression;
			}
		} while (parseCharacter (':'));

		if (!seqexpr) {
			seqexpr = lastPassedExpression;
		} else {
			seqexpr = rep->getExpr (seqexpr)->sequence = lastPassedExpression;
		}
	} while (parseCharacter ('&'));
	return returnExpr;
}


void holodec::holoir::HIRParser::parse (holodec::holoir::HIRRepresentation* rep) {
	string = rep->string;
	index = 0;
	this->rep = rep;
	rep->rootExpr = parseExpression();
}

void holodec::holoir::HIRExpression::print (HArchitecture* arch) {
	printf ("%lld = ", id);

	for (auto& entry : tokenmap) {
		if (entry.second.token == token) {
			printf ("#%s", entry.first.cstr());
			break;
		}
	}
	switch (token) {
	case HIR_TOKEN_NUMBER:
		printf ("0x%x", value);
		break;
	case HIR_TOKEN_FLOAT:
		printf ("%d", fvalue);
		break;
	case HIR_TOKEN_REGISTER:
		if (regacces)
			printf ("$%s", arch->getRegister (regacces)->name.cstr());
		else
			printf ("RegFail");
		break;
	case HIR_TOKEN_MEM:
		printf("[");
		if (mem.base)
			printf ("%s", arch->getRegister (mem.base)->name.cstr());
		else
			printf ("RegFail");
		if (mem.scale && mem.index)
			printf (" + %s", arch->getRegister (mem.index)->name.cstr());
		if (mem.scale && mem.scale != 1)
			printf ("*%d", mem.scale);
		if (mem.disp)
			printf (" + %d", mem.disp);
		printf("]");
		break;
	default:
		break;
	}
	if (mod.var_index)
		printf ("[%d]", mod.var_index);
	if (mod.name_index)
		printf ("[%s]", mod.name_index.cstr());
	if (subexpressions[0]) {
		printf ("(");
		printf ("%lld", subexpressions[0]);
		for (int i = 1; i < HIR_LOCAL_SUBEXPRESSION_COUNT && subexpressions[i]; i++) {
			printf (", %lld", subexpressions[i]);
		}
		printf (")");
	}
	if (mod.index != 0 || mod.size != 0)
		printf ("[%lld,%lld]", mod.index, mod.size);
	if (append) {
		printf (":");
		printf ("%lld", append);
	}
	if (sequence) {
		printf ("&");
		printf ("%lld", sequence);
	}
	printf ("\n");
}



bool holodec::holoir::operator== (holodec::holoir::HIRExpression::HIRExpressionMod& expr1, holodec::holoir::HIRExpression::HIRExpressionMod& expr2) {
	return expr1.name_index == expr2.name_index &&
	       expr1.var_index == expr2.var_index &&
	       expr1.index == expr2.index &&
	       expr1.size == expr2.size;
}

bool holodec::holoir::operator== (holodec::holoir::HIRExpression& expr1, holodec::holoir::HIRExpression& expr2) {
	for (int i = 0; i < HIR_LOCAL_SUBEXPRESSION_COUNT; i++) {
		if (expr1.subexpressions[i] != expr2.subexpressions[i])
			return false;
	}
	return expr1.token == expr2.token &&
	       expr1.value == expr2.value &&
	       expr1.regacces == expr2.regacces &&
	       expr1.mod == expr2.mod &&
	       expr1.append == expr2.append &&
	       expr1.sequence == expr2.sequence;
}
