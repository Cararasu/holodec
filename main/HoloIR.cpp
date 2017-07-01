#include "HoloIR.h"

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
	{"extend", { holodec::holoir::H_IR_TOKEN_OP_EXTEND, 1, 2}},
	{"sextend", { holodec::holoir::H_IR_TOKEN_OP_SEXTEND, 1, 2}},

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
	{"ld", { holodec::holoir::H_IR_TOKEN_OP_LOAD, 2, 3}},

	{"eq", { holodec::holoir::H_IR_TOKEN_CMP_E, 2, 2}},
	{"neq", { holodec::holoir::H_IR_TOKEN_CMP_NE, 2, 2}},
	{"l", { holodec::holoir::H_IR_TOKEN_CMP_L, 2, 2}},
	{"le", { holodec::holoir::H_IR_TOKEN_CMP_LE, 2, 2}},
	{"g", { holodec::holoir::H_IR_TOKEN_CMP_G, 2, 2}},
	{"ge", { holodec::holoir::H_IR_TOKEN_CMP_GE, 2, 2}},
	{"not", { holodec::holoir::H_IR_TOKEN_CMP_NOT, 2, 2}},

	{"and", { holodec::holoir::H_IR_TOKEN_BINOP_AND, 2}},
	{"or", { holodec::holoir::H_IR_TOKEN_BINOP_OR, 2}},
	{"xor", { holodec::holoir::H_IR_TOKEN_BINOP_XOR, 2}},
	{"not", { holodec::holoir::H_IR_TOKEN_BINOP_NOT, 1, 1}},

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
	char c = peek();
	while (c == ' ') {
		c = consume();
		c = peek();
	}
}
void holodec::holoir::HIRParser::printParseFailure (const char* str) {
	printf ("Invalid Token at '%s' expected %s\n", string.cstr() + index, str);
}
bool holodec::holoir::HIRParser::parseIdentifier (char *buffer, size_t buffersize) {
	size_t current_index = index;
	for (size_t i = 0; i < buffersize; i++) {
		char c = peek();
		if (('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || ('A' <= c && c <= 'Z'))
			buffer[i] = c;
		else {
			buffer[i] = '\0';
			return true;
		}
		consume();
	}
	return false;
}
bool holodec::holoir::HIRParser::parseSequence() {
	size_t current_index = index;
	skipWhitespaces();
	char c = peek();
	if (c == '&') {
		consume();
		return true;
	}
	return false;
}
bool holodec::holoir::HIRParser::parseIndex() {
	size_t current_index = index;
	skipWhitespaces();
	int64_t i = 0;
	if (peek() == '[') {
		consume();
		if(!parseExpression())
			return false;
		
		if (peek() == ':') {
			consume();
			 if(!parseExpression())
				 return false;
		}
		skipWhitespaces();
		if (peek() == ']') {
			consume();
			return true;
		}
		printParseFailure ("']'");
		return false;
	} else {
		return true;
	}
}
bool holodec::holoir::HIRParser::parseStringIndex() {
	size_t current_index = index;
	skipWhitespaces();
	int64_t i = 0;
	if (peek() == '[') {
		consume();
		char buffer[100];
		if(!parseIdentifier (buffer, 100))
			return false;
		printf("Parsed String Index %s\n",buffer);
		skipWhitespaces();
		if (peek() == ']') {
			consume();
			return true;
		}
		printParseFailure ("']'");
		return false;
	} else {
		return true;
	}
}
bool holodec::holoir::HIRParser::parseNumber(int64_t* num) {
	size_t current_index = index;
	skipWhitespaces();
	int64_t pos;
	int parsed = sscanf (string.cstr() + index, "%d%n", num, &pos);
	if (parsed != 1){
		return false;
	}else
		index += pos;
	return true;
}
int holodec::holoir::HIRParser::parseArguments() {
	size_t current_index = index;
	skipWhitespaces();
	int i = 0;
	if (peek() == '(') {
		skipWhitespaces();
		if (peek() == ')') {
			consume();
			return 0;
		}
		do {
			consume();
			if (!parseExpression()) {
				printf ("Failed to parse Argument %d\n", i);
				return -1;
			}
			i++;
			skipWhitespaces();
		} while (peek() == ',');

		if (peek() == ')') {
			consume();
		}
	}
	return 0;
}
holodec::holoir::HIRTokenType holodec::holoir::HIRParser::parseBuiltin() {
	size_t current_index = index;
	char buffer[100];
	if (parseIdentifier (buffer, 100)) {
		HString string (buffer);
		auto i = tokenmap.find (string);
		if (i != tokenmap.end()) {
			printf ("Parsed Identifier: %s\n", buffer);
			return (*i).second;
		}
	}
	return H_IR_TOKEN_INVALID;
}
holodec::holoir::HIRToken holodec::holoir::HIRParser::parseToken() {
	skipWhitespaces();
	while (char c = pop()) {
		size_t current_index = index;
		char c2 = peek();
		switch (c) {
		case '#':
			return parseBuiltin().token;
		case '$':
			return H_IR_TOKEN_CUSTOM;
		case '?':
			printf ("Parsed If\n");
			return H_IR_TOKEN_OP_IF;
		case '+':
			printf ("Parsed Add\n");
			return H_IR_TOKEN_OP_ADD;
		case '-':
			printf ("Parsed Sub\n");
			return H_IR_TOKEN_OP_SUB;
		case '*':
			printf ("Parsed Mul\n");
			return H_IR_TOKEN_OP_MUL;
		case '=':
			if (c2 == '=') {
				printf ("Parsed Eq\n");
				consume();
				return H_IR_TOKEN_CMP_E;
			}
			printf ("Parsed Assign\n");
			return H_IR_TOKEN_OP_ASSIGN;
			break;
		case '<':
			if (c2 == '=') {
				printf ("Parsed LE\n");
				consume();
				return H_IR_TOKEN_CMP_LE;
			} else if (c2 == '>') {
				printf ("Parsed NE\n");
				consume();
				return H_IR_TOKEN_CMP_NE;
			}
			printf ("Parsed L\n");
			return H_IR_TOKEN_CMP_L;
		case '>':
			if (c2 == '=') {
				printf ("Parsed GE\n");
				consume();
				return H_IR_TOKEN_CMP_GE;
			}
			printf ("Parsed G\n");
			return H_IR_TOKEN_CMP_G;
		case ' ':
			break;
		default:{
			int64_t num;
			pushback();
			if(!parseNumber(&num)){
				printf ("Unexpected Token %c\n", c);
				return H_IR_TOKEN_INVALID;
			}
			printf ("Parsed Number %d\n", num);
			return H_IR_TOKEN_NUMBER;
		}
		}
	}
	return H_IR_TOKEN_INVALID;
}
bool holodec::holoir::HIRParser::parseExpression() {
	do {
		size_t current_index = index;
		HIRToken token = parseToken();
		switch (token) {
		case H_IR_TOKEN_OP_REC:
			if (!parseStringIndex()){
				return false;
			}
			break;
		case H_IR_TOKEN_INVALID:
			break;
		case H_IR_TOKEN_CUSTOM: {
			char buffer[100];
			if (parseIdentifier (buffer, 100)) {
				printf ("Parsed Custom %s\n", buffer);
			}

		}
		break;
		case H_IR_TOKEN_OP_ARG:
		case H_IR_TOKEN_OP_STCK:
		case H_IR_TOKEN_OP_TMP:
			if (!parseIndex())
				return false;
			break;
		default:
			break;
		}
		if (parseArguments() < 0)
			return false;
		if (!parseIndex())
			return false;
	} while (parseSequence());
	return true;
}


void holodec::holoir::HIRParser::parse (holodec::holoir::HIRRepresentation* rep) {
	string = rep->string;
	index = 0;
	printf ("%s\n", string.cstr());
	parseExpression();
}
