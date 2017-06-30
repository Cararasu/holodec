#include "HoloIR.h"

holodec::HMap<holodec::HString, holodec::holoir::HIRToken> holodec::holoir::HIRParser::tokenmap {
	{"c", holodec::holoir::H_IR_TOKEN_FLAG_C},
	{"a", holodec::holoir::H_IR_TOKEN_FLAG_A},
	{"p", holodec::holoir::H_IR_TOKEN_FLAG_P},
	{"o", holodec::holoir::H_IR_TOKEN_FLAG_O},
	{"z", holodec::holoir::H_IR_TOKEN_FLAG_Z},
	{"s", holodec::holoir::H_IR_TOKEN_FLAG_S},

	{"arg", holodec::holoir::H_IR_TOKEN_OP_ARG},
	{"stck", holodec::holoir::H_IR_TOKEN_OP_STCK},
	{"t", holodec::holoir::H_IR_TOKEN_OP_TMP},

	{"jmp", holodec::holoir::H_IR_TOKEN_OP_JMP},
	{"call", holodec::holoir::H_IR_TOKEN_OP_CALL},
	{"ret", holodec::holoir::H_IR_TOKEN_OP_RET},
	{"syscall", holodec::holoir::H_IR_TOKEN_OP_SYSCALL},
	{"trap", holodec::holoir::H_IR_TOKEN_OP_TRAP},
	{"call", holodec::holoir::H_IR_TOKEN_OP_CALL},

	{"assign", holodec::holoir::H_IR_TOKEN_OP_ASSIGN},
	{"size", holodec::holoir::H_IR_TOKEN_OP_SIZE},
	{"popcnt", holodec::holoir::H_IR_TOKEN_OP_POPCNT},
	{"loop", holodec::holoir::H_IR_TOKEN_OP_LOOP},
	{"if", holodec::holoir::H_IR_TOKEN_OP_IF},
	{"rec", holodec::holoir::H_IR_TOKEN_OP_REC},
	{"extend", holodec::holoir::H_IR_TOKEN_OP_EXTEND},
	{"sextend", holodec::holoir::H_IR_TOKEN_OP_SEXTEND},

	{"add", holodec::holoir::H_IR_TOKEN_OP_ADD},
	{"fadd", holodec::holoir::H_IR_TOKEN_OP_FADD},
	{"sub", holodec::holoir::H_IR_TOKEN_OP_SUB},
	{"fsub", holodec::holoir::H_IR_TOKEN_OP_FSUB},
	{"mul", holodec::holoir::H_IR_TOKEN_OP_MUL},
	{"smul", holodec::holoir::H_IR_TOKEN_OP_SMUL},
	{"fmul", holodec::holoir::H_IR_TOKEN_OP_FMUL},
	{"div", holodec::holoir::H_IR_TOKEN_OP_DIV},
	{"sdiv", holodec::holoir::H_IR_TOKEN_OP_SDIV},
	{"fdiv", holodec::holoir::H_IR_TOKEN_OP_FDIV},

	{"st", holodec::holoir::H_IR_TOKEN_OP_STORE},
	{"ld", holodec::holoir::H_IR_TOKEN_OP_LOAD},

	{"eq", holodec::holoir::H_IR_TOKEN_CMP_E},
	{"neq", holodec::holoir::H_IR_TOKEN_CMP_NE},
	{"l", holodec::holoir::H_IR_TOKEN_CMP_L},
	{"le", holodec::holoir::H_IR_TOKEN_CMP_LE},
	{"g", holodec::holoir::H_IR_TOKEN_CMP_G},
	{"ge", holodec::holoir::H_IR_TOKEN_CMP_GE},
	{"not", holodec::holoir::H_IR_TOKEN_CMP_NOT},

	{"and", holodec::holoir::H_IR_TOKEN_BINOP_AND},
	{"or", holodec::holoir::H_IR_TOKEN_BINOP_OR},
	{"xor", holodec::holoir::H_IR_TOKEN_BINOP_XOR},
	{"not", holodec::holoir::H_IR_TOKEN_BINOP_NOT},

	{"shr", holodec::holoir::H_IR_TOKEN_BINOP_SHR},
	{"shl", holodec::holoir::H_IR_TOKEN_BINOP_SHL},
	{"sar", holodec::holoir::H_IR_TOKEN_BINOP_SAR},
	{"sal", holodec::holoir::H_IR_TOKEN_BINOP_SAL},
	{"ror", holodec::holoir::H_IR_TOKEN_BINOP_ROR},
	{"rol", holodec::holoir::H_IR_TOKEN_BINOP_ROL},

	{"i2f", holodec::holoir::H_IR_TOKEN_CAST_I2F},
	{"f2i", holodec::holoir::H_IR_TOKEN_CAST_F2I},
};

bool holodec::holoir::HIRParser::parseIdentifier (char *buffer, size_t buffersize) {
	for (size_t i = 0; i < buffersize; i++) {
		char c = peek();
		if ('a' <= c && c <= 'z')
			buffer[i] = c;
		else {
			buffer[i] = '\0';
			return true;
		}
		consume();
	}
	return false;
}

holodec::holoir::HIRToken holodec::holoir::HIRParser::parseBuiltin() {
	char buffer[100];
	if (parseIdentifier (buffer, 100)) {
		HString string (buffer);
		printf ("Parse Identifier: %s\n", buffer);
		printf ("Parse Identifier: %d\n", tokenmap.size());
		auto entry = tokenmap.find (string);
		if (entry != tokenmap.end()) {
			printf ("Parse Identifier: %s\n", buffer);
			printf ("Parse Identifier: %s\n", (*entry).first.cstr());
			return (*entry).second;
		}
	}
	return holodec::holoir::H_IR_TOKEN_INVALID;
}
holodec::holoir::HIRToken holodec::holoir::HIRParser::parseToken() {
	while (char c = pop()) {
		char c2 = peek();
		switch (c) {
		case '#':
			printf ("Parse Builtin\n");
			return parseBuiltin();
		case '$':
			printf ("Custom\n");
			return H_IR_TOKEN_CUSTOM;
		case '?':
			printf ("If\n");
			return H_IR_TOKEN_OP_IF;
		case '+':
			printf ("Add\n");
			return H_IR_TOKEN_OP_ADD;
		case '-':
			printf ("Sub\n");
			return H_IR_TOKEN_OP_SUB;
		case '*':
			printf ("Mul\n");
			return H_IR_TOKEN_OP_MUL;
		case '=':
			if (c2 == '=') {
				printf ("Eq\n");
				consume();
				return H_IR_TOKEN_CMP_E;
			}
			printf ("Assign\n");
			return H_IR_TOKEN_OP_ASSIGN;
			break;
		case '<':
			if (c2 == '=') {
				printf ("LE\n");
				consume();
				return H_IR_TOKEN_CMP_LE;
			} else if (c2 == '>') {
				printf ("NE\n");
				consume();
				return H_IR_TOKEN_CMP_NE;
			}
			printf ("L\n");
			return H_IR_TOKEN_CMP_L;
		case '>':
			if (c2 == '=') {
				printf ("GE\n");
				consume();
				return H_IR_TOKEN_CMP_GE;
			}
			printf ("G\n");
			return H_IR_TOKEN_CMP_G;
		case ' ':
			break;
		default:
			printf ("Unexpected Token %c\n", c);
			return H_IR_TOKEN_INVALID;
		}
	}
	return H_IR_TOKEN_INVALID;
}
bool holodec::holoir::HIRParser::parseExpression() {
	HIRToken token = parseToken();
	printf ("%d\n", token);
}


void holodec::holoir::HIRParser::parse (holodec::holoir::HIRRepresentation* rep) {
	string = rep->string;
	index = 0;
	printf ("%s\n", string.cstr());
	parseExpression();
}
