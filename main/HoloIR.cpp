#include "HoloIR.h"
#include "HArchitecture.h"
#include "HFunction.h"
#include <assert.h>

namespace holodec {

	HMap<HString, HIRTokenType> tokenmap = {
		{"c", { HIR_EXPR_FLAG, HIR_TOKEN_FLAG_C, 0, 0}},
		{"a", { HIR_EXPR_FLAG, HIR_TOKEN_FLAG_A, 0, 0}},
		{"p", { HIR_EXPR_FLAG, HIR_TOKEN_FLAG_P, 0, 0}},
		{"o", { HIR_EXPR_FLAG, HIR_TOKEN_FLAG_O, 0, 0}},
		{"z", { HIR_EXPR_FLAG, HIR_TOKEN_FLAG_Z, 0, 0}},
		{"s", { HIR_EXPR_FLAG, HIR_TOKEN_FLAG_S, 0, 0}},

		{"undef", { HIR_EXPR_UNDEF, 1}},

		{"arg", { HIR_EXPR_ARG, 0, 0}},
		{"stck", { HIR_EXPR_STCK, 0, 0}},
		{"t", { HIR_EXPR_TMP, 0, 0}},

		{"pop", { HIR_EXPR_POP}},
		{"push", { HIR_EXPR_PUSH}},

		{"nop", { HIR_EXPR_NOP, 0, 0}},
		{"val", { HIR_EXPR_VAL, 1, 1}},

		{"jmp", { HIR_EXPR_JMP, 1, 1}},
		{"rjmp", { HIR_EXPR_RJMP, 1, 1}},
		{"call", { HIR_EXPR_CALL, 1, 1}},
		{"ret", { HIR_EXPR_RET, 0, 0}},
		{"syscall", { HIR_EXPR_SYSCALL, 0, 1}},
		{"trap", { HIR_EXPR_TRAP, 0, 0}},
		{"call", { HIR_EXPR_CALL, 1, 1}},

		{"assign", { HIR_EXPR_ASSIGN, 2, 2}},
		{"size", { HIR_EXPR_SIZE, 1, 1}},
		{"bsize", { HIR_EXPR_BSIZE, 1, 1}},
		{"seq", { HIR_EXPR_SEQUENCE, 1, 1}},
		//{"popcnt", { HIR_TOKEN_POPCNT, 1, 1}},
		{"rep", { HIR_EXPR_LOOP, 2, 2}},
		{"if", { HIR_EXPR_IF, 2, 3}},
		{"rec", { HIR_EXPR_REC}},
		{"ext", { HIR_EXPR_EXTEND, 2, 2}},
		{"sext", { HIR_EXPR_SEXTEND, 2, 2}},
		{"fext", { HIR_EXPR_FEXTEND, 2, 2}},
		{"app", { HIR_EXPR_APPEND, 1}},

		{"add", { HIR_EXPR_OP, HIR_TOKEN_ADD, 2}},
		{"fadd", { HIR_EXPR_OP, HIR_TOKEN_FADD, 2}},
		{"sub", { HIR_EXPR_OP, HIR_TOKEN_SUB, 2}},
		{"fsub", { HIR_EXPR_OP, HIR_TOKEN_FSUB, 2}},
		{"mul", { HIR_EXPR_OP, HIR_TOKEN_MUL, 2}},
		{"smul", { HIR_EXPR_OP, HIR_TOKEN_SMUL, 2}},
		{"fmul", { HIR_EXPR_OP, HIR_TOKEN_FMUL, 2}},
		{"div", { HIR_EXPR_OP, HIR_TOKEN_DIV, 2, 2}},
		{"sdiv", { HIR_EXPR_OP, HIR_TOKEN_SDIV, 2, 2}},
		{"fdiv", { HIR_EXPR_OP, HIR_TOKEN_FDIV, 2, 2}},
		{"mod", { HIR_EXPR_OP, HIR_TOKEN_MOD, 2, 2}},
		{"smod", { HIR_EXPR_OP, HIR_TOKEN_SMOD, 2, 2}},
		{"fmod", { HIR_EXPR_OP, HIR_TOKEN_FMOD, 2, 2}},
		{"neg", { HIR_EXPR_OP, HIR_TOKEN_NEG, 1, 1}},
		{"fneg", { HIR_EXPR_OP, HIR_TOKEN_FNEG, 1, 1}},

		{"st", { HIR_EXPR_STORE, 2}},
		{"ld", { HIR_EXPR_LOAD, 1, 2}},

		{"eq", { HIR_EXPR_OP, HIR_TOKEN_CMP_E, 2, 2}},
		{"neq", { HIR_EXPR_OP, HIR_TOKEN_CMP_NE, 2, 2}},
		{"l", { HIR_EXPR_OP, HIR_TOKEN_CMP_L, 2, 2}},
		{"le", { HIR_EXPR_OP, HIR_TOKEN_CMP_LE, 2, 2}},
		{"g", { HIR_EXPR_OP, HIR_TOKEN_CMP_G, 2, 2}},
		{"ge", { HIR_EXPR_OP, HIR_TOKEN_CMP_GE, 2, 2}},
		{"not", { HIR_EXPR_OP, HIR_TOKEN_CMP_NOT, 1, 1}},

		{"and", { HIR_EXPR_OP, HIR_TOKEN_AND, 2}},
		{"or", { HIR_EXPR_OP, HIR_TOKEN_OR, 2}},
		{"xor", { HIR_EXPR_OP, HIR_TOKEN_XOR, 2}},

		{"band", { HIR_EXPR_OP, HIR_TOKEN_BAND, 2}},
		{"bor", { HIR_EXPR_OP, HIR_TOKEN_BOR, 2}},
		{"bxor", { HIR_EXPR_OP, HIR_TOKEN_BXOR, 2}},
		{"bnot", { HIR_EXPR_OP, HIR_TOKEN_BNOT, 1, 1}},

		{"shr", { HIR_EXPR_OP, HIR_TOKEN_SHR, 2, 2}},
		{"shl", { HIR_EXPR_OP, HIR_TOKEN_SHL, 2, 2}},
		{"sar", { HIR_EXPR_OP, HIR_TOKEN_SAR, 2, 2}},
		{"sal", { HIR_EXPR_OP, HIR_TOKEN_SAL, 2, 2}},
		{"ror", { HIR_EXPR_OP, HIR_TOKEN_ROR, 2, 2}},
		{"rol", { HIR_EXPR_OP, HIR_TOKEN_ROL, 2, 2}},

		{"i2f", { HIR_EXPR_CAST2F, 1, 2}},
		{"f2i", { HIR_EXPR_CAST2I, 1, 2}},
	};

	void HIRParser::skipWhitespaces() {
		while (pop() == ' ');
		pushback();
	}
	void HIRParser::printParseFailure (const char* str) {
		printf ("%s\n", string.cstr());
		printf ("Invalid Token at '%s' expected %s\n", string.cstr() + index, str);
	}
	bool HIRParser::parseIdentifier (char *buffer, size_t buffersize) {
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
	bool HIRParser::parseCharacter (char character) {
		skipWhitespaces();
		if (character == pop()) {
			return true;
		}
		pushback();
		return false;
	}
	bool HIRParser::parseIndex (HIRExpression* expr) {
		size_t current_index = index;
		if (parseCharacter ('[')) {
			const char* x = string.cstr() + index;
			if (! (expr->mod.index = parseExpression()))
				return false;
			x = string.cstr() + index;
			if (parseCharacter (',')) {
				if (! (expr->mod.size = parseExpression()))
					return false;
			}
			x = string.cstr() + index;
			if (parseCharacter (']')) {
				return true;
			}
			printParseFailure ("']'");
			return false;
		}
		return true;
	}
	bool HIRParser::parseNumberIndex (HIRExpression* expr) {
		size_t current_index = index;
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
	bool HIRParser::parseStringIndex (HIRExpression* expr) {
		size_t current_index = index;
		if (parseCharacter ('[')) {
			char buffer[100];
			if (!parseIdentifier (buffer, 100))
				return false;
			HString s = HString::create (buffer);
			expr->mod.name_index = s;
			if (parseCharacter (']')) {
				return true;
			}
			printParseFailure ("']'");
			return false;
		} else {
			return true;
		}
	}
	bool HIRParser::parseNumber (int64_t* num) {
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
	int HIRParser::parseArguments (HIRExpression* expr) {
		size_t current_index = index;
		skipWhitespaces();
		int i = 0;
		if (parseCharacter ('(')) {
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
			} while (parseCharacter (','));
			if (!parseCharacter (')')) {
				printParseFailure ("',', ')'");
				return -1;
			}
		}
		return i;
	}
	HIRTokenType HIRParser::parseBuiltin() {
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
		printParseFailure ("Token");
		return HIR_EXPR_INVALID;
	}
	HIRTokenType HIRParser::parseToken() {
		skipWhitespaces();
		char c;
		if (c = pop()) {
			size_t current_index = index;
			switch (c) {
			case '#':
				return parseBuiltin();
			case '$':
				return HIR_EXPR_CUSTOM;
			case '?':
				//printf ("Parsed If\n");
				return {HIR_EXPR_IF, 1, 3};
			case '+':
				//printf ("Parsed Add\n");
				return {HIR_EXPR_OP, HIR_TOKEN_ADD, 2};
			case '*':
				//printf ("Parsed Mul\n");
				return {HIR_EXPR_OP, HIR_TOKEN_MUL, 2};
			case '=':
				if (parseCharacter ('=')) {
					//printf ("Parsed Eq\n");
					return {HIR_EXPR_OP, HIR_TOKEN_CMP_E, 2, 2};
				}
				//printf ("Parsed Assign\n");
				return {HIR_EXPR_ASSIGN, 2, 2};
				break;
			case '<':
				if (parseCharacter ('=')) {
					//printf ("Parsed LE\n");
					return {HIR_EXPR_OP, HIR_TOKEN_CMP_LE, 2, 2};
				} else if (parseCharacter ('>')) {
					//printf ("Parsed NE\n");
					return {HIR_EXPR_OP, HIR_TOKEN_CMP_NE, 2, 2};
				}
				//printf ("Parsed L\n");
				return {HIR_EXPR_OP, HIR_TOKEN_CMP_L, 2, 2};
			case '>':
				if (parseCharacter ('=')) {
					//printf ("Parsed GE\n");
					return {HIR_EXPR_OP, HIR_TOKEN_CMP_GE, 2, 2};
				}
				//printf ("Parsed G\n");
				return {HIR_EXPR_OP, HIR_TOKEN_CMP_G, 2, 2};
			case ' ':
				break;
			case '-': {
				char c2 = peek();
				if (c2 < '0' || '9' < c2) {
					//printf ("Parsed Sub\n");
					return {HIR_EXPR_OP, HIR_TOKEN_SUB, 2};
				}
			}
			default: {
				int64_t num;
				pushback();
				if (!parseNumber (&num)) {
					printParseFailure ("Number");
					return HIR_EXPR_INVALID;
				}
				//printf ("Parsed Number %d\n", num);
				return {HIR_EXPR_NUMBER, 0, 0};
			}
			}
		}
		printf ("Parsed Invalid Char '%c'", c);
		return HIR_EXPR_INVALID;
	}
	HId HIRParser::parseExpression() {
		HIRExpression expression = HIRExpression();
		size_t current_index = index;
		HIRTokenType tokentype = parseToken();

		expression.type = tokentype.type;
		switch (tokentype.type) {
		case HIR_EXPR_OP:
		case HIR_EXPR_FLAG:
			expression.token = tokentype.token;
			break;
		case HIR_EXPR_REC:
			if (!parseStringIndex (&expression)) {
				return 0;
			}
			break;
		case HIR_EXPR_INVALID:
			assert (false);

			break;
		case HIR_EXPR_CUSTOM: {
			char buffer[100];
			if (parseIdentifier (buffer, 100)) {
				HRegister* reg = arch->getRegister (buffer);
				if (reg->id) {
					expression.type = HIR_EXPR_REG;
					expression.regacces = reg->id;
					expression.mod.size = reg->size;
				} else {
					printf ("Parsed Custom %s\n", buffer);
				}
				//printf ("Parsed Custom %s\n", buffer);
			} else {
				printf ("No custom token");
			}
		}
		break;
		case HIR_EXPR_ARG:
		case HIR_EXPR_STCK:
		case HIR_EXPR_TMP:
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
		return arch->addIrExpr (expression);
	}


	void HIRParser::parse (HIRRepresentation* rep) {
		string = rep->string;
		index = 0;
		this->rep = rep;
		rep->rootExpr = parseExpression();

		skipWhitespaces();
		if (peek() != '\0') {
			printf ("Not parsed the whole IR-String %s\n", string.cstr());
			printf ("Not parsed: '%s'\n", string.cstr() + index);
		}
	}

	void HIRExpression::print (HArchitecture* arch, size_t indent) {
		printIndent (indent);
		printf ("%lld = ", id);

		for (auto& entry : tokenmap) {
			if (entry.second.type == type && entry.second.token == token) {
				printf ("#%s", entry.first.cstr());
				break;
			}
		}
		switch (type) {
		case HIR_EXPR_NUMBER:
			printf ("0x%x", value);
			break;
		case HIR_EXPR_FLOAT:
			printf ("%d", fvalue);
			break;
		case HIR_EXPR_REG:
			if (regacces)
				printf ("$%s", arch->getRegister (regacces)->name.cstr());
			else
				printf ("RegFail");
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
		printf ("\n");
	}

	bool operator== (HIRExpression::HIRExpressionMod& expr1, HIRExpression::HIRExpressionMod& expr2) {
		return expr1.name_index == expr2.name_index &&
		       expr1.var_index == expr2.var_index &&
		       expr1.index == expr2.index &&
		       expr1.size == expr2.size;
	}

	bool operator== (HIRExpression& expr1, HIRExpression& expr2) {
		for (int i = 0; i < HIR_LOCAL_SUBEXPRESSION_COUNT; i++) {
			if (expr1.subexpressions[i] != expr2.subexpressions[i])
				return false;
		}
		return expr1.type == expr2.type &&
		       expr1.token == expr2.token &&
		       expr1.value == expr2.value &&
		       expr1.regacces == expr2.regacces &&
		       expr1.mod == expr2.mod;
	}
}
