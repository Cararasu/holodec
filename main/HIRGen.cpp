
#include "HIRGen.h"
#include <assert.h>

namespace holodec {
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
	HArgument HIRParser::parseIndex (HArgument arg) {
		size_t current_index = index;
		if (parseCharacter ('[')) {
			const char* x = string.cstr() + index;
			HArgument offset, size;
			bool hasSize = false;
			if (! (offset = parseIRExpression())) {
				printf ("Cannot parse Offset\n");
				return HArgument::create();//false;
			}
			x = string.cstr() + index;
			if (parseCharacter (',')) {
				hasSize = true;
				if (! (size = parseIRExpression())) {
					printf ("Cannot parse Size\n");
					return HArgument::create();
				}
			} else {
				size = HArgument::createVal ( (uint64_t) 0, arch->bitbase);
			}
			x = string.cstr() + index;
			if (parseCharacter (']')) {
				HIRExpression expression;
				expression.type = HIR_EXPR_SPLIT;
				expression.subExpressions.push_back (arg);
				expression.subExpressions.push_back (offset);
				expression.subExpressions.push_back (size);
				return HArgument::createId (HIR_ARGTYPE_ID, arch->addIrExpr (expression), expression.size);
			}
			printParseFailure ("']'");
			return HArgument::create();
		}
		return arg;
	}
	int64_t HIRParser::parseNumberIndex () {
		size_t current_index = index;
		if (parseCharacter ('[')) {
			int64_t number;
			if (!parseNumber (&number))
				return 0;
			if (parseCharacter (']')) {
				return number;
			}
			printParseFailure ("']'");
			return 0;
		} else {
			return 0;
		}
	}
	bool HIRParser::parseStringIndex (HIRExpression* expression) {
		size_t current_index = index;
		if (parseCharacter ('[')) {
			char buffer[100];
			if (!parseIdentifier (buffer, 100))
				return false;
			HString s = HString::create (buffer);
			expression->mod.instrId = arch->getInstrDef (s)->id;
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
				HArgument subexpr = parseIRExpression();
				if (expr && subexpr) {
					expr->subExpressions.push_back (subexpr);
				} else {
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
	HArgument HIRParser::parseIRExpression() {
		size_t current_index = index;

		HIRExpression expression;
		expression.type = HIR_EXPR_INVALID;
		skipWhitespaces();
		bool hasArgs = true;
		char c;
		if (c = pop()) {
			size_t current_index = index;
			switch (c) {
			case '#': {
				size_t current_index = index;
				char buffer[100];
				if (parseIdentifier (buffer, 100)) {
					HString string (buffer);
					if (string == "seq") {
						expression.type = HIR_EXPR_SEQUENCE;
						expression.exprtype = HSSA_TYPE_UNKNOWN;
					} else if (string == "arg") {
						HArgument arg = HArgument::createIndex (HIR_ARGTYPE_ARG, parseNumberIndex());
						return parseIndex (arg);
					} else if (string == "tmp" || string == "t") {
						HArgument arg = HArgument::createIndex (HIR_ARGTYPE_TMP, parseNumberIndex());
						return parseIndex (arg);
					} else if (string == "z") {
						expression.type = HIR_EXPR_FLAG;
						expression.mod.flagType = HSSA_FLAG_Z;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = 1;
					} else if (string == "p") {
						expression.type = HIR_EXPR_FLAG;
						expression.mod.flagType = HSSA_FLAG_P;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = 1;
					} else if (string == "o") {
						expression.type = HIR_EXPR_FLAG;
						expression.mod.flagType = HSSA_FLAG_O;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = 1;
					}  else if (string == "s") {
						expression.type = HIR_EXPR_FLAG;
						expression.mod.flagType = HSSA_FLAG_S;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = 1;
					} else if (string == "c") {
						expression.type = HIR_EXPR_FLAG;
						expression.mod.flagType = HSSA_FLAG_C;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = 1;
					} else if (string == "a") {
						expression.type = HIR_EXPR_FLAG;
						expression.mod.flagType = HSSA_FLAG_A;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = 1;
					}  else if (string == "app") {
						expression.type = HIR_EXPR_APPEND;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "undef") {
						expression.type = HIR_EXPR_UNDEF;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "sadd") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_ADD;
						expression.exprtype = HSSA_TYPE_INT;
					} else if (string == "fadd") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_ADD;
						expression.exprtype = HSSA_TYPE_FLOAT;
					} else if (string == "sub") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_SUB;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "ssub") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_SUB;
						expression.exprtype = HSSA_TYPE_INT;
					} else if (string == "fsub") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_SUB;
						expression.exprtype = HSSA_TYPE_FLOAT;
					} else if (string == "mul") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_MUL;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "smul") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_MUL;
						expression.exprtype = HSSA_TYPE_INT;
					} else if (string == "fmul") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_MUL;
						expression.exprtype = HSSA_TYPE_FLOAT;
					} else if (string == "div") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_DIV;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "sdiv") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_DIV;
						expression.exprtype = HSSA_TYPE_INT;
					} else if (string == "fdiv") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_DIV;
						expression.exprtype = HSSA_TYPE_FLOAT;
					} else if (string == "mod") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_MOD;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "smod") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_MOD;
						expression.exprtype = HSSA_TYPE_INT;
					} else if (string == "fmod") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_MOD;
						expression.exprtype = HSSA_TYPE_FLOAT;
					} else if (string == "shr") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_SHR;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "shl") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_SHL;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "sar") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_SAR;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "sal") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_SAL;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "ror") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_ROR;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "rol") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_ROL;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "ext") {
						expression.type = HIR_EXPR_EXTEND;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "sext") {
						expression.type = HIR_EXPR_EXTEND;
						expression.exprtype = HSSA_TYPE_INT;
					}  else if (string == "i2f") {
						expression.type = HIR_EXPR_CAST;
						expression.exprtype = HSSA_TYPE_FLOAT;
					}  else if (string == "f2i") {
						expression.type = HIR_EXPR_CAST;
						expression.exprtype = HSSA_TYPE_INT;
					} else if (string == "push") {
						expression.type = HIR_EXPR_PUSH;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "pop") {
						expression.type = HIR_EXPR_POP;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "ld") {
						expression.type = HIR_EXPR_LOAD;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "st") {
						expression.type = HIR_EXPR_STORE;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "fext") {
						expression.type = HIR_EXPR_EXTEND;
						expression.exprtype = HSSA_TYPE_FLOAT;
					} else if (string == "and") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_AND;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = 1;
					} else if (string == "or") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_OR;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = 1;
					} else if (string == "xor") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_XOR;
						expression.size = 1;
					} else if (string == "not") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_NOT;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = 1;
					} else if (string == "band") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_BAND;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "bor") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_BOR;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "bxor") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_BXOR;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "bnot") {
						expression.type = HIR_EXPR_OP;
						expression.mod.opType = HSSA_OP_BNOT;
						expression.exprtype = HSSA_TYPE_UINT;
					} else if (string == "fext") {
						expression.type = HIR_EXPR_EXTEND;
						expression.exprtype = HSSA_TYPE_FLOAT;
					} else if (string == "trap") {
						expression.type = HIR_EXPR_TRAP;
						expression.exprtype = HSSA_TYPE_UNKNOWN;
					} else if (string == "syscall") {
						expression.type = HIR_EXPR_SYSCALL;
						expression.exprtype = HSSA_TYPE_UNKNOWN;
					} else if (string == "call") {
						expression.type = HIR_EXPR_CALL;
						expression.exprtype = HSSA_TYPE_UNKNOWN;
					} else if (string == "jmp") {
						expression.type = HIR_EXPR_JMP;
						expression.exprtype = HSSA_TYPE_PC;
					} else if (string == "cjmp") {
						expression.type = HIR_EXPR_CJMP;
						expression.exprtype = HSSA_TYPE_PC;
					} else if (string == "ret") {
						expression.type = HIR_EXPR_RETURN;
						expression.exprtype = HSSA_TYPE_UNKNOWN;
					} else if (string == "val") {
						expression.type = HIR_EXPR_VALUE;
						expression.exprtype = HSSA_TYPE_UINT;
						expression.size = arch->bitbase;
					} else if (string == "nop") {
						expression.type = HIR_EXPR_NOP;
						expression.exprtype = HSSA_TYPE_UNKNOWN;
						hasArgs = false;
					} else if (string == "bsize") {
						parseArguments (&expression);
						assert (expression.subExpressions.size() == 1);
						if (expression.subExpressions[0].size)
							return HArgument::createVal ( (uint64_t) (expression.subExpressions[0].size), arch->bitbase);
						else {
							expression.type = HIR_EXPR_BSIZE;
						}
					} else if (string == "size") {
						parseArguments (&expression);
						assert (expression.subExpressions.size() == 1);
						if (expression.subExpressions[0].size)
							return HArgument::createVal ( (uint64_t) (expression.subExpressions[0].size / arch->wordbase), arch->bitbase);
						else {
							expression.type = HIR_EXPR_SIZE;
						}
					} else if (string == "rec") {
						expression.type = HIR_EXPR_REC;
						parseStringIndex (&expression);
						//TODO do the recursion here already
					} else if (string == "rep") {
						expression.type = HIR_EXPR_REP;
						expression.exprtype = HSSA_TYPE_UNKNOWN;
					} else {
						printf ("Invalid Token %s\n", buffer);
						printParseFailure ("Token");
					}
				}
			}
			break;
			case '$': {
				char buffer[100];
				if (parseIdentifier (buffer, 100)) {
					HString str = buffer;
					HRegister* reg = arch->getRegister (str);
					if (reg) {
						return HArgument::createReg (reg);
					}

					HStack* stack = arch->getStack (str);
					if (stack) {
						return HArgument::createStck (stack, parseNumberIndex());
					}

					HMemory* memory = arch->getMemory (str);
					if (memory) {
						return HArgument::createMem (memory);
					}

					printf ("Parsed Custom %s\n", buffer);
					printParseFailure ("Custom");
					assert(false);
					//printf ("Parsed Custom %s\n", buffer);
				} else {
					printf ("No custom token");
				}
				return HArgument::create();
			}
			case '?':
				expression.type = HIR_EXPR_IF;
				break;
			case '+':
				expression.type = HIR_EXPR_OP;
				expression.mod.opType = HSSA_OP_ADD;
				expression.exprtype = HSSA_TYPE_UINT;
				break;
			case '*':
				expression.type = HIR_EXPR_OP;
				expression.mod.opType = HSSA_OP_MUL;
				expression.exprtype = HSSA_TYPE_UINT;
				break;
			case '=':
				if (parseCharacter ('=')) {
					expression.type = HIR_EXPR_OP;
					expression.mod.opType = HSSA_OP_E;
					expression.exprtype = HSSA_TYPE_UINT;
					expression.size = 1;
					break;
				}
				expression.type = HIR_EXPR_ASSIGN;
				expression.exprtype = HSSA_TYPE_UNKNOWN;
				break;
			case '<':
				if (parseCharacter ('=')) {
					expression.type = HIR_EXPR_OP;
					expression.mod.opType = HSSA_OP_LE;
					expression.exprtype = HSSA_TYPE_UINT;
					expression.size = 1;
				} else if (parseCharacter ('>')) {
					expression.type = HIR_EXPR_OP;
					expression.mod.opType = HSSA_OP_NE;
					expression.exprtype = HSSA_TYPE_UINT;
					expression.size = 1;
				} else {
					expression.type = HIR_EXPR_OP;
					expression.mod.opType = HSSA_OP_L;
					expression.exprtype = HSSA_TYPE_UINT;
					expression.size = 1;
				}
				break;
			case '>':
				if (parseCharacter ('=')) {
					expression.type = HIR_EXPR_OP;
					expression.mod.opType = HSSA_OP_GE;
					expression.exprtype = HSSA_TYPE_UINT;
					expression.size = 1;
				} else {
					expression.type = HIR_EXPR_OP;
					expression.mod.opType = HSSA_OP_G;
					expression.exprtype = HSSA_TYPE_UINT;
					expression.size = 1;
				}
				break;
			case ' ':
				assert (false);
				break;
			case '-': {
				char c2 = peek();
				if (c2 < '0' || '9' < c2) {
					expression.type = HIR_EXPR_OP;
					expression.mod.opType = HSSA_OP_SUB;
					expression.exprtype = HSSA_TYPE_UINT;
					//printf ("Parsed Sub\n");
					break;
				}
			}
			default: {
				int64_t num;
				pushback();
				if (!parseNumber (&num)) {
					printParseFailure ("Number");
					return HArgument::create();//HIR_EXPR_INVALID;
				}
				return HArgument::createVal ( (uint64_t) num, arch->bitbase);
			}
			}
			if (hasArgs)
				parseArguments (&expression);
			switch (expression.type) {
			case HIR_EXPR_LOAD:
				assert (expression.subExpressions.size() == 3);
				break;
			case HIR_EXPR_STORE:
				assert (expression.subExpressions.size() == 3);
				break;
			case HIR_EXPR_INVALID:
				printf ("%s\n", string.cstr());
				printf ("%s\n", string.cstr() + index);
				assert (false);
			default:
				break;
			}
			return parseIndex (HArgument::createId (HIR_ARGTYPE_ID, arch->addIrExpr (expression), expression.size));
		}
		printf ("Parsed Invalid Char '%c'", c);

	}


	void HIRParser::parse (HIRRepresentation* rep) {
		this->rep = rep;
		if (rep->condstring) {
			string = rep->condstring;
			index = 0;
			rep->condExpr = parseIRExpression();
		}
		string = rep->irstring;
		index = 0;
		rep->rootExpr = parseIRExpression();
		skipWhitespaces();
		if (peek() != '\0') {
			printf ("Not parsed the whole IR-String %s\n", string.cstr());
			printf ("Not parsed: '%s'\n", string.cstr() + index);
		}
	}
}
