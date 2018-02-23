
#include "IRGen.h"
#include <assert.h>

namespace holodec {


	IRParser::IRParser (Architecture* arch) : arch (arch) {
		IRExpression expression;
		{
			expression.exprtype = SSAType::eUnknown;
			expression.type = IR_EXPR_UNDEF;
			expressionmap.insert (std::make_pair ("undef", expression));
			expression.type = IR_EXPR_SEQUENCE;
			expressionmap.insert (std::make_pair ("seq", expression));
			expression.type = IR_EXPR_TRAP;
			expressionmap.insert (std::make_pair ("trap", expression));
			expression.type = IR_EXPR_SYSCALL;
			expressionmap.insert (std::make_pair ("syscall", expression));
			expression.type = IR_EXPR_CALL;
			expressionmap.insert (std::make_pair ("call", expression));
			expression.type = IR_EXPR_JMP;
			expressionmap.insert (std::make_pair ("jmp", expression));
			expression.type = IR_EXPR_CJMP;
			expressionmap.insert (std::make_pair ("cjmp", expression));
			expression.type = IR_EXPR_RETURN;
			expressionmap.insert (std::make_pair ("ret", expression));
			expression.type = IR_EXPR_NOP;
			expressionmap.insert (std::make_pair ("nop", expression));
			expression.type = IR_EXPR_IF;
			expressionmap.insert (std::make_pair ("if", expression));
			expression.type = IR_EXPR_REP;
			expressionmap.insert (std::make_pair ("rep", expression));
			expression.type = IR_EXPR_ASSIGN;
			expressionmap.insert (std::make_pair ("assign", expression));
		}

		{
			expression.exprtype = SSAType::eUInt;
			{
				expression.type = IR_EXPR_FLAG;
				expression.size = 1;
				expression.mod.flagType = SSAFlagType::eO;
				expressionmap.insert(std::make_pair("o", expression));
				expression.mod.flagType = SSAFlagType::eU;
				expressionmap.insert(std::make_pair("u", expression));
				expression.mod.flagType = SSAFlagType::eC;
				expressionmap.insert (std::make_pair ("c", expression));
				expression.type = IR_EXPR_APPEND;
				expression.mod.flagType = SSAFlagType::eUnknown;
				expressionmap.insert (std::make_pair ("app", expression));
			}
			{
				expression.type = IR_EXPR_OP;
				expression.mod.opType = SSAOpType::eAdd;
				expressionmap.insert (std::make_pair ("add", expression));
				expression.mod.opType = SSAOpType::eSub;
				expressionmap.insert (std::make_pair ("sub", expression));
				expression.mod.opType = SSAOpType::eMul;
				expressionmap.insert (std::make_pair ("mul", expression));
				expression.mod.opType = SSAOpType::eDiv;
				expressionmap.insert (std::make_pair ("div", expression));
				expression.mod.opType = SSAOpType::eMod;
				expressionmap.insert (std::make_pair ("mod", expression));
				expression.mod.opType = SSAOpType::eShr;
				expressionmap.insert (std::make_pair ("shr", expression));
				expression.mod.opType = SSAOpType::eShl;
				expressionmap.insert (std::make_pair ("shl", expression));
				expression.mod.opType = SSAOpType::eSar;
				expressionmap.insert (std::make_pair ("sar", expression));
				expression.mod.opType = SSAOpType::eSal;
				expressionmap.insert (std::make_pair ("sal", expression));
				expression.mod.opType = SSAOpType::eRor;
				expressionmap.insert (std::make_pair ("ror", expression));
				expression.mod.opType = SSAOpType::eRol;
				expressionmap.insert (std::make_pair ("rol", expression));
				expression.mod.opType = SSAOpType::eAnd;
				expressionmap.insert (std::make_pair ("and", expression));
				expression.mod.opType = SSAOpType::eOr;
				expressionmap.insert (std::make_pair ("or", expression));
				expression.mod.opType = SSAOpType::eNot;
				expressionmap.insert (std::make_pair ("not", expression));
				expression.mod.opType = SSAOpType::eBAnd;
				expressionmap.insert (std::make_pair ("band", expression));
				expression.mod.opType = SSAOpType::eBOr;
				expressionmap.insert (std::make_pair ("bor", expression));
				expression.mod.opType = SSAOpType::eBXor;
				expressionmap.insert (std::make_pair ("bxor", expression));
				expression.mod.opType = SSAOpType::eBNot;
				expressionmap.insert (std::make_pair ("bnot", expression));

				expression.size = 1;
				expression.mod.opType = SSAOpType::eEq;
				expressionmap.insert (std::make_pair ("eq", expression));
				expression.mod.opType = SSAOpType::eNe;
				expressionmap.insert (std::make_pair ("ne", expression));
				expression.mod.opType = SSAOpType::eLower;
				expressionmap.insert (std::make_pair ("l", expression));
				expression.mod.opType = SSAOpType::eLe;
				expressionmap.insert (std::make_pair ("le", expression));
				expression.mod.opType = SSAOpType::eGreater;
				expressionmap.insert (std::make_pair ("g", expression));
				expression.mod.opType = SSAOpType::eGe;
				expressionmap.insert (std::make_pair ("ge", expression));
			}
			expression.type = IR_EXPR_EXTEND;
			expressionmap.insert (std::make_pair ("ext", expression));

			expression.type = IR_EXPR_CAST;
			expressionmap.insert (std::make_pair ("f2i", expression));

			expression.type = IR_EXPR_PUSH;
			expressionmap.insert (std::make_pair ("push", expression));
			expression.type = IR_EXPR_POP;
			expressionmap.insert (std::make_pair ("pop", expression));

			expression.type = IR_EXPR_LOAD;
			expressionmap.insert (std::make_pair ("ld", expression));
			expression.type = IR_EXPR_STORE;
			expressionmap.insert (std::make_pair ("st", expression));

			expression.type = IR_EXPR_VALUE;
			expressionmap.insert (std::make_pair ("val", expression));

			expression.type = IR_EXPR_BSIZE;
			expressionmap.insert (std::make_pair ("bsize", expression));
			expression.type = IR_EXPR_SIZE;
			expressionmap.insert (std::make_pair ("size", expression));

		}
		{
			expression.exprtype = SSAType::eInt;
			expression.type = IR_EXPR_CAST;
			expressionmap.insert (std::make_pair ("f2s", expression));

		}
		{
			expression.exprtype = SSAType::eFloat;

			expression.type = IR_EXPR_CAST;
			expressionmap.insert (std::make_pair ("i2f", expression));

		}
	}

	void IRParser::skipWhitespaces() {
		while (pop() == ' ');
		pushback();
	}
	void IRParser::printParseFailure (const char* str) {
		printf ("%s\n", string.cstr());
		printf ("Invalid Token at '%s' expected %s\n", string.cstr() + index, str);
	}
	bool IRParser::parseIdentifier (char *buffer, size_t buffersize) {
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
	bool IRParser::parseCharacter (char character) {
		skipWhitespaces();
		if (character == pop()) {
			return true;
		}
		pushback();
		return false;
	}
	IRArgument IRParser::parseIndex (IRArgument arg) {
		if (parseCharacter ('[')) {
			IRArgument offset, size;
			if (! (offset = parseIRExpression())) {
				printf ("Cannot parse Offset\n");
				return IRArgument::create();//false;
			}
			if (parseCharacter (',')) {
				if (! (size = parseIRExpression())) {
					printf ("Cannot parse Size\n");
					return IRArgument::create();
				}
			} else {
				size = IRArgument::createUVal( (uint64_t) 1, arch->bitbase);
			}
			if (parseCharacter (']')) {
				IRExpression expression;
				expression.type = IR_EXPR_SPLIT;
				expression.subExpressions.push_back (arg);
				expression.subExpressions.push_back (offset);
				expression.subExpressions.push_back (size);
				expression.size = size.uval;
				IRArgument arg = IRArgument::createIRId (arch->addIrExpr (expression), expression.size);
				return arg;
			}
			printParseFailure ("']'");
			return IRArgument::create();
		}
		return arg;
	}
	int64_t IRParser::parseNumberIndex () {
		size_t x = index;
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
	bool IRParser::parseStringIndex (IRExpression* expression) {
		if (parseCharacter ('[')) {
			char buffer[100];
			if (!parseIdentifier (buffer, 100))
				return false;
			HString s = buffer;
			InstrDefinition* instrDef = arch->getInstrDef(s);
			assert(instrDef);
			expression->mod.instrId = instrDef->id;
			if (parseCharacter (']')) {
				return true;
			}
			printParseFailure ("']'");
			return false;
		} else {
			return true;
		}
	}
	bool IRParser::parseNumber (int64_t* num) {
		size_t x = index;
		skipWhitespaces();
		int pos;
		int parsed = sscanf_s(string.cstr() + index, "%" SCNd64 "%n", num, &pos);
		if (parsed != 1) {
			return false;
		} else {
			consume (static_cast<uint64_t>(pos));
		}
		return true;
	}
	int IRParser::parseArguments (IRExpression* expr) {
		skipWhitespaces();
		int i = 0;
		if (parseCharacter ('(')) {
			if (parseCharacter (')')) {
				return 0;
			}
			do {
				i++;
				size_t x = index;
				IRArgument subexpr = parseIRExpression();
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
	bool IRParser::parseProcFlags(IRExpression* expr) {
		size_t x = index;
		if (parseCharacter('[')) {
			while (true) {
				switch (peek()) {
				case 'u':
					expr->exprtype = SSAType::eUInt;
					consume(1);
					continue;
				case 's':
					expr->exprtype = SSAType::eInt;
					consume(1);
					continue;
				case 'f':
					expr->exprtype = SSAType::eFloat;
					consume(1);
					continue;
				case '0':case '1':case '2':case '3':case '4':
				case '5':case '6':case '7':case '8':case '9':
					int64_t size;
					if (parseNumber(&size))
						expr->size = size;
					continue;
				default:
					break;
				}
				break;
			}
			if (!parseCharacter(']')) {
				printParseFailure("']'");
				return false;
			}
			return true;
		}
		return true;
	}
	bool IRParser::parseArgFlags(IRArgument* arg) {
		size_t x = index;
		if (parseCharacter('[')) {
			while (true) {
				switch (peek()) {
				case '0':case '1':case '2':case '3':case '4':
				case '5':case '6':case '7':case '8':case '9':
					int64_t size;
					if (parseNumber(&size))
						arg->size = size;
					continue;
				default:
					break;
				}
				break;
			}
			if (!parseCharacter(']')) {
				printParseFailure("']'");
				return false;
			}
			return true;
		}
		return true;
	}

	IRArgument IRParser::parseIRExpression() {

		IRExpression expression;
		expression.type = IR_EXPR_INVALID;
		skipWhitespaces();
		char c;
		if ( (c = pop())) {
			switch (c) {
			case '#': {
				char buffer[100];
				if (parseIdentifier (buffer, 100)) {
					HString string (buffer);
					auto it = expressionmap.find (string);
					if (it !=  expressionmap.end()) {
						expression = it->second;
					} else {
						if (string == "arg") {
							IRArgument arg = IRArgument::create (IR_ARGTYPE_ARG, { (HId) parseNumberIndex(), 0});
							return parseIndex (arg);
						} else if (string == "tmp" || string == "t") {
							IRArgument arg = IRArgument::create (IR_ARGTYPE_TMP,  { (HId) parseNumberIndex(), 0});
							return parseIndex (arg);
						} else if (string == "rec") {
							expression.type = IR_EXPR_REC;
							parseStringIndex (&expression);
						} else if (string == "ip") {
							return IRArgument::create (IR_ARGTYPE_IP);
						} else {
							printf ("Invalid Token %s\n", buffer);
							printParseFailure ("Token");
						}
					}
				}
			}
			break;
			case '$': {
				char buffer[100];
				if (parseIdentifier (buffer, 100)) {
					HString str = buffer;
					Register* reg = arch->getRegister (str);
					if (reg->id) {
						IRArgument arg = IRArgument::createReg(reg);
						parseArgFlags(&arg);
						return arg;
					}

					Stack* stack = arch->getStack (str);
					if (stack->id) {
						return IRArgument::createStck (stack, parseNumberIndex());
					}

					Memory* memory = arch->getMemory (str);
					if (memory->id) {
						return IRArgument::createMem (memory);
					}

					Builtin* builtin = arch->getBuiltin(str);
					if (builtin) {
						expression.type = IRExprType::IR_EXPR_BUILTIN;
						expression.mod.builtinId = builtin->id;
						break;
					}

					printParseFailure ("Register/Stack/Memory/Builtin");
					assert (false);
					//printf ("Parsed Custom %s\n", buffer);
				} else {
					printf ("No custom token");
				}
				return IRArgument::create();
			}
			case '?':
				expression = expressionmap.find ("if")->second;
				break;
			case '+':
				expression = expressionmap.find ("add")->second;
				break;
			case '*':
				expression = expressionmap.find ("mul")->second;
				break;
			case '=':
				if (parseCharacter ('=')) {
					expression = expressionmap.find ("eq")->second;
					break;
				}
				expression = expressionmap.find ("assign")->second;
				break;
			case '<':
				if (parseCharacter ('=')) {
					expression = expressionmap.find ("le")->second;
				} else if (parseCharacter ('>')) {
					expression = expressionmap.find ("ne")->second;
				} else {
					expression = expressionmap.find ("l")->second;
				}
				break;
			case '>':
				if (parseCharacter ('=')) {
					expression = expressionmap.find ("ge")->second;
				} else {
					expression = expressionmap.find ("g")->second;
				}
				break;
			case ' ':
				assert (false);
				break;
			case '-': {
				char c2 = peek();
				if (c2 < '0' || '9' < c2) {
					expression = expressionmap.find ("sub")->second;
					break;
				}
			}
			default: {
				int64_t num;
				pushback();
				if (!parseNumber (&num)) {
					printParseFailure ("Number");
					return IRArgument::create();//IR_EXPR_INVALID;
				}
				IRArgument arg = IRArgument::createUVal((uint64_t)num, 0);
				parseArgFlags(&arg);
				return arg;
			}
			}
			size_t x = index;

			parseProcFlags(&expression);
			parseArguments (&expression);
			switch (expression.type) {
			case IR_EXPR_LOAD:
				assert (expression.subExpressions.size() == 3);
				break;
			case IR_EXPR_STORE:
				assert (expression.subExpressions.size() == 3);
				break;
			case IR_EXPR_BSIZE:
				assert (expression.subExpressions.size() == 1);
				if (expression.subExpressions[0].size)
					return IRArgument::createUVal( (uint64_t) (expression.subExpressions[0].size), arch->bitbase);
				break;
			case IR_EXPR_SIZE:
				assert (expression.subExpressions.size() == 1);
				if (expression.subExpressions[0].size)
					return IRArgument::createUVal( (uint64_t) (expression.subExpressions[0].size / arch->wordbase), arch->bitbase);
				break;
			case IR_EXPR_INVALID:
				printf ("%s\n", string.cstr());
				printf ("%s\n", string.cstr() + index);
				assert (false);
			default:
				break;
			}
			return parseIndex (IRArgument::createIRId (arch->addIrExpr (expression), expression.size));
		}
		printf ("Parsed Invalid Char '%c'", c);
		return IRArgument::create();
	}


	void IRParser::parse (IRRepresentation* rep) {
		size_t x = index;
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
