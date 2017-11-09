
#include "IRGen.h"
#include <assert.h>

namespace holodec {
	
	
	IRParser::IRParser (Architecture* arch) : arch (arch) {
		IRExpression expression;
		{expression.returntype = SSA_TYPE_UNKNOWN;
			expression.type = IR_EXPR_UNDEF;
			expressionmap.insert(std::make_pair("undef", expression));
			expression.type = IR_EXPR_SEQUENCE;
			expressionmap.insert(std::make_pair("seq", expression));
			expression.type = IR_EXPR_TRAP;
			expressionmap.insert(std::make_pair("trap", expression));
			expression.type = IR_EXPR_SYSCALL;
			expressionmap.insert(std::make_pair("syscall", expression));
			expression.type = IR_EXPR_CALL;
			expressionmap.insert(std::make_pair("call", expression));
			expression.type = IR_EXPR_JMP;
			expressionmap.insert(std::make_pair("jmp", expression));
			expression.type = IR_EXPR_CJMP;
			expressionmap.insert(std::make_pair("cjmp", expression));
			expression.type = IR_EXPR_RETURN;
			expressionmap.insert(std::make_pair("ret", expression));
			expression.type = IR_EXPR_NOP;
			expressionmap.insert(std::make_pair("nop", expression));
			expression.type = IR_EXPR_IF;
			expressionmap.insert(std::make_pair("if", expression));
			expression.type = IR_EXPR_REP;
			expressionmap.insert(std::make_pair("rep", expression));
			expression.type = IR_EXPR_ASSIGN;
			expressionmap.insert(std::make_pair("assign", expression));
		}
		
		{expression.returntype = SSA_TYPE_UINT;
			{expression.type = IR_EXPR_FLAG;
				expression.size = 1;
				expression.mod.flagType = SSA_FLAG_Z;
				expressionmap.insert(std::make_pair("z", expression));
				expression.mod.flagType = SSA_FLAG_P;
				expressionmap.insert(std::make_pair("p", expression));
				expression.mod.flagType = SSA_FLAG_O;
				expressionmap.insert(std::make_pair("o", expression));
				expression.mod.flagType = SSA_FLAG_S;
				expressionmap.insert(std::make_pair("s", expression));
				expression.mod.flagType = SSA_FLAG_C;
				expressionmap.insert(std::make_pair("c", expression));
				expression.mod.flagType = SSA_FLAG_A;
				expressionmap.insert(std::make_pair("a", expression));
				expression.type = IR_EXPR_APPEND;
				expressionmap.insert(std::make_pair("app", expression));
			}
			{expression.type = IR_EXPR_OP;
				expression.mod.opType = H_OP_ADD;
				expressionmap.insert(std::make_pair("add", expression));
				expression.mod.opType = H_OP_SUB;
				expressionmap.insert(std::make_pair("sub", expression));
				expression.mod.opType = H_OP_MUL;
				expressionmap.insert(std::make_pair("mul", expression));
				expression.mod.opType = H_OP_DIV;
				expressionmap.insert(std::make_pair("div", expression));
				expression.mod.opType = H_OP_MOD;
				expressionmap.insert(std::make_pair("mod", expression));
				expression.mod.opType = H_OP_SHR;
				expressionmap.insert(std::make_pair("shr", expression));
				expression.mod.opType = H_OP_SHL;
				expressionmap.insert(std::make_pair("shl", expression));
				expression.mod.opType = H_OP_SAR;
				expressionmap.insert(std::make_pair("sar", expression));
				expression.mod.opType = H_OP_SAL;
				expressionmap.insert(std::make_pair("sal", expression));
				expression.mod.opType = H_OP_ROR;
				expressionmap.insert(std::make_pair("ror", expression));
				expression.mod.opType = H_OP_ROL;
				expressionmap.insert(std::make_pair("rol", expression));
				expression.mod.opType = H_OP_AND;
				expressionmap.insert(std::make_pair("and", expression));
				expression.mod.opType = H_OP_OR;
				expressionmap.insert(std::make_pair("or", expression));
				expression.mod.opType = H_OP_XOR;
				expressionmap.insert(std::make_pair("xor", expression));
				expression.mod.opType = H_OP_NOT;
				expressionmap.insert(std::make_pair("not", expression));
				expression.mod.opType = H_OP_BAND;
				expressionmap.insert(std::make_pair("band", expression));
				expression.mod.opType = H_OP_BOR;
				expressionmap.insert(std::make_pair("bor", expression));
				expression.mod.opType = H_OP_BXOR;
				expressionmap.insert(std::make_pair("bxor", expression));
				expression.mod.opType = H_OP_BNOT;
				expressionmap.insert(std::make_pair("bnot", expression));
				
				expression.size = 1;
				expression.mod.opType = H_OP_EQ;
				expressionmap.insert(std::make_pair("eq", expression));
				expression.mod.opType = H_OP_NE;
				expressionmap.insert(std::make_pair("ne", expression));
				expression.mod.opType = H_OP_L;
				expressionmap.insert(std::make_pair("l", expression));
				expression.mod.opType = H_OP_LE;
				expressionmap.insert(std::make_pair("le", expression));
				expression.mod.opType = H_OP_G;
				expressionmap.insert(std::make_pair("g", expression));
				expression.mod.opType = H_OP_GE;
				expressionmap.insert(std::make_pair("ge", expression));
			}
			expression.type = IR_EXPR_EXTEND;
			expressionmap.insert(std::make_pair("ext", expression));
			
			expression.type = IR_EXPR_CAST;
			expressionmap.insert(std::make_pair("f2i", expression));
			
			expression.type = IR_EXPR_PUSH;
			expressionmap.insert(std::make_pair("push", expression));
			expression.type = IR_EXPR_POP;
			expressionmap.insert(std::make_pair("pop", expression));
			
			expression.type = IR_EXPR_LOAD;
			expressionmap.insert(std::make_pair("ld", expression));
			expression.type = IR_EXPR_STORE;
			expressionmap.insert(std::make_pair("st", expression));
			
			expression.type = IR_EXPR_VALUE;
			expressionmap.insert(std::make_pair("val", expression));
			
			expression.type = IR_EXPR_BSIZE;
			expressionmap.insert(std::make_pair("bsize", expression));
			expression.type = IR_EXPR_SIZE;
			expressionmap.insert(std::make_pair("size", expression));
			
		}
		{expression.returntype = SSA_TYPE_INT;
			{expression.type = IR_EXPR_OP;
				expression.mod.opType = H_OP_ADD;
				expressionmap.insert(std::make_pair("sadd", expression));
				expression.mod.opType = H_OP_SUB;
				expressionmap.insert(std::make_pair("ssub", expression));
				expression.mod.opType = H_OP_MUL;
				expressionmap.insert(std::make_pair("smul", expression));
				expression.mod.opType = H_OP_DIV;
				expressionmap.insert(std::make_pair("sdiv", expression));
				expression.mod.opType = H_OP_MOD;
				expressionmap.insert(std::make_pair("smod", expression));
			}
			expression.type = IR_EXPR_EXTEND;
			expressionmap.insert(std::make_pair("sext", expression));
			
			expression.type = IR_EXPR_CAST;
			expressionmap.insert(std::make_pair("f2s", expression));
			
			expression.type = IR_EXPR_PUSH;
			expressionmap.insert(std::make_pair("spush", expression));
			
			expression.type = IR_EXPR_POP;
			expressionmap.insert(std::make_pair("spop", expression));
			
			expression.type = IR_EXPR_LOAD;
			expressionmap.insert(std::make_pair("sld", expression));
			
			expression.type = IR_EXPR_STORE;
			expressionmap.insert(std::make_pair("sst", expression));
			
		}
		{expression.returntype = SSA_TYPE_FLOAT;
			{expression.type = IR_EXPR_OP;
				expression.mod.opType = H_OP_ADD;
				expressionmap.insert(std::make_pair("fadd", expression));
				expression.mod.opType = H_OP_SUB;
				expressionmap.insert(std::make_pair("fsub", expression));
				expression.mod.opType = H_OP_MUL;
				expressionmap.insert(std::make_pair("fmul", expression));
				expression.mod.opType = H_OP_DIV;
				expressionmap.insert(std::make_pair("fdiv", expression));
				expression.mod.opType = H_OP_MOD;
				expressionmap.insert(std::make_pair("fmod", expression));
			}
			expression.type = IR_EXPR_EXTEND;
			expressionmap.insert(std::make_pair("fext", expression));
			
			expression.type = IR_EXPR_CAST;
			expressionmap.insert(std::make_pair("i2f", expression));
			
			expression.type = IR_EXPR_PUSH;
			expressionmap.insert(std::make_pair("fpush", expression));
			
			expression.type = IR_EXPR_POP;
			expressionmap.insert(std::make_pair("fpop", expression));
			
			expression.type = IR_EXPR_LOAD;
			expressionmap.insert(std::make_pair("fld", expression));
			
			expression.type = IR_EXPR_STORE;
			expressionmap.insert(std::make_pair("fst", expression));
			
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
	bool IRParser::parseCharacter (char character) {
		skipWhitespaces();
		if (character == pop()) {
			return true;
		}
		pushback();
		return false;
	}
	IRArgument IRParser::parseIndex (IRArgument arg) {
		size_t current_index = index;
		if (parseCharacter ('[')) {
			const char* x = string.cstr() + index;
			IRArgument offset, size;
			bool hasSize = false;
			if (! (offset = parseIRExpression())) {
				printf ("Cannot parse Offset\n");
				return IRArgument::create();//false;
			}
			x = string.cstr() + index;
			if (parseCharacter (',')) {
				hasSize = true;
				if (! (size = parseIRExpression())) {
					printf ("Cannot parse Size\n");
					return IRArgument::create();
				}
			} else {
				size = IRArgument::createVal ( (uint64_t) 0, arch->bitbase);
			}
			x = string.cstr() + index;
			if (parseCharacter (']')) {
				IRExpression expression;
				expression.type = IR_EXPR_SPLIT;
				expression.subExpressions.push_back (arg);
				expression.subExpressions.push_back (offset);
				expression.subExpressions.push_back (size);
				return IRArgument::createIRId (arch->addIrExpr (expression), expression.size);
			}
			printParseFailure ("']'");
			return IRArgument::create();
		}
		return arg;
	}
	int64_t IRParser::parseNumberIndex () {
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
	bool IRParser::parseStringIndex (IRExpression* expression) {
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
	bool IRParser::parseNumber (int64_t* num) {
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
	int IRParser::parseArguments (IRExpression* expr) {
		size_t current_index = index;
		skipWhitespaces();
		int i = 0;
		if (parseCharacter ('(')) {
			if (parseCharacter (')')) {
				return 0;
			}
			do {
				i++;
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
	IRArgument IRParser::parseIRExpression() {
		size_t current_index = index;

		IRExpression expression;
		expression.type = IR_EXPR_INVALID;
		skipWhitespaces();
		char c;
		if (c = pop()) {
			size_t current_index = index;
			switch (c) {
			case '#': {
				size_t current_index = index;
				char buffer[100];
				if (parseIdentifier (buffer, 100)) {
					HString string (buffer);
					auto it = expressionmap.find(string);
					if(it !=  expressionmap.end()){
						expression = it->second;
					}else{
						if (string == "arg") {
							IRArgument arg = IRArgument::create (IR_ARGTYPE_ARG, {parseNumberIndex(),0});
							return parseIndex (arg);
						} else if (string == "tmp" || string == "t") {
							IRArgument arg = IRArgument::create (IR_ARGTYPE_TMP,  {parseNumberIndex(),0});
							return parseIndex (arg);
						} else if (string == "rec") {
							expression.type = IR_EXPR_REC;
							parseStringIndex (&expression);
							//TODO do the recursion here already
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
						return IRArgument::createReg (reg);
					}

					Stack* stack = arch->getStack (str);
					if (stack) {
						return IRArgument::createStck (stack, parseNumberIndex());
					}

					Memory* memory = arch->getMemory (str);
					if (memory) {
						return IRArgument::createMem (memory);
					}

					printf ("Parsed Custom %s\n", buffer);
					printParseFailure ("Custom");
					assert(false);
					//printf ("Parsed Custom %s\n", buffer);
				} else {
					printf ("No custom token");
				}
				return IRArgument::create();
			}
			case '?':
				expression = expressionmap.find("if")->second;
				break;
			case '+':
				expression = expressionmap.find("add")->second;
				break;
			case '*':
				expression = expressionmap.find("mul")->second;
				break;
			case '=':
				if (parseCharacter ('=')) {
					expression = expressionmap.find("eq")->second;
					break;
				}
				expression = expressionmap.find("assign")->second;
				break;
			case '<':
				if (parseCharacter ('=')) {
					expression = expressionmap.find("le")->second;
				} else if (parseCharacter ('>')) {
					expression = expressionmap.find("ne")->second;
				} else {
					expression = expressionmap.find("l")->second;
				}
				break;
			case '>':
				if (parseCharacter ('=')) {
					expression = expressionmap.find("ge")->second;
				} else {
					expression = expressionmap.find("g")->second;
				}
				break;
			case ' ':
				assert (false);
				break;
			case '-': {
				char c2 = peek();
				if (c2 < '0' || '9' < c2) {
					expression = expressionmap.find("sub")->second;
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
				return IRArgument::createVal ( (uint64_t) num, arch->bitbase);
			}
			}
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
					return IRArgument::createVal ( (uint64_t) (expression.subExpressions[0].size), arch->bitbase);
				break;
			case IR_EXPR_SIZE:
				assert (expression.subExpressions.size() == 1);
				if (expression.subExpressions[0].size)
					return IRArgument::createVal ( (uint64_t) (expression.subExpressions[0].size / arch->wordbase), arch->bitbase);
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
