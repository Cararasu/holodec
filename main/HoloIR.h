#ifndef HIRPARSER_H
#define HIRPARSER_H

#include "HGeneral.h"
#include <limits>


namespace holodec {

	class HArchitecture;
	class HRegister;

	namespace holoir {

		struct HIRRepresentation;

		enum HIRToken {
			H_IR_TOKEN_INVALID = 0,

			H_IR_TOKEN_FLAG_C,
			H_IR_TOKEN_FLAG_A,
			H_IR_TOKEN_FLAG_P,
			H_IR_TOKEN_FLAG_O,
			H_IR_TOKEN_FLAG_Z,
			H_IR_TOKEN_FLAG_S,

			//Variables
			H_IR_TOKEN_OP_ARG,
			H_IR_TOKEN_OP_STCK,
			H_IR_TOKEN_OP_TMP,

			H_IR_TOKEN_NUMBER,

			//Call - Return
			H_IR_TOKEN_OP_JMP,
			H_IR_TOKEN_OP_CALL,
			H_IR_TOKEN_OP_RET,
			H_IR_TOKEN_OP_SYSCALL,
			H_IR_TOKEN_OP_TRAP,
			//Misc
			H_IR_TOKEN_OP_ASSIGN,
			H_IR_TOKEN_OP_SIZE,
			H_IR_TOKEN_OP_POPCNT,
			H_IR_TOKEN_OP_LOOP,
			H_IR_TOKEN_OP_IF,
			H_IR_TOKEN_OP_REC,
			H_IR_TOKEN_OP_EXTEND,
			H_IR_TOKEN_OP_SEXTEND,
			//Arithmetic
			H_IR_TOKEN_OP_ADD,
			H_IR_TOKEN_OP_FADD,
			H_IR_TOKEN_OP_SUB,
			H_IR_TOKEN_OP_FSUB,
			H_IR_TOKEN_OP_MUL,
			H_IR_TOKEN_OP_SMUL,
			H_IR_TOKEN_OP_FMUL,
			H_IR_TOKEN_OP_DIV,
			H_IR_TOKEN_OP_SDIV,
			H_IR_TOKEN_OP_FDIV,
			//Memory
			H_IR_TOKEN_OP_STORE,
			H_IR_TOKEN_OP_LOAD,
			//Comparison
			H_IR_TOKEN_CMP_E,
			H_IR_TOKEN_CMP_NE,
			H_IR_TOKEN_CMP_L,
			H_IR_TOKEN_CMP_LE,
			H_IR_TOKEN_CMP_G,
			H_IR_TOKEN_CMP_GE,
			H_IR_TOKEN_CMP_NOT,
			//
			H_IR_TOKEN_OP_AND,
			H_IR_TOKEN_OP_OR,
			H_IR_TOKEN_OP_XOR,
			//Bit Operators
			H_IR_TOKEN_BINOP_AND,
			H_IR_TOKEN_BINOP_OR,
			H_IR_TOKEN_BINOP_XOR,
			H_IR_TOKEN_BINOP_NOT,
			//Shifts - Rotates
			H_IR_TOKEN_BINOP_SHR,
			H_IR_TOKEN_BINOP_SHL,
			H_IR_TOKEN_BINOP_SAR,
			H_IR_TOKEN_BINOP_SAL,
			H_IR_TOKEN_BINOP_ROR,
			H_IR_TOKEN_BINOP_ROL,
			//Casts
			H_IR_TOKEN_CAST_I2F,
			H_IR_TOKEN_CAST_F2I,

			H_IR_TOKEN_CUSTOM,
		};
		
		struct HIRTokenType {
			HIRToken token;
			size_t minargs = 0;
			size_t maxargs = std::numeric_limits<size_t>::max();

			HIRTokenType (HIRToken token) : token (token) {}
			HIRTokenType (HIRToken token, size_t minargs) : token (token), minargs (minargs) {}
			HIRTokenType (HIRToken token, size_t minargs, size_t maxargs) : token (token), minargs (minargs), maxargs (maxargs) {}
		};
		extern HMap<HString, HIRTokenType> tokenmap;

		struct HIRExpression {
			HIRToken token = H_IR_TOKEN_INVALID;
			HList<HIRExpression*> subexpressions = HList<HIRExpression*>();
			int64_t value = 0;
			HRegister* regacces;
			struct {
				HString name_index;
				size_t var_index = 0;
				HIRExpression* index = 0, * size = 0;
			} mod;

			HIRExpression* append = 0;
			HIRExpression* sequence = 0;

			size_t bitsize;

			void free ();
			void print ();
		};

		struct HIRParser {
			size_t index;
			HString string;

			HArchitecture* arch;
			//Arguments
			//Stack
			//Temp

			HIRParser (HArchitecture* arch) : arch (arch) {}

			char peek() {
				return string[index];
			}
			char pop() {
				return string[index++];
			}
			char consume (size_t count = 1) {
				index += count;
			}
			void pushback (size_t count = 1) {
				index -= count;
			}

			bool parseIndex (HIRExpression* expr);
			int parseArguments (HIRExpression* expr);
			HIRExpression* parseExpression();

			bool parseIdentifier (char *buffer, size_t buffersize);
			HIRTokenType parseBuiltin();
			HIRTokenType parseToken();
			bool parseCharacter (char character);
			void skipWhitespaces();
			bool parseStringIndex (HIRExpression* expr);
			bool parseNumberIndex (HIRExpression* expr);
			bool parseNumber (int64_t* num);

			void printParseFailure (const char*);

			void parse (HIRRepresentation* rep);
		};

		struct HIRRepresentation {
			HString string;
			HIRExpression* expression;

			HIRRepresentation() : string (0) {}
			HIRRepresentation (int i) : string (0) {}
			HIRRepresentation (const char* ptr) : string (ptr) {}
			HIRRepresentation (HString string) : string (string) {}
			void parse (HIRParser* parser) {
				parser->parse (this);
			}

			bool operator!() {
				return !string;
			}
			operator bool() {
				return string;
			}

			void print (int indent = 0) {
				if (string) {
					printIndent (indent);
					printf ("IL-String: %s\n", string.cstr());
				} else {

					printIndent (indent);
					printf ("No IL-String----------------\n");
				}
			}
		};

	}
}

#endif // HIRPARSER_H
