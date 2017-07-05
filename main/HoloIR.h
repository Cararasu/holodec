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
			HIR_TOKEN_INVALID = 0,

			HIR_TOKEN_FLAG_C,
			HIR_TOKEN_FLAG_A,
			HIR_TOKEN_FLAG_P,
			HIR_TOKEN_FLAG_O,
			HIR_TOKEN_FLAG_Z,
			HIR_TOKEN_FLAG_S,

			//Variables
			HIR_TOKEN_OP_ARG,
			HIR_TOKEN_OP_STCK,
			HIR_TOKEN_OP_TMP,

			HIR_TOKEN_NUMBER,
			
			HIR_TOKEN_VALUE,

			//Call - Return
			HIR_TOKEN_OP_JMP,
			HIR_TOKEN_OP_CALL,
			HIR_TOKEN_OP_RET,
			HIR_TOKEN_OP_SYSCALL,
			HIR_TOKEN_OP_TRAP,
			//Misc
			HIR_TOKEN_OP_ASSIGN,
			HIR_TOKEN_OP_SIZE,
			HIR_TOKEN_OP_POPCNT,
			HIR_TOKEN_OP_LOOP,
			HIR_TOKEN_OP_IF,
			HIR_TOKEN_OP_REC,
			HIR_TOKEN_OP_EXTEND,
			HIR_TOKEN_OP_SEXTEND,
			//Arithmetic
			HIR_TOKEN_OP_ADD,
			HIR_TOKEN_OP_SADD,
			HIR_TOKEN_OP_FADD,
			HIR_TOKEN_OP_SUB,
			HIR_TOKEN_OP_SSUB,
			HIR_TOKEN_OP_FSUB,
			HIR_TOKEN_OP_MUL,
			HIR_TOKEN_OP_SMUL,
			HIR_TOKEN_OP_FMUL,
			HIR_TOKEN_OP_DIV,
			HIR_TOKEN_OP_SDIV,
			HIR_TOKEN_OP_FDIV,
			//Memory
			HIR_TOKEN_OP_STORE,
			HIR_TOKEN_OP_LOAD,
			//Comparison
			HIR_TOKEN_CMP_E,
			HIR_TOKEN_CMP_NE,
			HIR_TOKEN_CMP_L,
			HIR_TOKEN_CMP_LE,
			HIR_TOKEN_CMP_G,
			HIR_TOKEN_CMP_GE,
			HIR_TOKEN_CMP_NOT,
			//
			HIR_TOKEN_OP_AND,
			HIR_TOKEN_OP_OR,
			HIR_TOKEN_OP_XOR,
			//Bit Operators
			HIR_TOKEN_BINOP_AND,
			HIR_TOKEN_BINOP_OR,
			HIR_TOKEN_BINOP_XOR,
			HIR_TOKEN_BINOP_NOT,
			//Shifts - Rotates
			HIR_TOKEN_BINOP_SHR,
			HIR_TOKEN_BINOP_SHL,
			HIR_TOKEN_BINOP_SAR,
			HIR_TOKEN_BINOP_SAL,
			HIR_TOKEN_BINOP_ROR,
			HIR_TOKEN_BINOP_ROL,
			//Casts
			HIR_TOKEN_CAST_I2F,
			HIR_TOKEN_CAST_F2I,

			HIR_TOKEN_CUSTOM,
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
			HIRToken token = HIR_TOKEN_INVALID;
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
				if(expression){
					printIndent (indent);
					printf ("Parsed Expression: ");
					expression->print();
					printf ("\n");
				}
			}
		};

	}
}

#endif // HIRPARSER_H
