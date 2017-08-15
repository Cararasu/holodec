#ifndef HIRPARSER_H
#define HIRPARSER_H

#include "HGeneral.h"
#include <limits>
#include "HId.h"
#include <assert.h>


namespace holodec {

	class HArchitecture;
	class HRegister;

	struct HIRRepresentation;

	enum HIRExpressionType {
		HIR_EXPR_INVALID = 0,

		HIR_EXPR_UNDEF,//undef
		HIR_EXPR_OP,//add,sub,...
		HIR_EXPR_NOP,//nop
		HIR_EXPR_ASSIGN,//eq,=
		HIR_EXPR_FLOAT,
		HIR_EXPR_NUMBER,

		HIR_EXPR_SIZE,//size
		HIR_EXPR_BSIZE,//size
		//HIR_EXPR_POPCOUNT
		HIR_EXPR_SEQUENCE,//seq
		HIR_EXPR_LOOP,//rep
		HIR_EXPR_IF,//if,?

		HIR_EXPR_APPEND,//app

		HIR_EXPR_EXTEND,//ext
		HIR_EXPR_SEXTEND,//sext
		HIR_EXPR_FEXTEND,//fext

		HIR_EXPR_TMP,//t
		HIR_EXPR_ARG,//arg
		HIR_EXPR_STCK,//stck
		HIR_EXPR_REG,//reg

		HIR_EXPR_REC,//rec
		HIR_EXPR_CUSTOM,//$...

		HIR_EXPR_JMP,//jmp
		HIR_EXPR_RJMP,//rjmp
		HIR_EXPR_CALL,//call
		HIR_EXPR_RET,//ret
		HIR_EXPR_SYSCALL,//syscall
		HIR_EXPR_TRAP,//trap

		HIR_EXPR_VAL,//val

		HIR_EXPR_CAST2F,//i2f
		HIR_EXPR_CAST2I,//f2i

		HIR_EXPR_PUSH,//push
		HIR_EXPR_POP,//pop

		HIR_EXPR_STORE,//st
		HIR_EXPR_LOAD,//ld

		HIR_EXPR_FLAG,//c,o,a,p,...
	};


	enum HIROpToken {
		HIR_TOKEN_INVALID = 0,

		HIR_TOKEN_FLAG_C,
		HIR_TOKEN_FLAG_A,
		HIR_TOKEN_FLAG_P,
		HIR_TOKEN_FLAG_O,
		HIR_TOKEN_FLAG_Z,
		HIR_TOKEN_FLAG_S,

		//Arithmetic
		HIR_TOKEN_ADD,
		HIR_TOKEN_SADD,
		HIR_TOKEN_FADD,
		HIR_TOKEN_SUB,
		HIR_TOKEN_SSUB,
		HIR_TOKEN_FSUB,
		HIR_TOKEN_MUL,
		HIR_TOKEN_SMUL,
		HIR_TOKEN_FMUL,
		HIR_TOKEN_DIV,
		HIR_TOKEN_SDIV,
		HIR_TOKEN_FDIV,
		HIR_TOKEN_MOD,
		HIR_TOKEN_SMOD,
		HIR_TOKEN_FMOD,
		HIR_TOKEN_NEG,
		HIR_TOKEN_FNEG,
		//Comparison
		HIR_TOKEN_CMP_E,
		HIR_TOKEN_CMP_NE,
		HIR_TOKEN_CMP_L,
		HIR_TOKEN_CMP_LE,
		HIR_TOKEN_CMP_G,
		HIR_TOKEN_CMP_GE,
		HIR_TOKEN_CMP_NOT,
		//
		HIR_TOKEN_AND,
		HIR_TOKEN_OR,
		HIR_TOKEN_XOR,
		//Bit Operators
		HIR_TOKEN_BAND,
		HIR_TOKEN_BOR,
		HIR_TOKEN_BXOR,
		HIR_TOKEN_BNOT,
		//Shifts - Rotates
		HIR_TOKEN_SHR,
		HIR_TOKEN_SHL,
		HIR_TOKEN_SAR,
		HIR_TOKEN_SAL,
		HIR_TOKEN_ROR,
		HIR_TOKEN_ROL,
	};

	struct HIRTokenType {
		HIRExpressionType type = HIR_EXPR_INVALID;
		HIROpToken token = HIR_TOKEN_INVALID;
		size_t minargs = 0;
		size_t maxargs = std::numeric_limits<size_t>::max();

		HIRTokenType (HIRExpressionType type) : type (type) {}
		HIRTokenType (HIRExpressionType type, size_t minargs) : type (type), minargs (minargs) {}
		HIRTokenType (HIRExpressionType type, size_t minargs, size_t maxargs) : type (type), minargs (minargs), maxargs (maxargs) {}

		HIRTokenType (HIRExpressionType type, HIROpToken token) : type (type), token (token) {}
		HIRTokenType (HIRExpressionType type, HIROpToken token, size_t minargs) : type (type), token (token), minargs (minargs) {}
		HIRTokenType (HIRExpressionType type, HIROpToken token, size_t minargs, size_t maxargs) : type (type), token (token), minargs (minargs), maxargs (maxargs) {}
	};
	extern HMap<HString, HIRTokenType> tokenmap;

#define HIR_LOCAL_SUBEXPRESSION_COUNT (10)

	struct HIRExpression {
		HId id = 0;
		HIRExpressionType type = HIR_EXPR_INVALID;
		HIROpToken token = HIR_TOKEN_INVALID;
		uint64_t subexprcount;
		HId subexpressions[HIR_LOCAL_SUBEXPRESSION_COUNT] = {0};
		union {
			int64_t value = 0;
			double fvalue;
			HId reg;
			HId stck;
			struct {
				HId base, offset;
				int64_t disp, scale;
			} mem;
		};
		struct HIRExpressionMod {
			HString name_index;
			size_t var_index = 0;
			HId index = 0, size = 0;
		} mod;

		HIRExpression() = default;
		HIRExpression (const HIRExpression&) = default;

		HIRExpression& operator= (const HIRExpression& expr) = default;

		void print (HArchitecture* arch, size_t indent = 0);

		bool addSubExpression (HId id) {
			assert (subexprcount < HIR_LOCAL_SUBEXPRESSION_COUNT);
			for (int i = 0; i < HIR_LOCAL_SUBEXPRESSION_COUNT; i++) {
				if (!subexpressions[i]) {
					subexpressions[i] = id;
					subexprcount++;
					return true;
				}
			}
			return false;
		}
	};
	bool operator== (HIRExpression::HIRExpressionMod& expr1, HIRExpression::HIRExpressionMod& expr2);

	bool operator== (HIRExpression& expr1, HIRExpression& expr2);

	struct HIRParser {
		size_t index;
		HString string;

		HArchitecture* arch;
		HIRRepresentation* rep;
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
		void consume (size_t count = 1) {
			index += count;
		}
		void pushback (size_t count = 1) {
			index -= count;
		}

		bool parseIndex (HIRExpression* expr);
		int parseArguments (HIRExpression* expr);
		HId parseExpression();

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
		int64_t argcount;
		HString cond;
		HString ir;
		HList<HIRExpression> expressions;

		HId rootExpr;
		HIdGenerator gen_expr;

		HIRRepresentation() : HIRRepresentation (-1, nullptr, nullptr) {}
		HIRRepresentation (HString ir) :  HIRRepresentation (-1, nullptr, ir) {}
		HIRRepresentation (int64_t argcount, HString ir) : HIRRepresentation (argcount, nullptr, ir) {}
		HIRRepresentation (HString cond, HString ir) : HIRRepresentation (-1, cond, ir) {}
		HIRRepresentation (int64_t argcount, HString cond, HString ir) : argcount (argcount), cond (cond), ir (ir) {}

		bool operator!() {
			return !ir;
		}
		operator bool() {
			return ir;
		}
		void print (HArchitecture* arch, int indent = 0) {
			if (ir) {
				printIndent (indent);
				printf ("IL-String: %s\n", ir.cstr());
			} else {
				printIndent (indent);
				printf ("No IL-String----------------\n");
			}
		}
	};
}

#endif // HIRPARSER_H
