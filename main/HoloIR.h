#ifndef HIRPARSER_H
#define HIRPARSER_H

#include "HGeneral.h"
#include <limits>
#include "HId.h"


namespace holodec {

	class HArchitecture;
	class HRegister;

	struct HIRRepresentation;


	enum HIRStatementType {
	    HIR_STAT_ASSIGN,

	    HIR_STAT_REC,

	    HIR_STAT_DO,
	    HIR_STAT_SKIP,
	    HIR_STAT_REP,
	};

	struct HIRStatement{
		HIRStatementType type;
		HId cond;
		HId lhs, rhs;
	};

	enum HIRExpressionType {
	    HIR_EXPR_OP,//add,sub,...
	    HIR_EXPR_VAL,//number,float
	    HIR_EXPR_VAR,//t,arg,reg,stck

	    HIR_EXPR_DO,//val
	    HIR_EXPR_SKIP,//val
	    HIR_EXPR_REP,//val
	};
	enum HIROpType {
	    HIR_OP_,
	};

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

	    HIR_TOKEN_REGISTER,
	    HIR_TOKEN_NUMBER,
	    HIR_TOKEN_FLOAT,

	    HIR_TOKEN_VALUE,
	    HIR_TOKEN_MEM,

	    HIR_TOKEN_POP,
	    HIR_TOKEN_PUSH,

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
	};

	struct HIRTokenType {
		HIRToken token;
		size_t minargs = 0;
		size_t maxargs = std::numeric_limits<size_t>::max();

		HIRTokenType ( HIRToken token ) : token ( token ) {}
		HIRTokenType ( HIRToken token, size_t minargs ) : token ( token ), minargs ( minargs ) {}
		HIRTokenType ( HIRToken token, size_t minargs, size_t maxargs ) : token ( token ), minargs ( minargs ), maxargs ( maxargs ) {}
	};
	extern HMap<HString, HIRTokenType> tokenmap;

#define HIR_LOCAL_SUBEXPRESSION_COUNT (10)

	struct HIRExpression {
		HId id = 0;
		HIRToken token = HIR_TOKEN_INVALID;
		HId subexpressions[HIR_LOCAL_SUBEXPRESSION_COUNT] = {0};
		union {
			int64_t value = 0;
			double fvalue;
			HId regacces;
			struct {
				HId base, index;
				int64_t disp, scale;
			} mem;
		};
		struct HIRExpressionMod {
			HString name_index;
			size_t var_index = 0;
			HId index = 0, size = 0;
		} mod;

		HId append = 0;
		HId sequence = 0;

		HIRExpression() = default;
		HIRExpression ( const HIRExpression& ) = default;

		HIRExpression& operator= ( const HIRExpression& expr ) = default;

		void print ( HArchitecture* arch );

		bool addSubExpression ( HId id ) {
			for ( int i = 0; i < HIR_LOCAL_SUBEXPRESSION_COUNT; i++ ) {
				if ( !subexpressions[i] ) {
					subexpressions[i] = id;
					return true;
				}
			}
			return false;
		}
	};
	bool operator== ( HIRExpression::HIRExpressionMod& expr1, HIRExpression::HIRExpressionMod& expr2 );

	bool operator== ( HIRExpression& expr1, HIRExpression& expr2 );

	struct HIRParser {
		size_t index;
		HString string;

		HArchitecture* arch;
		HIRRepresentation* rep;
		//Arguments
		//Stack
		//Temp

		HIRParser ( HArchitecture* arch ) : arch ( arch ) {}

		char peek() {
			return string[index];
		}
		char pop() {
			return string[index++];
		}
		void consume ( size_t count = 1 ) {
			index += count;
		}
		void pushback ( size_t count = 1 ) {
			index -= count;
		}

		bool parseIndex ( HIRExpression* expr );
		int parseArguments ( HIRExpression* expr );
		HId parseExpression();

		bool parseIdentifier ( char *buffer, size_t buffersize );
		HIRTokenType parseBuiltin();
		HIRTokenType parseToken();
		bool parseCharacter ( char character );
		void skipWhitespaces();
		bool parseStringIndex ( HIRExpression* expr );
		bool parseNumberIndex ( HIRExpression* expr );
		bool parseNumber ( int64_t* num );

		void printParseFailure ( const char* );

		void parse ( HIRRepresentation* rep );
	};

	struct HIRRepresentation {
		HString string;
		HList<HIRExpression> expressions;

		HId rootExpr;
		HIdGenerator gen_expr;

		HIRRepresentation() : string ( 0 ) {}
		HIRRepresentation ( int i ) : string ( 0 ) {}
		HIRRepresentation ( const char* ptr ) : string ( ptr ) {}
		HIRRepresentation ( HString string ) : string ( string ) {}

		bool operator!() {
			return !string;
		}
		operator bool() {
			return string;
		}
		HIRExpression* getExpr ( HId id ) {
			if ( expressions[id - 1].id == id ) {
				return &expressions[id - 1];
			} else if ( expressions[id - 1].id < id ) { //search upwards
				for ( int i = id - 1; i < expressions.size(); i++ ) {
					if ( expressions[i].id == id )
						return &expressions[id - 1];
				}
			} else if ( expressions[id - 1].id > id ) { //search downwards
				for ( int i = id - 1; i >= 0; i-- ) {
					if ( expressions[i].id == id )
						return &expressions[id - 1];
				}
			}
			return nullptr;
		}
		HId addExpr ( HIRExpression expr ) {
			for ( HIRExpression& expression : expressions ) { //Do CSE
				if ( expression == expr )
					return expression.id;
			}
			expr.id = gen_expr.next();
			expressions.push_back ( expr );
			return expr.id;
		}
		void print ( HArchitecture* arch, int indent = 0 ) {
			if ( string ) {
				printIndent ( indent );
				printf ( "IL-String: %s\n", string.cstr() );
			} else {

				printIndent ( indent );
				printf ( "No IL-String----------------\n" );
				for ( HIRExpression&	expr : expressions ) {
					expr.print ( arch );
				}
			}
		}
	};
}

#endif // HIRPARSER_H
