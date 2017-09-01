
#ifndef HSSA_H
#define HSSA_H

#include "HId.h"
#include "HStack.h"
#include "HRegister.h"

#define HSSA_LOCAL_USEID_MAX (4)

namespace holodec {

	class HArchitecture;
	
	enum HSSAExprType {
		HSSA_EXPR_INVALID = 0,
		HSSA_EXPR_INPUT,  // Predefined variables, correspond to input arguments
		HSSA_EXPR_UNDEF,
		HSSA_EXPR_NOP,

		HSSA_EXPR_PHI,
		HSSA_EXPR_ASSIGN,//assign to label = jump to branch, assign to pc = jump to other memory location

		HSSA_EXPR_OP,
		HSSA_EXPR_COND,
		
		// Call - Return
		HSSA_EXPR_CALL,  // a call to a function
		HSSA_EXPR_RETURN,  // a return
		HSSA_EXPR_SYSCALL,  // a syscall
		HSSA_EXPR_TRAP,  // a trap

		HSSA_EXPR_BUILTIN,  // call a builtin(invalidates all previous variables and creates a new def)
		HSSA_EXPR_EXTEND,  // zero extend a value
		HSSA_EXPR_SPLIT,  // access to part of a variable
		HSSA_EXPR_APPEND,  // combine variables
		HSSA_EXPR_CAST,  // cast to other type

		HSSA_EXPR_MEM,  // addr = base, index, scale, disp, ?segment?
		// Memory
		HSSA_EXPR_STORE, //mem = mem, addr, value
		HSSA_EXPR_LOAD, //value = mem, addr

		HSSA_EXPR_FLAG,
	};
	enum HSSAOpType {
		HSSA_OP_INVALID = 0,
		HSSA_OP_ADD,
		HSSA_OP_SUB,
		HSSA_OP_MUL,
		HSSA_OP_DIV,
		HSSA_OP_MOD,

		HSSA_OP_AND,
		HSSA_OP_OR,
		HSSA_OP_XOR,
		HSSA_OP_NOT,

		HSSA_OP_E,
		HSSA_OP_NE,
		HSSA_OP_L,
		HSSA_OP_LE,
		HSSA_OP_G,
		HSSA_OP_GE,

		HSSA_OP_BAND,
		HSSA_OP_BOR,
		HSSA_OP_BXOR,
		HSSA_OP_BNOT,

		HSSA_OP_SHR,
		HSSA_OP_SHL,
		HSSA_OP_SAR,
		HSSA_OP_SAL,
		HSSA_OP_ROR,
		HSSA_OP_ROL,
	};
	enum HSSAType {
		HSSA_TYPE_UNKNOWN = 0,
		HSSA_TYPE_INT,
		HSSA_TYPE_UINT,
		HSSA_TYPE_FLOAT,
		HSSA_TYPE_MEM,
		HSSA_TYPE_PC,
	};
	enum HSSAArgType {
		HSSA_ARGTYPE_INVALID = 0,
		HSSA_ARGTYPE_INT,
		HSSA_ARGTYPE_UINT,
		HSSA_ARGTYPE_FLOAT,
		HSSA_ARGTYPE_SSA,
		HSSA_ARGTYPE_LABEL,
	};
	enum HSSAFlagType {
		HSSA_FLAG_C,
		HSSA_FLAG_A,
		HSSA_FLAG_P,
		HSSA_FLAG_O,
		HSSA_FLAG_Z,
		HSSA_FLAG_S,
	};
	struct HStackId {
		HId id;
		HId index;

		operator bool() {
			return id && index;
		}
	};
	struct HSSAArg { //196 bit
		HSSAArgType type = HSSA_ARGTYPE_INVALID;
		union { //128 bit
			struct { //UInt/Int/Float
				union {
					int64_t sval;
					uint64_t uval;
					double fval;
				};
				uint64_t size;
			};
			HId ssaId;
			HId index;//Tmp/Arg
			HId regId;//Register
			HStackId stackId;//Stack
		};
		HSSAArg() = default;
		bool operator!() {
			return type == HSSA_ARGTYPE_INVALID;
		}
		operator bool() {
			return type != HSSA_ARGTYPE_INVALID;
		}
		bool isConst() {
			return type == HSSA_ARGTYPE_INT || type == HSSA_ARGTYPE_UINT || type == HSSA_ARGTYPE_FLOAT;
		}
		static inline HSSAArg create() {
			return HSSAArg();
		}
		static inline HSSAArg createVal (int64_t val, uint64_t size) {
			HSSAArg arg;
			arg.type = HSSA_ARGTYPE_INT;
			arg.sval = val;
			arg.size = size;
			return arg;
		}
		static inline HSSAArg createVal (uint64_t val, uint64_t size) {
			HSSAArg arg;
			arg.type = HSSA_ARGTYPE_UINT;
			arg.uval = val;
			arg.size = size;
			return arg;
		}
		static inline HSSAArg createVal (double val, uint64_t size) {
			HSSAArg arg;
			arg.type = HSSA_ARGTYPE_FLOAT;
			arg.fval = val;
			arg.size = size;
			return arg;
		}
		static inline HSSAArg createSSA (HId id) {
			HSSAArg arg;
			arg.type = HSSA_ARGTYPE_SSA;
			arg.ssaId = id;
			arg.size = 0;
			return arg;
		}
		void print(HArchitecture* arch, int indent = 0);
	};
	struct HSSAExpression {
		HId id;
		HSSAExprType type;
		uint64_t size;
		HSSAType exprtype;
		struct { //196 bit
			union { //64 bit
				HSSAFlagType flagType;
				HId index;
				HSSAOpType opType;
				HId builtinId;
				HId instrId;
			};
		} mod;
		HLocalBackedLists<HSSAArg, HSSA_LOCAL_USEID_MAX> subExpressions;

		bool operator!() {
			return type == HSSA_EXPR_INVALID;
		}
		operator bool() {
			return type != HSSA_EXPR_INVALID;
		}
		void print(HArchitecture* arch, int indent = 0);
	};
	inline bool operator== (HStackId& lhs, HStackId& rhs) {
		return lhs.id == rhs.id && lhs.index == rhs.index;
	}
	inline bool operator== (HSSAArg& lhs, HSSAArg& rhs) {
		if (lhs.type == rhs.type) {
			switch (lhs.type) {
			case HSSA_ARGTYPE_INT:
				return lhs.sval == rhs.sval && lhs.size == rhs.size;
			case HSSA_ARGTYPE_UINT:
				return lhs.uval == rhs.uval && lhs.size == rhs.size;
			case HSSA_ARGTYPE_FLOAT:
				return lhs.fval == rhs.fval && lhs.size == rhs.size;
			case HSSA_ARGTYPE_SSA:
				return lhs.ssaId == rhs.ssaId;
			}
		}
		return false;
	}
	inline bool operator!= (HSSAArg& lhs, HSSAArg& rhs) {
		return ! (lhs == rhs);
	}
	inline bool operator== (HSSAExpression& lhs, HSSAExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.exprtype == rhs.exprtype) {
			if (lhs.subExpressions.size() == rhs.subExpressions.size()) {
				for (int i = 0; i < lhs.subExpressions.size(); i++) {
					if (lhs.subExpressions[i] != rhs.subExpressions[i])
						return false;
				}
			}
			switch (rhs.type) {
			case HSSA_EXPR_FLAG:
				return lhs.mod.flagType == rhs.mod.flagType;
			case HSSA_EXPR_OP:
				return lhs.mod.opType == rhs.mod.opType;
			case HSSA_EXPR_BUILTIN:
				return lhs.mod.index == rhs.mod.index;
			}
		}
		return false;
	}


	struct HSSARepresentation {
		int64_t argcount;
		HString condstring;
		HString ssastring;
		HList<HSSAExpression> expressions;

		HSSAArg condExpr = HSSAArg::create();
		HSSAArg rootExpr = HSSAArg::create();
		HIdGenerator gen_expr;

		HSSARepresentation() : HSSARepresentation (-1, nullptr, nullptr) {}
		HSSARepresentation (HString ssastring) :  HSSARepresentation (-1, nullptr, ssastring) {}
		HSSARepresentation (int64_t argcount, HString ssastring) : HSSARepresentation (argcount, nullptr, ssastring) {}
		HSSARepresentation (HString condstring, HString ssastring) : HSSARepresentation (-1, condstring, ssastring) {}
		HSSARepresentation (int64_t argcount, HString condstring, HString ssastring) : argcount (argcount), condstring (condstring), ssastring (ssastring) {}

		bool operator!() {
			return !ssastring;
		}
		operator bool() {
			return ssastring;
		}
		void print (HArchitecture* arch, int indent = 0) {
			if (condstring) {
				printIndent (indent);
				printf ("Cond-String: %s\n", condstring.cstr());
			}
			if (ssastring) {
				printIndent (indent);
				printf ("IL-String: %s\n", ssastring.cstr());
			} else {
				printIndent (indent);
				printf ("No IL-String----------------\n");
			}
		}
	};
}

#endif //HSSA_H
