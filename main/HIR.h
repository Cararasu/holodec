
#ifndef HIR_H
#define HIR_H

#include "HId.h"
#include "HStack.h"
#include "HRegister.h"

#define HIR_LOCAL_USEID_MAX (4)

namespace holodec {

	class HArchitecture;
	
	enum HIRExprType {
		HIR_EXPR_INVALID = 0,
		//HIR_EXPR_INPUT,  // Predefined variables, correspond to input arguments
		HIR_EXPR_UNDEF,
		HIR_EXPR_NOP,

		HIR_EXPR_ASSIGN,//attaches IR val to a reg/arg/tmp/stack

		HIR_EXPR_IF,
		HIR_EXPR_JMP,//jump depending on value
		HIR_EXPR_OP,
		HIR_EXPR_COND,
		// Call - Return
		HIR_EXPR_CALL,  // a call to a function
		HIR_EXPR_RETURN,  // a return
		HIR_EXPR_SYSCALL,  // a syscall
		HIR_EXPR_TRAP,  // a trap

		HIR_EXPR_BUILTIN,  // call a builtin(invalidates all previous variables and creates a new def)
		HIR_EXPR_EXTEND,  // zero extend a value
		HIR_EXPR_SPLIT,  // access to part of a variable
		HIR_EXPR_APPEND,  // combine variables
		HIR_EXPR_CAST,  // cast to other type

		HIR_EXPR_MEM,  // addr = base, index, scale, disp, ?segment?
		// Memory
		HIR_EXPR_STORE, //mem = mem, addr, value
		HIR_EXPR_LOAD, //value = mem, addr

		//IR only
		HIR_EXPR_PUSH,
		HIR_EXPR_POP,
		
		HIR_EXPR_VALUE,
		HIR_EXPR_REC,
		HIR_EXPR_REP,
		HIR_EXPR_SIZE,
		HIR_EXPR_BSIZE,
		HIR_EXPR_SEQUENCE,//only for ir gets resolved in ir generation

		HIR_EXPR_FLAG,
	};
	enum HIROpType {
		HIR_OP_INVALID = 0,
		HIR_OP_ADD,
		HIR_OP_SUB,
		HIR_OP_MUL,
		HIR_OP_DIV,
		HIR_OP_MOD,

		HIR_OP_AND,
		HIR_OP_OR,
		HIR_OP_XOR,
		HIR_OP_NOT,

		HIR_OP_E,
		HIR_OP_NE,
		HIR_OP_L,
		HIR_OP_LE,
		HIR_OP_G,
		HIR_OP_GE,

		HIR_OP_BAND,
		HIR_OP_BOR,
		HIR_OP_BXOR,
		HIR_OP_BNOT,

		HIR_OP_SHR,
		HIR_OP_SHL,
		HIR_OP_SAR,
		HIR_OP_SAL,
		HIR_OP_ROR,
		HIR_OP_ROL,
	};
	enum HIRType {
		HIR_TYPE_UNKNOWN = 0,
		HIR_TYPE_INT,
		HIR_TYPE_UINT,
		HIR_TYPE_FLOAT,
		HIR_TYPE_MEM,
		HIR_TYPE_PC,
	};
	enum HIRArgType {
		HIR_ARGTYPE_INVALID = 0,
		HIR_ARGTYPE_INT,
		HIR_ARGTYPE_UINT,
		HIR_ARGTYPE_FLOAT,
		HIR_ARGTYPE_IR,
		HIR_ARGTYPE_STACK,
		HIR_ARGTYPE_ARG,
		HIR_ARGTYPE_TMP,
		HIR_ARGTYPE_REG,
		HIR_ARGTYPE_REC,
	};
	enum HIRFlagType {
		HIR_FLAG_C,
		HIR_FLAG_A,
		HIR_FLAG_P,
		HIR_FLAG_O,
		HIR_FLAG_Z,
		HIR_FLAG_S,
	};
	struct HStackId {
		HId id;
		HId index;

		operator bool() {
			return id && index;
		}
	};
	struct HIRArg { //196 bit
		HIRArgType type = HIR_ARGTYPE_INVALID;
		union { //128 bit
			struct { //UInt/Int/Float
				union {
					int64_t sval;
					uint64_t uval;
					double fval;
				};
				uint64_t size;
			};
			HId irId;
			HId index;//Tmp/Arg
			HId regId;//Register
			HStackId stackId;//Stack
		};
		HIRArg() = default;
		bool operator!() {
			return type == HIR_ARGTYPE_INVALID;
		}
		operator bool() {
			return type != HIR_ARGTYPE_INVALID;
		}
		bool isConst() {
			return type == HIR_ARGTYPE_INT || type == HIR_ARGTYPE_UINT || type == HIR_ARGTYPE_FLOAT;
		}
		static inline HIRArg create() {
			return HIRArg();
		}
		static inline HIRArg createVal (int64_t val, uint64_t size) {
			HIRArg arg;
			arg.type = HIR_ARGTYPE_INT;
			arg.sval = val;
			arg.size = size;
			return arg;
		}
		static inline HIRArg createVal (uint64_t val, uint64_t size) {
			HIRArg arg;
			arg.type = HIR_ARGTYPE_UINT;
			arg.uval = val;
			arg.size = size;
			return arg;
		}
		static inline HIRArg createVal (double val, uint64_t size) {
			HIRArg arg;
			arg.type = HIR_ARGTYPE_FLOAT;
			arg.fval = val;
			arg.size = size;
			return arg;
		}
		static inline HIRArg createIR (HId id) {
			HIRArg arg;
			arg.type = HIR_ARGTYPE_IR;
			arg.irId = id;
			arg.size = 0;
			return arg;
		}
		static inline HIRArg createTmp (HId index) {
			HIRArg arg;
			arg.type = HIR_ARGTYPE_TMP;
			arg.index = index;
			arg.size = 0;
			return arg;
		}
		static inline HIRArg createArg (HId index) {
			HIRArg arg;
			arg.type = HIR_ARGTYPE_ARG;
			arg.index = index;
			arg.size = 0;
			return arg;
		}
		static inline HIRArg createReg (HRegister* reg) {
			HIRArg arg;
			arg.type = HIR_ARGTYPE_REG;
			arg.regId = reg->id;
			arg.size = reg->size;
			return arg;
		}
		static inline HIRArg createStck (HStack* stack, HId index) {
			HIRArg arg;
			arg.type = HIR_ARGTYPE_STACK;
			arg.stackId.id = stack->id;
			arg.stackId.index = index;
			arg.size = stack->wordbitsize;
			return arg;
		}
		void print(HArchitecture* arch, int indent = 0);
	};
	struct HIRExpression {
		HId id;
		HIRExprType type;
		uint64_t size;
		HIRType exprtype;
		struct { //196 bit
			union { //64 bit
				HIRFlagType flagType;
				HId index;
				HIROpType opType;
				HId builtinId;
				HId instrId;
			};
		} mod;
		HLocalBackedLists<HIRArg, HIR_LOCAL_USEID_MAX> subExpressions;

		bool operator!() {
			return type == HIR_EXPR_INVALID;
		}
		operator bool() {
			return type != HIR_EXPR_INVALID;
		}
		void print(HArchitecture* arch, int indent = 0);
	};
	inline bool operator== (HStackId& lhs, HStackId& rhs) {
		return lhs.id == rhs.id && lhs.index == rhs.index;
	}
	inline bool operator== (HIRArg& lhs, HIRArg& rhs) {
		if (lhs.type == rhs.type) {
			switch (lhs.type) {
			case HIR_ARGTYPE_INT:
				return lhs.sval == rhs.sval && lhs.size == rhs.size;
			case HIR_ARGTYPE_UINT:
				return lhs.uval == rhs.uval && lhs.size == rhs.size;
			case HIR_ARGTYPE_FLOAT:
				return lhs.fval == rhs.fval && lhs.size == rhs.size;
			case HIR_ARGTYPE_IR:
				return lhs.irId == rhs.irId;
			case HIR_ARGTYPE_STACK:
				return lhs.stackId == rhs.stackId;
			case HIR_ARGTYPE_ARG:
			case HIR_ARGTYPE_TMP:
				return lhs.index == rhs.index;
			case HIR_ARGTYPE_REG:
				return lhs.regId == rhs.regId;
			}
		}
		return false;
	}
	inline bool operator!= (HIRArg& lhs, HIRArg& rhs) {
		return ! (lhs == rhs);
	}
	inline bool operator== (HIRExpression& lhs, HIRExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.exprtype == rhs.exprtype) {
			if (lhs.subExpressions.size() == rhs.subExpressions.size()) {
				for (int i = 0; i < lhs.subExpressions.size(); i++) {
					if (lhs.subExpressions[i] != rhs.subExpressions[i])
						return false;
				}
			}
			switch (rhs.type) {
			case HIR_EXPR_FLAG:
				return lhs.mod.flagType == rhs.mod.flagType;
			case HIR_EXPR_OP:
				return lhs.mod.opType == rhs.mod.opType;
			case HIR_EXPR_BUILTIN:
				return lhs.mod.index == rhs.mod.index;
			}
		}
		return false;
	}


	struct HIRRepresentation {
		int64_t argcount;
		HString condstring;
		HString irstring;

		HIRArg condExpr = HIRArg::create();
		HIRArg rootExpr = HIRArg::create();

		HIRRepresentation() : HIRRepresentation (-1, nullptr, nullptr) {}
		HIRRepresentation (HString irstring) :  HIRRepresentation (-1, nullptr, irstring) {}
		HIRRepresentation (int64_t argcount, HString irstring) : HIRRepresentation (argcount, nullptr, irstring) {}
		HIRRepresentation (HString condstring, HString irstring) : HIRRepresentation (-1, condstring, irstring) {}
		HIRRepresentation (int64_t argcount, HString condstring, HString irstring) : argcount (argcount), condstring (condstring), irstring (irstring) {}

		bool operator!() {
			return !irstring;
		}
		operator bool() {
			return irstring;
		}
		void print (HArchitecture* arch, int indent = 0) {
			if (condstring) {
				printIndent (indent);
				printf ("Cond-String: %s\n", condstring.cstr());
			}
			if (irstring) {
				printIndent (indent);
				printf ("IL-String: %s\n", irstring.cstr());
			} else {
				printIndent (indent);
				printf ("No IL-String----------------\n");
			}
		}
	};

}

#endif //HIR_H
