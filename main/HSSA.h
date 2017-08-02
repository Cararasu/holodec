
#include "HId.h"
#include "HClass.h"

#define HSSA_LOCAL_USEID_MAX (8)

namespace holodec {

	enum HSSAExprType {
		HSSA_EXPR_INVALID = 0,
		HSSA_EXPR_INPUT,  // Predefined variables, correspond to input arguments

		HSSA_EXPR_OP,  // Predefined variables, correspond to input arguments
		// Call - Return
		HSSA_EXPR_BR,  // Branch
		HSSA_EXPR_CALL,  // a call to a function
		HSSA_EXPR_RET,  // a return
		HSSA_EXPR_SYSCALL,  // a syscall
		HSSA_EXPR_TRAP,  // a trap
		// Misc
		// Int,Any... -> Any
		HSSA_EXPR_IF,  // depending on the first value n returns the nth value(for conditional jumps/conditional moves/...)
		// Any... -> Any
		HSSA_EXPR_BUILTIN,  // call a builtin(invalidates all previous variables and creates a new def)
		// Any  -> Any
		HSSA_EXPR_EXTEND,  // zero extend a value
		// Any -> Int
		HSSA_EXPR_SPLIT,  // access to part of a variable
		// Any -> Any
		HSSA_EXPR_APPEND,  // combine variables
		HSSA_EXPR_CAST,  // cast to other type

		HSSA_EXPR_MEM,  // addr = base, index, scale, disp
		// Memory
		HSSA_EXPR_STORE, //mem = mem, addr, value
		HSSA_EXPR_LOAD, //value = mem, addr
	};
	enum HSSAOperatorType {
		HSSA_OP_INVALID = 0,
		HSSA_OP_ADD,
		HSSA_OP_SUB,
		HSSA_OP_MUL,
		HSSA_OP_DIV,

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

	struct HSSAExpression {
		HId id;
		HSSAExprType type;
		HSSAOperatorType opType;
		HId typeId;//refers to the return type

		HId regId;//what register this expression refers to
		HId instrId;//what instruction this expression refers to

		HLocalBackedLists<HId, HSSA_LOCAL_USEID_MAX> subExpressions;
	};

	inline bool operator== (HSSAExpression& lhs, HSSAExpression& rhs) {
		if (lhs.type == rhs.type && lhs.opType == rhs.opType && lhs.typeId == rhs.typeId && lhs.subExpressions.size() == rhs.subExpressions.size()) {
			for (size_t i = 0; i < lhs.subExpressions.size(); i++) {
				if (lhs.subExpressions[i] != rhs.subExpressions[i])
					return false;
			}
			return true;
		}
		return false;
	}
	struct HSSABasicBlock {
		HId id;
		HIdList<HSSAExpression> expressions;
		
		HId bbId;//what basicblock this expression refers to
	};
	struct HSSAFunction {
		HId id;
		HIdList<HSSABasicBlock> basicblocks;
		
		HId funcId;//what function this expression refers to
	};

}
