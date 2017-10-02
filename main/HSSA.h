
#ifndef HSSA_H
#define HSSA_H

#include "HId.h"
#include "HStack.h"
#include "HRegister.h"
#include "HArgument.h"

#define HSSA_LOCAL_USEID_MAX (4)

namespace holodec {

	class HArchitecture;
	
	enum HSSAExprType {
		HSSA_EXPR_INVALID = 0,
		HSSA_EXPR_LABEL,//1st Argument is address of 
		
		HSSA_EXPR_INPUT,  // Predefined variables, correspond to input arguments
		HSSA_EXPR_UNDEF,
		HSSA_EXPR_NOP,

		HSSA_EXPR_PHI,
		HSSA_EXPR_ASSIGN,//assign to label = jump to branch, assign to pc = jump to other memory location

		HSSA_EXPR_JMP,
		HSSA_EXPR_CJMP,
		
		HSSA_EXPR_OP,
		HSSA_EXPR_COND,
		
		HSSA_EXPR_PUSH,
		HSSA_EXPR_POP,
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
		HSSA_TYPE_PC,
		HSSA_TYPE_MEM,
	};
	enum HSSAFlagType {
		HSSA_FLAG_C,
		HSSA_FLAG_A,
		HSSA_FLAG_P,
		HSSA_FLAG_O,
		HSSA_FLAG_U,
		HSSA_FLAG_Z,
		HSSA_FLAG_S,
	};
	struct HSSAExpression {
		HId id = 0;
		HSSAExprType type = HSSA_EXPR_INVALID;
		uint64_t size = 0;
		HSSAType exprtype = HSSA_TYPE_UNKNOWN;
		union { //64 bit
			HSSAFlagType flagType;
			HId index;
			HSSAOpType opType;
			HId builtinId;
			HId instrId;
		};
		HId regId = 0;
		HArgStck stackId = {0,0};
		uint64_t instrAddr;
		
		HLocalBackedList<HArgument, HSSA_LOCAL_USEID_MAX> subExpressions;

		bool operator!() {
			return type == HSSA_EXPR_INVALID;
		}
		operator bool() {
			return type != HSSA_EXPR_INVALID;
		}
		void print(HArchitecture* arch, int indent = 0);
	};
	inline bool operator== (HSSAExpression& lhs, HSSAExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.exprtype == rhs.exprtype) {
			if (lhs.subExpressions.size() == rhs.subExpressions.size()) {
				for (size_t i = 0; i < lhs.subExpressions.size(); i++) {
					if (lhs.subExpressions[i] != rhs.subExpressions[i])
						return false;
				}
			}
			switch (rhs.type) {
			case HSSA_EXPR_FLAG:
				return lhs.flagType == rhs.flagType;
			case HSSA_EXPR_OP:
				return lhs.opType == rhs.opType;
			case HSSA_EXPR_BUILTIN:
				return lhs.index == rhs.index;
			default:
				return true;
			}
		}
		return false;
	}

	struct HSSARegUse{
		HId regId,parentRegId;
		uint64_t offset, size;
	};
	
	struct HSSABB {
		HId id;
		HId fallthroughId = 0;
		uint64_t startaddr = (uint64_t)-1;
		uint64_t endaddr = 0;
		HList<HId> exprIds;

		HList<HSSARegUse> inputs;
		HList<HSSARegUse> outputs;

		HSSABB() {}
		HSSABB (HId fallthroughId, uint64_t startaddr, uint64_t endaddr, HList<HId> exprIds) :id(0),fallthroughId(fallthroughId),startaddr(startaddr),endaddr(endaddr),exprIds(exprIds),inputs(),outputs(){}
		~HSSABB() = default;


		HId getInputSSA (HRegister* reg);
	};


	struct HSSARepresentation {
		HList<HId> inputs;
		HIdList<HSSABB> bbs;
		HIdList<HSSAExpression> expressions;

		void clear(){
			inputs.clear();
			bbs.clear();
			expressions.clear();
		}

		void print (HArchitecture* arch, int indent = 0);
	};
}

#endif //HSSA_H
