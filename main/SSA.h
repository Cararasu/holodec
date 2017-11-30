
#ifndef SSA_H
#define SSA_H


#include "Stack.h"
#include "Register.h"
#include "Argument.h"
#include "General.h"
#include "HIdList.h"

#define SSA_LOCAL_USEID_MAX (4)

namespace holodec {

	class Architecture;
	
#define SSA_EXPR_CONTROL_FLOW		(0x1000)
#define SSA_EXPR_TRANSIENT_NODE		(0x2000)//TODO rename as this is a bad name
#define SSA_EXPR_MEMWRITE			(0x4000)

#define EXPR_IS_CONTROLFLOW(type) (type & SSA_EXPR_CONTROL_FLOW)
#define EXPR_IS_TRANSIENT(type) (type & SSA_EXPR_TRANSIENT_NODE)

#define EXPR_HAS_SIDEEFFECT(type) (type & (SSA_EXPR_CONTROL_FLOW | SSA_EXPR_MEMWRITE))
	enum SSAExprType {
		SSA_EXPR_INVALID	= 0x0,
		
		SSA_EXPR_LABEL		= 0x10,
		SSA_EXPR_UNDEF		= 0x11,
		SSA_EXPR_NOP		= 0x12,
		
		SSA_EXPR_OP			= 0x13,
		SSA_EXPR_LOADADDR	= 0x14,
		SSA_EXPR_FLAG		= 0x15,
		SSA_EXPR_BUILTIN	= 0x16,
		SSA_EXPR_EXTEND		= 0x17,
		SSA_EXPR_SPLIT		= 0x18,
		SSA_EXPR_UPDATEPART	= SSA_EXPR_TRANSIENT_NODE | 0x19,
		SSA_EXPR_APPEND		= 0x1A,
		SSA_EXPR_CAST		= 0x1B,
		
		SSA_EXPR_INPUT		= 0x21,
		SSA_EXPR_OUTPUT		= 0x22,
		
		SSA_EXPR_CALL		= SSA_EXPR_CONTROL_FLOW | 0x23,
		SSA_EXPR_RETURN		= SSA_EXPR_CONTROL_FLOW | 0x24,
		SSA_EXPR_SYSCALL	= SSA_EXPR_CONTROL_FLOW | 0x25,
		SSA_EXPR_TRAP		= SSA_EXPR_CONTROL_FLOW | 0x26,

		SSA_EXPR_PHI		= SSA_EXPR_TRANSIENT_NODE | 0x31,
		SSA_EXPR_ASSIGN		= 0x32,

		SSA_EXPR_JMP		= SSA_EXPR_CONTROL_FLOW | 0x41,
		SSA_EXPR_CJMP		= SSA_EXPR_CONTROL_FLOW | 0x42,
		SSA_EXPR_MULTIBR	= SSA_EXPR_CONTROL_FLOW | 0x43,

		SSA_EXPR_MEMACCESS	= 0x50,
		SSA_EXPR_PUSH		= SSA_EXPR_MEMWRITE | 0x54,
		SSA_EXPR_POP		= 0x55,
		SSA_EXPR_STORE		= SSA_EXPR_MEMWRITE | 0x58,
		SSA_EXPR_LOAD		= 0x59,

	};
	enum SSAOpType {
		H_OP_INVALID = 0,
		H_OP_ADD,
		H_OP_SUB,
		H_OP_MUL,
		H_OP_DIV,
		H_OP_MOD,

		H_OP_AND,
		H_OP_OR,
		H_OP_XOR,
		H_OP_NOT,

		H_OP_EQ,
		H_OP_NE,
		H_OP_L,
		H_OP_LE,
		H_OP_G,
		H_OP_GE,

		H_OP_BAND,
		H_OP_BOR,
		H_OP_BXOR,
		H_OP_BNOT,

		H_OP_SHR,
		H_OP_SHL,
		H_OP_SAR,
		H_OP_SAL,
		H_OP_ROR,
		H_OP_ROL,
	};
	enum SSAType {
		SSA_TYPE_UNKNOWN = 0,
		SSA_TYPE_INT,
		SSA_TYPE_UINT,
		SSA_TYPE_FLOAT,
		SSA_TYPE_PC,
		SSA_TYPE_MEMACCESS,
	};
	enum SSAFlagType {
		SSA_FLAG_UNKNOWN = 0,
		SSA_FLAG_C,
		SSA_FLAG_A,
		SSA_FLAG_P,
		SSA_FLAG_O,
		SSA_FLAG_U,
		SSA_FLAG_Z,
		SSA_FLAG_S,
	};
	enum SSAExprLocation{
		SSA_LOCATION_NONE,
		SSA_LOCATION_REG,
		SSA_LOCATION_STACK,
		SSA_LOCATION_MEM,
	};
	struct SSAExpression {
		HId id = 0;
		SSAExprType type = SSA_EXPR_INVALID;
		uint64_t refcount = 0;
		uint64_t size = 0;
		SSAType returntype = SSA_TYPE_UNKNOWN;
		union { //64 bit
			SSAFlagType flagType;
			SSAOpType opType;
			HId builtinId;
			//HId instrId;
		};
		SSAExprLocation location = SSA_LOCATION_NONE;
		Reference locref = {0,0};
		uint64_t instrAddr = 0;
		
		//HLocalBackedList<SSAArgument, SSA_LOCAL_USEID_MAX> subExpressions;
		HList<SSAArgument> subExpressions;

		bool operator!() {
			return type == SSA_EXPR_INVALID;
		}
		operator bool() {
			return type != SSA_EXPR_INVALID;
		}
		void print(Architecture* arch, int indent = 0);
	};
	inline bool operator== (SSAExpression& lhs, SSAExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.returntype == rhs.returntype && lhs.location == rhs.location && lhs.locref.refId == rhs.locref.refId && lhs.locref.index == rhs.locref.index) {
			if (lhs.subExpressions.size() == rhs.subExpressions.size()) {
				for (size_t i = 0; i < lhs.subExpressions.size(); i++) {
					if (lhs.subExpressions[i] != rhs.subExpressions[i])
						return false;
				}
			}
			switch (rhs.type) {
			case SSA_EXPR_FLAG:
				return lhs.flagType == rhs.flagType;
			case SSA_EXPR_OP:
				return lhs.opType == rhs.opType;
			case SSA_EXPR_BUILTIN:
				return lhs.builtinId == rhs.builtinId;
			default:
				return true;
			}
		}
		return false;
	}
	
	struct SSABB {
		HId id;
		HId fallthroughId = 0;
		uint64_t startaddr = (uint64_t)-1;
		uint64_t endaddr = 0;
		HList<HId> exprIds;
		HSet<HId> inBlocks;
		HSet<HId> outBlocks;

		SSABB() {}
		SSABB (HId fallthroughId, uint64_t startaddr, uint64_t endaddr, HList<HId> exprIds, HSet<HId> inBlocks, HSet<HId> outBlocks) :
			id(0),fallthroughId(fallthroughId),startaddr(startaddr),endaddr(endaddr),exprIds(exprIds),inBlocks(inBlocks),outBlocks(outBlocks){}
		~SSABB() = default;


		HId getInputSSA (Register* reg);
	};


	struct SSARepresentation {
		HIdList<SSABB> bbs;
		HSparseIdList<SSAExpression> expressions;

		void clear(){
			bbs.clear();
			expressions.clear();
		}

		void replaceNodes(HMap<HId,SSAArgument>* replacements);
		void removeNodes(HSet<HId>* ids);
		
		void compress();
		
		void propagateRefCount(HId id, int64_t count = 1);
		
		void changeRefCount(HId id, int64_t count = 1);
		void changeRefCount(HId id, std::vector<bool>& visited, int64_t count = 1);
		
		HId addExpr(SSAExpression* expr);
		
		HId addAtEnd(SSAExpression* expr, HId blockId);
		HId addAtEnd(SSAExpression* expr, SSABB* bb);
		HId addAtStart(SSAExpression* expr, HId blockId);
		HId addAtStart(SSAExpression* expr, SSABB* bb);
		
		HId addBefore(SSAExpression* expr, HId ssaId, HId blockId);
		HId addBefore(SSAExpression* expr, HId ssaId, SSABB* bb = nullptr);
		HList<HId>::iterator addBefore(SSAExpression* expr, HList<HId>& ids, HList<HId>::iterator it);
		HId addAfter(SSAExpression* expr, HId ssaId, HId blockId);
		HId addAfter(SSAExpression* expr, HId ssaId, SSABB* bb = nullptr);
		HList<HId>::iterator addAfter(SSAExpression* expr, HList<HId>& ids, HList<HId>::iterator it);
		
		HList<HId>::iterator removeExpr(HList<HId>& ids, HList<HId>::iterator it);
		void removeExpr(HId ssaId, HId blockId);
		void removeExpr(HId ssaId, SSABB* bb = nullptr);


		void print (Architecture* arch, int indent = 0);
	};
}

#endif //SSA_H
