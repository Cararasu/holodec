
#ifndef SSA_H
#define SSA_H


#include "Stack.h"
#include "Register.h"
#include "Argument.h"
#include "General.h"
#include "HIdList.h"
#include "CHolodecHeader.h"

#define SSA_LOCAL_USEID_MAX (4)

namespace holodec {

	struct Architecture;
	
	enum class SSAExprType {
		eInvalid	= SSA_EXPR_INVALID,
		
		eLabel		= SSA_EXPR_LABEL,
		eUndef		= SSA_EXPR_UNDEF,
		eNop		= SSA_EXPR_NOP,
		
		eOp			= SSA_EXPR_OP,
		eLoadAddr	= SSA_EXPR_LOADADDR,
		eFlag		= SSA_EXPR_FLAG,
		eBuiltin	= SSA_EXPR_BUILTIN,
		eExtend		= SSA_EXPR_EXTEND,
		eSplit		= SSA_EXPR_SPLIT,
		eUpdatePart	= SSA_EXPR_UPDATEPART,
		eAppend		= SSA_EXPR_APPEND,
		eCast		= SSA_EXPR_CAST,
		
		eInput		= SSA_EXPR_INPUT,
		eOutput		= SSA_EXPR_OUTPUT,
		
		eCall		= SSA_EXPR_CALL,
		eReturn		= SSA_EXPR_RETURN,
		eSyscall	= SSA_EXPR_SYSCALL,
		eTrap		= SSA_EXPR_TRAP,

		ePhi		= SSA_EXPR_PHI,
		eAssign		= SSA_EXPR_ASSIGN,

		eJmp		= SSA_EXPR_JMP,
		eCJmp		= SSA_EXPR_CJMP,
		eMultiBranch	= SSA_EXPR_MULTIBR,

		eMemAccess	= SSA_EXPR_MEMACCESS,
		ePush		= SSA_EXPR_PUSH,
		ePop		= SSA_EXPR_POP,
		eStore		= SSA_EXPR_STORE,
		eLoad		= SSA_EXPR_LOAD,

	};
	enum class SSAOpType {
		eInvalid = SSA_OP_INVALID,
		eAdd = SSA_OP_ADD,
		eSub = SSA_OP_SUB,
		eMul = SSA_OP_MUL,
		eDiv = SSA_OP_DIV,
		eMod = SSA_OP_MOD,

		eAnd = SSA_OP_AND,
		eOr = SSA_OP_OR,
		eXor = SSA_OP_XOR,
		eNot = SSA_OP_NOT,

		eEq = SSA_OP_EQ,
		eNe = SSA_OP_NE,
		eLower = SSA_OP_LOWER,
		eLe = SSA_OP_LE,
		eGreater = SSA_OP_GREATER,
		eGe = SSA_OP_GE,

		eBAnd = SSA_OP_BAND,
		eBOr = SSA_OP_BOR,
		eBXor = SSA_OP_BXOR,
		eBNot = SSA_OP_BNOT,

		eShr = SSA_OP_SHR,
		eShl = SSA_OP_SHL,
		eSar = SSA_OP_SAR,
		eSal = SSA_OP_SAL,
		eRor = SSA_OP_ROR,
		eRol = SSA_OP_ROL,
	};
	enum class SSAType {
		eUnknown = SSA_TYPE_UNKNOWN,
		eInt = SSA_TYPE_INT,
		eUInt = SSA_TYPE_UINT,
		eFloat = SSA_TYPE_FLOAT,
		ePc = SSA_TYPE_PC,
		eMemaccess = SSA_TYPE_MEMACCESS,
	};
	enum class SSAFlagType {
		eUnknown = SSA_FLAG_UNKNOWN,
		eC = SSA_FLAG_C,
		eA = SSA_FLAG_A,
		eO = SSA_FLAG_O,
		eU = SSA_FLAG_U,
	};
	enum class SSAExprLocation{
		eNone = SSA_LOCATION_NONE,
		eReg = SSA_LOCATION_REG,
		eStack = SSA_LOCATION_STACK,
		eMem = SSA_LOCATION_MEM,
		eBlock = SSA_LOCATION_BLOCK,
	};
	
	enum class SSAArgType{
		eUndef = SSA_ARGTYPE_UNDEF,
		eSInt = SSA_ARGTYPE_SINT,
		eUInt = SSA_ARGTYPE_UINT,
		eFloat = SSA_ARGTYPE_FLOAT,
		eId = SSA_ARGTYPE_ID
	};
	
	struct SSAArgument {
		//HId id = 0;
		SSAArgType type = SSAArgType::eUndef;
		uint32_t size = 0;
		union {
			HId ssaId;
			ArgSInt sval;
			ArgUInt uval;
			ArgFloat fval;
		};
		SSAExprLocation location = SSAExprLocation::eNone;
		Reference locref = {0, 0};

		bool operator!() {
			return type != SSAArgType::eUndef;
		}
		operator bool() {
			return type == SSAArgType::eUndef;
		}
		bool isConst() {
			return type == SSAArgType::eSInt || type == SSAArgType::eUInt || type == SSAArgType::eFloat;
		}
		bool isValue(uint32_t val){
			if(type == SSAArgType::eSInt){
				return sval == val;
			}else if(type == SSAArgType::eUInt){
				return uval == val;
			}else if(type == SSAArgType::eFloat){
				return fval == (ArgFloat)val;
			}
			return false;
		}
		static inline SSAArgument create() {
			return SSAArgument();
		}
		static inline SSAArgument createSVal (int64_t val, uint32_t size) {
			SSAArgument arg;
			arg.type = SSAArgType::eSInt;
			arg.sval = val;
			arg.size = size;
			return arg;
		}
		static inline SSAArgument createUVal (uint64_t val, uint32_t size) {
			SSAArgument arg;
			arg.type = SSAArgType::eUInt;
			arg.uval = val;
			arg.size = size;
			return arg;
		}
		static inline SSAArgument createDVal (double val, uint32_t size) {
			SSAArgument arg;
			arg.type = SSAArgType::eFloat;
			arg.fval = val;
			arg.size = size;
			return arg;
		}
		static inline SSAArgument create (HId ssaId, uint32_t size = 0, SSAExprLocation location = SSAExprLocation::eNone, Reference locref = {0, 0}) {
			SSAArgument arg;
			arg.type = SSAArgType::eId;
			arg.ssaId = ssaId;
			arg.location = location;
			arg.locref = locref;
			arg.size = size;
			return arg;
		}
		static inline SSAArgument createUndef (SSAExprLocation location, Reference locref, uint32_t size = 0) {
			SSAArgument arg;
			arg.type = SSAArgType::eUndef;
			arg.location = location;
			arg.locref = locref;
			arg.size = size;
			return arg;
		}
		static inline SSAArgument createId (HId ssaId, uint32_t size) {
			return create(ssaId, size, SSAExprLocation::eNone, {0, 0});
		}
		static inline SSAArgument createReg (Register* reg, HId ssaId = 0) {
			return create(ssaId, reg->size, SSAExprLocation::eReg, {reg->id, 0});
		}
		static inline SSAArgument createReg (Reference ref, uint32_t size, HId ssaId = 0) {
			return create(ssaId, size, SSAExprLocation::eReg, ref);
		}
		static inline SSAArgument createMem (Memory* mem, HId ssaId = 0) {
			return create(ssaId, 0, SSAExprLocation::eMem, {mem->id, 0});
		}
		static inline SSAArgument createMem (HId memId, HId ssaId = 0) {
			return create(ssaId, 0, SSAExprLocation::eMem, {memId, 0});
		}
		static inline SSAArgument createStck (Stack* stack, HId index) {
			return create(0, stack->wordbitsize, SSAExprLocation::eStack, {stack->id, index});
		}
		static inline SSAArgument createStck (Reference ref, uint32_t size, HId ssaId = 0) {
			return create(ssaId, size, SSAExprLocation::eStack, ref);
		}
		static inline SSAArgument createBlock (HId blockId) {
			return create(0, 0, SSAExprLocation::eBlock, {blockId, 0});
		}

		void print (Architecture* arch);
	};


	inline bool operator== (SSAArgument& lhs, SSAArgument& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.location == rhs.location && lhs.locref == rhs.locref) {
			switch (lhs.type) {
			case SSAArgType::eSInt:
				return lhs.sval == rhs.sval;
			case SSAArgType::eUInt:
				return lhs.uval == rhs.uval;
			case SSAArgType::eFloat:
				return lhs.fval == rhs.fval;
			case SSAArgType::eId:
				return lhs.ssaId == rhs.ssaId;
			default:
				return false;
			}
			return true;
		}
		return false;
	}
	inline bool operator!= (SSAArgument& lhs, SSAArgument& rhs) {
		return ! (lhs == rhs);
	}
	
	struct SSAExpression {
		HId id = 0;
		SSAExprType type = SSAExprType::eInvalid;
		uint64_t refcount = 0;
		uint32_t size = 0;
		SSAType exprtype = SSAType::eUnknown;
		union { //64 bit
			SSAFlagType flagType;
			SSAOpType opType;
			HId builtinId;
			//HId instrId;
		};
		SSAExprLocation location = SSAExprLocation::eNone;
		Reference locref = {0,0};
		uint64_t instrAddr = 0;
		
		//HLocalBackedList<SSAArgument, SSA_LOCAL_USEID_MAX> subExpressions;
		HList<SSAArgument> subExpressions;

		bool operator!() {
			return type == SSAExprType::eInvalid;
		}
		operator bool() {
			return type != SSAExprType::eInvalid;
		}
		void print(Architecture* arch, int indent = 0);
	};
	inline bool operator== (SSAExpression& lhs, SSAExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.exprtype == rhs.exprtype && lhs.location == rhs.location && lhs.locref.refId == rhs.locref.refId && lhs.locref.index == rhs.locref.index) {
			if (lhs.subExpressions.size() == rhs.subExpressions.size()) {
				for (size_t i = 0; i < lhs.subExpressions.size(); i++) {
					if (lhs.subExpressions[i] != rhs.subExpressions[i])
						return false;
				}
			}
			switch (rhs.type) {
			case SSAExprType::eFlag:
				return lhs.flagType == rhs.flagType;
			case SSAExprType::eOp:
				return lhs.opType == rhs.opType;
			case SSAExprType::eBuiltin:
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
		HUniqueList<HId> inBlocks;
		HUniqueList<HId> outBlocks;

		SSABB() {}
		SSABB (HId fallthroughId, uint64_t startaddr, uint64_t endaddr, HList<HId> exprIds, HUniqueList<HId> inBlocks, HUniqueList<HId> outBlocks) :
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
		
		void propagateRefCount(SSAExpression* expr, int64_t modifier);
		void propagateRefCount(HId id, int64_t modifier = 1);
		
		void changeRefCount(HId id, int64_t count = 1);
		void changeRefCount(HId id, std::vector<bool>& visited, int64_t count = 1);
		
		void recalcRefCounts();

		bool calcConstValue(SSAArgument argument, uint64_t* result);
		
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
