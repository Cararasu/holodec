
#ifndef SSA_H
#define SSA_H


#include "Stack.h"
#include "Register.h"
#include "General.h"
#include "Memory.h"
#include "HIdList.h"
#include "CHolodecHeader.h"

#include <assert.h>

#define SSA_LOCAL_USEID_MAX (4)

namespace holodec {

	struct Architecture;
	struct SSAExpression;
	
	enum class SSAExprType {
		eInvalid	= SSA_EXPR_INVALID,
		
		eLabel		= SSA_EXPR_LABEL,
		eUndef		= SSA_EXPR_UNDEF,
		eNop		= SSA_EXPR_NOP,
		eValue		= SSA_EXPR_VALUE,
		
		eOp			= SSA_EXPR_OP,
		eLoadAddr	= SSA_EXPR_LOADADDR,
		eFlag		= SSA_EXPR_FLAG,
		eBuiltin	= SSA_EXPR_BUILTIN,
		eSplit		= SSA_EXPR_SPLIT,
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

		eBranch		= SSA_EXPR_BRANCH,

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
		eRor = SSA_OP_ROR,
		eRol = SSA_OP_ROL,
	};
	enum class SSAType {
		eUInt = SSA_TYPE_UINT,
		eInt = SSA_TYPE_INT,
		eFloat = SSA_TYPE_FLOAT,
		ePc = SSA_TYPE_PC,
		eMemaccess = SSA_TYPE_MEMACCESS,
	};
	enum class SSAFlagType {
		eUnknown = SSA_FLAG_UNKNOWN,
		eC = SSA_FLAG_C,
		eO = SSA_FLAG_O,
		eU = SSA_FLAG_U,
	};
	enum class SSALocation{
		eNone = SSA_LOCATION_NONE,
		eReg = SSA_LOCATION_REG,
		eMem = SSA_LOCATION_MEM,
	};
	
	enum class SSAArgType{
		eUndef = SSA_ARGTYPE_UNDEF,
		eBlock = SSA_ARGTYPE_BLOCK,
		eId = SSA_ARGTYPE_ID,
	};
	struct Reference {
		SSALocation location;
		HId id;
		Reference() : location(SSALocation::eNone), id(0) {}
		Reference(SSALocation location, HId id) : location(location), id(id) {}
		Reference(Register* reg) : location(SSALocation::eReg), id(reg->id) {}
		Reference(Memory* mem) : location(SSALocation::eMem), id(mem->id) {}

		inline bool isLocation(SSALocation location) const {
			return this->location == location;
		}
		inline bool isReg(Register* reg) const {
			return this->isLocation(SSALocation::eReg) && id == reg->id;
		}
		inline bool isMem(Memory* mem) const {
			return this->isLocation(SSALocation::eMem) && id == mem->id;
		}

		explicit operator HReference() const {
			switch (location) {
			case SSALocation::eReg:
				return { SSA_LOCATION_REG , id };
			case SSALocation::eMem:
				return { SSA_LOCATION_MEM , id };
			case SSALocation::eNone:
			default:
				return { SSA_LOCATION_NONE , id };
			}
		}
		explicit operator bool() const {
			return location != SSALocation::eNone || !id;
		}
		bool operator !() const {
			return location == SSALocation::eNone && id;
		}
	};
	inline bool operator==(Reference& lhs, Reference& rhs) {
		return lhs.location == rhs.location && lhs.id == rhs.id;
	}
	inline bool operator!=(Reference& lhs, Reference& rhs) {
		return lhs.location != rhs.location ||lhs.id != rhs.id;
	}
	
	struct SSAArgument {
		SSAArgType type = SSAArgType::eUndef;
		HId ssaId;
		Reference ref;


		bool operator!() {
			return type != SSAArgType::eUndef;
		}
		explicit operator bool() {
			return type == SSAArgType::eUndef;
		}
		void replace(SSAArgument arg) {
			if (!ref) {
				ref = arg.ref;
			}
			this->ssaId = arg.ssaId;
		}
		static SSAArgument replace(SSAArgument basearg, SSAArgument arg) {
			basearg.replace(arg);
			return basearg;
		}
		void set(SSAArgument arg) {
			*this = arg;
		}
		static inline SSAArgument create() {
			return SSAArgument();
		}
		static inline SSAArgument create(HId ssaId, Reference ref = Reference()) {
			SSAArgument arg = { SSAArgType::eId };
			arg.ssaId = ssaId;
			arg.ref = ref;
			return arg;
		}
		static inline SSAArgument createOther(SSAArgType argType, Reference ref = Reference()) {
			SSAArgument arg = { argType };
			arg.ref = ref;
			return arg;
		}
		static inline SSAArgument createUndef (Reference ref) {
			SSAArgument arg = { SSAArgType::eUndef };
			arg.ref = ref;
			return arg;
		}
		static inline SSAArgument create(SSAExpression* expr);

		static inline SSAArgument createId(HId ssaId, Reference ref = Reference()) {
			assert(ssaId);
			return create(ssaId, ref);
		}
		static inline SSAArgument createReg(Register* reg, HId ssaId = 0) {
			return create(ssaId, { SSALocation::eReg, reg->id });
		}
		static inline SSAArgument createMem(Memory* mem, HId ssaId = 0) {
			return  create(ssaId, { SSALocation::eMem, mem->id });
		}
		static inline SSAArgument createMem (HId memId, HId ssaId = 0) {
			return  create(ssaId, { SSALocation::eMem, memId });
		}
		static inline SSAArgument createBlock (HId blockId) {
			SSAArgument arg = { SSAArgType::eBlock };
			arg.ssaId = blockId;
			return arg;
		}

		void print(Architecture* arch);
		void printSimple(Architecture* arch);
	};


	inline bool operator== (SSAArgument& lhs, SSAArgument& rhs) {
		if (lhs.type == rhs.type && lhs.ref == rhs.ref) {
			switch (lhs.type) {
			case SSAArgType::eId:
				return lhs.ssaId == rhs.ssaId;
			case SSAArgType::eBlock:
				return lhs.ssaId == rhs.ssaId;
			default:
				return false;
			}
			return true;
		}
		return false;
	}
	inline bool weak_equals(SSAArgument& lhs, SSAArgument& rhs) {
		if (lhs.type == rhs.type) {
			switch (lhs.type) {
			case SSAArgType::eId:
				return lhs.ssaId && lhs.ssaId == rhs.ssaId;
			case SSAArgType::eBlock:
				return lhs.ssaId && lhs.ssaId == rhs.ssaId;
			default:
				return true;
			}
			return true;
		}
		return false;
	}
	inline bool consecutive_arg_todo(SSAArgument& lhs, SSAArgument& rhs) {
		if (lhs.type == rhs.type) {
			switch (lhs.type) {
			case SSAArgType::eId:
				return lhs.ssaId == rhs.ssaId;
			case SSAArgType::eBlock:
				return lhs.ssaId == rhs.ssaId;
			default:
				return false;
			}
			return true;
		}
		return false;
	}
	inline bool consecutive_args_todo(HList<SSAArgument>::iterator lhs, HList<SSAArgument>::iterator rhs) {
		if (std::distance(lhs, rhs) <= 0)
			return false;
		for (; lhs != rhs; ++lhs) {
			if (!consecutive_arg_todo(*lhs, *(lhs + 1))) {
				return false;
			}
		}
		return true;
	}
	inline bool operator!= (SSAArgument& lhs, SSAArgument& rhs) {
		return ! (lhs == rhs);
	}
	
	class SSARepresentation;

	struct SSAExpression {
		HId id = 0;
		HId uniqueId = 0;
		HId blockId = 0;
		SSAExprType type = SSAExprType::eInvalid;
		uint32_t size = 0;
		SSAType exprtype = SSAType::eUInt;
		union { //64 bit
			struct {
				SSAFlagType flagType;
				uint32_t flagbit;
			};
			SSAOpType opType;
			HId builtinId;
			uint32_t offset;
			SSAType sourcetype;
			int64_t sval;
			uint64_t uval;
			double fval;
		};
		Reference ref;
		uint64_t instrAddr = 0;

		HList<HId> directRefs;
		HList<SSAArgument> subExpressions;

		SSAExpression() {}
		SSAExpression(SSAExprType type, uint32_t size, SSAType exprtype) : type(type), size(size), exprtype(exprtype){}

		void addArgument(SSARepresentation* rep, SSAArgument arg);
		void setArgument(SSARepresentation* rep, size_t index, SSAArgument arg);
		void setArgument(SSARepresentation* rep, HList<SSAArgument>::iterator it, SSAArgument arg);
		size_t removeArgument(SSARepresentation* rep, size_t index);
		HList<SSAArgument>::iterator removeArgument(SSARepresentation* rep, HList<SSAArgument>::iterator it);
		HList<SSAArgument>::iterator removeArguments(SSARepresentation* rep, HList<SSAArgument>::iterator beginit, HList<SSAArgument>::iterator endit);
		size_t insertArgument(SSARepresentation* rep, size_t index, SSAArgument arg);
		HList<SSAArgument>::iterator insertArgument(SSARepresentation* rep, HList<SSAArgument>::iterator it, SSAArgument arg);
		size_t replaceArgument(SSARepresentation* rep, size_t index, SSAArgument arg);
		HList<SSAArgument>::iterator replaceArgument(SSARepresentation* rep, HList<SSAArgument>::iterator index, SSAArgument arg);
		void setAllArguments(SSARepresentation* rep, HList<SSAArgument> args);

		bool isConst() {
			return type == SSAExprType::eValue;
		}
		bool isConst(SSAType type) {
			return this->type == SSAExprType::eValue && exprtype == type;
		}
		bool isValue(uint64_t value) {
			return type == SSAExprType::eValue && exprtype == SSAType::eUInt && uval == value;
		}
		bool isOp() {
			return type == SSAExprType::eOp;
		}
		bool isOp(SSAOpType opType) {
			return type == SSAExprType::eOp && this->opType == opType;
		}

		bool operator!() {
			return type == SSAExprType::eInvalid;
		}
		operator bool() {
			return type != SSAExprType::eInvalid;
		}
		void print(Architecture* arch, int indent = 0);
		void printSimple(Architecture* arch, int indent = 0);
	};

	inline SSAArgument SSAArgument::create(SSAExpression* expr) {
		return create(expr->id, expr->ref);
	}

	inline bool weak_equals(SSAExpression& lhs, SSAExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.exprtype == rhs.exprtype) {
			if (lhs.subExpressions.size() == rhs.subExpressions.size()) {
				for (size_t i = 0; i < lhs.subExpressions.size(); i++) {
					if (!weak_equals(lhs.subExpressions[i], rhs.subExpressions[i])) return false;
				}
			}
			else {
				return false;
			}
			if (EXPR_IS_CONTROLFLOW(rhs.type))
				return false;
			switch (rhs.type) {
			case SSAExprType::eFlag:
				return lhs.flagType == rhs.flagType && lhs.flagbit == rhs.flagbit;
			case SSAExprType::eOp:
				return lhs.opType == rhs.opType;
			case SSAExprType::eBuiltin:
				return lhs.builtinId == rhs.builtinId;
			case SSAExprType::eValue:
				switch (rhs.exprtype) {
				case SSAType::eFloat:
					return lhs.fval == rhs.fval;
				case SSAType::eUInt:
					return lhs.uval == rhs.uval;
				case SSAType::eInt:
					return lhs.sval == rhs.sval;
				}
			case SSAExprType::eCast:
				return lhs.sourcetype == rhs.sourcetype;
			case SSAExprType::eSplit:
				return lhs.offset == rhs.offset;
			case SSAExprType::eInput:
			case SSAExprType::eOutput:
				return lhs.ref == rhs.ref;
			default:
				return true;
			}
		}
		return false;
	}
	
	struct SSABB {
		HId id;
		uint64_t startaddr = (uint64_t)-1;
		uint64_t endaddr = 0;
		HList<HId> exprIds;
		HSet<HId> inBlocks;
		HSet<HId> outBlocks;

		SSABB() {}
		SSABB (uint64_t startaddr, uint64_t endaddr, HList<HId> exprIds, HSet<HId> inBlocks, HSet<HId> outBlocks) :
			id(0),startaddr(startaddr),endaddr(endaddr),exprIds(exprIds),inBlocks(inBlocks),outBlocks(outBlocks){}
		~SSABB() = default;


		HId getInputSSA (Register* reg);
	};


	class SSARepresentation {
		HList<HId>::iterator addBefore(SSAExpression* expr, HList<HId>& ids, HList<HId>::iterator it);
		HList<HId>::iterator addAfter(SSAExpression* expr, HList<HId>& ids, HList<HId>::iterator it);
	public:
		HIdList<SSABB> bbs;
		HSparseIdList<SSAExpression> expressions;

		HIdGenerator exprIdGen;

		void clear(){
			bbs.clear();
			expressions.clear();
		}

		void replaceNodes(HMap<HId,SSAArgument>* replacements);
		uint64_t replaceAllArgs(SSAExpression& origExpr, SSAArgument replaceArg);
		bool isReplaceable(SSAExpression& origExpr);
		uint64_t replaceExpr(SSAExpression& origExpr, SSAArgument replaceArg);
		uint64_t replaceAllExprs(SSAExpression& origExpr, SSAArgument replaceArg);
		uint64_t replaceOpExpr(SSAExpression& origExpr, SSAArgument replaceArg, SSAArgument opArg, uint32_t baseoffset);
		void removeNodes(HSet<HId>* ids);
		
		void compress();
		
		bool checkIntegrity();

		void propagateRefCount(SSAExpression* expr);
		void propagateRefCount(HId id);
		
		void changeRefCount(HId id, HId refId);
		void changeRefCount(HId id, std::vector<bool>& visited, HId refId);
		
		void recalcRefCounts();

		bool calcConstValue(SSAArgument argument, uint64_t* result);

		HId addExpr(SSAExpression* expr);
		
		HId addAtEnd(SSAExpression* expr, HId blockId);
		HId addAtEnd(SSAExpression* expr, SSABB* bb);
		HId addAtStart(SSAExpression* expr, HId blockId);
		HId addAtStart(SSAExpression* expr, SSABB* bb);
		
		HId addBefore(SSAExpression* expr, HId ssaId);
		HId addAfter(SSAExpression* expr, HId ssaId);

		bool isNotUsedBefore(SSAExpression& firstExpr, SSAExpression& secondExpr);
		bool areArgsNotDefedBefore(SSAExpression& firstExpr, SSAExpression& secondExpr);

		HList<HId>::iterator removeExpr(HList<HId>& ids, HList<HId>::iterator it);
		void removeExpr(HId ssaId);

		bool usedOnlyInFlags(SSAExpression& expr) {
			for (HId id : expr.directRefs) {//iterate refs
				if (expressions[id].type != SSAExprType::eFlag)
					return false;
			}
			return true;
		}
		bool isUsed(SSAExpression& expr) {
			return expr.directRefs.size() != 0;
		}

		void print(Architecture* arch, int indent = 0);
		void printSimple(Architecture* arch, int indent = 0);
		
	};
	

	SSAExpression* find_baseexpr(SSARepresentation* ssaRep, SSAArgument arg);
	HId find_basearg(SSARepresentation* ssaRep, SSAArgument arg);
	bool calculate_difference(SSARepresentation* ssaRep, HId firstid, HId secid, int64_t* change);

	//returns the distance traveled from the ssaId
	//if distance is 0 then the expression with id == ssaId was neither an addition or a subtraction
	uint64_t calculate_basearg_plus_offset(SSARepresentation* ssaRep, HId ssaId, 
		int64_t* fixedValueChange/* result | the value that was added or subtracted */, HId* baseExprId/* result | the furthest argument we can travel to */);

	bool combine_operations(SSARepresentation* ssaRep, HId* exprsToReplace, SSAArgument* firstargss, SSAArgument* secargss, uint32_t count, SSAExpression expr, uint64_t instrAddr);

	bool is_part_of(SSARepresentation* ssaRep, SSAArgument firstArg, SSAArgument secondArg);

	//checks if the expressions refer to the same expressions just split so they are laid out consecutive
	//or they refer to load expressions that are consequitve in memory
	bool consecutive_exprs(Architecture* arch, SSARepresentation* ssaRep, HId expr1, HId expr2);
}



#endif //SSA_H
