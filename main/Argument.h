
#ifndef H_ARGUMENT_H
#define H_ARGUMENT_H

#include <stdint.h>
#include "General.h"

#include "Register.h"
#include "Stack.h"
#include "Memory.h"

namespace holodec {

	class Architecture;

	enum SSAArgTypes{
		SSA_ARGTYPE_UNKN = 0x0,
		SSA_ARGTYPE_REG,
		SSA_ARGTYPE_STACK,
		SSA_ARGTYPE_MEM,
		SSA_ARGTYPE_SINT,
		SSA_ARGTYPE_UINT,
		SSA_ARGTYPE_FLOAT,
		SSA_ARGTYPE_ID,
		SSA_ARGTYPE_BLOCK
	};

	typedef int64_t ArgSInt;
	typedef uint64_t ArgUInt;
	typedef double ArgFloat;
	struct ArgStck {
		HId id;//id of the stack
		HId index;//index into the stack or 0 for whole stack
	};
	bool inline operator==(ArgStck& lhs, ArgStck& rhs){
		return lhs.id == rhs.id && lhs.index == rhs.index;
	}
	bool inline operator!=(ArgStck& lhs, ArgStck& rhs){
		return !(lhs == rhs);
	}
	struct Reference{
		HId refId;
		HId index;
		
		explicit operator bool(){
			return (bool)refId;
		}
		operator !(){
			return !refId;
		}
	};
	inline bool operator==(Reference& lhs, Reference& rhs){
		return lhs.refId == rhs.refId && lhs.index == rhs.index;
	}
	
	struct SSAArgument {
		//HId id = 0;
		HId ssaId = 0;
		SSAArgTypes type = SSA_ARGTYPE_UNKN;
		uint32_t size = 0;
		union {
			ArgSInt sval;
			ArgUInt uval;
			ArgFloat fval;
			Reference ref;
		};

		bool operator!() {
			return !type;
		}
		operator bool() {
			return !!type;
		}
		bool isConst() {
			return type == SSA_ARGTYPE_SINT || type == SSA_ARGTYPE_UINT || type == SSA_ARGTYPE_FLOAT;
		}
		bool isValue(uint32_t val){
			if(type == SSA_ARGTYPE_SINT){
				return sval == val;
			}else if(type == SSA_ARGTYPE_UINT){
				return uval == val;
			}else if(type == SSA_ARGTYPE_FLOAT){
				return fval == (ArgFloat)val;
			}
			return false;
		}
		static inline SSAArgument create() {
			return SSAArgument();
		}
		static inline SSAArgument createVal (int64_t val, uint64_t size) {
			SSAArgument arg;
			arg.type = SSA_ARGTYPE_SINT;
			arg.sval = val;
			arg.size = size;
			return arg;
		}
		static inline SSAArgument createVal (uint64_t val, uint64_t size) {
			SSAArgument arg;
			arg.type = SSA_ARGTYPE_UINT;
			arg.uval = val;
			arg.size = size;
			return arg;
		}
		static inline SSAArgument createVal (double val, uint64_t size) {
			SSAArgument arg;
			arg.type = SSA_ARGTYPE_FLOAT;
			arg.fval = val;
			arg.size = size;
			return arg;
		}
		static inline SSAArgument create (SSAArgTypes type, HId ssaId = 0, Reference ref = {0, 0}, uint32_t size = 0) {
			SSAArgument arg;
			arg.type = type;
			arg.ssaId = ssaId;
			arg.ref = ref;
			arg.size = size;
			return arg;
		}
		static inline SSAArgument createId (HId ssaId, uint64_t size) {
			return create(SSA_ARGTYPE_ID, ssaId, {0, 0}, size);
		}
		static inline SSAArgument createReg (Register* reg, HId ssaId = 0) {
			return create(SSA_ARGTYPE_REG, ssaId, {reg->id, 0}, reg->size);
		}
		static inline SSAArgument createReg (Reference ref, uint32_t size, HId ssaId = 0) {
			return create(SSA_ARGTYPE_REG, ssaId, ref, size);
		}
		static inline SSAArgument createMem (Memory* mem, HId ssaId = 0) {
			return create(SSA_ARGTYPE_MEM, ssaId, {mem->id, 0}, 0);
		}
		static inline SSAArgument createMem (HId memId, HId ssaId = 0) {
			return create(SSA_ARGTYPE_MEM, ssaId, {memId, 0}, 0);
		}
		static inline SSAArgument createStck (Stack* stack, HId index) {
			return create(SSA_ARGTYPE_STACK, 0, {stack->id, index}, stack->wordbitsize);
		}
		static inline SSAArgument createStck (Reference ref, uint32_t size, HId ssaId = 0) {
			return create(SSA_ARGTYPE_STACK, ssaId, ref, size);
		}
		static inline SSAArgument createBlock (HId blockId) {
			return create(SSA_ARGTYPE_BLOCK, 0, {blockId, 0});
		}

		void print (Architecture* arch);
	};


	inline bool operator== (SSAArgument& lhs, SSAArgument& rhs) {
		if (lhs.type == rhs.type && lhs.ssaId == rhs.ssaId && lhs.size == rhs.size) {
			switch (lhs.type) {
			case SSA_ARGTYPE_SINT:
				return lhs.sval == rhs.sval;
			case SSA_ARGTYPE_UINT:
				return lhs.uval == rhs.uval;
			case SSA_ARGTYPE_FLOAT:
				return lhs.fval == rhs.fval;
			case SSA_ARGTYPE_REG:
			case SSA_ARGTYPE_STACK:
			case SSA_ARGTYPE_MEM:
			case SSA_ARGTYPE_ID:
			case SSA_ARGTYPE_BLOCK:
				return lhs.ref.refId == rhs.ref.refId && lhs.ref.index == rhs.ref.index;
				return true;
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

	struct ArgMem { //segment::[base + index*scale + disp]
		HId segment;
		HId base;
		HId index;
		ArgSInt scale;
		ArgSInt disp;
	};
	bool inline operator==(ArgMem& lhs, ArgMem& rhs){
		return lhs.segment == rhs.segment && lhs.base == rhs.base && lhs.index == rhs.index && lhs.scale == rhs.scale && lhs.disp == rhs.disp;
	}
	bool inline operator!=(ArgMem& lhs, ArgMem& rhs){
		return !(lhs == rhs);
	}
	enum IRArgTypes{
		IR_ARGTYPE_UNKN = 0,
		IR_ARGTYPE_REG,
		IR_ARGTYPE_STACK,
		IR_ARGTYPE_MEM,
		IR_ARGTYPE_SINT,
		IR_ARGTYPE_UINT,
		IR_ARGTYPE_FLOAT,

		IR_ARGTYPE_ID,
		IR_ARGTYPE_SSAID,
		IR_ARGTYPE_ARG,
		IR_ARGTYPE_TMP,
		IR_ARGTYPE_MEMOP,
	};
	struct IRArgument {
		IRArgTypes type = IR_ARGTYPE_UNKN;
		uint32_t size = 0;
		union {
			ArgSInt sval;
			ArgUInt uval;
			ArgFloat fval;
			ArgMem mem;
			Reference ref;
		};

		bool operator!() {
			return !type;
		}
		operator bool() {
			return !!type;
		}
		bool isConst() {
			return type == IR_ARGTYPE_SINT || type == IR_ARGTYPE_UINT || type == IR_ARGTYPE_FLOAT;
		}
		static inline IRArgument create() {
			return IRArgument();
		}
		static inline IRArgument createVal (int64_t val, uint64_t size) {
			IRArgument arg;
			arg.type = IR_ARGTYPE_SINT;
			arg.sval = val;
			arg.size = size;
			return arg;
		}
		static inline IRArgument createVal (uint64_t val, uint64_t size) {
			IRArgument arg;
			arg.type = IR_ARGTYPE_UINT;
			arg.uval = val;
			arg.size = size;
			return arg;
		}
		static inline IRArgument createVal (double val, uint64_t size) {
			IRArgument arg;
			arg.type = IR_ARGTYPE_FLOAT;
			arg.fval = val;
			arg.size = size;
			return arg;
		}
		static inline IRArgument createMemOp (Register* segment, Register* base, Register* index, ArgSInt scale, ArgSInt disp, uint64_t size) {
			IRArgument arg;
			arg.type = IR_ARGTYPE_MEMOP;
			arg.mem.segment = segment ? segment->id : 0;
			arg.mem.base = base ? base->id : 0;
			arg.mem.index = index ? index->id : 0;
			arg.mem.scale = scale;
			arg.mem.disp = disp;
			arg.size = size;
			return arg;
		}
		static inline IRArgument create (IRArgTypes type, Reference ref = {0,0}, uint32_t size = 0) {
			IRArgument arg;
			arg.type = type;
			arg.ref = ref;
			arg.size = size;
			return arg;
		}
		static inline IRArgument createIRId (HId id,uint64_t size) {
			return create(IR_ARGTYPE_ID, {id, 0}, size);
		}
		static inline IRArgument createSSAId (HId ssaId, uint64_t size) {
			return create(IR_ARGTYPE_SSAID, {ssaId, 0}, size);
		}
		static inline IRArgument createTmp (HId id, uint32_t size = 0) {
			return create(IR_ARGTYPE_TMP, {id, 0}, size);
		}
		static inline IRArgument createReg (Register* reg) {
			return create(IR_ARGTYPE_REG, {reg->id, 0}, reg->size);
		}
		static inline IRArgument createMem (Memory* memory, HId index = 0) {
			return create(IR_ARGTYPE_MEM, {memory->id, index}, 0);
		}
		static inline IRArgument createStck (Stack* stack, HId index = 0) {
			return create(IR_ARGTYPE_STACK, {stack->id, index}, stack->wordbitsize);
		}

		void print (Architecture* arch);
	};


	inline bool operator== (IRArgument& lhs, IRArgument& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size) {
			switch (lhs.type) {
			case IR_ARGTYPE_SINT:
				return lhs.sval == rhs.sval;
			case IR_ARGTYPE_UINT:
				return lhs.uval == rhs.uval;
			case IR_ARGTYPE_FLOAT:
				return lhs.fval == rhs.fval;
			case IR_ARGTYPE_REG:
			case IR_ARGTYPE_STACK:
			case IR_ARGTYPE_MEM:
			case IR_ARGTYPE_ARG:
			case IR_ARGTYPE_TMP:
			case IR_ARGTYPE_ID:
				return lhs.ref.refId == rhs.ref.refId && lhs.ref.index == rhs.ref.index;
			case IR_ARGTYPE_MEMOP:
				return lhs.mem == rhs.mem;
			default:
				return false;
			}
			return true;
		}
		return false;
	}
	inline bool operator!= (IRArgument& lhs, IRArgument& rhs) {
		return ! (lhs == rhs);
	}
}

#endif //H_ARGUMENT_H
