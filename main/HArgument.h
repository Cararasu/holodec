
#ifndef H_ARGUMENT_H
#define H_ARGUMENT_H

#include <stdint.h>
#include "HGeneral.h"
#include "HId.h"
#include "HRegister.h"
#include "HStack.h"
#include "HMemory.h"

namespace holodec {

	class HArchitecture;

	enum HSSAArgTypes{
		HSSA_ARGTYPE_UNKN = 0,
		HSSA_ARGTYPE_REG,
		HSSA_ARGTYPE_STACK,
		HSSA_ARGTYPE_MEM,
		HSSA_ARGTYPE_SINT,
		HSSA_ARGTYPE_UINT,
		HSSA_ARGTYPE_FLOAT,
		HSSA_ARGTYPE_ID,
		HSSA_ARGTYPE_BLOCK,
	};

	typedef int64_t HArgSInt;
	typedef uint64_t HArgUInt;
	typedef double HArgFloat;
	struct HArgMem { //segment::[base + index*scale + disp]
		HId segment;
		HId base;
		HId index;
		HArgSInt scale;
		HArgSInt disp;
	};
	bool inline operator==(HArgMem& lhs, HArgMem& rhs){
		return lhs.segment == rhs.segment && lhs.base == rhs.base && lhs.index == rhs.index && lhs.scale == rhs.scale && lhs.disp == rhs.disp;
	}
	bool inline operator!=(HArgMem& lhs, HArgMem& rhs){
		return !(lhs == rhs);
	}
	struct HArgStck {
		HId id;//id of the stack
		HId index;//index into the stack or 0 for whole stack
	};
	bool inline operator==(HArgStck& lhs, HArgStck& rhs){
		return lhs.id == rhs.id && lhs.index == rhs.index;
	}
	bool inline operator!=(HArgStck& lhs, HArgStck& rhs){
		return !(lhs == rhs);
	}
	struct HSSAArgument {
		HId id = 0;
		HSSAArgTypes type = HSSA_ARGTYPE_UNKN;
		uint32_t size = 0;
		union {
			HArgSInt sval;
			HArgUInt uval;
			HArgFloat fval;
			struct{
				HId refId;
				HId wusl;
			};
		};

		bool operator!() {
			return !type;
		}
		operator bool() {
			return !!type;
		}
		bool isConst() {
			return type == HSSA_ARGTYPE_SINT || type == HSSA_ARGTYPE_UINT || type == HSSA_ARGTYPE_FLOAT;
		}
		static inline HSSAArgument create() {
			return HSSAArgument();
		}
		static inline HSSAArgument createVal (int64_t val, uint64_t size) {
			HSSAArgument arg;
			arg.type = HSSA_ARGTYPE_SINT;
			arg.sval = val;
			arg.size = size;
			return arg;
		}
		static inline HSSAArgument createVal (uint64_t val, uint64_t size) {
			HSSAArgument arg;
			arg.type = HSSA_ARGTYPE_UINT;
			arg.uval = val;
			arg.size = size;
			return arg;
		}
		static inline HSSAArgument createVal (double val, uint64_t size) {
			HSSAArgument arg;
			arg.type = HSSA_ARGTYPE_FLOAT;
			arg.fval = val;
			arg.size = size;
			return arg;
		}
		static inline HSSAArgument create (HSSAArgTypes type, HId id = 0, HId refId = 0, HId index = 0, uint32_t size = 0) {
			HSSAArgument arg;
			arg.type = type;
			arg.id = id;
			arg.refId = refId;
			arg.wusl = index;
			arg.size = size;
			return arg;
		}
		static inline HSSAArgument createId (HId id, uint64_t size) {
			return create(HSSA_ARGTYPE_ID, id, 0, 0, size);
		}
		static inline HSSAArgument createReg (HRegister* reg, HId id = 0) {
			return create(HSSA_ARGTYPE_REG, id, reg->id, 0, reg->size);
		}
		static inline HSSAArgument createReg (HId refId, uint32_t size, HId id = 0) {
			return create(HSSA_ARGTYPE_REG, id, refId, 0, size);
		}
		static inline HSSAArgument createMem (HMemory* mem, HId id = 0) {
			return create(HSSA_ARGTYPE_MEM, id, mem->id, 0, 0);
		}
		static inline HSSAArgument createMem (HId refId, HId id = 0) {
			return create(HSSA_ARGTYPE_MEM, id, refId, 0, 0);
		}
		static inline HSSAArgument createStck (HStack* stack, HId index) {
			return create(HSSA_ARGTYPE_STACK, 0, stack->id, 0, stack->wordbitsize);
		}
		static inline HSSAArgument createStck (HId refId, uint32_t size, HId id = 0) {
			return create(HSSA_ARGTYPE_STACK, id, refId, 0, size);
		}
		static inline HSSAArgument createBlock (HId refId) {
			return create(HSSA_ARGTYPE_BLOCK, 0, refId);
		}

		void print (HArchitecture* arch);
	};


	inline bool operator== (HSSAArgument& lhs, HSSAArgument& rhs) {
		if (lhs.type == rhs.type && lhs.id == rhs.id && lhs.size == rhs.size) {
			switch (lhs.type) {
			case HSSA_ARGTYPE_SINT:
				return lhs.sval == rhs.sval;
			case HSSA_ARGTYPE_UINT:
				return lhs.uval == rhs.uval;
			case HSSA_ARGTYPE_FLOAT:
				return lhs.fval == rhs.fval;
			case HSSA_ARGTYPE_REG:
			case HSSA_ARGTYPE_STACK:
			case HSSA_ARGTYPE_MEM:
			case HSSA_ARGTYPE_ID:
			case HSSA_ARGTYPE_BLOCK:
				return lhs.refId == rhs.refId && lhs.wusl == rhs.wusl;
				return true;
			default:
				return false;
			}
			return true;
		}
		return false;
	}
	inline bool operator!= (HSSAArgument& lhs, HSSAArgument& rhs) {
		return ! (lhs == rhs);
	}

	enum HIRArgTypes{
		HIR_ARGTYPE_UNKN = 0,
		HIR_ARGTYPE_REG,
		HIR_ARGTYPE_STACK,
		HIR_ARGTYPE_MEM,
		HIR_ARGTYPE_SINT,
		HIR_ARGTYPE_UINT,
		HIR_ARGTYPE_FLOAT,

		HIR_ARGTYPE_ID,
		HIR_ARGTYPE_SSAID,
		HIR_ARGTYPE_ARG,
		HIR_ARGTYPE_TMP,
		HIR_ARGTYPE_MEMOP,
	};
	struct HIRArgument {
		HIRArgTypes type = HIR_ARGTYPE_UNKN;
		uint32_t size = 0;
		union {
			HArgSInt sval;
			HArgUInt uval;
			HArgFloat fval;
			HArgMem mem;
			struct{
				HId refId;
				HId index;
			};
		};

		bool operator!() {
			return !type;
		}
		operator bool() {
			return !!type;
		}
		bool isConst() {
			return type == HIR_ARGTYPE_SINT || type == HIR_ARGTYPE_UINT || type == HIR_ARGTYPE_FLOAT;
		}
		static inline HIRArgument create() {
			return HIRArgument();
		}
		static inline HIRArgument createVal (int64_t val, uint64_t size) {
			HIRArgument arg;
			arg.type = HIR_ARGTYPE_SINT;
			arg.sval = val;
			arg.size = size;
			return arg;
		}
		static inline HIRArgument createVal (uint64_t val, uint64_t size) {
			HIRArgument arg;
			arg.type = HIR_ARGTYPE_UINT;
			arg.uval = val;
			arg.size = size;
			return arg;
		}
		static inline HIRArgument createVal (double val, uint64_t size) {
			HIRArgument arg;
			arg.type = HIR_ARGTYPE_FLOAT;
			arg.fval = val;
			arg.size = size;
			return arg;
		}
		static inline HIRArgument createMemOp (HRegister* segment, HRegister* base, HRegister* index, HArgSInt scale, HArgSInt disp, uint64_t size) {
			HIRArgument arg;
			arg.type = HIR_ARGTYPE_MEMOP;
			arg.mem.segment = segment ? segment->id : 0;
			arg.mem.base = base ? base->id : 0;
			arg.mem.index = index ? index->id : 0;
			arg.mem.scale = scale;
			arg.mem.disp = disp;
			arg.size = size;
			return arg;
		}
		static inline HIRArgument create (HIRArgTypes type, HId refId = 0, HId index = 0, uint32_t size = 0) {
			HIRArgument arg;
			arg.type = type;
			arg.refId = refId;
			arg.index = index;
			arg.size = size;
			return arg;
		}
		static inline HIRArgument createIRId (HId id,uint64_t size) {
			return create(HIR_ARGTYPE_ID, id, 0, size);
		}
		static inline HIRArgument createSSAId (HId id,uint64_t size) {
			return create(HIR_ARGTYPE_SSAID, id, 0, size);
		}
		static inline HIRArgument createTmp (HId id, uint32_t size = 0) {
			return create(HIR_ARGTYPE_TMP, id, 0, size);
		}
		static inline HIRArgument createReg (HRegister* reg) {
			return create(HIR_ARGTYPE_REG, reg->id, 0, reg->size);
		}
		static inline HIRArgument createMem (HMemory* memory, HId index = 0) {
			return create(HIR_ARGTYPE_STACK, memory->id, index, 0);
		}
		static inline HIRArgument createStck (HStack* stack, HId index = 0) {
			return create(HIR_ARGTYPE_STACK, stack->id, index, stack->wordbitsize);
		}

		void print (HArchitecture* arch);
	};


	inline bool operator== (HIRArgument& lhs, HIRArgument& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size) {
			switch (lhs.type) {
			case HIR_ARGTYPE_SINT:
				return lhs.sval == rhs.sval;
			case HIR_ARGTYPE_UINT:
				return lhs.uval == rhs.uval;
			case HIR_ARGTYPE_FLOAT:
				return lhs.fval == rhs.fval;
			case HIR_ARGTYPE_REG:
			case HIR_ARGTYPE_STACK:
			case HIR_ARGTYPE_MEM:
			case HIR_ARGTYPE_ARG:
			case HIR_ARGTYPE_TMP:
			case HIR_ARGTYPE_ID:
				return lhs.refId == rhs.refId && lhs.index == rhs.index;
			case HIR_ARGTYPE_MEMOP:
				return lhs.mem == rhs.mem;
			default:
				return false;
			}
			return true;
		}
		return false;
	}
	inline bool operator!= (HIRArgument& lhs, HIRArgument& rhs) {
		return ! (lhs == rhs);
	}
}

#endif //H_ARGUMENT_H
