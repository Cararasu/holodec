
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

#define H_ARGTYPE_UNKN		0x00001
#define H_ARGTYPE_REG 		0x00002
#define H_ARGTYPE_STACK		0x00003
#define H_ARGTYPE_MEM 		0x00004
#define H_ARGTYPE_SINT		0x00006
#define H_ARGTYPE_UINT 		0x00007
#define H_ARGTYPE_FLOAT		0x00008

#define HIR_ARGTYPE_ID 		0x10001
#define HIR_ARGTYPE_ARG 	0x10003
#define HIR_ARGTYPE_TMP 	0x10004
#define HIR_ARGTYPE_MEMOP	0x10005

#define HSSA_ARGTYPE_ID 	0x20001
#define HSSA_ARGTYPE_BLOCK	0x20002

	typedef int64_t HArgSInt;
	typedef int64_t HArgUInt;
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
	struct HArgument {
		uint32_t type = 0;
		HId id = 0;
		uint32_t size = 0;
		union { //ordered first because of tighter memory layout
			HArgSInt sval;
			HArgUInt uval;
			HArgFloat fval;
			HArgMem mem;
			HId reg;
			HId index;
			HArgStck stack;
		};

		bool operator!() {
			return !type;
		}
		operator bool() {
			return !!type;
		}
		bool isConst() {
			return type == H_ARGTYPE_SINT || type == H_ARGTYPE_UINT || type == H_ARGTYPE_FLOAT;
		}
		static inline HArgument create() {
			return HArgument();
		}
		static inline HArgument createUnknown() {
			HArgument arg;
			arg.type = H_ARGTYPE_UNKN;
			return arg;
		}
		static inline HArgument createUnknownReg(HRegister* reg) {
			HArgument arg;
			arg.type = H_ARGTYPE_REG;
			arg.reg = reg->id;
			return arg;
		}
		static inline HArgument createUnknownReg(HId id) {
			HArgument arg;
			arg.type = H_ARGTYPE_REG;
			arg.reg = id;
			return arg;
		}
		static inline HArgument createUnknownMem(HMemory* mem) {
			HArgument arg;
			arg.type = H_ARGTYPE_MEM;
			arg.index = mem->id;
			return arg;
		}
		static inline HArgument createUnknownMem(HId id) {
			HArgument arg;
			arg.type = H_ARGTYPE_MEM;
			arg.index = id;
			return arg;
		}
		static inline HArgument createVal (int64_t val, uint64_t size) {
			HArgument arg;
			arg.type = H_ARGTYPE_SINT;
			arg.sval = val;
			arg.size = size;
			return arg;
		}
		static inline HArgument createVal (uint64_t val, uint64_t size) {
			HArgument arg;
			arg.type = H_ARGTYPE_UINT;
			arg.uval = val;
			arg.size = size;
			return arg;
		}
		static inline HArgument createVal (double val, uint64_t size) {
			HArgument arg;
			arg.type = H_ARGTYPE_FLOAT;
			arg.fval = val;
			arg.size = size;
			return arg;
		}
		static inline HArgument createMemOp (HRegister* segment, HRegister* base, HRegister* index, HArgSInt scale, HArgSInt disp, uint64_t size) {
			HArgument arg;
			arg.type = HIR_ARGTYPE_MEMOP;
			arg.mem.segment = segment ? segment->id : 0;
			arg.mem.base = base ? base->id : 0;
			arg.mem.index = index ? index->id : 0;
			arg.mem.scale = scale;
			arg.mem.disp = disp;
			arg.size = size;
			return arg;
		}
		static inline HArgument createId (uint32_t type,HId id,uint64_t size) {
			HArgument arg;
			arg.type = type;
			arg.id = id;
			arg.size = size;
			return arg;
		}
		static inline HArgument createIndex (uint32_t type, HId index) {
			HArgument arg;
			arg.type = type;
			arg.index = index;
			arg.size = 0;
			return arg;
		}
		static inline HArgument createMem (HMemory* memory, HId id = 0) {
			HArgument arg;
			arg.type = H_ARGTYPE_MEM;
			arg.index = memory->id;
			arg.id = id;
			arg.size = 0;
			return arg;
		}
		static inline HArgument createReg (HRegister* reg, HId id = 0) {
			HArgument arg;
			arg.type = H_ARGTYPE_REG;
			arg.reg = reg->id;
			arg.id = id;
			arg.size = reg->size;
			return arg;
		}
		static inline HArgument createStck (HStack* stack, HId index) {
			HArgument arg;
			arg.type = H_ARGTYPE_STACK;
			arg.stack.id = stack->id;
			arg.stack.index = index;
			arg.size = stack->wordbitsize;
			return arg;
		}

		void print (HArchitecture* arch);
	};


	inline bool operator== (HArgument& lhs, HArgument& rhs) {
		if (lhs.type == rhs.type && lhs.id == rhs.id && lhs.size == rhs.size) {
			switch (lhs.type) {
			case H_ARGTYPE_SINT:
				return lhs.sval == rhs.sval;
			case H_ARGTYPE_UINT:
				return lhs.uval == rhs.uval;
			case H_ARGTYPE_FLOAT:
				return lhs.fval == rhs.fval;
			case H_ARGTYPE_REG:
				return lhs.reg == rhs.reg;
			case H_ARGTYPE_STACK:
				return lhs.stack == rhs.stack;
			case H_ARGTYPE_MEM:
			case HIR_ARGTYPE_ARG:
			case HIR_ARGTYPE_TMP:
				return lhs.index == rhs.index;
			case HIR_ARGTYPE_MEMOP:
				return lhs.mem == rhs.mem;
			case HSSA_ARGTYPE_BLOCK:
			case HSSA_ARGTYPE_ID:
			case HIR_ARGTYPE_ID:
				return true;
			default:
				return false;
			}
			return true;
		}
		return false;
	}
	inline bool operator!= (HArgument& lhs, HArgument& rhs) {
		return ! (lhs == rhs);
	}

}

#endif //H_ARGUMENT_H
