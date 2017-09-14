
#ifndef H_ARGUMENT_H
#define H_ARGUMENT_H

#include <stdint.h>
#include "HGeneral.h"
#include "HId.h"
#include "HRegister.h"
#include "HStack.h"

namespace holodec {

	class HArchitecture;

#define H_ARGTYPE_REG 		0x00001
#define H_ARGTYPE_STACK		0x00002
#define H_ARGTYPE_MEM 		0x00004
#define H_ARGTYPE_SINT		0x00006
#define H_ARGTYPE_UINT 		0x00007
#define H_ARGTYPE_FLOAT		0x00008

#define HIR_ARGTYPE_ID 		0x10001
#define HIR_ARGTYPE_INSTR 	0x10002
#define HIR_ARGTYPE_ARG 	0x10003
#define HIR_ARGTYPE_TMP 	0x10004

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
	struct HArgStck {
		HId id;//id of the stack
		HId index;//index into the stack or 0 for whole stack
	};
	struct HArgument {
		union { //ordered first because of tighter memory layout
			HArgSInt sval;
			HArgUInt uval;
			HArgFloat fval;
			HArgMem mem;
			HId reg;
			HId index;
			HArgStck stack;
		};
		HId id = 0;
		uint64_t size = 0;
		uint64_t type = 0;

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
		static inline HArgument createMem (HRegister* segment, HRegister* base, HRegister* index, HArgSInt scale, HArgSInt disp, uint64_t size) {
			HArgument arg;
			arg.type = H_ARGTYPE_MEM;
			arg.mem.segment = segment->id;
			arg.mem.base = base->id;
			arg.mem.index = index->id;
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
		static inline HArgument createReg (HRegister* reg) {
			HArgument arg;
			arg.type = H_ARGTYPE_REG;
			arg.reg = reg->id;
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
		if (lhs.type == rhs.type) {
			switch (lhs.type) {
			case H_ARGTYPE_SINT:
				return lhs.sval == rhs.sval && lhs.size == rhs.size;
			case H_ARGTYPE_UINT:
				return lhs.uval == rhs.uval && lhs.size == rhs.size;
			case H_ARGTYPE_FLOAT:
				return lhs.fval == rhs.fval && lhs.size == rhs.size;
			}
		}
		return false;
	}
	inline bool operator!= (HArgument& lhs, HArgument& rhs) {
		return ! (lhs == rhs);
	}
}

#endif //H_ARGUMENT_H
