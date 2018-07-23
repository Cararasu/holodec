
#ifndef H_ARGUMENT_H
#define H_ARGUMENT_H

#include <stdint.h>
#include <assert.h>
#include "General.h"

#include "Register.h"
#include "Stack.h"
#include "Memory.h"
#include "SSA.h"
#include "CHolodecHeader.h"

namespace holodec {

	struct Architecture;

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
	
	struct ArgMem { //segment::[base + index*scale + disp]
		HId segment;
		HId base;
		HId index;
		int64_t scale;
		int64_t disp;
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
		IR_ARGTYPE_VALUE,

		IR_ARGTYPE_ID,
		IR_ARGTYPE_SSAID,
		IR_ARGTYPE_ARG,
		IR_ARGTYPE_TMP,
		IR_ARGTYPE_IP,
		IR_ARGTYPE_MEMOP,
	};
	struct IRArgument {
		IRArgTypes type = IR_ARGTYPE_UNKN;
		SSAType argtype = SSAType::eUnknown;
		union {
			int64_t sval;
			uint64_t uval;
			double fval;
			ArgMem mem;
			Reference ref;
		};
		uint32_t offset = 0, size = 0;

		bool operator!() {
			return type == IR_ARGTYPE_UNKN;
		}
		operator bool() {
			return type != IR_ARGTYPE_UNKN;
		}
		bool isConst() {
			return type == IR_ARGTYPE_VALUE;
		}
		bool isConst(SSAType argtype) {
			return type == IR_ARGTYPE_VALUE && this->argtype == argtype;
		}
		static inline IRArgument create() {
			return IRArgument();
		}
		static inline IRArgument createSVal (int64_t val, uint32_t size) {
			IRArgument arg;
			arg.type = IR_ARGTYPE_VALUE;
			arg.argtype = SSAType::eInt;
			arg.sval = val;
			arg.size = size;
			return arg;
		}
		static inline IRArgument createUVal (uint64_t val, uint32_t size) {
			IRArgument arg;
			arg.type = IR_ARGTYPE_VALUE;
			arg.argtype = SSAType::eUInt;
			arg.uval = val;
			arg.size = size;
			return arg;
		}
		static inline IRArgument createFVal (double val, uint32_t size) {
			IRArgument arg;
			arg.type = IR_ARGTYPE_VALUE;
			arg.argtype = SSAType::eFloat;
			arg.fval = val;
			arg.size = size;
			return arg;
		}
		static inline IRArgument createMemOp (Register* segment, Register* base, Register* index, int64_t scale, int64_t disp, uint32_t size) {
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
		static inline IRArgument create (IRArgTypes type, Reference ref = {0,0}, uint32_t size = 0, uint32_t offset = 0) {
			IRArgument arg;
			arg.type = type;
			arg.ref = ref;
			arg.size = size;
			arg.offset = offset;
			return arg;
		}
		static inline IRArgument createIRId (HId id, uint32_t size) {
			return create(IR_ARGTYPE_ID, {id, 0}, size);
		}
		static inline IRArgument createSSAId(HId ssaId, uint32_t size) {
			return create(IR_ARGTYPE_SSAID, { ssaId, 0 }, size);
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
		if (lhs.type == rhs.type && lhs.argtype == rhs.argtype && lhs.size == rhs.size && lhs.offset == rhs.offset) {
			switch (lhs.type) {
			case IR_ARGTYPE_IP:
				return true;
			case IR_ARGTYPE_VALUE:
				switch (lhs.argtype) {
				case SSAType::eInt:
					return lhs.sval == rhs.sval;
				case SSAType::eUInt:
					return lhs.uval == rhs.uval;
				case SSAType::eFloat:
					return lhs.fval == rhs.fval;
				}
				return false;
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
