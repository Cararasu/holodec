#ifndef HINSTRDEFINITION_H
#define HINSTRDEFINITION_H


#include "HString.h"
#include <stdint.h>
#include "General.h"

#include "IR.h"

namespace holodec {

#define H_AHG_IN (0x100)
#define H_AHG_OUT (0x200)

	enum class InstructionType {
		eUnknown = INSTR_TYPE_UNKNOWN,

		eNop = INSTR_TYPE_NOP,
		eJmp = INSTR_TYPE_JMP,
		eCJmp = INSTR_TYPE_CJMP,
		eCall = INSTR_TYPE_CALL,
		eRCall = INSTR_TYPE_RCALL,
		eRet = INSTR_TYPE_RET,

		eComp = INSTR_TYPE_COMP,

		eMov = INSTR_TYPE_MOV,
		eLea = INSTR_TYPE_LEA,
		eLoad = INSTR_TYPE_LOAD,
		eStore = INSTR_TYPE_STORE,
		eXchg = INSTR_TYPE_XCHG,
		eExtend = INSTR_TYPE_EXTEND,

		ePush = INSTR_TYPE_PUSH,
		ePop = INSTR_TYPE_POP,
		eEnter = INSTR_TYPE_ENTER,
		eLeave = INSTR_TYPE_LEAVE,

		eCmp = INSTR_TYPE_CMP,

		eAdd = INSTR_TYPE_ADD,
		eSub = INSTR_TYPE_SUB,
		eMul = INSTR_TYPE_MUL,
		eDiv = INSTR_TYPE_DIV,
		eAbs = INSTR_TYPE_ABS,
		eOr = INSTR_TYPE_OR,
		eAnd = INSTR_TYPE_AND,
		eXor = INSTR_TYPE_XOR,
		eNot = INSTR_TYPE_NOT,
		eNeg = INSTR_TYPE_NEG,
		eCpl = INSTR_TYPE_CPL,

		eShr = INSTR_TYPE_SHR,
		eShl = INSTR_TYPE_SHL,
		eRor = INSTR_TYPE_ROR,
		eRol = INSTR_TYPE_ROL,
		eSwap = INSTR_TYPE_SWAP,

		eBitTest = INSTR_TYPE_BITTEST,
		eBitSet = INSTR_TYPE_BITSET,
		eBitReset = INSTR_TYPE_BITRESET,

		eNew = INSTR_TYPE_NEW,
		eIO = INSTR_TYPE_IO,
		eSwitch = INSTR_TYPE_SWITCH,
		eCase = INSTR_TYPE_CASE,
		eCrypto = INSTR_TYPE_CRYPTO,
		eSync = INSTR_TYPE_SYNC,

		eTrap = INSTR_TYPE_TRAP,
		eSyscall = INSTR_TYPE_SYSCALL,
		eHalt = INSTR_TYPE_HALT,

		eUndefined = INSTR_TYPE_UNDEFINED,
		eIllegal = INSTR_TYPE_ILLEGAL,
	};

	
	struct InstrDefinition {//16*8 -> 128 bytes
		HId id;
		HString mnemonics;
		HList<IRRepresentation> irs;
		InstructionType type;
		InstructionType type2;

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Instruction: %s\n", mnemonics.cstr());
			
		}
	};

}

#endif // HINSTRDEFINITION_H
