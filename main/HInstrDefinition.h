#ifndef HINSTRDEFINITION_H
#define HINSTRDEFINITION_H


#include "HString.h"
#include <stdint.h>
#include "HGeneral.h"
#include "HId.h"
#include "HIR.h"

namespace holodec {

#define H_AHG_IN (0x100)
#define H_AHG_OUT (0x200)

	enum HInstructionType {
		H_INSTR_TYPE_UNKNOWN = 0,

		H_INSTR_TYPE_NOP,
		H_INSTR_TYPE_JMP,
		H_INSTR_TYPE_CJMP,
		H_INSTR_TYPE_CALL,
		H_INSTR_TYPE_RCALL,
		H_INSTR_TYPE_RET,

		H_INSTR_TYPE_COMP,

		H_INSTR_TYPE_MOV,
		H_INSTR_TYPE_LEA,
		H_INSTR_TYPE_LOAD,
		H_INSTR_TYPE_STORE,
		H_INSTR_TYPE_XCHG,
		H_INSTR_TYPE_EXTEND,

		H_INSTR_TYPE_PUSH,
		H_INSTR_TYPE_POP,
		H_INSTR_TYPE_ENTER,
		H_INSTR_TYPE_LEAVE,

		H_INSTR_TYPE_CMP,

		H_INSTR_TYPE_ADD,
		H_INSTR_TYPE_SUB,
		H_INSTR_TYPE_MUL,
		H_INSTR_TYPE_DIV,
		H_INSTR_TYPE_ABS,
		H_INSTR_TYPE_OR,
		H_INSTR_TYPE_AND,
		H_INSTR_TYPE_XOR,
		H_INSTR_TYPE_NOT,
		H_INSTR_TYPE_NEG,
		H_INSTR_TYPE_CPL,

		H_INSTR_TYPE_SHH,
		H_INSTR_TYPE_SHL,
		H_INSTR_TYPE_ROR,
		H_INSTR_TYPE_ROL,
		H_INSTR_TYPE_SWAP,

		H_INSTR_TYPE_BITTEST,
		H_INSTR_TYPE_BITSET,
		H_INSTR_TYPE_BITRESET,

		H_INSTR_TYPE_NEW,
		H_INSTR_TYPE_IO,
		H_INSTR_TYPE_SWITCH,
		H_INSTR_TYPE_CASE,
		H_INSTR_TYPE_CRYPTO,
		H_INSTR_TYPE_SYNC,

		H_INSTR_TYPE_TRAP,
		H_INSTR_TYPE_SYSCALL,
		H_INSTR_TYPE_HALT,

		H_INSTR_TYPE_UNDEFINED,
		H_INSTR_TYPE_ILLEGAL,
	};

	
	struct HInstrDefinition {//16*8 -> 128 bytes
		HId id;
		HString mnemonics;
		HLocalBackedList<HIRRepresentation,4> irs;
		HInstructionType type;
		HInstructionType type2;

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Instruction: %s\n", mnemonics.cstr());
			
		}
	};

}

#endif // HINSTRDEFINITION_H
