#ifndef HINSTRDEFINITION_H
#define HINSTRDEFINITION_H


#include "HString.h"
#include <stdint.h>
#include "HGeneral.h"
#include "HoloIR.h"

namespace holodec {

#define H_AHG_IN (0x100)
#define H_AHG_OUT (0x200)

	enum HInstructionCondition {
		H_INSTR_COND_TRUE = 	0x0,//always executed/jumped
		H_INSTR_COND_E,	//equals
		H_INSTR_COND_NE,	//non equals
		H_INSTR_COND_G,	//greater signed
		H_INSTR_COND_GE,	//greater equals signed
		H_INSTR_COND_L,	//lower signed
		H_INSTR_COND_LE,	//lower equals signed
		H_INSTR_COND_A,	//above unsigned
		H_INSTR_COND_AE,	//above equals unsigned
		H_INSTR_COND_B,	//below unsigned
		H_INSTR_COND_BE,	//below equals unsigned
		H_INSTR_COND_C,	//carry
		H_INSTR_COND_NC,	//non carry
		H_INSTR_COND_O,	//overflow
		H_INSTR_COND_NO,	//non overflow
		H_INSTR_COND_NEG,//negative
		H_INSTR_COND_POS,//positive
		H_INSTR_COND_UNK,//unknown
		H_INSTR_COND_FALSE = 0x80000,//not executed/jumped
	};

	enum HInstructionType {
		H_INSTR_TYPE_UNKNOWN = 0,

		H_INSTR_TYPE_NOP,
		H_INSTR_TYPE_JMP,
		H_INSTR_TYPE_RJMP,
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
		HString mnemonics;
		HLocalBackedLists<HIRRepresentation,4> irs;
		size_t type;
		size_t type2;
		HInstructionCondition condition;
		size_t cycles;
		size_t failcycles;

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Instruction: %s\n", mnemonics.cstr());
			
		}
	};

}

#endif // HINSTRDEFINITION_H
