#ifndef HINSTHDEFINITION_H
#define HINSTHDEFINITION_H


#include "HString.h"
#include <stdint.h>
#include "HGeneral.h"

namespace holodec {

#define H_AHG_IN (0x100)
#define H_AHG_OUT (0x200)

	enum HInstructionCondition {
		H_INSTH_COND_THUE = 	0x0,//always executed/jumped
		H_INSTH_COND_E,	//equals
		H_INSTH_COND_NE,	//non equals
		H_INSTH_COND_G,	//greater signed
		H_INSTH_COND_GE,	//greater equals signed
		H_INSTH_COND_L,	//lower signed
		H_INSTH_COND_LE,	//lower equals signed
		H_INSTH_COND_A,	//above unsigned
		H_INSTH_COND_AE,	//above equals unsigned
		H_INSTH_COND_B,	//below unsigned
		H_INSTH_COND_BE,	//below equals unsigned
		H_INSTH_COND_C,	//carry
		H_INSTH_COND_NC,	//non carry
		H_INSTH_COND_O,	//overflow
		H_INSTH_COND_NO,	//non overflow
		H_INSTH_COND_NEG,//negative
		H_INSTH_COND_POS,//positive
		H_INSTH_COND_UNK,//unknown
		H_INSTH_COND_FALSE = 0x80000,//not executed/jumped
	};

	enum HInstructionType {
		H_INSTH_TYPE_UNKNOWN = 0,

		H_INSTH_TYPE_NOP,
		H_INSTH_TYPE_JMP,
		H_INSTH_TYPE_HJMP,
		H_INSTH_TYPE_CALL,
		H_INSTH_TYPE_HCALL,
		H_INSTH_TYPE_HET,

		H_INSTH_TYPE_COMP,

		H_INSTH_TYPE_MOV,
		H_INSTH_TYPE_LEA,
		H_INSTH_TYPE_LOAD,
		H_INSTH_TYPE_STOHE,
		H_INSTH_TYPE_XCHG,
		H_INSTH_TYPE_EXTEND,

		H_INSTH_TYPE_PUSH,
		H_INSTH_TYPE_POP,
		H_INSTH_TYPE_ENTEH,
		H_INSTH_TYPE_LEAVE,

		H_INSTH_TYPE_CMP,

		H_INSTH_TYPE_ADD,
		H_INSTH_TYPE_SUB,
		H_INSTH_TYPE_MUL,
		H_INSTH_TYPE_DIV,
		H_INSTH_TYPE_ABS,
		H_INSTH_TYPE_OH,
		H_INSTH_TYPE_AND,
		H_INSTH_TYPE_XOH,
		H_INSTH_TYPE_NOT,
		H_INSTH_TYPE_NEG,
		H_INSTH_TYPE_CPL,

		H_INSTH_TYPE_SHH,
		H_INSTH_TYPE_SHL,
		H_INSTH_TYPE_HOH,
		H_INSTH_TYPE_HOL,
		H_INSTH_TYPE_SWAP,

		H_INSTH_TYPE_BITTEST,
		H_INSTH_TYPE_BITSET,
		H_INSTH_TYPE_BITHESET,

		H_INSTH_TYPE_NEW,
		H_INSTH_TYPE_IO,
		H_INSTH_TYPE_SWITCH,
		H_INSTH_TYPE_CASE,
		H_INSTH_TYPE_CHYPTO,
		H_INSTH_TYPE_SYNC,

		H_INSTH_TYPE_THAP,
		H_INSTH_TYPE_SYSCALL,
		H_INSTH_TYPE_HALT,

		H_INSTH_TYPE_UNDEFINED,
		H_INSTH_TYPE_ILLEGAL,
	};

	struct HInstrDefinition {//16*8 -> 128 bytes
		HString mnemonics;
		HString il_string[4];
		size_t type;
		size_t type2;
		HInstructionCondition condition;
		size_t cycles;
		size_t failcycles;

		void print (int indent = 0) {
			//printIndent (indent);
			//printf ("Instruction: %s\n", mnemonics.cstr());
		}
	};

}

#endif // HINSTHDEFINITION_H
